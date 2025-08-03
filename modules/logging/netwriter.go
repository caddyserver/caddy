// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rosedblabs/wal"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(&NetWriter{})
}

// NetWriter implements a log writer that outputs to a network socket. If
// the socket goes down, it will dump logs to stderr while it attempts to
// reconnect. Logs are written to a WAL first and then asynchronously
// flushed to the network to avoid blocking HTTP request handling.
type NetWriter struct {
	// The address of the network socket to which to connect.
	Address string `json:"address,omitempty"`

	// The timeout to wait while connecting to the socket.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// If enabled, allow connections errors when first opening the
	// writer. The error and subsequent log entries will be reported
	// to stderr instead until a connection can be re-established.
	SoftStart bool `json:"soft_start,omitempty"`

	// How often to attempt reconnection when the network connection fails.
	ReconnectInterval caddy.Duration `json:"reconnect_interval,omitempty"`

	// Buffer size for the WAL flush channel.
	BufferSize int `json:"buffer_size,omitempty"`

	logger              *slog.Logger
	addr                caddy.NetworkAddress
	wal                 *wal.WAL
	walDir              string
	flushCtx            context.Context
	flushCtxCancel      context.CancelFunc
	flushWg             sync.WaitGroup
	lastProcessedOffset int64
	mu                  sync.RWMutex
	walMu               sync.Mutex // synchronizes WAL read/write operations
}

// CaddyModule returns the Caddy module information.
func (*NetWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.writers.net",
		New: func() caddy.Module { return new(NetWriter) },
	}
}

// Provision sets up the module.
func (nw *NetWriter) Provision(ctx caddy.Context) error {
	nw.logger = slog.Default()
	repl := caddy.NewReplacer()
	address, err := repl.ReplaceOrErr(nw.Address, true, true)
	if err != nil {
		return fmt.Errorf("invalid host in address: %v", err)
	}

	nw.addr, err = caddy.ParseNetworkAddress(address)
	if err != nil {
		return fmt.Errorf("parsing network address '%s': %v", address, err)
	}

	if nw.addr.PortRangeSize() != 1 {
		return fmt.Errorf("multiple ports not supported")
	}

	if nw.DialTimeout < 0 {
		return fmt.Errorf("timeout cannot be less than 0")
	}

	if nw.DialTimeout == 0 {
		nw.DialTimeout = caddy.Duration(10 * time.Second)
	}

	if nw.ReconnectInterval == 0 {
		nw.ReconnectInterval = caddy.Duration(10 * time.Second)
	}

	if nw.BufferSize <= 0 {
		nw.BufferSize = 1000
	}

	return nil
}

func (nw *NetWriter) String() string {
	return nw.addr.String()
}

// WriterKey returns a unique key representing this nw.
func (nw *NetWriter) WriterKey() string {
	return nw.addr.String()
}

// OpenWriter opens a new network connection and sets up the WAL.
func (nw *NetWriter) OpenWriter() (io.WriteCloser, error) {
	// Set up WAL directory
	baseDir := caddy.AppDataDir()

	nw.walDir = filepath.Join(baseDir, "wal", "netwriter", nw.addr.String())
	if err := os.MkdirAll(nw.walDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %v", err)
	}

	// Open WAL
	opts := wal.DefaultOptions
	opts.DirPath = nw.walDir
	opts.SegmentSize = 64 * 1024 * 1024 // 64MB segments
	w, err := wal.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open WAL: %v", err)
	}
	nw.wal = w

	// Load last processed offset from metadata file if it exists
	nw.loadLastProcessedOffset()

	// If SoftStart is disabled, test the connection immediately
	if !nw.SoftStart {
		testConn, err := net.DialTimeout(nw.addr.Network, nw.addr.JoinHostPort(0), time.Duration(nw.DialTimeout))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to log destination (SoftStart disabled): %v", err)
		}
		testConn.Close()
	}

	// Create the writer wrapper
	writer := &netWriterConn{
		nw: nw,
	}

	// Start the background flusher
	nw.flushCtx, nw.flushCtxCancel = context.WithCancel(context.Background())
	nw.flushWg.Add(1)
	go nw.backgroundFlusher()

	return writer, nil
}

// loadLastProcessedOffset loads the last processed offset from a metadata file
func (nw *NetWriter) loadLastProcessedOffset() {
	metaFile := filepath.Join(nw.walDir, "last_processed")
	data, err := os.ReadFile(metaFile)
	if err != nil {
		// Use -1 to indicate "no entries processed yet"
		nw.lastProcessedOffset = -1
		nw.logger.Debug("no last processed offset file found, starting from beginning", "file", metaFile, "error", err)
		return
	}

	var offset int64
	if _, err := fmt.Sscanf(string(data), "%d", &offset); err != nil {
		// Use -1 to indicate "no entries processed yet"
		nw.lastProcessedOffset = -1
		return
	}

	nw.lastProcessedOffset = offset
	nw.logger.Debug("loaded last processed offset", "offset", offset)
}

// saveLastProcessedOffset saves the last processed offset to a metadata file
func (nw *NetWriter) saveLastProcessedOffset(cp *wal.ChunkPosition) {
	// Create a unique offset by combining segment, block, and chunk offset
	offset := (int64(cp.SegmentId) << 32) | (int64(cp.BlockNumber) << 16) | (cp.ChunkOffset)

	nw.mu.Lock()
	nw.lastProcessedOffset = offset
	nw.mu.Unlock()

	metaFile := filepath.Join(nw.walDir, "last_processed")
	data := fmt.Sprintf("%d", offset)
	if err := os.WriteFile(metaFile, []byte(data), 0o600); err != nil {
		nw.logger.Error("failed to save last processed offset", "error", err)
	} else {
		nw.logger.Debug("saved last processed offset", "offset", offset)
	}
}

// backgroundFlusher runs in the background and flushes WAL entries to the network
func (nw *NetWriter) backgroundFlusher() {
	defer nw.flushWg.Done()
	nw.logger.Debug("background flusher started")

	var conn net.Conn
	var connMu sync.RWMutex

	// Function to establish connection
	dial := func() error {
		newConn, err := net.DialTimeout(nw.addr.Network, nw.addr.JoinHostPort(0), time.Duration(nw.DialTimeout))
		if err != nil {
			return err
		}

		connMu.Lock()
		if conn != nil {
			conn.Close()
		}
		conn = newConn
		connMu.Unlock()

		nw.logger.Info("connected to log destination", "address", nw.addr.String())
		return nil
	}

	// Function to write data to connection
	writeToConn := func(data []byte) error {
		connMu.RLock()
		currentConn := conn
		connMu.RUnlock()

		if currentConn == nil {
			return errors.New("no connection")
		}

		_, err := currentConn.Write(data)
		if err != nil {
			// Connection failed, clear it so reconnection logic kicks in
			connMu.Lock()
			if conn == currentConn {
				conn.Close()
				conn = nil
			}
			connMu.Unlock()
		}
		return err
	}

	// Try initial connection
	if err := dial(); err != nil {
		if !nw.SoftStart {
			nw.logger.Error("failed to connect to log destination", "error", err)
		} else {
			nw.logger.Warn("failed to connect to log destination, will retry", "error", err)
		}
	}

	// Process any existing entries in the WAL immediately
	nw.processWALEntries(writeToConn)

	ticker := time.NewTicker(100 * time.Millisecond) // Check for new entries every 100ms
	defer ticker.Stop()

	reconnectTicker := time.NewTicker(time.Duration(nw.ReconnectInterval))
	defer reconnectTicker.Stop()

	for {
		select {
		case <-nw.flushCtx.Done():
			// Flush remaining entries before shutting down
			nw.flushRemainingWALEntries(writeToConn)

			connMu.Lock()
			if conn != nil {
				conn.Close()
			}
			connMu.Unlock()
			return

		case <-ticker.C:
			// Process available WAL entries
			nw.processWALEntries(writeToConn)

		case <-reconnectTicker.C:
			// Try to reconnect if we don't have a connection
			connMu.RLock()
			hasConn := conn != nil
			connMu.RUnlock()

			nw.logger.Debug("reconnect ticker fired", "hasConn", hasConn)
			if !hasConn {
				if err := dial(); err != nil {
					nw.logger.Debug("reconnection attempt failed", "error", err)
				} else {
					// Successfully reconnected, process any buffered WAL entries
					nw.logger.Info("reconnected, processing buffered WAL entries")
					nw.processWALEntries(writeToConn)
				}
			}
		}
	}
}

// processWALEntries processes all available entries in the WAL using a fresh reader
func (nw *NetWriter) processWALEntries(writeToConn func([]byte) error) {
	// Synchronize WAL access to prevent race conditions with writers
	nw.walMu.Lock()
	// Create a fresh reader to see all current entries
	reader := nw.wal.NewReader()
	nw.walMu.Unlock()

	processed := 0
	skipped := 0
	nw.logger.Debug("processing available WAL entries")
	for {
		nw.walMu.Lock()
		data, cp, err := reader.Next()
		nw.walMu.Unlock()

		if err == io.EOF {
			if processed > 0 {
				nw.logger.Debug("processed WAL entries", "processed", processed, "skipped", skipped)
			}
			break
		}
		if err != nil {
			if err == wal.ErrClosed {
				nw.logger.Debug("WAL closed during processing")
				return
			}
			nw.logger.Error("error reading from WAL", "error", err)
			break
		}

		// Check if we've already processed this entry
		nw.mu.RLock()
		lastProcessedOffset := nw.lastProcessedOffset
		nw.mu.RUnlock()

		// Create current entry offset for comparison
		currentOffset := (int64(cp.SegmentId) << 32) | (int64(cp.BlockNumber) << 16) | (cp.ChunkOffset)
		nw.logger.Debug("found WAL entry", "segmentId", cp.SegmentId, "blockNumber", cp.BlockNumber, "chunkOffset", cp.ChunkOffset, "currentOffset", currentOffset, "lastProcessedOffset", lastProcessedOffset, "size", len(data))

		if currentOffset <= lastProcessedOffset {
			// Already processed, skip
			nw.logger.Debug("skipping already processed entry", "currentOffset", currentOffset, "lastProcessedOffset", lastProcessedOffset)
			skipped++
			continue
		}

		if err := nw.processWALEntry(data, cp, writeToConn); err != nil {
			nw.logger.Error("error processing WAL entry", "error", err)
			// Don't break here - we want to continue processing other entries
		} else {
			processed++
		}
	}
}

// processWALEntry processes a single WAL entry
func (nw *NetWriter) processWALEntry(data []byte, cp *wal.ChunkPosition, writeToConn func([]byte) error) error {
	if err := writeToConn(data); err != nil {
		// Connection failed, dump to stderr as fallback
		os.Stderr.Write(data)
		return err
	}

	// Mark this entry as processed
	nw.saveLastProcessedOffset(cp)
	nw.logger.Debug("processed WAL entry", "segmentId", cp.SegmentId, "blockNumber", cp.BlockNumber, "chunkOffset", cp.ChunkOffset, "data", string(data))
	return nil
}

// flushRemainingWALEntries flushes all remaining entries during shutdown
func (nw *NetWriter) flushRemainingWALEntries(writeToConn func([]byte) error) {
	nw.logger.Info("flushing remaining WAL entries during shutdown")

	// Synchronize WAL access to prevent race conditions with writers
	nw.walMu.Lock()
	// Create a fresh reader for shutdown processing
	reader := nw.wal.NewReader()
	nw.walMu.Unlock()

	count := 0
	for {
		nw.walMu.Lock()
		data, cp, err := reader.Next()
		nw.walMu.Unlock()

		if err == io.EOF {
			break
		}
		if err != nil {
			nw.logger.Error("error reading from WAL during shutdown flush", "error", err)
			break
		}

		// Check if we've already processed this entry
		nw.mu.RLock()
		lastProcessedOffset := nw.lastProcessedOffset
		nw.mu.RUnlock()

		// Create current entry offset for comparison
		currentOffset := (int64(cp.SegmentId) << 32) | (int64(cp.BlockNumber) << 16) | (cp.ChunkOffset)

		if currentOffset <= lastProcessedOffset {
			// Already processed, skip
			continue
		}

		// During shutdown, we try harder to deliver logs
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			if err := writeToConn(data); err != nil {
				if i == maxRetries-1 {
					// Final attempt failed, dump to stderr
					os.Stderr.Write(data)
					nw.logger.Error("failed to send log entry during shutdown, dumped to stderr", "error", err)
				} else {
					time.Sleep(time.Second)
				}
			} else {
				nw.saveLastProcessedOffset(cp)
				nw.logger.Debug("flushed WAL entry during shutdown", "segmentId", cp.SegmentId, "blockNumber", cp.BlockNumber, "chunkOffset", cp.ChunkOffset)
				break
			}
		}
		count++
	}

	if count > 0 {
		nw.logger.Info("flushed WAL entries during shutdown", "count", count)
	}
}

// netWriterConn implements io.WriteCloser and writes to the WAL
type netWriterConn struct {
	nw *NetWriter
}

// Write writes data to the WAL (non-blocking)
func (w *netWriterConn) Write(p []byte) (n int, err error) {
	if w.nw.wal == nil {
		w.nw.logger.Error("WAL not initialized")
		return 0, errors.New("WAL not initialized")
	}

	w.nw.logger.Debug("writing to WAL", "size", len(p))

	// Synchronize WAL access to prevent race conditions
	w.nw.walMu.Lock()
	defer w.nw.walMu.Unlock()

	// Write to WAL - this should be fast and non-blocking
	_, err = w.nw.wal.Write(p)
	if err != nil {
		w.nw.logger.Error("failed to write to WAL", "error", err)
		return 0, fmt.Errorf("failed to write to WAL: %v", err)
	}

	// Sync WAL to ensure data is available for reading
	if err = w.nw.wal.Sync(); err != nil {
		w.nw.logger.Error("failed to sync WAL", "error", err)
	}

	w.nw.logger.Debug("wrote data to WAL", "size", len(p))
	return len(p), nil
}

// Close closes the writer and flushes all remaining data
func (w *netWriterConn) Close() error {
	if w.nw.flushCtxCancel != nil {
		w.nw.flushCtxCancel()
	}

	// Wait for background flusher to complete
	w.nw.flushWg.Wait()

	var errs []error

	// Sync and close WAL with synchronization
	if w.nw.wal != nil {
		w.nw.walMu.Lock()
		if err := w.nw.wal.Sync(); err != nil {
			errs = append(errs, fmt.Errorf("WAL sync error: %v", err))
		}
		if err := w.nw.wal.Close(); err != nil {
			errs = append(errs, fmt.Errorf("WAL close error: %v", err))
		}
		w.nw.walMu.Unlock()
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	net <address> {
//	    dial_timeout <duration>
//	    soft_start
//	}
func (nw *NetWriter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume writer name
	if !d.NextArg() {
		return d.ArgErr()
	}
	nw.Address = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid duration: %s", d.Val())
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			nw.DialTimeout = caddy.Duration(timeout)

		case "soft_start":
			if d.NextArg() {
				return d.ArgErr()
			}
			nw.SoftStart = true

		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*NetWriter)(nil)
	_ caddy.WriterOpener    = (*NetWriter)(nil)
	_ caddyfile.Unmarshaler = (*NetWriter)(nil)
)
