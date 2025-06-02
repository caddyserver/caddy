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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/rosedblabs/wal"
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

	logger             *slog.Logger
	addr               caddy.NetworkAddress
	wal                *wal.WAL
	walDir             string
	flushCtx           context.Context
	flushCtxCancel     context.CancelFunc
	flushWg            sync.WaitGroup
	lastProcessedChunk uint32
	mu                 sync.RWMutex
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
	nw.walDir = filepath.Join(caddy.AppDataDir(), "wal", "netwriter", nw.addr.String())
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

	// Load last processed chunk position from metadata file if it exists
	nw.loadLastProcessedChunk()

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

// loadLastProcessedChunk loads the last processed chunk position from a metadata file
func (nw *NetWriter) loadLastProcessedChunk() {
	metaFile := filepath.Join(nw.walDir, "last_processed")
	data, err := os.ReadFile(metaFile)
	if err != nil {
		nw.lastProcessedChunk = 0
		return
	}

	var chunk uint32
	if _, err := fmt.Sscanf(string(data), "%d", &chunk); err != nil {
		nw.lastProcessedChunk = 0
		return
	}

	nw.lastProcessedChunk = chunk
	nw.logger.Info("loaded last processed chunk", "block", chunk)
}

// saveLastProcessedChunk saves the last processed chunk position to a metadata file
func (nw *NetWriter) saveLastProcessedChunk(chunk uint32) {
	nw.mu.Lock()
	nw.lastProcessedChunk = chunk
	nw.mu.Unlock()

	metaFile := filepath.Join(nw.walDir, "last_processed")
	data := fmt.Sprintf("%d", chunk)
	if err := os.WriteFile(metaFile, []byte(data), 0o644); err != nil {
		nw.logger.Error("failed to save last processed chunk", "error", err)
	}
}

// backgroundFlusher runs in the background and flushes WAL entries to the network
func (nw *NetWriter) backgroundFlusher() {
	defer nw.flushWg.Done()

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

	// Set up WAL reader
	reader := nw.wal.NewReader()

	// Skip already processed entries
	nw.mu.RLock()
	lastChunk := nw.lastProcessedChunk
	nw.mu.RUnlock()

	if lastChunk > 0 {
		nw.logger.Info("skipping already processed entries", "lastProcessedBlock", lastChunk)
		// Skip already processed entries
		skipped := 0
		for {
			data, cp, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				nw.logger.Error("error reading WAL during skip", "error", err)
				break
			}

			// Skip entries that have already been processed
			if cp.BlockNumber <= lastChunk {
				skipped++
				continue
			}

			// This is a new entry, process it
			if err := nw.processWALEntry(data, cp, writeToConn); err != nil {
				nw.logger.Error("error processing WAL entry", "error", err)
			}
		}
		nw.logger.Info("skipped processed entries", "count", skipped)
	}

	ticker := time.NewTicker(100 * time.Millisecond) // Check for new entries every 100ms
	defer ticker.Stop()

	reconnectTicker := time.NewTicker(time.Duration(nw.ReconnectInterval))
	defer reconnectTicker.Stop()

	for {
		select {
		case <-nw.flushCtx.Done():
			// Flush remaining entries before shutting down
			nw.flushRemainingEntries(reader, writeToConn)

			connMu.Lock()
			if conn != nil {
				conn.Close()
			}
			connMu.Unlock()
			return

		case <-ticker.C:
			// Process available WAL entries
			nw.processAvailableEntries(reader, writeToConn)

		case <-reconnectTicker.C:
			// Try to reconnect if we don't have a connection
			connMu.RLock()
			hasConn := conn != nil
			connMu.RUnlock()

			if !hasConn {
				if err := dial(); err != nil {
					nw.logger.Debug("reconnection attempt failed", "error", err)
				}
			}
		}
	}
}

// processAvailableEntries processes all available entries in the WAL
func (nw *NetWriter) processAvailableEntries(reader *wal.Reader, writeToConn func([]byte) error) {
	for {
		data, cp, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if err == wal.ErrClosed {
				return
			}
			nw.logger.Error("error reading from WAL", "error", err)
			break
		}

		// Check if we've already processed this block
		nw.mu.RLock()
		lastProcessed := nw.lastProcessedChunk
		nw.mu.RUnlock()

		if cp.BlockNumber <= lastProcessed {
			// Already processed, skip
			continue
		}

		if err := nw.processWALEntry(data, cp, writeToConn); err != nil {
			nw.logger.Error("error processing WAL entry", "error", err)
			// Don't break here - we want to continue processing other entries
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

	// Mark this block as processed
	nw.saveLastProcessedChunk(cp.BlockNumber)
	nw.logger.Debug("processed WAL entry", "blockNumber", cp.BlockNumber)
	return nil
}

// flushRemainingEntries flushes all remaining entries during shutdown
func (nw *NetWriter) flushRemainingEntries(reader *wal.Reader, writeToConn func([]byte) error) {
	nw.logger.Info("flushing remaining WAL entries during shutdown")

	count := 0
	for {
		data, cp, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			nw.logger.Error("error reading from WAL during shutdown flush", "error", err)
			break
		}

		// Check if we've already processed this block
		nw.mu.RLock()
		lastProcessed := nw.lastProcessedChunk
		nw.mu.RUnlock()

		if cp.BlockNumber <= lastProcessed {
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
				nw.saveLastProcessedChunk(cp.BlockNumber)
				nw.logger.Debug("flushed WAL entry during shutdown", "blockNumber", cp.BlockNumber)
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
		return 0, errors.New("WAL not initialized")
	}

	// Write to WAL - this should be fast and non-blocking
	_, err = w.nw.wal.Write(p)
	if err != nil {
		return 0, fmt.Errorf("failed to write to WAL: %v", err)
	}

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

	// Sync and close WAL
	if w.nw.wal != nil {
		if err := w.nw.wal.Sync(); err != nil {
			errs = append(errs, fmt.Errorf("WAL sync error: %v", err))
		}
		if err := w.nw.wal.Close(); err != nil {
			errs = append(errs, fmt.Errorf("WAL close error: %v", err))
		}
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
