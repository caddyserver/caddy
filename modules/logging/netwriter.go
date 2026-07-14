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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rosedblabs/wal"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(&NetWriter{})
}

const (
	// walSegmentSize is the maximum size of a WAL segment file.
	walSegmentSize = 64 * 1024 * 1024

	// walTruncateThreshold is the number of delivered payload bytes
	// after which the WAL is truncated (once the backlog is fully
	// delivered) to reclaim disk space and keep flush scans cheap.
	walTruncateThreshold = 4 * 1024 * 1024
)

// NetWriter implements a log writer that outputs to a network socket.
// Log entries are first appended to a write-ahead log (WAL) on disk and
// then delivered to the socket by a background goroutine, so logging
// never blocks on a slow or unavailable destination. If the socket goes
// down, entries accumulate in the WAL and are delivered once the
// connection is re-established, including across process restarts.
type NetWriter struct {
	// The address of the network socket to which to connect.
	Address string `json:"address,omitempty"`

	// The timeout to wait while connecting to the socket.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// If enabled, a failure to connect to the socket when first
	// opening the writer is not fatal; log entries are buffered
	// in the WAL until a connection can be established.
	SoftStart bool `json:"soft_start,omitempty"`

	// How often to attempt reconnection when the network connection fails.
	ReconnectInterval caddy.Duration `json:"reconnect_interval,omitempty"`

	logger         *slog.Logger
	addr           caddy.NetworkAddress
	wal            *wal.WAL
	walDir         string
	flushCtx       context.Context
	flushCtxCancel context.CancelFunc
	flushWg        sync.WaitGroup

	// walMu synchronizes WAL open/read/write/truncate operations
	walMu sync.Mutex

	// mu protects the fields below; when held together with walMu,
	// it is always acquired after walMu
	mu sync.RWMutex
	// position of the last WAL entry delivered to the destination,
	// or nil if nothing has been delivered from the current WAL
	lastProcessed *wal.ChunkPosition
	// whether the WAL may contain undelivered entries
	pending bool

	// number of payload bytes delivered since the WAL was last
	// truncated; only accessed by the background flusher goroutine
	deliveredSinceTruncate int64
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
	// set up WAL directory
	baseDir := caddy.AppDataDir()
	nw.walDir = filepath.Join(baseDir, "wal", "netwriter", strings.ReplaceAll(nw.addr.String(), ":", "-"))
	if err := os.MkdirAll(nw.walDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %v", err)
	}

	if err := nw.openWAL(); err != nil {
		return nil, err
	}

	// resume where a previous run left off, if applicable
	nw.loadLastProcessed()
	nw.pending = !nw.wal.IsEmpty()

	// if SoftStart is disabled, test the connection immediately
	if !nw.SoftStart {
		testConn, err := net.DialTimeout(nw.addr.Network, nw.addr.JoinHostPort(0), time.Duration(nw.DialTimeout))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to log destination (SoftStart disabled): %v", err)
		}
		testConn.Close()
	}

	// create the writer wrapper
	writer := &netWriterConn{
		nw: nw,
	}

	// start the background flusher; the cancel function is called by Close
	nw.flushCtx, nw.flushCtxCancel = context.WithCancel(context.Background()) //nolint:gosec
	nw.flushWg.Add(1)
	go nw.backgroundFlusher()

	return writer, nil
}

// openWAL opens the write-ahead log in nw.walDir.
func (nw *NetWriter) openWAL() error {
	opts := wal.DefaultOptions
	opts.DirPath = nw.walDir
	opts.SegmentSize = walSegmentSize
	w, err := wal.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open WAL: %v", err)
	}
	nw.wal = w
	return nil
}

// walMetaFile returns the path of the file that records the position
// of the last delivered WAL entry.
func (nw *NetWriter) walMetaFile() string {
	return filepath.Join(nw.walDir, "last_processed")
}

// comparePositions orders two WAL chunk positions; it returns a negative
// number if a comes before b, 0 if they are equal, and a positive number
// otherwise.
func comparePositions(a, b *wal.ChunkPosition) int {
	if c := cmp.Compare(a.SegmentId, b.SegmentId); c != 0 {
		return c
	}
	if c := cmp.Compare(a.BlockNumber, b.BlockNumber); c != 0 {
		return c
	}
	return cmp.Compare(a.ChunkOffset, b.ChunkOffset)
}

// loadLastProcessed restores the position of the last delivered entry
// from the metadata file, if present.
func (nw *NetWriter) loadLastProcessed() {
	data, err := os.ReadFile(nw.walMetaFile())
	if err != nil {
		nw.lastProcessed = nil
		return
	}
	var segmentID, blockNumber uint32
	var chunkOffset int64
	if _, err := fmt.Sscanf(string(data), "%d %d %d", &segmentID, &blockNumber, &chunkOffset); err != nil {
		nw.lastProcessed = nil
		return
	}
	nw.lastProcessed = &wal.ChunkPosition{
		SegmentId:   segmentID,
		BlockNumber: blockNumber,
		ChunkOffset: chunkOffset,
	}
	nw.logger.Debug("loaded last processed WAL position",
		"segment", nw.lastProcessed.SegmentId,
		"block", nw.lastProcessed.BlockNumber,
		"offset", nw.lastProcessed.ChunkOffset)
}

// persistLastProcessed writes the position of the last delivered entry
// to the metadata file so that delivery can resume where it left off
// after a restart.
func (nw *NetWriter) persistLastProcessed() {
	nw.mu.RLock()
	lp := nw.lastProcessed
	nw.mu.RUnlock()
	if lp == nil {
		return
	}
	data := fmt.Sprintf("%d %d %d", lp.SegmentId, lp.BlockNumber, lp.ChunkOffset)
	if err := os.WriteFile(nw.walMetaFile(), []byte(data), 0o600); err != nil {
		nw.logger.Error("failed to save WAL position", "error", err)
	}
}

// backgroundFlusher runs in the background and flushes WAL entries to the network
func (nw *NetWriter) backgroundFlusher() {
	defer nw.flushWg.Done()
	nw.logger.Debug("background flusher started")

	var conn net.Conn
	var connMu sync.RWMutex

	// establish a connection
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

	hasConn := func() bool {
		connMu.RLock()
		defer connMu.RUnlock()
		return conn != nil
	}

	// write data to the connection
	writeToConn := func(data []byte) error {
		connMu.RLock()
		currentConn := conn
		connMu.RUnlock()

		if currentConn == nil {
			return errors.New("no connection")
		}

		_, err := currentConn.Write(data)
		if err != nil {
			// connection failed, clear it so reconnection logic kicks in
			connMu.Lock()
			if conn == currentConn {
				conn.Close()
				conn = nil
			}
			connMu.Unlock()
		}
		return err
	}

	// try initial connection
	if err := dial(); err != nil {
		nw.logger.Warn("failed to connect to log destination, will retry", "error", err)
	}

	// deliver any backlog left over from a previous run
	nw.processWALEntries(writeToConn)

	ticker := time.NewTicker(100 * time.Millisecond) // check for new entries every 100ms
	defer ticker.Stop()

	reconnectTicker := time.NewTicker(time.Duration(nw.ReconnectInterval))
	defer reconnectTicker.Stop()

	for {
		select {
		case <-nw.flushCtx.Done():
			// best-effort final flush; anything undelivered stays in
			// the WAL and will be delivered after the next start
			if !hasConn() {
				if err := dial(); err != nil {
					nw.logger.Warn("cannot connect for final flush", "error", err)
				}
			}
			if hasConn() {
				nw.processWALEntries(writeToConn)
			}

			nw.mu.RLock()
			pending := nw.pending
			nw.mu.RUnlock()
			if pending {
				nw.logger.Warn("undelivered log entries remain in the WAL and will be delivered after the next start", "wal_dir", nw.walDir)
			}

			connMu.Lock()
			if conn != nil {
				conn.Close()
			}
			connMu.Unlock()
			return

		case <-ticker.C:
			// deliver new WAL entries, but only if there may be any
			// and the destination is reachable; otherwise entries
			// keep accumulating in the WAL until reconnection
			if !hasConn() {
				continue
			}
			nw.mu.RLock()
			pending := nw.pending
			nw.mu.RUnlock()
			if pending {
				nw.processWALEntries(writeToConn)
			}

		case <-reconnectTicker.C:
			// try to reconnect if we don't have a connection
			if hasConn() {
				continue
			}
			if err := dial(); err != nil {
				nw.logger.Debug("reconnection attempt failed", "error", err)
				continue
			}
			// successfully reconnected, deliver any buffered WAL entries
			nw.processWALEntries(writeToConn)
		}
	}
}

// processWALEntries delivers all undelivered WAL entries to the network
// connection. If a write fails, delivery stops and the remaining backlog
// is kept in the WAL to be retried once the connection is restored.
func (nw *NetWriter) processWALEntries(writeToConn func([]byte) error) {
	// optimistically mark the backlog as flushed; this is set again if
	// delivery fails partway or if an entry is written concurrently
	nw.mu.Lock()
	nw.pending = false
	lastProcessed := nw.lastProcessed
	nw.mu.Unlock()

	nw.walMu.Lock()
	reader := nw.wal.NewReader()
	nw.walMu.Unlock()

	delivered := 0
	caughtUp := true
	for {
		nw.walMu.Lock()
		data, cp, err := reader.Next()
		nw.walMu.Unlock()

		if err == io.EOF {
			break
		}
		if err != nil {
			nw.logger.Error("error reading from WAL", "error", err)
			caughtUp = false
			break
		}

		// skip entries that were already delivered
		if lastProcessed != nil && comparePositions(cp, lastProcessed) <= 0 {
			continue
		}

		if err := writeToConn(data); err != nil {
			// connection is down; keep the backlog in the WAL and let
			// the reconnect logic trigger another delivery attempt
			caughtUp = false
			break
		}

		nw.mu.Lock()
		nw.lastProcessed = cp
		nw.mu.Unlock()
		lastProcessed = cp
		delivered++
		nw.deliveredSinceTruncate += int64(len(data))
	}

	if !caughtUp {
		nw.mu.Lock()
		nw.pending = true
		nw.mu.Unlock()
	}
	if delivered > 0 {
		nw.persistLastProcessed()
		nw.logger.Debug("delivered WAL entries", "count", delivered)
	}
	if caughtUp {
		nw.maybeTruncateWAL()
	}
}

// maybeTruncateWAL discards delivered WAL entries by deleting and
// re-opening the WAL once enough data has been delivered, reclaiming
// disk space; without this, the WAL would grow without bound. It must
// only be called by the background flusher, and only when the backlog
// has been fully delivered.
func (nw *NetWriter) maybeTruncateWAL() {
	if nw.deliveredSinceTruncate < walTruncateThreshold {
		return
	}

	nw.walMu.Lock()
	defer nw.walMu.Unlock()
	nw.mu.Lock()
	defer nw.mu.Unlock()

	// an entry may have been written after the backlog was drained;
	// truncating now would discard it, so wait for the next chance
	if nw.pending {
		return
	}

	if err := nw.wal.Delete(); err != nil {
		nw.logger.Error("failed to truncate WAL", "error", err)
		return
	}
	if err := nw.openWAL(); err != nil {
		nw.logger.Error("failed to re-open WAL after truncation", "error", err)
		return
	}

	// positions restart in the new WAL, so the old ones no longer apply
	nw.lastProcessed = nil
	nw.deliveredSinceTruncate = 0
	if err := os.Remove(nw.walMetaFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		nw.logger.Error("failed to remove WAL position file", "error", err)
	}
	nw.logger.Debug("truncated WAL")
}

// netWriterConn implements io.WriteCloser and writes to the WAL
type netWriterConn struct {
	nw *NetWriter
}

// Write appends the entry to the WAL; the background flusher delivers
// it to the network destination asynchronously.
func (w *netWriterConn) Write(p []byte) (n int, err error) {
	nw := w.nw

	nw.walMu.Lock()
	defer nw.walMu.Unlock()

	if nw.wal == nil {
		return 0, errors.New("WAL not initialized")
	}
	if _, err = nw.wal.Write(p); err != nil {
		// the entry cannot be persisted, so dump it to stderr
		// rather than losing it silently
		os.Stderr.Write(p)
		return 0, fmt.Errorf("failed to write to WAL: %v", err)
	}

	nw.mu.Lock()
	nw.pending = true
	nw.mu.Unlock()

	return len(p), nil
}

// Close closes the writer and flushes all remaining data
func (w *netWriterConn) Close() error {
	if w.nw.flushCtxCancel != nil {
		w.nw.flushCtxCancel()
	}

	// wait for the background flusher to finish its final flush
	w.nw.flushWg.Wait()

	var errs []error

	w.nw.walMu.Lock()
	if w.nw.wal != nil {
		if err := w.nw.wal.Sync(); err != nil {
			errs = append(errs, fmt.Errorf("WAL sync error: %v", err))
		}
		if err := w.nw.wal.Close(); err != nil {
			errs = append(errs, fmt.Errorf("WAL close error: %v", err))
		}
	}
	w.nw.walMu.Unlock()

	return errors.Join(errs...)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	net <address> {
//	    dial_timeout <duration>
//	    reconnect_interval <duration>
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

		case "reconnect_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			interval, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid duration: %s", d.Val())
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			nw.ReconnectInterval = caddy.Duration(interval)

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
