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

package internal

import (
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogBufferCore is a zapcore.Core that buffers log entries in memory.
type LogBufferCore struct {
	mu      sync.Mutex
	entries []zapcore.Entry
	fields  [][]zapcore.Field
	level   zapcore.LevelEnabler
	// dest is where entries are written by Flush. It is the logger that was
	// in use when this buffer was created, so that buffered entries reach
	// their original output even if they are never handed off to a new
	// logger, for example because loading a config failed. It may be nil, in
	// which case Flush is a no-op and the entries are left untouched.
	dest *zap.Logger
}

type LogBufferCoreInterface interface {
	zapcore.Core
	FlushTo(*zap.Logger)
	Flush()
}

func NewLogBufferCore(level zapcore.LevelEnabler, dest *zap.Logger) *LogBufferCore {
	return &LogBufferCore{
		level: level,
		dest:  dest,
	}
}

func (c *LogBufferCore) Enabled(lvl zapcore.Level) bool {
	return c.level.Enabled(lvl)
}

func (c *LogBufferCore) With(fields []zapcore.Field) zapcore.Core {
	return c
}

func (c *LogBufferCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *LogBufferCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, entry)
	c.fields = append(c.fields, fields)
	return nil
}

func (c *LogBufferCore) Sync() error { return nil }

// FlushTo flushes buffered logs to the given zap.Logger.
func (c *LogBufferCore) FlushTo(logger *zap.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushTo(logger)
}

// Flush writes buffered logs to the logger that was in use when this buffer
// was created, then empties the buffer. If that logger is itself backed by a
// LogBufferCore -- which happens when BufferedLog is called more than once --
// the intervening buffers are flushed first, oldest first, so that no entry is
// left stranded in a buffer that nothing else holds a reference to. It is a
// no-op if the destination is gone, leaving the entries untouched, and it is
// safe to call more than once: the buffer is drained, so repeated calls do not
// duplicate entries.
func (c *LogBufferCore) Flush() {
	// Collect the buffers between c and a non-buffered destination, then write
	// straight to that destination. Reading dest needs no lock because it is
	// only ever set when the buffer is created, before anything else can hold
	// a reference to it.
	var chain []*LogBufferCore
	dest := c.dest
	for dest != nil {
		core, ok := dest.Core().(*LogBufferCore)
		if !ok || core == c {
			break
		}
		chain = append(chain, core)
		dest = core.dest
	}

	// Flush the intervening buffers before ours, oldest first, so that entries
	// logged before the most recent BufferedLog call stay ahead of ours in the
	// output. Each FlushTo takes and releases that one buffer's mutex before
	// the next lock is taken, so no two buffer locks are ever held at once and
	// concurrent flushes cannot deadlock against each other.
	for _, core := range chain {
		core.FlushTo(dest)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushTo(dest)
}

// flushTo writes the buffer to logger and empties it. The caller must hold
// c.mu. Note that replayed entries are stamped with the time of the flush
// rather than the time they were logged, because zap assigns an entry's
// timestamp when the entry is checked.
func (c *LogBufferCore) flushTo(logger *zap.Logger) {
	if logger == nil {
		return
	}
	// Writing into c itself would deadlock, since FlushTo and Flush both hold
	// this non-reentrant mutex while they write. Flush resolves its
	// destination first so it never arrives here with a buffer, but FlushTo
	// is exported and a caller could hand us one.
	if destCore, ok := logger.Core().(*LogBufferCore); ok && destCore == c {
		return
	}
	for idx, entry := range c.entries {
		logger.WithOptions().Check(entry.Level, entry.Message).Write(c.fields[idx]...)
	}
	c.entries = nil
	c.fields = nil
}

var (
	_ zapcore.Core           = (*LogBufferCore)(nil)
	_ LogBufferCoreInterface = (*LogBufferCore)(nil)
)
