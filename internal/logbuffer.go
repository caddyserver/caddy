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
}

type LogBufferCoreInterface interface {
	zapcore.Core
	FlushTo(*zap.Logger)
}

func NewLogBufferCore(level zapcore.LevelEnabler) *LogBufferCore {
	return &LogBufferCore{
		level: level,
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
