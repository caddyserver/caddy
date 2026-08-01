package internal

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogBufferCoreEnabled(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)

	if !core.Enabled(zapcore.InfoLevel) {
		t.Error("expected InfoLevel to be enabled")
	}
	if !core.Enabled(zapcore.ErrorLevel) {
		t.Error("expected ErrorLevel to be enabled")
	}
	if core.Enabled(zapcore.DebugLevel) {
		t.Error("expected DebugLevel to be disabled")
	}
}

func TestLogBufferCoreWriteAndFlush(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)

	// Write entries
	entry1 := zapcore.Entry{Level: zapcore.InfoLevel, Message: "message1"}
	entry2 := zapcore.Entry{Level: zapcore.WarnLevel, Message: "message2"}

	if err := core.Write(entry1, []zapcore.Field{zap.String("key1", "val1")}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := core.Write(entry2, []zapcore.Field{zap.String("key2", "val2")}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify entries are buffered
	if len(core.entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(core.entries))
	}
	if len(core.fields) != 2 {
		t.Errorf("expected 2 field sets, got %d", len(core.fields))
	}

	// Set up an observed logger to capture flushed entries
	observedCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedCore)

	core.FlushTo(logger)

	// Verify entries were flushed
	if logs.Len() != 2 {
		t.Errorf("expected 2 flushed log entries, got %d", logs.Len())
	}

	// Verify buffer is cleared after flush
	if len(core.entries) != 0 {
		t.Errorf("expected entries to be cleared after flush, got %d", len(core.entries))
	}
	if len(core.fields) != 0 {
		t.Errorf("expected fields to be cleared after flush, got %d", len(core.fields))
	}
}

func TestLogBufferCoreSync(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)
	if err := core.Sync(); err != nil {
		t.Errorf("Sync() error = %v", err)
	}
}

func TestLogBufferCoreWith(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)

	// With() currently returns the same core (known limitation)
	result := core.With([]zapcore.Field{zap.String("test", "val")})
	if result != core {
		t.Error("With() should return the same core instance")
	}
}

func TestLogBufferCoreCheck(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)

	// Check for enabled level should add core
	entry := zapcore.Entry{Level: zapcore.InfoLevel, Message: "test"}
	ce := &zapcore.CheckedEntry{}
	result := core.Check(entry, ce)
	if result == nil {
		t.Error("Check() should return non-nil for enabled level")
	}

	// Check for disabled level should not add core
	debugEntry := zapcore.Entry{Level: zapcore.DebugLevel, Message: "test"}
	ce2 := &zapcore.CheckedEntry{}
	result2 := core.Check(debugEntry, ce2)
	// The ce2 should be returned unchanged (no core added)
	if result2 != ce2 {
		t.Error("Check() should return unchanged CheckedEntry for disabled level")
	}
}

func TestLogBufferCoreEmptyFlush(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)

	// Flushing with no entries should not panic
	observedCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(observedCore)

	core.FlushTo(logger)

	if logs.Len() != 0 {
		t.Errorf("expected 0 flushed entries for empty buffer, got %d", logs.Len())
	}
}

func TestLogBufferCoreConcurrentWrites(t *testing.T) {
	core := NewLogBufferCore(zapcore.InfoLevel)

	done := make(chan struct{})
	const numWriters = 10
	const numWrites = 100

	for i := 0; i < numWriters; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < numWrites; j++ {
				entry := zapcore.Entry{Level: zapcore.InfoLevel, Message: "concurrent"}
				_ = core.Write(entry, nil)
			}
		}()
	}

	for i := 0; i < numWriters; i++ {
		<-done
	}

	core.mu.Lock()
	count := len(core.entries)
	core.mu.Unlock()

	if count != numWriters*numWrites {
		t.Errorf("expected %d entries, got %d", numWriters*numWrites, count)
	}
}
