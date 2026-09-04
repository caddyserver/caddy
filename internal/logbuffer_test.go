package internal

import (
	"bytes"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLogBufferCoreSync(t *testing.T) {
	var output bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	logger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&output), zap.InfoLevel))
	buffer := NewLogBufferCore(zap.InfoLevel)
	buffer.SetFlushLogger(logger)

	zap.New(buffer).Error("startup failed")
	if output.Len() != 0 {
		t.Fatal("buffered log was written before sync")
	}

	if err := buffer.Sync(); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if !bytes.Contains(output.Bytes(), []byte("startup failed")) {
		t.Fatal("sync did not flush buffered log")
	}
}
