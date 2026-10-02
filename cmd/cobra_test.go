package caddycmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
)

// TestWrapCommandFuncForCobraFlushesErrorLog covers the regression reported in
// #7962: the default logger is buffered until a config is loaded, so an error
// logged by the cobra wrapper landed in a buffer that nothing ever drained, and
// the process then exited without printing it.
//
// The wrapper flushes to the real default logger, whose output cannot be
// reached from a test, so this asserts the half that is observable here: the
// entry must have left the startup buffer by the time the wrapper returns.
// TestFlushLogs covers the other half, that a flushed entry reaches the logger
// the buffer was created with.
func TestWrapCommandFuncForCobraFlushesErrorLog(t *testing.T) {
	const errMsg = "wrapped command failed"

	_, _, bufferCore := caddy.BufferedLog()

	// BufferedLog swapped the process-wide default logger and there is no way
	// to hand the previous one back, so at least drain it once the test is done
	t.Cleanup(caddy.FlushLogs)

	run := WrapCommandFuncForCobra(func(Flags) (int, error) {
		return 0, errors.New(errMsg)
	})
	if err := run(&cobra.Command{}, nil); err == nil {
		t.Fatal("wrapper returned no error, want the error from the command func")
	}

	// Flush the buffer to a logger this test owns. Anything still in here when
	// the wrapper returns is exactly what would have been dropped at exit.
	var stragglers bytes.Buffer
	encoder := zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
	bufferCore.FlushTo(zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&stragglers), zapcore.InfoLevel)))

	if strings.Contains(stragglers.String(), errMsg) {
		t.Errorf("error %q was still buffered when the wrapper returned, so it would be lost on exit", errMsg)
	}
}
