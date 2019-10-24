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

package caddy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	RegisterModule(StdoutWriter{})
	RegisterModule(StderrWriter{})
}

// Logging facilitates logging within Caddy.
type Logging struct {
	Sink *StandardLibLog       `json:"sink,omitempty"`
	Logs map[string]*CustomLog `json:"logs,omitempty"`

	// a list of all keys for open writers; all writers
	// that are opened to provision this logging config
	// must have their keys added to this list so they
	// can be closed when cleaning up
	writerKeys []string
}

// openLogs sets up the config and opens all the configured writers.
// It closes its logs when ctx is cancelled, so it should clean up
// after itself.
func (logging *Logging) openLogs(ctx Context) error {
	// make sure to deallocate resources when context is done
	ctx.OnCancel(func() {
		err := logging.closeLogs()
		if err != nil {
			Log().Error("closing logs", zap.Error(err))
		}
	})

	// set up the "sink" log first (std lib's default global logger)
	if logging.Sink != nil {
		err := logging.Sink.provision(ctx, logging)
		if err != nil {
			return fmt.Errorf("setting up sink log: %v", err)
		}
	}

	// as a special case, set up the default structured Caddy log first
	if logging.Logs != nil {
		newDefault := new(defaultCustomLog)
		var ok bool
		newDefault.CustomLog, ok = logging.Logs["default"]
		if ok {
			err := newDefault.CustomLog.provision(ctx, logging)
			if err != nil {
				return fmt.Errorf("setting up default log: %v", err)
			}
			newDefault.logger = zap.New(newDefault.CustomLog.core)
		} else {
			var err error
			newDefault, err = newDefaultProductionLog()
			if err != nil {
				return fmt.Errorf("setting up default production log: %v", err)
			}
		}

		// redirect the default caddy logs
		defaultLoggerMu.Lock()
		oldDefault := defaultLogger
		defaultLogger = newDefault
		defaultLoggerMu.Unlock()

		// if the new writer is different, indicate it in the logs for convenience
		var newDefaultLogWriterKey, currentDefaultLogWriterKey string
		var newDefaultLogWriterStr, currentDefaultLogWriterStr string
		if newDefault.writerOpener != nil {
			newDefaultLogWriterKey = newDefault.writerOpener.WriterKey()
			newDefaultLogWriterStr = newDefault.writerOpener.String()
		}
		if oldDefault.writerOpener != nil {
			currentDefaultLogWriterKey = oldDefault.writerOpener.WriterKey()
			currentDefaultLogWriterStr = oldDefault.writerOpener.String()
		}
		if newDefaultLogWriterKey != currentDefaultLogWriterKey {
			oldDefault.logger.Info("redirected default logger",
				zap.String("from", currentDefaultLogWriterStr),
				zap.String("to", newDefaultLogWriterStr),
			)
		}
	}

	// then set up any other custom logs
	for name, l := range logging.Logs {
		if name == "default" {
			continue
		}
		err := l.provision(ctx, logging)
		if err != nil {
			return fmt.Errorf("setting up custom log '%s': %v", name, err)
		}
	}

	return nil
}

// closeLogs cleans up resources allocated during openLogs.
// A successful call to openLogs calls this automatically
// when the context is cancelled.
func (logging *Logging) closeLogs() error {
	for _, key := range logging.writerKeys {
		_, err := writers.Delete(key)
		if err != nil {
			log.Printf("[ERROR] Closing log writer %v: %v", key, err)
		}
	}
	return nil
}

// Logger returns a logger that is ready for the module to use.
func (logging *Logging) Logger(mod Module) *zap.Logger {
	modName := mod.CaddyModule().Name
	var cores []zapcore.Core

	for _, l := range logging.Logs {
		if l.matchesModule(modName) {
			cores = append(cores, l.core)
		}
	}

	multiCore := zapcore.NewTee(cores...)

	return zap.New(multiCore).Named(modName)
}

// openWriter opens a writer using opener, and returns true if
// the writer is new, or false if the writer already exists.
func (logging *Logging) openWriter(opener WriterOpener) (io.WriteCloser, bool, error) {
	key := opener.WriterKey()
	writer, loaded, err := writers.LoadOrNew(key, func() (Destructor, error) {
		w, err := opener.OpenWriter()
		return writerDestructor{w}, err
	})
	if err == nil {
		logging.writerKeys = append(logging.writerKeys, key)
	}
	return writer.(io.WriteCloser), !loaded, err
}

// WriterOpener is a module that can open a log writer.
// It can return a human-readable string representation
// of itself so that operators can understand where
// the logs are going.
type WriterOpener interface {
	fmt.Stringer

	// WriterKey is a string that uniquely identifies this
	// writer configuration. It is not shown to humans.
	WriterKey() string

	// OpenWriter opens a log for writing. The writer
	// should be safe for concurrent use but need not
	// be synchronous.
	OpenWriter() (io.WriteCloser, error)
}

type writerDestructor struct {
	io.WriteCloser
}

func (wdest writerDestructor) Destruct() error {
	return wdest.Close()
}

// StandardLibLog configures the default Go standard library
// global logger in the log package. This is necessary because
// module dependencies which are not built specifically for
// Caddy will use the standard logger.
type StandardLibLog struct {
	WriterRaw json.RawMessage `json:"writer,omitempty"`

	writer io.WriteCloser
}

func (sll *StandardLibLog) provision(ctx Context, logging *Logging) error {
	if sll.WriterRaw != nil {
		val, err := ctx.LoadModuleInline("output", "caddy.logging.writers", sll.WriterRaw)
		if err != nil {
			return fmt.Errorf("loading sink log writer module: %v", err)
		}
		wo := val.(WriterOpener)
		sll.WriterRaw = nil // allow GC to deallocate

		var isNew bool
		sll.writer, isNew, err = logging.openWriter(wo)
		if err != nil {
			return fmt.Errorf("opening sink log writer %#v: %v", val, err)
		}

		if isNew {
			log.Printf("[INFO] Redirecting sink to: %s", wo)
			log.SetOutput(sll.writer)
			log.Printf("[INFO] Redirected sink to here (%s)", wo)
		}
	}

	return nil
}

// CustomLog represents a custom logger configuration.
type CustomLog struct {
	WriterRaw    json.RawMessage `json:"writer,omitempty"`
	EncoderRaw   json.RawMessage `json:"encoder,omitempty"`
	Level        string          `json:"level,omitempty"`
	Sampling     *LogSampling    `json:"sampling,omitempty"`
	AllowModules []string        `json:"allow_modules,omitempty"`
	DenyModules  []string        `json:"deny_modules,omitempty"`

	writerOpener WriterOpener
	writer       io.WriteCloser
	encoder      zapcore.Encoder
	levelEnabler zapcore.LevelEnabler
	core         zapcore.Core
}

func (cl *CustomLog) provision(ctx Context, logging *Logging) error {
	// set up the log level
	switch cl.Level {
	case "debug":
		cl.levelEnabler = zapcore.DebugLevel
	case "", "info":
		cl.levelEnabler = zapcore.InfoLevel
	case "warn":
		cl.levelEnabler = zapcore.WarnLevel
	case "error":
		cl.levelEnabler = zapcore.ErrorLevel
	case "panic":
		cl.levelEnabler = zapcore.PanicLevel
	case "fatal":
		cl.levelEnabler = zapcore.FatalLevel
	default:
		return fmt.Errorf("unrecognized log level: %s", cl.Level)
	}

	// If both Allow and Deny lists are populated, then each item must
	// be a superspace or subspace of an item in the other list, because
	// populating both lists means that any given item is either a rule
	// or an exception to another rule. But if the item is not a super-
	// or sub-space of any item in the other list, it is neither a rule
	// nor an exception, and is a contradiction. Ensure, too, that the
	// sets do not intersect, which is also a contradiction.
	if len(cl.AllowModules) > 0 && len(cl.DenyModules) > 0 {
		// prevent intersections
		for _, allow := range cl.AllowModules {
			for _, deny := range cl.DenyModules {
				if allow == deny {
					return fmt.Errorf("allow_modules and deny_modules must not intersect, but found %s in both lists", allow)
				}
			}
		}

		// ensure namespaces are nested
	outer:
		for _, allow := range cl.AllowModules {
			for _, deny := range cl.DenyModules {
				if strings.HasPrefix(allow+".", deny+".") ||
					strings.HasPrefix(deny+".", allow+".") {
					continue outer
				}
			}
			return fmt.Errorf("when both allow_modules and deny_modules are populated, each element must be a superspace or subspace of one in the other list; check '%s' in allow_modules", allow)
		}
	}

	if cl.EncoderRaw != nil {
		val, err := ctx.LoadModuleInline("format", "caddy.logging.encoders", cl.EncoderRaw)
		if err != nil {
			return fmt.Errorf("loading log encoder module: %v", err)
		}
		cl.EncoderRaw = nil // allow GC to deallocate
		cl.encoder = val.(zapcore.Encoder)
	}
	if cl.encoder == nil {
		cl.encoder = zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig())
	}

	if cl.WriterRaw != nil {
		val, err := ctx.LoadModuleInline("output", "caddy.logging.writers", cl.WriterRaw)
		if err != nil {
			return fmt.Errorf("loading log writer module: %v", err)
		}
		cl.WriterRaw = nil // allow GC to deallocate
		cl.writerOpener = val.(WriterOpener)
	}
	if cl.writerOpener == nil {
		cl.writerOpener = StderrWriter{}
	}
	var err error
	cl.writer, _, err = logging.openWriter(cl.writerOpener)
	if err != nil {
		return fmt.Errorf("opening log writer using %#v: %v", cl.writerOpener, err)
	}

	cl.buildCore()

	return nil
}

func (cl *CustomLog) buildCore() {
	c := zapcore.NewCore(
		cl.encoder,
		zapcore.AddSync(cl.writer),
		cl.levelEnabler,
	)
	if cl.Sampling != nil && cl.Sampling.Interval > 0 {
		if cl.Sampling.Interval == 0 {
			cl.Sampling.Interval = 1 * time.Second
		}
		if cl.Sampling.First == 0 {
			cl.Sampling.First = 100
		}
		if cl.Sampling.Thereafter == 0 {
			cl.Sampling.Thereafter = 100
		}
		c = zapcore.NewSampler(c, cl.Sampling.Interval,
			cl.Sampling.First, cl.Sampling.Thereafter)
	}
	cl.core = c
}

func (cl *CustomLog) matchesModule(moduleName string) bool {
	// accept all modules by default
	if len(cl.AllowModules) == 0 && len(cl.DenyModules) == 0 {
		return true
	}

	// append a dot so that partial namespaces don't match
	// (i.e. we don't want "foo.b" to match "foo.bar"); we
	// will also have to append a dot when we do HasPrefix
	// below to compensate for when when namespaces are equal
	moduleName += "."

	var longestAccept, longestReject int

	if len(cl.AllowModules) > 0 {
		for _, namespace := range cl.AllowModules {
			if strings.HasPrefix(moduleName, namespace+".") &&
				len(namespace) > longestAccept {
				longestAccept = len(namespace)
			}
		}
		// the accept list was populated, meaning that
		// a match in this list is absolutely required
		// if we are to accept the entry
		if longestAccept == 0 {
			return false
		}
	}

	if len(cl.DenyModules) > 0 {
		for _, namespace := range cl.DenyModules {
			if strings.HasPrefix(moduleName, namespace+".") &&
				len(namespace) > longestReject {
				longestReject = len(namespace)
			}
		}
		// the reject list is populated, so we have to
		// reject this entry if its match is better
		// than the best from the accept list
		if longestReject > longestAccept {
			return false
		}
	}

	return longestAccept > longestReject
}

// LogSampling configures log entry sampling.
type LogSampling struct {
	Interval   time.Duration `json:"interval,omitempty"`
	First      int           `json:"first,omitempty"`
	Thereafter int           `json:"thereafter,omitempty"`
}

type (
	// StdoutWriter can write logs to stdout.
	StdoutWriter struct{}

	// StderrWriter can write logs to stdout.
	StderrWriter struct{}
)

// CaddyModule returns the Caddy module information.
func (StdoutWriter) CaddyModule() ModuleInfo {
	return ModuleInfo{
		Name: "log.writers.stdout",
		New:  func() Module { return new(StdoutWriter) },
	}
}

// CaddyModule returns the Caddy module information.
func (StderrWriter) CaddyModule() ModuleInfo {
	return ModuleInfo{
		Name: "log.writers.stderr",
		New:  func() Module { return new(StderrWriter) },
	}
}

func (sw StdoutWriter) String() string { return "stdout" }

func (sw StderrWriter) String() string { return "stderr" }

// WriterKey returns a unique key representing sw.
func (sw StdoutWriter) WriterKey() string {
	return "std:out"
}

// WriterKey returns a unique key representing sw.
func (sw StderrWriter) WriterKey() string {
	return "std:err"
}

// OpenWriter returns os.Stdout that can't be closed.
func (sw StdoutWriter) OpenWriter() (io.WriteCloser, error) {
	return notClosable{os.Stdout}, nil
}

// OpenWriter returns os.Stderr that can't be closed.
func (sw StderrWriter) OpenWriter() (io.WriteCloser, error) {
	return notClosable{os.Stderr}, nil
}

// notClosable is an io.WriteCloser that can't be closed.
type notClosable struct{ io.Writer }

func (fc notClosable) Close() error { return nil }

// Log returns the current default logger.
func Log() *zap.Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger.logger
}

// newDefaultProductionLog configures a custom log that is
// intended for use by default if no other log is specified
// in a config. It writes to stderr, uses the console encoder,
// and enables INFO-level logs and higher.
func newDefaultProductionLog() (*defaultCustomLog, error) {
	cl := new(CustomLog)
	cl.writerOpener = StderrWriter{}
	var err error
	cl.writer, err = cl.writerOpener.OpenWriter()
	if err != nil {
		return nil, err
	}
	encCfg := zap.NewDevelopmentEncoderConfig()
	cl.encoder = zapcore.NewConsoleEncoder(encCfg)
	cl.levelEnabler = zapcore.InfoLevel

	cl.buildCore()

	return &defaultCustomLog{
		CustomLog: cl,
		logger:    zap.New(cl.core),
	}, nil
}

type defaultCustomLog struct {
	*CustomLog
	logger *zap.Logger
}

var (
	defaultLogger, _ = newDefaultProductionLog()
	defaultLoggerMu  sync.RWMutex
)

var writers = NewUsagePool()
