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
	"golang.org/x/term"
)

func init() {
	RegisterModule(StdoutWriter{})
	RegisterModule(StderrWriter{})
	RegisterModule(DiscardWriter{})
}

// Logging facilitates logging within Caddy. The default log is
// called "default" and you can customize it. You can also define
// additional logs.
//
// By default, all logs at INFO level and higher are written to
// standard error ("stderr" writer) in a human-readable format
// ("console" encoder if stdout is an interactive terminal, "json"
// encoder otherwise).
//
// All defined logs accept all log entries by default, but you
// can filter by level and module/logger names. A logger's name
// is the same as the module's name, but a module may append to
// logger names for more specificity. For example, you can
// filter logs emitted only by HTTP handlers using the name
// "http.handlers", because all HTTP handler module names have
// that prefix.
//
// Caddy logs (except the sink) are zero-allocation, so they are
// very high-performing in terms of memory and CPU time. Enabling
// sampling can further increase throughput on extremely high-load
// servers.
type Logging struct {
	// Sink is the destination for all unstructured logs emitted
	// from Go's standard library logger. These logs are common
	// in dependencies that are not designed specifically for use
	// in Caddy. Because it is global and unstructured, the sink
	// lacks most advanced features and customizations.
	Sink *SinkLog `json:"sink,omitempty"`

	// Logs are your logs, keyed by an arbitrary name of your
	// choosing. The default log can be customized by defining
	// a log called "default". You can further define other logs
	// and filter what kinds of entries they accept.
	Logs map[string]*CustomLog `json:"logs,omitempty"`

	// a list of all keys for open writers; all writers
	// that are opened to provision this logging config
	// must have their keys added to this list so they
	// can be closed when cleaning up
	writerKeys []string
}

// openLogs sets up the config and opens all the configured writers.
// It closes its logs when ctx is canceled, so it should clean up
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

	// as a special case, set up the default structured Caddy log next
	if err := logging.setupNewDefault(ctx); err != nil {
		return err
	}

	// then set up any other custom logs
	for name, l := range logging.Logs {
		// the default log is already set up
		if name == DefaultLoggerName {
			continue
		}

		err := l.provision(ctx, logging)
		if err != nil {
			return fmt.Errorf("setting up custom log '%s': %v", name, err)
		}

		// Any other logs that use the discard writer can be deleted
		// entirely. This avoids encoding and processing of each
		// log entry that would just be thrown away anyway. Notably,
		// we do not reach this point for the default log, which MUST
		// exist, otherwise core log emissions would panic because
		// they use the Log() function directly which expects a non-nil
		// logger. Even if we keep logs with a discard writer, they
		// have a nop core, and keeping them at all seems unnecessary.
		if _, ok := l.writerOpener.(*DiscardWriter); ok {
			delete(logging.Logs, name)
			continue
		}
	}

	return nil
}

func (logging *Logging) setupNewDefault(ctx Context) error {
	if logging.Logs == nil {
		logging.Logs = make(map[string]*CustomLog)
	}

	// extract the user-defined default log, if any
	newDefault := new(defaultCustomLog)
	if userDefault, ok := logging.Logs[DefaultLoggerName]; ok {
		newDefault.CustomLog = userDefault
	} else {
		// if none, make one with our own default settings
		var err error
		newDefault, err = newDefaultProductionLog()
		if err != nil {
			return fmt.Errorf("setting up default Caddy log: %v", err)
		}
		logging.Logs[DefaultLoggerName] = newDefault.CustomLog
	}

	// options for the default logger
	options, err := newDefault.CustomLog.buildOptions()
	if err != nil {
		return fmt.Errorf("setting up default log: %v", err)
	}

	// set up this new log
	err = newDefault.CustomLog.provision(ctx, logging)
	if err != nil {
		return fmt.Errorf("setting up default log: %v", err)
	}
	newDefault.logger = zap.New(newDefault.CustomLog.core, options...)

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

	return nil
}

// closeLogs cleans up resources allocated during openLogs.
// A successful call to openLogs calls this automatically
// when the context is canceled.
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
	modID := string(mod.CaddyModule().ID)
	var cores []zapcore.Core
	var options []zap.Option

	if logging != nil {
		for _, l := range logging.Logs {
			if l.matchesModule(modID) {
				if len(l.Include) == 0 && len(l.Exclude) == 0 {
					cores = append(cores, l.core)
					continue
				}
				if len(options) == 0 {
					newOptions, err := l.buildOptions()
					if err != nil {
						Log().Error("building options for logger", zap.String("module", modID), zap.Error(err))
					}
					options = newOptions
				}
				cores = append(cores, &filteringCore{Core: l.core, cl: l})
			}
		}
	}

	multiCore := zapcore.NewTee(cores...)

	return zap.New(multiCore, options...).Named(modID)
}

// openWriter opens a writer using opener, and returns true if
// the writer is new, or false if the writer already exists.
func (logging *Logging) openWriter(opener WriterOpener) (io.WriteCloser, bool, error) {
	key := opener.WriterKey()
	writer, loaded, err := writers.LoadOrNew(key, func() (Destructor, error) {
		w, err := opener.OpenWriter()
		return writerDestructor{w}, err
	})
	if err != nil {
		return nil, false, err
	}
	logging.writerKeys = append(logging.writerKeys, key)
	return writer.(io.WriteCloser), !loaded, nil
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

// IsWriterStandardStream returns true if the input is a
// writer-opener to a standard stream (stdout, stderr).
func IsWriterStandardStream(wo WriterOpener) bool {
	switch wo.(type) {
	case StdoutWriter, StderrWriter,
		*StdoutWriter, *StderrWriter:
		return true
	}
	return false
}

type writerDestructor struct {
	io.WriteCloser
}

func (wdest writerDestructor) Destruct() error {
	return wdest.Close()
}

// BaseLog contains the common logging parameters for logging.
type BaseLog struct {
	// The module that writes out log entries for the sink.
	WriterRaw json.RawMessage `json:"writer,omitempty" caddy:"namespace=caddy.logging.writers inline_key=output"`

	// The encoder is how the log entries are formatted or encoded.
	EncoderRaw json.RawMessage `json:"encoder,omitempty" caddy:"namespace=caddy.logging.encoders inline_key=format"`

	// Tees entries through a zap.Core module which can extract
	// log entry metadata and fields for further processing.
	CoreRaw json.RawMessage `json:"core,omitempty" caddy:"namespace=caddy.logging.cores inline_key=module"`

	// Level is the minimum level to emit, and is inclusive.
	// Possible levels: DEBUG, INFO, WARN, ERROR, PANIC, and FATAL
	Level string `json:"level,omitempty"`

	// Sampling configures log entry sampling. If enabled,
	// only some log entries will be emitted. This is useful
	// for improving performance on extremely high-pressure
	// servers.
	Sampling *LogSampling `json:"sampling,omitempty"`

	// If true, the log entry will include the caller's
	// file name and line number. Default off.
	WithCaller bool `json:"with_caller,omitempty"`

	// If non-zero, and `with_caller` is true, this many
	// stack frames will be skipped when determining the
	// caller. Default 0.
	WithCallerSkip int `json:"with_caller_skip,omitempty"`

	// If not empty, the log entry will include a stack trace
	// for all logs at the given level or higher. See `level`
	// for possible values. Default off.
	WithStacktrace string `json:"with_stacktrace,omitempty"`

	writerOpener WriterOpener
	writer       io.WriteCloser
	encoder      zapcore.Encoder
	levelEnabler zapcore.LevelEnabler
	core         zapcore.Core
}

func (cl *BaseLog) provisionCommon(ctx Context, logging *Logging) error {
	if cl.WriterRaw != nil {
		mod, err := ctx.LoadModule(cl, "WriterRaw")
		if err != nil {
			return fmt.Errorf("loading log writer module: %v", err)
		}
		cl.writerOpener = mod.(WriterOpener)
	}
	if cl.writerOpener == nil {
		cl.writerOpener = StderrWriter{}
	}
	var err error
	cl.writer, _, err = logging.openWriter(cl.writerOpener)
	if err != nil {
		return fmt.Errorf("opening log writer using %#v: %v", cl.writerOpener, err)
	}

	// set up the log level
	cl.levelEnabler, err = parseLevel(cl.Level)
	if err != nil {
		return err
	}

	if cl.EncoderRaw != nil {
		mod, err := ctx.LoadModule(cl, "EncoderRaw")
		if err != nil {
			return fmt.Errorf("loading log encoder module: %v", err)
		}
		cl.encoder = mod.(zapcore.Encoder)

		// if the encoder module needs the writer to determine
		// the correct default to use for a nested encoder, we
		// pass it down as a secondary provisioning step
		if cfd, ok := mod.(ConfiguresFormatterDefault); ok {
			if err := cfd.ConfigureDefaultFormat(cl.writerOpener); err != nil {
				return fmt.Errorf("configuring default format for encoder module: %v", err)
			}
		}
	}
	if cl.encoder == nil {
		cl.encoder = newDefaultProductionLogEncoder(cl.writerOpener)
	}
	cl.buildCore()
	if cl.CoreRaw != nil {
		mod, err := ctx.LoadModule(cl, "CoreRaw")
		if err != nil {
			return fmt.Errorf("loading log core module: %v", err)
		}
		core := mod.(zapcore.Core)
		cl.core = zapcore.NewTee(cl.core, core)
	}
	return nil
}

func (cl *BaseLog) buildCore() {
	// logs which only discard their output don't need
	// to perform encoding or any other processing steps
	// at all, so just shortcut to a nop core instead
	if _, ok := cl.writerOpener.(*DiscardWriter); ok {
		cl.core = zapcore.NewNopCore()
		return
	}
	c := zapcore.NewCore(
		cl.encoder,
		zapcore.AddSync(cl.writer),
		cl.levelEnabler,
	)
	if cl.Sampling != nil {
		if cl.Sampling.Interval == 0 {
			cl.Sampling.Interval = 1 * time.Second
		}
		if cl.Sampling.First == 0 {
			cl.Sampling.First = 100
		}
		if cl.Sampling.Thereafter == 0 {
			cl.Sampling.Thereafter = 100
		}
		c = zapcore.NewSamplerWithOptions(c, cl.Sampling.Interval,
			cl.Sampling.First, cl.Sampling.Thereafter)
	}
	cl.core = c
}

func (cl *BaseLog) buildOptions() ([]zap.Option, error) {
	var options []zap.Option
	if cl.WithCaller {
		options = append(options, zap.AddCaller())
		if cl.WithCallerSkip != 0 {
			options = append(options, zap.AddCallerSkip(cl.WithCallerSkip))
		}
	}
	if cl.WithStacktrace != "" {
		levelEnabler, err := parseLevel(cl.WithStacktrace)
		if err != nil {
			return options, fmt.Errorf("setting up default Caddy log: %v", err)
		}
		options = append(options, zap.AddStacktrace(levelEnabler))
	}
	return options, nil
}

// SinkLog configures the default Go standard library
// global logger in the log package. This is necessary because
// module dependencies which are not built specifically for
// Caddy will use the standard logger. This is also known as
// the "sink" logger.
type SinkLog struct {
	BaseLog
}

func (sll *SinkLog) provision(ctx Context, logging *Logging) error {
	if err := sll.provisionCommon(ctx, logging); err != nil {
		return err
	}

	options, err := sll.buildOptions()
	if err != nil {
		return err
	}

	logger := zap.New(sll.core, options...)
	ctx.cleanupFuncs = append(ctx.cleanupFuncs, zap.RedirectStdLog(logger))
	return nil
}

// CustomLog represents a custom logger configuration.
//
// By default, a log will emit all log entries. Some entries
// will be skipped if sampling is enabled. Further, the Include
// and Exclude parameters define which loggers (by name) are
// allowed or rejected from emitting in this log. If both Include
// and Exclude are populated, their values must be mutually
// exclusive, and longer namespaces have priority. If neither
// are populated, all logs are emitted.
type CustomLog struct {
	BaseLog

	// Include defines the names of loggers to emit in this
	// log. For example, to include only logs emitted by the
	// admin API, you would include "admin.api".
	Include []string `json:"include,omitempty"`

	// Exclude defines the names of loggers that should be
	// skipped by this log. For example, to exclude only
	// HTTP access logs, you would exclude "http.log.access".
	Exclude []string `json:"exclude,omitempty"`
}

func (cl *CustomLog) provision(ctx Context, logging *Logging) error {
	if err := cl.provisionCommon(ctx, logging); err != nil {
		return err
	}

	// If both Include and Exclude lists are populated, then each item must
	// be a superspace or subspace of an item in the other list, because
	// populating both lists means that any given item is either a rule
	// or an exception to another rule. But if the item is not a super-
	// or sub-space of any item in the other list, it is neither a rule
	// nor an exception, and is a contradiction. Ensure, too, that the
	// sets do not intersect, which is also a contradiction.
	if len(cl.Include) > 0 && len(cl.Exclude) > 0 {
		// prevent intersections
		for _, allow := range cl.Include {
			for _, deny := range cl.Exclude {
				if allow == deny {
					return fmt.Errorf("include and exclude must not intersect, but found %s in both lists", allow)
				}
			}
		}

		// ensure namespaces are nested
	outer:
		for _, allow := range cl.Include {
			for _, deny := range cl.Exclude {
				if strings.HasPrefix(allow+".", deny+".") ||
					strings.HasPrefix(deny+".", allow+".") {
					continue outer
				}
			}
			return fmt.Errorf("when both include and exclude are populated, each element must be a superspace or subspace of one in the other list; check '%s' in include", allow)
		}
	}
	return nil
}

func (cl *CustomLog) matchesModule(moduleID string) bool {
	return cl.loggerAllowed(moduleID, true)
}

// loggerAllowed returns true if name is allowed to emit
// to cl. isModule should be true if name is the name of
// a module and you want to see if ANY of that module's
// logs would be permitted.
func (cl *CustomLog) loggerAllowed(name string, isModule bool) bool {
	// accept all loggers by default
	if len(cl.Include) == 0 && len(cl.Exclude) == 0 {
		return true
	}

	// append a dot so that partial names don't match
	// (i.e. we don't want "foo.b" to match "foo.bar"); we
	// will also have to append a dot when we do HasPrefix
	// below to compensate for when namespaces are equal
	if name != "" && name != "*" && name != "." {
		name += "."
	}

	var longestAccept, longestReject int

	if len(cl.Include) > 0 {
		for _, namespace := range cl.Include {
			var hasPrefix bool
			if isModule {
				hasPrefix = strings.HasPrefix(namespace+".", name)
			} else {
				hasPrefix = strings.HasPrefix(name, namespace+".")
			}
			if hasPrefix && len(namespace) > longestAccept {
				longestAccept = len(namespace)
			}
		}
		// the include list was populated, meaning that
		// a match in this list is absolutely required
		// if we are to accept the entry
		if longestAccept == 0 {
			return false
		}
	}

	if len(cl.Exclude) > 0 {
		for _, namespace := range cl.Exclude {
			// * == all logs emitted by modules
			// . == all logs emitted by core
			if (namespace == "*" && name != ".") ||
				(namespace == "." && name == ".") {
				return false
			}
			if strings.HasPrefix(name, namespace+".") &&
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

	return (longestAccept > longestReject) ||
		(len(cl.Include) == 0 && longestReject == 0)
}

// filteringCore filters log entries based on logger name,
// according to the rules of a CustomLog.
type filteringCore struct {
	zapcore.Core
	cl *CustomLog
}

// With properly wraps With.
func (fc *filteringCore) With(fields []zapcore.Field) zapcore.Core {
	return &filteringCore{
		Core: fc.Core.With(fields),
		cl:   fc.cl,
	}
}

// Check only allows the log entry if its logger name
// is allowed from the include/exclude rules of fc.cl.
func (fc *filteringCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if fc.cl.loggerAllowed(e.LoggerName, false) {
		return fc.Core.Check(e, ce)
	}
	return ce
}

// LogSampling configures log entry sampling.
type LogSampling struct {
	// The window over which to conduct sampling.
	Interval time.Duration `json:"interval,omitempty"`

	// Log this many entries within a given level and
	// message for each interval.
	First int `json:"first,omitempty"`

	// If more entries with the same level and message
	// are seen during the same interval, keep one in
	// this many entries until the end of the interval.
	Thereafter int `json:"thereafter,omitempty"`
}

type (
	// StdoutWriter writes logs to standard out.
	StdoutWriter struct{}

	// StderrWriter writes logs to standard error.
	StderrWriter struct{}

	// DiscardWriter discards all writes.
	DiscardWriter struct{}
)

// CaddyModule returns the Caddy module information.
func (StdoutWriter) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "caddy.logging.writers.stdout",
		New: func() Module { return new(StdoutWriter) },
	}
}

// CaddyModule returns the Caddy module information.
func (StderrWriter) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "caddy.logging.writers.stderr",
		New: func() Module { return new(StderrWriter) },
	}
}

// CaddyModule returns the Caddy module information.
func (DiscardWriter) CaddyModule() ModuleInfo {
	return ModuleInfo{
		ID:  "caddy.logging.writers.discard",
		New: func() Module { return new(DiscardWriter) },
	}
}

func (StdoutWriter) String() string  { return "stdout" }
func (StderrWriter) String() string  { return "stderr" }
func (DiscardWriter) String() string { return "discard" }

// WriterKey returns a unique key representing stdout.
func (StdoutWriter) WriterKey() string { return "std:out" }

// WriterKey returns a unique key representing stderr.
func (StderrWriter) WriterKey() string { return "std:err" }

// WriterKey returns a unique key representing discard.
func (DiscardWriter) WriterKey() string { return "discard" }

// OpenWriter returns os.Stdout that can't be closed.
func (StdoutWriter) OpenWriter() (io.WriteCloser, error) {
	return notClosable{os.Stdout}, nil
}

// OpenWriter returns os.Stderr that can't be closed.
func (StderrWriter) OpenWriter() (io.WriteCloser, error) {
	return notClosable{os.Stderr}, nil
}

// OpenWriter returns io.Discard that can't be closed.
func (DiscardWriter) OpenWriter() (io.WriteCloser, error) {
	return notClosable{io.Discard}, nil
}

// notClosable is an io.WriteCloser that can't be closed.
type notClosable struct{ io.Writer }

func (fc notClosable) Close() error { return nil }

type defaultCustomLog struct {
	*CustomLog
	logger *zap.Logger
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
	cl.encoder = newDefaultProductionLogEncoder(cl.writerOpener)
	cl.levelEnabler = zapcore.InfoLevel

	cl.buildCore()

	logger := zap.New(cl.core)

	// capture logs from other libraries which
	// may not be using zap logging directly
	_ = zap.RedirectStdLog(logger)

	return &defaultCustomLog{
		CustomLog: cl,
		logger:    logger,
	}, nil
}

func newDefaultProductionLogEncoder(wo WriterOpener) zapcore.Encoder {
	encCfg := zap.NewProductionEncoderConfig()
	if IsWriterStandardStream(wo) && term.IsTerminal(int(os.Stderr.Fd())) {
		// if interactive terminal, make output more human-readable by default
		encCfg.EncodeTime = func(ts time.Time, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString(ts.UTC().Format("2006/01/02 15:04:05.000"))
		}
		if coloringEnabled {
			encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		return zapcore.NewConsoleEncoder(encCfg)
	}
	return zapcore.NewJSONEncoder(encCfg)
}

func parseLevel(levelInput string) (zapcore.LevelEnabler, error) {
	repl := NewReplacer()
	level, err := repl.ReplaceOrErr(levelInput, true, true)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %v", err)
	}
	level = strings.ToLower(level)

	// set up the log level
	switch level {
	case "debug":
		return zapcore.DebugLevel, nil
	case "", "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "panic":
		return zapcore.PanicLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	default:
		return nil, fmt.Errorf("unrecognized log level: %s", level)
	}
}

// Log returns the current default logger.
func Log() *zap.Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger.logger
}

var (
	coloringEnabled  = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "xterm-mono"
	defaultLogger, _ = newDefaultProductionLog()
	defaultLoggerMu  sync.RWMutex
)

var writers = NewUsagePool()

// ConfiguresFormatterDefault is an optional interface that
// encoder modules can implement to configure the default
// format of their encoder. This is useful for encoders
// which nest an encoder, that needs to know the writer
// in order to determine the correct default.
type ConfiguresFormatterDefault interface {
	ConfigureDefaultFormat(WriterOpener) error
}

const DefaultLoggerName = "default"

// Interface guards
var (
	_ io.WriteCloser = (*notClosable)(nil)
	_ WriterOpener   = (*StdoutWriter)(nil)
	_ WriterOpener   = (*StderrWriter)(nil)
)
