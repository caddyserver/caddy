package utils

import (
	"log"
	"os"
	"strconv"
	"time"
)

// LogLevel of quic-go
type LogLevel uint8

const (
	logEnv = "QUIC_GO_LOG_LEVEL"

	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug LogLevel = iota
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelNothing disables
	LogLevelNothing
)

var (
	logLevel   = LogLevelNothing
	timeFormat = ""
)

// SetLogLevel sets the log level
func SetLogLevel(level LogLevel) {
	logLevel = level
}

// SetLogTimeFormat sets the format of the timestamp
// an empty string disables the logging of timestamps
func SetLogTimeFormat(format string) {
	log.SetFlags(0) // disable timestamp logging done by the log package
	timeFormat = format
}

// Debugf logs something
func Debugf(format string, args ...interface{}) {
	if logLevel == LogLevelDebug {
		logMessage(format, args...)
	}
}

// Infof logs something
func Infof(format string, args ...interface{}) {
	if logLevel <= LogLevelInfo {
		logMessage(format, args...)
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel <= LogLevelError {
		logMessage(format, args...)
	}
}

func logMessage(format string, args ...interface{}) {
	if len(timeFormat) > 0 {
		log.Printf(time.Now().Format(timeFormat)+" "+format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Debug returns true if the log level is LogLevelDebug
func Debug() bool {
	return logLevel == LogLevelDebug
}

func init() {
	readLoggingEnv()
}

func readLoggingEnv() {
	env := os.Getenv(logEnv)
	if env == "" {
		return
	}
	level, err := strconv.Atoi(env)
	if err != nil {
		return
	}
	logLevel = LogLevel(level)
}
