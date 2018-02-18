package utils

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// LogLevel of quic-go
type LogLevel uint8

const logEnv = "QUIC_GO_LOG_LEVEL"

const (
	// LogLevelNothing disables
	LogLevelNothing LogLevel = iota
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug
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
	if logLevel >= LogLevelInfo {
		logMessage(format, args...)
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel >= LogLevelError {
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
	switch strings.ToLower(os.Getenv(logEnv)) {
	case "":
		return
	case "debug":
		logLevel = LogLevelDebug
	case "info":
		logLevel = LogLevelInfo
	case "error":
		logLevel = LogLevelError
	default:
		fmt.Fprintln(os.Stderr, "invalid quic-go log level, see https://github.com/lucas-clemente/quic-go/wiki/Logging")
	}
}
