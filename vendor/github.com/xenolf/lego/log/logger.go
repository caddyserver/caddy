package log

import (
	"log"
	"os"
)

// Logger is an optional custom logger.
var Logger *log.Logger

// Fatal writes a log entry.
// It uses Logger if not nil, otherwise it uses the default log.Logger.
func Fatal(args ...interface{}) {
	if Logger == nil {
		Logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	Logger.Fatal(args...)
}

// Fatalf writes a log entry.
// It uses Logger if not nil, otherwise it uses the default log.Logger.
func Fatalf(format string, args ...interface{}) {
	if Logger == nil {
		Logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	Logger.Fatalf(format, args...)
}

// Print writes a log entry.
// It uses Logger if not nil, otherwise it uses the default log.Logger.
func Print(args ...interface{}) {
	if Logger == nil {
		Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	Logger.Print(args...)
}

// Println writes a log entry.
// It uses Logger if not nil, otherwise it uses the default log.Logger.
func Println(args ...interface{}) {
	if Logger == nil {
		Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	Logger.Println(args...)
}

// Printf writes a log entry.
// It uses Logger if not nil, otherwise it uses the default log.Logger.
func Printf(format string, args ...interface{}) {
	if Logger == nil {
		Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	Logger.Printf(format, args...)
}
