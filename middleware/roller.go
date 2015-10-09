package middleware

import (
	"io"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogRoller implements a middleware that provides a rolling logger.
type LogRoller struct {
	Filename   string
	MaxSize    int
	MaxAge     int
	MaxBackups int
	LocalTime  bool
}

// GetLogWriter returns an io.Writer that writes to a rolling logger.
func (l LogRoller) GetLogWriter() io.Writer {
	return &lumberjack.Logger{
		Filename:   l.Filename,
		MaxSize:    l.MaxSize,
		MaxAge:     l.MaxAge,
		MaxBackups: l.MaxBackups,
		LocalTime:  l.LocalTime,
	}
}
