package middleware

import (
	"io"

	"gopkg.in/natefinch/lumberjack.v2"
)

type LogRoller struct {
	Filename   string
	MaxSize    int
	MaxAge     int
	MaxBackups int
	LocalTime  bool
}

func (l LogRoller) GetLogWriter() io.Writer {
	return &lumberjack.Logger{
		Filename:   l.Filename,
		MaxSize:    l.MaxSize,
		MaxAge:     l.MaxAge,
		MaxBackups: l.MaxBackups,
		LocalTime:  l.LocalTime,
	}
}
