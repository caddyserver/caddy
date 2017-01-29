package httpserver

import (
	"io"
	"strconv"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogRoller implements a type that provides a rolling logger.
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

// IsLogRollerSubdirective is true if the subdirective is for the log roller.
func IsLogRollerSubdirective(subdir string) bool {
	return subdir == directiveRotateSize ||
		subdir == directiveRotateAge ||
		subdir == directiveRotateKeep
}

// ParseRoller parses roller contents out of c.
func ParseRoller(l *LogRoller, what string, where string) error {
	if l == nil {
		l = DefaultLogRoller()
	}
	var value int
	var err error
	value, err = strconv.Atoi(where)
	if err != nil {
		return err
	}
	switch what {
	case directiveRotateSize:
		l.MaxSize = value
	case directiveRotateAge:
		l.MaxAge = value
	case directiveRotateKeep:
		l.MaxBackups = value
	}
	return nil
}

// DefaultLogRoller will roll logs by default.
func DefaultLogRoller() *LogRoller {
	return &LogRoller{
		MaxSize:    defaultRotateSize,
		MaxAge:     defaultRotateAge,
		MaxBackups: defaultRotateKeep,
		LocalTime:  true,
	}
}

const (
	// defaultRotateSize is 100 MB.
	defaultRotateSize = 100
	// defaultRotateAge is 14 days.
	defaultRotateAge = 14
	// defaultRotateKeep is 10 files.
	defaultRotateKeep   = 10
	directiveRotateSize = "rotate_size"
	directiveRotateAge  = "rotate_age"
	directiveRotateKeep = "rotate_keep"
)
