package httpserver

import (
	"io"
	"path/filepath"
	"strconv"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogRoller implements a type that provides a rolling logger.
type LogRoller struct {
	Filename   string
	MaxSize    int
	MaxAge     int
	MaxBackups int
	Compress   bool
	LocalTime  bool
}

// GetLogWriter returns an io.Writer that writes to a rolling logger.
// This should be called only from the main goroutine (like during
// server setup) because this method is not thread-safe; it is careful
// to create only one log writer per log file, even if the log file
// is shared by different sites or middlewares. This ensures that
// rolling is synchronized, since a process (or multiple processes)
// should not create more than one roller on the same file at the
// same time. See issue #1363.
func (l LogRoller) GetLogWriter() io.Writer {
	absPath, err := filepath.Abs(l.Filename)
	if err != nil {
		absPath = l.Filename // oh well, hopefully they're consistent in how they specify the filename
	}
	lj, has := lumberjacks[absPath]
	if !has {
		lj = &lumberjack.Logger{
			Filename:   l.Filename,
			MaxSize:    l.MaxSize,
			MaxAge:     l.MaxAge,
			MaxBackups: l.MaxBackups,
			Compress:   l.Compress,
			LocalTime:  l.LocalTime,
		}
		lumberjacks[absPath] = lj
	}
	return lj
}

// IsLogRollerSubdirective is true if the subdirective is for the log roller.
func IsLogRollerSubdirective(subdir string) bool {
	return subdir == directiveRotateSize ||
		subdir == directiveRotateAge ||
		subdir == directiveRotateKeep ||
		subdir == directiveRotateCompress
}

// ParseRoller parses roller contents out of c.
func ParseRoller(l *LogRoller, what string, where string) error {
	if l == nil {
		l = DefaultLogRoller()
	}
	var value int
	var err error
	value, err = strconv.Atoi(where)
	if what != directiveRotateCompress && err != nil {
		return err
	}
	switch what {
	case directiveRotateSize:
		l.MaxSize = value
	case directiveRotateAge:
		l.MaxAge = value
	case directiveRotateKeep:
		l.MaxBackups = value
	case directiveRotateCompress:
		l.Compress = true
	}
	return nil
}

// DefaultLogRoller will roll logs by default.
func DefaultLogRoller() *LogRoller {
	return &LogRoller{
		MaxSize:    defaultRotateSize,
		MaxAge:     defaultRotateAge,
		MaxBackups: defaultRotateKeep,
		Compress:   false,
		LocalTime:  true,
	}
}

const (
	// defaultRotateSize is 100 MB.
	defaultRotateSize = 100
	// defaultRotateAge is 14 days.
	defaultRotateAge = 14
	// defaultRotateKeep is 10 files.
	defaultRotateKeep = 10

	directiveRotateSize     = "rotate_size"
	directiveRotateAge      = "rotate_age"
	directiveRotateKeep     = "rotate_keep"
	directiveRotateCompress = "rotate_compress"
)

// lumberjacks maps log filenames to the logger
// that is being used to keep them rolled/maintained.
var lumberjacks = make(map[string]*lumberjack.Logger)
