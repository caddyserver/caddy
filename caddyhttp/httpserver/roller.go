package httpserver

import (
	"io"
	"path/filepath"
	"strconv"

	"github.com/mholt/caddy"

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
			LocalTime:  l.LocalTime,
		}
		lumberjacks[absPath] = lj
	}
	return lj
}

// ParseRoller parses roller contents out of c.
func ParseRoller(c *caddy.Controller) (*LogRoller, error) {
	var size, age, keep int
	// This is kind of a hack to support nested blocks:
	// As we are already in a block: either log or errors,
	// c.nesting > 0 but, as soon as c meets a }, it thinks
	// the block is over and return false for c.NextBlock.
	for c.NextBlock() {
		what := c.Val()
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		value := c.Val()
		var err error
		switch what {
		case "size":
			size, err = strconv.Atoi(value)
		case "age":
			age, err = strconv.Atoi(value)
		case "keep":
			keep, err = strconv.Atoi(value)
		}
		if err != nil {
			return nil, err
		}
	}
	return &LogRoller{
		MaxSize:    size,
		MaxAge:     age,
		MaxBackups: keep,
		LocalTime:  true,
	}, nil
}

// lumberjacks maps log filenames to the logger
// that is being used to keep them rolled/maintained.
var lumberjacks = make(map[string]*lumberjack.Logger)
