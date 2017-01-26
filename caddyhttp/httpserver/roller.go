package httpserver

import (
	"io"
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
func (l LogRoller) GetLogWriter() io.Writer {
	return &lumberjack.Logger{
		Filename:   l.Filename,
		MaxSize:    l.MaxSize,
		MaxAge:     l.MaxAge,
		MaxBackups: l.MaxBackups,
		LocalTime:  l.LocalTime,
	}
}

// ParseRoller parses roller contents out of c.
func ParseRoller(c *caddy.Controller) (*LogRoller, error) {
	var size, age, keep int
	size = DefaultRotateSize
	age = DefaultRotateAge
	keep = DefaultRotateKeep
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
		case "rotate_size":
			size, err = strconv.Atoi(value)
		case "rotate_age":
			age, err = strconv.Atoi(value)
		case "rotate_keep":
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

// DefaultLogRoller will roll logs by default.
func DefaultLogRoller() *LogRoller {
	return &LogRoller{
		MaxSize:    DefaultRotateSize,
		MaxAge:     DefaultRotateAge,
		MaxBackups: DefaultRotateKeep,
		LocalTime:  true,
	}
}

const (
	// DefaultRotateSize is 100 MB.
	DefaultRotateSize = 100
	// DefaultRotateAge is 14 days.
	DefaultRotateAge = 14
	// DefaultRotateKeep is 10 files.
	DefaultRotateKeep = 10
)
