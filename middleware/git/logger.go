package git

import (
	"log"
	"os"
	"sync"
)

// logger is used to log errors
var logger = &gitLogger{l: log.New(os.Stderr, "", log.LstdFlags)}

// gitLogger wraps log.Logger with mutex for thread safety.
type gitLogger struct {
	l *log.Logger
	sync.RWMutex
}

func (g *gitLogger) logger() *log.Logger {
	g.RLock()
	defer g.RUnlock()
	return g.l
}

func (g *gitLogger) setLogger(l *log.Logger) {
	g.Lock()
	g.l = l
	g.Unlock()
}

// Logger gets the currently available logger
func Logger() *log.Logger {
	return logger.logger()
}

// SetLogger sets the current logger to l
func SetLogger(l *log.Logger) {
	logger.setLogger(l)
}
