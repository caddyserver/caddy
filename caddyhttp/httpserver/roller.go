// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"errors"
	"io"
	"path/filepath"
	"strconv"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// LogRoller implements a type that provides a rolling logger.
type LogRoller struct {
	Disabled   bool
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
		subdir == directiveRotateCompress ||
		subdir == directiveRotateDisable
}

var errInvalidRollParameter = errors.New("invalid roller parameter")

// ParseRoller parses roller contents out of c.
func ParseRoller(l *LogRoller, what string, where ...string) error {
	if l == nil {
		l = DefaultLogRoller()
	}

	// rotate_compress doesn't accept any parameters.
	// others only accept one parameter
	if ((what == directiveRotateCompress || what == directiveRotateDisable) && len(where) != 0) ||
		((what != directiveRotateCompress && what != directiveRotateDisable) && len(where) != 1) {
		return errInvalidRollParameter
	}

	var (
		value int
		err   error
	)
	if what != directiveRotateCompress && what != directiveRotateDisable {
		value, err = strconv.Atoi(where[0])
		if err != nil {
			return err
		}
	}

	switch what {
	case directiveRotateDisable:
		l.Disabled = true
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

	directiveRotateDisable  = "rotate_disable"
	directiveRotateSize     = "rotate_size"
	directiveRotateAge      = "rotate_age"
	directiveRotateKeep     = "rotate_keep"
	directiveRotateCompress = "rotate_compress"
)

// lumberjacks maps log filenames to the logger
// that is being used to keep them rolled/maintained.
var lumberjacks = make(map[string]io.Writer)
