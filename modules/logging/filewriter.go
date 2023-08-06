// Copyright 2015 Matthew Holt and The Caddy Authors
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

package logging

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dustin/go-humanize"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(FileWriter{})
}

// FileWriter can write logs to files. By default, log files
// are rotated ("rolled") when they get large, and old log
// files get deleted, to ensure that the process does not
// exhaust disk space.
type FileWriter struct {
	// Filename is the name of the file to write.
	Filename string `json:"filename,omitempty"`

	// Roll toggles log rolling or rotation, which is
	// enabled by default.
	Roll *bool `json:"roll,omitempty"`

	// When a log file reaches approximately this size,
	// it will be rotated.
	RollSizeMB int `json:"roll_size_mb,omitempty"`

	// Whether to compress rolled files. Default: true
	RollCompress *bool `json:"roll_gzip,omitempty"`

	// Whether to use local timestamps in rolled filenames.
	// Default: false
	RollLocalTime bool `json:"roll_local_time,omitempty"`

	// The maximum number of rolled log files to keep.
	// Default: 10
	RollKeep int `json:"roll_keep,omitempty"`

	// How many days to keep rolled log files. Default: 90
	RollKeepDays int `json:"roll_keep_days,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (FileWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.writers.file",
		New: func() caddy.Module { return new(FileWriter) },
	}
}

// Provision sets up the module
func (fw *FileWriter) Provision(ctx caddy.Context) error {
	// Replace placeholder in filename
	repl := caddy.NewReplacer()
	filename, err := repl.ReplaceOrErr(fw.Filename, true, true)
	if err != nil {
		return fmt.Errorf("invalid filename for log file: %v", err)
	}

	fw.Filename = filename
	return nil
}

func (fw FileWriter) String() string {
	fpath, err := filepath.Abs(fw.Filename)
	if err == nil {
		return fpath
	}
	return fw.Filename
}

// WriterKey returns a unique key representing this fw.
func (fw FileWriter) WriterKey() string {
	return "file:" + fw.Filename
}

// OpenWriter opens a new file writer.
func (fw FileWriter) OpenWriter() (io.WriteCloser, error) {
	// roll log files by default
	if fw.Roll == nil || *fw.Roll {
		if fw.RollSizeMB == 0 {
			fw.RollSizeMB = 100
		}
		if fw.RollCompress == nil {
			compress := true
			fw.RollCompress = &compress
		}
		if fw.RollKeep == 0 {
			fw.RollKeep = 10
		}
		if fw.RollKeepDays == 0 {
			fw.RollKeepDays = 90
		}

		return &lumberjack.Logger{
			Filename:   fw.Filename,
			MaxSize:    fw.RollSizeMB,
			MaxAge:     fw.RollKeepDays,
			MaxBackups: fw.RollKeep,
			LocalTime:  fw.RollLocalTime,
			Compress:   *fw.RollCompress,
		}, nil
	}

	// otherwise just open a regular file
	return os.OpenFile(fw.Filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o666)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	file <filename> {
//	    roll_disabled
//	    roll_size     <size>
//	    roll_uncompressed
//	    roll_local_time
//	    roll_keep     <num>
//	    roll_keep_for <days>
//	}
//
// The roll_size value has megabyte resolution.
// Fractional values are rounded up to the next whole megabyte (MiB).
//
// By default, compression is enabled, but can be turned off by setting
// the roll_uncompressed option.
//
// The roll_keep_for duration has day resolution.
// Fractional values are rounded up to the next whole number of days.
//
// If any of the roll_size, roll_keep, or roll_keep_for subdirectives are
// omitted or set to a zero value, then Caddy's default value for that
// subdirective is used.
func (fw *FileWriter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		fw.Filename = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "roll_disabled":
				var f bool
				fw.Roll = &f
				if d.NextArg() {
					return d.ArgErr()
				}

			case "roll_size":
				var sizeStr string
				if !d.AllArgs(&sizeStr) {
					return d.ArgErr()
				}
				size, err := humanize.ParseBytes(sizeStr)
				if err != nil {
					return d.Errf("parsing size: %v", err)
				}
				fw.RollSizeMB = int(math.Ceil(float64(size) / humanize.MiByte))

			case "roll_uncompressed":
				var f bool
				fw.RollCompress = &f
				if d.NextArg() {
					return d.ArgErr()
				}

			case "roll_local_time":
				fw.RollLocalTime = true
				if d.NextArg() {
					return d.ArgErr()
				}

			case "roll_keep":
				var keepStr string
				if !d.AllArgs(&keepStr) {
					return d.ArgErr()
				}
				keep, err := strconv.Atoi(keepStr)
				if err != nil {
					return d.Errf("parsing roll_keep number: %v", err)
				}
				fw.RollKeep = keep

			case "roll_keep_for":
				var keepForStr string
				if !d.AllArgs(&keepForStr) {
					return d.ArgErr()
				}
				keepFor, err := caddy.ParseDuration(keepForStr)
				if err != nil {
					return d.Errf("parsing roll_keep_for duration: %v", err)
				}
				if keepFor < 0 {
					return d.Errf("negative roll_keep_for duration: %v", keepFor)
				}
				fw.RollKeepDays = int(math.Ceil(keepFor.Hours() / 24))
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*FileWriter)(nil)
	_ caddy.WriterOpener    = (*FileWriter)(nil)
	_ caddyfile.Unmarshaler = (*FileWriter)(nil)
)
