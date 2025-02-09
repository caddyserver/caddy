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
	"encoding/json"
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

// fileMode is a string made of 1 to 4 octal digits representing
// a numeric mode as specified with the `chmod` unix command.
// `"0777"` and `"777"` are thus equivalent values.
type fileMode os.FileMode

// UnmarshalJSON satisfies json.Unmarshaler.
func (m *fileMode) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return io.EOF
	}

	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	mode, err := parseFileMode(s)
	if err != nil {
		return err
	}

	*m = fileMode(mode)
	return err
}

// MarshalJSON satisfies json.Marshaler.
func (m *fileMode) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%04o\"", *m)), nil
}

// parseFileMode parses a file mode string,
// adding support for `chmod` unix command like
// 1 to 4 digital octal values.
func parseFileMode(s string) (os.FileMode, error) {
	modeStr := fmt.Sprintf("%04s", s)
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(mode), nil
}

// FileWriter can write logs to files. By default, log files
// are rotated ("rolled") when they get large, and old log
// files get deleted, to ensure that the process does not
// exhaust disk space.
type FileWriter struct {
	// Filename is the name of the file to write.
	Filename string `json:"filename,omitempty"`

	// The file permissions mode.
	// 0600 by default.
	Mode fileMode `json:"mode,omitempty"`

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
	fpath, err := caddy.FastAbs(fw.Filename)
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
	modeIfCreating := os.FileMode(fw.Mode)
	if modeIfCreating == 0 {
		modeIfCreating = 0o600
	}

	// roll log files as a sensible default to avoid disk space exhaustion
	roll := fw.Roll == nil || *fw.Roll

	// create the file if it does not exist; create with the configured mode, or default
	// to restrictive if not set. (lumberjack will reuse the file mode across log rotation)
	if err := os.MkdirAll(filepath.Dir(fw.Filename), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(fw.Filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, modeIfCreating)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if roll {
		file.Close() // lumberjack will reopen it on its own
	}

	// Ensure already existing files have the right mode, since OpenFile will not set the mode in such case.
	if configuredMode := os.FileMode(fw.Mode); configuredMode != 0 {
		if err != nil {
			return nil, fmt.Errorf("unable to stat log file to see if we need to set permissions: %v", err)
		}
		// only chmod if the configured mode is different
		if info.Mode()&os.ModePerm != configuredMode&os.ModePerm {
			if err = os.Chmod(fw.Filename, configuredMode); err != nil {
				return nil, err
			}
		}
	}

	// if not rolling, then the plain file handle is all we need
	if !roll {
		return file, nil
	}

	// otherwise, return a rolling log
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

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//	file <filename> {
//	    mode          <mode>
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
// If any of the mode, roll_size, roll_keep, or roll_keep_for subdirectives are
// omitted or set to a zero value, then Caddy's default value for that
// subdirective is used.
func (fw *FileWriter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume writer name
	if !d.NextArg() {
		return d.ArgErr()
	}
	fw.Filename = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "mode":
			var modeStr string
			if !d.AllArgs(&modeStr) {
				return d.ArgErr()
			}
			mode, err := parseFileMode(modeStr)
			if err != nil {
				return d.Errf("parsing mode: %v", err)
			}
			fw.Mode = fileMode(mode)

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
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*FileWriter)(nil)
	_ caddy.WriterOpener    = (*FileWriter)(nil)
	_ caddyfile.Unmarshaler = (*FileWriter)(nil)
)
