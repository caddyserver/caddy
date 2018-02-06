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
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-syslog"
	"github.com/mholt/caddy"
)

var remoteSyslogPrefixes = map[string]string{
	"syslog+tcp://": "tcp",
	"syslog+udp://": "udp",
	"syslog://":     "udp",
}

// Logger is shared between errors and log plugins and supports both logging to
// a file (with an optional file roller), local and remote syslog servers.
type Logger struct {
	Output string
	*log.Logger
	Roller       *LogRoller
	writer       io.Writer
	fileMu       *sync.RWMutex
	V4ipMask     net.IPMask
	V6ipMask     net.IPMask
	IPMaskExists bool
}

// NewTestLogger creates logger suitable for testing purposes
func NewTestLogger(buffer *bytes.Buffer) *Logger {
	return &Logger{
		Logger: log.New(buffer, "", 0),
		fileMu: new(sync.RWMutex),
	}
}

// Println wraps underlying logger with mutex
func (l Logger) Println(args ...interface{}) {
	l.fileMu.RLock()
	l.Logger.Println(args...)
	l.fileMu.RUnlock()
}

// Printf wraps underlying logger with mutex
func (l Logger) Printf(format string, args ...interface{}) {
	l.fileMu.RLock()
	l.Logger.Printf(format, args...)
	l.fileMu.RUnlock()
}

func (l Logger) MaskIP(ip string) string {
	var reqIP net.IP
	// If unable to parse, simply return IP as provided.
	reqIP = net.ParseIP(ip)
	if reqIP == nil {
		return ip
	}

	if reqIP.To4() != nil {
		return reqIP.Mask(l.V4ipMask).String()
	} else {
		return reqIP.Mask(l.V6ipMask).String()
	}

}

// Attach binds logger Start and Close functions to
// controller's OnStartup and OnShutdown hooks.
func (l *Logger) Attach(controller *caddy.Controller) {
	if controller != nil {
		// Opens file or connect to local/remote syslog
		controller.OnStartup(l.Start)

		// Closes file or disconnects from local/remote syslog
		controller.OnShutdown(l.Close)
	}
}

type syslogAddress struct {
	network string
	address string
}

func parseSyslogAddress(location string) *syslogAddress {
	for prefix, network := range remoteSyslogPrefixes {
		if strings.HasPrefix(location, prefix) {
			return &syslogAddress{
				network: network,
				address: strings.TrimPrefix(location, prefix),
			}
		}
	}

	return nil
}

// Start initializes logger opening files or local/remote syslog connections
func (l *Logger) Start() error {
	// initialize mutex on start
	l.fileMu = new(sync.RWMutex)

	var err error

selectwriter:
	switch l.Output {
	case "", "stderr":
		l.writer = os.Stderr
	case "stdout":
		l.writer = os.Stdout
	case "syslog":
		l.writer, err = gsyslog.NewLogger(gsyslog.LOG_ERR, "LOCAL0", "caddy")
		if err != nil {
			return err
		}
	default:
		if address := parseSyslogAddress(l.Output); address != nil {
			l.writer, err = gsyslog.DialLogger(address.network, address.address, gsyslog.LOG_ERR, "LOCAL0", "caddy")

			if err != nil {
				return err
			}

			break selectwriter
		}

		var file *os.File

		file, err = os.OpenFile(l.Output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return err
		}

		if l.Roller != nil {
			file.Close()
			l.Roller.Filename = l.Output
			l.writer = l.Roller.GetLogWriter()
		} else {
			l.writer = file
		}
	}

	l.Logger = log.New(l.writer, "", 0)

	return nil

}

// Close closes open log files or connections to syslog.
func (l *Logger) Close() error {
	// don't close stdout or stderr
	if l.writer == os.Stdout || l.writer == os.Stderr {
		return nil
	}

	// Will close local/remote syslog connections too :)
	if closer, ok := l.writer.(io.WriteCloser); ok {
		l.fileMu.Lock()
		err := closer.Close()
		l.fileMu.Unlock()
		return err
	}

	return nil
}
