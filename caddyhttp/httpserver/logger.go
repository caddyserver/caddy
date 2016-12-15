package httpserver

import (
	"bytes"
	"github.com/hashicorp/go-syslog"
	"github.com/mholt/caddy"
	"io"
	"log"
	"os"
	"strings"
)

var remoteSyslogPrefixes = map[string]string{
	"syslog+tcp://": "tcp",
	"syslog+udp://": "udp",
	"syslog://":     "udp",
}

type Logger struct {
	Output string
	*log.Logger
	Roller *LogRoller
	writer io.Writer
}

func NewTestLogger(buffer *bytes.Buffer) *Logger {
	return &Logger{
		Logger: log.New(buffer, "", 0),
	}
}

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

func (l *Logger) Start() error {
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

func (l *Logger) Close() error {
	// Will close local/remote syslog connections too :)
	if closer, ok := l.writer.(io.WriteCloser); ok {
		return closer.Close()
	}

	return nil
}
