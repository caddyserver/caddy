package format

import (
	"bufio"

	"gopkg.in/mcuadros/go-syslog.v2/internal/syslogparser/rfc3164"
)

type RFC3164 struct{}

func (f *RFC3164) GetParser(line []byte) LogParser {
	return &parserWrapper{rfc3164.NewParser(line)}
}

func (f *RFC3164) GetSplitFunc() bufio.SplitFunc {
	return nil
}
