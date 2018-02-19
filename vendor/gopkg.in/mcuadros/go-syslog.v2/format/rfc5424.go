package format

import (
	"bufio"

	"gopkg.in/mcuadros/go-syslog.v2/internal/syslogparser/rfc5424"
)

type RFC5424 struct{}

func (f *RFC5424) GetParser(line []byte) LogParser {
	return &parserWrapper{rfc5424.NewParser(line)}
}

func (f *RFC5424) GetSplitFunc() bufio.SplitFunc {
	return nil
}
