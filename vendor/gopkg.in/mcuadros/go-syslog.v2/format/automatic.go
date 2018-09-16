package format

import (
	"bufio"
	"bytes"
	"errors"
	"strconv"

	"gopkg.in/mcuadros/go-syslog.v2/internal/syslogparser/rfc3164"
	"gopkg.in/mcuadros/go-syslog.v2/internal/syslogparser/rfc5424"
)

/* Selecting an 'Automatic' format detects incoming format (i.e. RFC3164 vs RFC5424) and Framing
 * (i.e. RFC6587 s3.4.1 octet counting as described here as RFC6587, and either no framing or
 * RFC6587 s3.4.2 octet stuffing / non-transparent framing, described here as either RFC3164
 * or RFC6587).
 *
 * In essence if you don't know which format to select, or have multiple incoming formats, this
 * is the one to go for. There is a theoretical performance penalty (it has to look at a few bytes
 * at the start of the frame), and a risk that you may parse things you don't want to parse
 * (rogue syslog clients using other formats), so if you can be absolutely sure of your syslog
 * format, it would be best to select it explicitly.
 */

type Automatic struct{}

const (
	detectedUnknown = iota
	detectedRFC3164 = iota
	detectedRFC5424 = iota
	detectedRFC6587 = iota
)

func detect(data []byte) (detected int, err error) {
	// all formats have a sapce somewhere
	if i := bytes.IndexByte(data, ' '); i > 0 {
		pLength := data[0:i]
		if _, err := strconv.Atoi(string(pLength)); err == nil {
			return detectedRFC6587, nil
		}

		// is there a close angle bracket before the ' '? there should be
		angle := bytes.IndexByte(data, '>')
		if (angle < 0) || (angle >= i) {
			return detectedUnknown, errors.New("No close angle bracket before space")
		}

		// if a single digit immediately follows the angle bracket, then a space
		// it is RFC5424, as RFC3164 must begin with a letter (month name)
		if (angle+2 == i) && (data[angle+1] >= '0') && (data[angle+1] <= '9') {
			return detectedRFC5424, nil
		} else {
			return detectedRFC3164, nil
		}
	}
	return detectedUnknown, nil
}

func (f *Automatic) GetParser(line []byte) LogParser {
	switch format, _ := detect(line); format {
	case detectedRFC3164:
		return &parserWrapper{rfc3164.NewParser(line)}
	case detectedRFC5424:
		return &parserWrapper{rfc5424.NewParser(line)}
	default:
		// If the line was an RFC6587 line, the splitter should already have removed the length,
		// so one of the above two will be chosen if the line is correctly formed. However, it
		// may have a second length illegally placed at the start, in which case the detector
		// will return detectedRFC6587. The line may also simply be malformed after the length in
		// which case we will have detectedUnknown. In this case we return the simplest parser so
		// the illegally formatted line is properly handled
		return &parserWrapper{rfc3164.NewParser(line)}
	}
}

func (f *Automatic) GetSplitFunc() bufio.SplitFunc {
	return f.automaticScannerSplit
}

func (f *Automatic) automaticScannerSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	switch format, err := detect(data); format {
	case detectedRFC6587:
		return rfc6587ScannerSplit(data, atEOF)
	case detectedRFC3164, detectedRFC5424:
		// the default
		return bufio.ScanLines(data, atEOF)
	default:
		if err != nil {
			return 0, nil, err
		}
		// Request more data
		return 0, nil, nil
	}
}
