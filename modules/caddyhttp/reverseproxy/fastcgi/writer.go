package fastcgi

import (
	"bufio"
	"encoding/binary"
)

// bufWriter encapsulates bufio.Writer but also closes the underlying stream when
// Closed.
type bufWriter struct {
	sw *streamWriter
	*bufio.Writer
}

func (w *bufWriter) endStream() error {
	if err := w.Writer.Flush(); err != nil {
		return err
	}
	return w.sw.endStream()
}

func (w *bufWriter) recycle() {
	putBufWriter(w.Writer)
}

func newWriter(c *FCGIClient) *bufWriter {
	s := &streamWriter{c: c}
	w := getBufWriter(s)
	return &bufWriter{s, w}
}

func (w *bufWriter) writePairs(pairs map[string]string) error {
	b := make([]byte, 8)
	nn := 0
	for k, v := range pairs {
		m := 8 + len(k) + len(v)
		if m > maxWrite {
			// param data size exceed 65535 bytes"
			vl := maxWrite - 8 - len(k)
			v = v[:vl]
		}
		n := encodeSize(b, uint32(len(k)))
		n += encodeSize(b[n:], uint32(len(v)))
		m = n + len(k) + len(v)
		if (nn + m) > maxWrite {
			if err := w.Flush(); err != nil {
				return err
			}
			nn = 0
		}
		nn += m
		if _, err := w.Write(b[:n]); err != nil {
			return err
		}
		if _, err := w.WriteString(k); err != nil {
			return err
		}
		if _, err := w.WriteString(v); err != nil {
			return err
		}
	}
	return w.endStream()
}

func encodeSize(b []byte, size uint32) int {
	if size > 127 {
		size |= 1 << 31
		binary.BigEndian.PutUint32(b, size)
		return 4
	}
	b[0] = byte(size)
	return 1
}

// streamWriter abstracts out the separation of a stream into discrete records.
// It only writes maxWrite bytes at a time.
type streamWriter struct {
	c       *FCGIClient
	recType uint8
}

func (w *streamWriter) Write(p []byte) (int, error) {
	nn := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxWrite {
			n = maxWrite
		}
		if err := w.c.writeRecord(w.recType, p[:n]); err != nil {
			return nn, err
		}
		nn += n
		p = p[n:]
	}
	return nn, nil
}

func (w *streamWriter) endStream() error {
	// send empty record to close the stream
	return w.c.writeRecord(w.recType, nil)
}
