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

package fastcgi

import (
	"bytes"
	"encoding/binary"
)

// streamWriter abstracts out the separation of a stream into discrete records.
// It only writes maxWrite bytes at a time.
type streamWriter struct {
	c       *client
	h       header
	buf     *bytes.Buffer
	recType uint8
}

func (w *streamWriter) writeRecord(recType uint8, content []byte) (err error) {
	w.h.init(recType, w.c.reqID, len(content))
	w.buf.Write(pad[:8])
	w.writeHeader()
	w.buf.Write(content)
	w.buf.Write(pad[:w.h.PaddingLength])
	_, err = w.buf.WriteTo(w.c.rwc)
	return err
}

func (w *streamWriter) writeBeginRequest(role uint16, flags uint8) error {
	b := [8]byte{byte(role >> 8), byte(role), flags}
	return w.writeRecord(BeginRequest, b[:])
}

func (w *streamWriter) Write(p []byte) (int, error) {
	// init header
	if w.buf.Len() < 8 {
		w.buf.Write(pad[:8])
	}

	nn := 0
	for len(p) > 0 {
		n := len(p)
		nl := maxWrite + 8 - w.buf.Len()
		if n > nl {
			n = nl
			w.buf.Write(p[:n])
			if err := w.Flush(); err != nil {
				return nn, err
			}
			// reset headers
			w.buf.Write(pad[:8])
		} else {
			w.buf.Write(p[:n])
		}
		nn += n
		p = p[n:]
	}
	return nn, nil
}

func (w *streamWriter) endStream() error {
	// send empty record to close the stream
	return w.writeRecord(w.recType, nil)
}

func (w *streamWriter) writePairs(pairs map[string]string) error {
	b := make([]byte, 8)
	nn := 0
	// init headers
	w.buf.Write(b)
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
			// reset headers
			w.buf.Write(b)
			nn = 0
		}
		nn += m
		w.buf.Write(b[:n])
		w.buf.WriteString(k)
		w.buf.WriteString(v)
	}
	return w.FlushStream()
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

// writeHeader populate header wire data in buf, it abuses buffer.Bytes() modification
func (w *streamWriter) writeHeader() {
	h := w.buf.Bytes()[:8]
	h[0] = w.h.Version
	h[1] = w.h.Type
	binary.BigEndian.PutUint16(h[2:4], w.h.ID)
	binary.BigEndian.PutUint16(h[4:6], w.h.ContentLength)
	h[6] = w.h.PaddingLength
	h[7] = w.h.Reserved
}

// Flush write buffer data to the underlying connection, it assumes header data is the first 8 bytes of buf
func (w *streamWriter) Flush() error {
	w.h.init(w.recType, w.c.reqID, w.buf.Len()-8)
	w.writeHeader()
	w.buf.Write(pad[:w.h.PaddingLength])
	_, err := w.buf.WriteTo(w.c.rwc)
	return err
}

// FlushStream flush data then end current stream
func (w *streamWriter) FlushStream() error {
	if err := w.Flush(); err != nil {
		return err
	}
	return w.endStream()
}
