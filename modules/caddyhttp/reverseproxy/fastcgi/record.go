package fastcgi

import (
	"encoding/binary"
	"errors"
	"io"
)

type record struct {
	h       header
	lr      io.LimitedReader
	padding int64
}

func (rec *record) fill(r io.Reader) (err error) {
	rec.lr.N = rec.padding
	rec.lr.R = r
	if _, err = io.Copy(io.Discard, rec); err != nil {
		return
	}

	if err = binary.Read(r, binary.BigEndian, &rec.h); err != nil {
		return
	}
	if rec.h.Version != 1 {
		err = errors.New("fcgi: invalid header version")
		return
	}
	if rec.h.Type == EndRequest {
		err = io.EOF
		return
	}
	rec.lr.N = int64(rec.h.ContentLength)
	rec.padding = int64(rec.h.PaddingLength)
	return
}

func (rec *record) Read(p []byte) (n int, err error) {
	return rec.lr.Read(p)
}

func (rec *record) hasMore() bool {
	return rec.lr.N > 0
}
