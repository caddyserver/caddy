package fastcgi

import (
	"bytes"
	"io"
)

type streamReader struct {
	c      *client
	rec    record
	stderr bytes.Buffer
}

func (w *streamReader) Read(p []byte) (n int, err error) {
	for !w.rec.hasMore() {
		err = w.rec.fill(w.c.rwc)
		if err != nil {
			return 0, err
		}

		// standard error output
		if w.rec.h.Type == Stderr {
			if _, err = io.Copy(&w.stderr, &w.rec); err != nil {
				return 0, err
			}
		}
	}

	return w.rec.Read(p)
}
