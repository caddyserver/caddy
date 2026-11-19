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
	"io"
)

// maxStderr limits how much of the responder's stderr is kept for logging.
const maxStderr = 64 << 10

type streamReader struct {
	c      *client
	rec    record
	stderr bytes.Buffer

	// stderrDropped counts stderr bytes discarded beyond maxStderr.
	stderrDropped int64
}

func (w *streamReader) Read(p []byte) (n int, err error) {
	for !w.rec.hasMore() {
		err = w.rec.fill(w.c.rwc)
		if err != nil {
			return 0, err
		}

		// standard error output; it is only kept if it will be logged
		if w.rec.h.Type == Stderr {
			if w.c.stderr {
				room := max(maxStderr-int64(w.stderr.Len()), 0)
				if _, err = io.Copy(&w.stderr, io.LimitReader(&w.rec, room)); err != nil {
					return 0, err
				}
			}
			var n int64
			n, err = io.Copy(io.Discard, &w.rec)
			if w.c.stderr {
				w.stderrDropped += n
			}
			if err != nil {
				return 0, err
			}
		}
	}

	return w.rec.Read(p)
}
