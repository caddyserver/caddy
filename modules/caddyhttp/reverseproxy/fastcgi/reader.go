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
