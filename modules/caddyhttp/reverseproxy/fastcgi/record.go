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
