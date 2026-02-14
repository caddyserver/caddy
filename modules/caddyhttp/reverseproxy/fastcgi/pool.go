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
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// putBuf returns a buffer to the pool if its capacity
// does not exceed maxBufferSize, otherwise it is discarded
// so memory can be reclaimed after load subsides.
func putBuf(buf *bytes.Buffer) {
	if buf.Cap() > maxBufferSize {
		return
	}
	buf.Reset()
	bufPool.Put(buf)
}

const maxBufferSize = 64 * 1024
