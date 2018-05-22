// Copyright 2015 Light Code Labs, LLC
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

package compress

import (
	"io/ioutil"
	"io"
	"sync"

	"github.com/DataDog/zstd"
)

// pool zstdWriter according to compress level
// so we can reuse allocations over time
var (
	zstdWriterPool             = map[int]*sync.Pool{}
	zstdDefaultWriterPoolIndex int
)

//type zstdWriter zstd.Writer
type zstdWriter struct {
	zstd.Writer
}

// Reset discards the Writer z's state and makes it equivalent to the
// result of its original state from NewWriter or NewWriterLevel, but
// writing to w instead. This permits reusing a Writer rather than
// allocating a new one.
func (z *zstdWriter) Reset(w io.Writer) {
	zstd.NewWriterLevel(z, z.CompressionLevel)
}


func initZstdWriterPool() {
	var i int
	newWriterPool := func(level int) *sync.Pool {
		return &sync.Pool{
			New: func() interface{} {
				w := zstd.NewWriterLevel(ioutil.Discard, level)
				return w
			},
		}
	}
	for i = zstd.BestSpeed; i <= zstd.BestCompression; i++ {
		zstdWriterPool[i] = newWriterPool(i)
	}

	// add default writer pool
	zstdDefaultWriterPoolIndex = i
	zstdWriterPool[zstdDefaultWriterPoolIndex] = newWriterPool(zstd.DefaultCompression)
}

func getZstdWriter(level int) *zstdWriter {
	index := zstdDefaultWriterPoolIndex
	if level >= zstd.BestSpeed && level <= zstd.BestCompression {
		index = level
	}
	w := zstdWriterPool[index].Get().(*zstdWriter)
	w.Reset(ioutil.Discard)
	return w
}

func putZstdWriter(level int, w *zstdWriter) {
	index := zstdDefaultWriterPoolIndex
	if level >= zstd.BestSpeed && level <= zstd.BestCompression {
		index = level
	}
	w.Close()
	zstdWriterPool[index].Put(w)
}
