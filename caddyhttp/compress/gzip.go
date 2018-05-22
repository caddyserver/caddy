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
	"compress/gzip"
	"io/ioutil"
	"sync"
)


var (
	gzipWriterPool             = map[int]*sync.Pool{}
	gzipDefaultWriterPoolIndex int
)

func initGzipWriterPool() {
	var i int
	newWriterPool := func(level int) *sync.Pool {
		return &sync.Pool{
			New: func() interface{} {
				w, _ := gzip.NewWriterLevel(ioutil.Discard, level)
				return w
			},
		}
	}
	for i = gzip.BestSpeed; i <= gzip.BestCompression; i++ {
		gzipWriterPool[i] = newWriterPool(i)
	}

	// add default writer pool
	gzipDefaultWriterPoolIndex = i
	gzipWriterPool[gzipDefaultWriterPoolIndex] = newWriterPool(gzip.DefaultCompression)
}

func getGzipWriter(level int) *gzip.Writer {
	index := gzipDefaultWriterPoolIndex
	if level >= gzip.BestSpeed && level <= gzip.BestCompression {
		index = level
	}
	w := gzipWriterPool[index].Get().(*gzip.Writer)
	w.Reset(ioutil.Discard)
	return w
}

func putGzipWriter(level int, w *gzip.Writer) {
	index := gzipDefaultWriterPoolIndex
	if level >= gzip.BestSpeed && level <= gzip.BestCompression {
		index = level
	}
	w.Close()
	gzipWriterPool[index].Put(w)
}
