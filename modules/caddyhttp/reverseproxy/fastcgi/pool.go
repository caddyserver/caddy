package fastcgi

import (
	"bufio"
	"bytes"
	"io"
	"sync"
)

var (
	bufPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	bufWriterPool = sync.Pool{
		New: func() any {
			return bufio.NewWriterSize(nil, maxWrite)
		},
	}
)

func getBufWriter(w io.Writer) *bufio.Writer {
	bw := bufWriterPool.Get().(*bufio.Writer)
	bw.Reset(w)
	return bw
}

func putBufWriter(bw *bufio.Writer) {
	bw.Reset(nil)
	bufWriterPool.Put(bw)
}
