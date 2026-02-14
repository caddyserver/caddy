package reverseproxy

import (
	"bytes"
	"io"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestBuffering(t *testing.T) {
	var (
		h  Handler
		zr zeroReader
	)
	type args struct {
		body  io.ReadCloser
		limit int64
	}
	tests := []struct {
		name        string
		args        args
		resultCheck func(io.ReadCloser, int64, args) bool
	}{
		{
			name: "0 limit, body is returned as is",
			args: args{
				body:  io.NopCloser(&zr),
				limit: 0,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				return res == args.body && read == args.limit && read == 0
			},
		},
		{
			name: "negative limit, body is read completely",
			args: args{
				body:  io.NopCloser(io.LimitReader(&zr, 100)),
				limit: -1,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				brc, ok := res.(bodyReadCloser)
				return ok && brc.body == nil && brc.buf.Len() == 100 && read == 100
			},
		},
		{
			name: "positive limit, body is read partially",
			args: args{
				body:  io.NopCloser(io.LimitReader(&zr, 100)),
				limit: 50,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				brc, ok := res.(bodyReadCloser)
				return ok && brc.body != nil && brc.buf.Len() == 50 && read == 50
			},
		},
		{
			name: "positive limit, body is read completely",
			args: args{
				body:  io.NopCloser(io.LimitReader(&zr, 100)),
				limit: 101,
			},
			resultCheck: func(res io.ReadCloser, read int64, args args) bool {
				brc, ok := res.(bodyReadCloser)
				return ok && brc.body == nil && brc.buf.Len() == 100 && read == 100
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, read := h.bufferedBody(tt.args.body, tt.args.limit)
			if !tt.resultCheck(res, read, tt.args) {
				t.Error("Handler.bufferedBody() test failed")
				return
			}
		})
	}
}

func TestPutBufDiscardOversized(t *testing.T) {
	// Drain the pool so we start from a known state.
	for {
		b := bufPool.Get().(*bytes.Buffer)
		if b.Cap() == 0 {
			break
		}
	}

	// A small buffer (within limit) should be returned to the pool
	// and should be reset before being pooled.
	small := bytes.NewBuffer(make([]byte, 0, 1024))
	small.WriteString("hello")
	putBuf(small)
	if small.Len() != 0 {
		t.Error("expected small buffer to be reset after putBuf")
	}

	// A large buffer (exceeding limit) should NOT be returned.
	// Verify indirectly: after putting a large buffer, getting from pool
	// should never return a buffer with capacity > maxBufferSize.
	large := bytes.NewBuffer(make([]byte, 0, maxBufferSize+1))
	large.WriteString("world")
	putBuf(large)

	// Verify the large buffer was NOT reset (putBuf skipped it).
	if large.Len() == 0 {
		t.Error("expected large buffer to NOT be reset by putBuf")
	}

	// Get from pool: should never get the oversized buffer back.
	got := bufPool.Get().(*bytes.Buffer)
	if got.Cap() > maxBufferSize {
		t.Errorf("expected pool to not contain oversized buffer, got cap=%d", got.Cap())
	}
}
