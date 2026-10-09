package reverseproxy

import (
	"io"
	"strings"
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

// TestBufferingBoundary documents where a buffered body stops being fully
// buffered, which is what decides whether the caller can learn its length and
// set Content-Length. A body the size of the limit counts as partial: io.CopyN
// filling the buffer cannot be told apart from a body with more to come, and
// finding out would mean a blocking read on a stream that may never deliver.
func TestBufferingBoundary(t *testing.T) {
	const body = "0123456789"

	for limit := int64(1); limit <= int64(len(body))+2; limit++ {
		var h Handler
		res, read := h.bufferedBody(io.NopCloser(strings.NewReader(body)), limit)

		// Whatever the limit, the upstream must still receive every byte.
		got, err := io.ReadAll(res)
		if err != nil {
			t.Fatalf("limit %d: reading buffered body: %v", limit, err)
		}
		if string(got) != body {
			t.Errorf("limit %d: body changed: got %q, want %q", limit, got, body)
		}
		if err := res.Close(); err != nil {
			t.Errorf("limit %d: closing buffered body: %v", limit, err)
		}

		brc, ok := res.(bodyReadCloser)
		if !ok {
			t.Fatalf("limit %d: expected a bodyReadCloser", limit)
		}
		wantFull := limit > int64(len(body))
		if gotFull := brc.body == nil; gotFull != wantFull {
			t.Errorf("limit %d: fully buffered = %v, want %v", limit, gotFull, wantFull)
		}
		if wantFull && read != int64(len(body)) {
			t.Errorf("limit %d: read %d bytes, want %d", limit, read, len(body))
		}
	}
}
