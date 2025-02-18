package reverseproxy

import (
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
