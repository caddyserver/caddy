package caddycmd

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

type trackingReadCloser struct {
	*bytes.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestDownloadBuildClosesErrorResponseBody(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	body := &trackingReadCloser{Reader: bytes.NewReader([]byte(`{"error":{"message":"bad request","id":"test"}}`))}
	http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       body,
			Request:    req,
		}, nil
	})

	if _, err := downloadBuild(url.Values{}); err == nil {
		t.Fatal("downloadBuild succeeded, want error")
	}
	if !body.closed {
		t.Fatal("downloadBuild did not close the error response body")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

var _ io.ReadCloser = (*trackingReadCloser)(nil)
