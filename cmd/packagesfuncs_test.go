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

func TestModuleContainsPackage(t *testing.T) {
	tests := []struct {
		name        string
		modulePath  string
		packagePath string
		want        bool
	}{
		{name: "module root", modulePath: "example.com/mod", packagePath: "example.com/mod", want: true},
		{name: "module package", modulePath: "example.com/mod", packagePath: "example.com/mod/pkg", want: true},
		{name: "shared prefix", modulePath: "example.com/mod", packagePath: "example.com/module", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := moduleContainsPackage(tt.modulePath, tt.packagePath); got != tt.want {
				t.Fatalf("moduleContainsPackage(%q, %q) = %v, want %v", tt.modulePath, tt.packagePath, got, tt.want)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

var _ io.ReadCloser = (*trackingReadCloser)(nil)
