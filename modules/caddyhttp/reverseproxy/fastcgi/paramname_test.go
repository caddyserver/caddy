package fastcgi

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A client-controlled header whose name cannot fit in a Params record fails
// the request through Transport.RoundTrip, and the backend sees the
// BeginRequest record and then EOF: no params, partial or otherwise.
func TestRoundTripRejectsOversizedHeaderName(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type received struct {
		data []byte
		err  error
	}
	got := make(chan received, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- received{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		data, err := io.ReadAll(conn)
		got <- received{data: data, err: err}
	}()

	// buildEnv turns the header into HTTP_X_<name>, which is longer than
	// any name a record can carry.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/index.php", nil)
	req.Header.Set("X-"+strings.Repeat("a", maxWrite), "1")

	res, err := fcgiRoundTrip(t, ln.Addr().String(), req)
	if !errors.Is(err, errParamNameTooLong) {
		t.Fatalf("RoundTrip() error = %v, want %v", err, errParamNameTooLong)
	}
	if res != nil {
		t.Errorf("RoundTrip() response = %v, want nil", res)
	}

	r := <-got
	if r.err != nil {
		t.Fatalf("backend read: %v (want EOF after the records)", r.err)
	}
	types := recordTypes(t, r.data)
	if len(types) != 1 || types[0] != BeginRequest {
		t.Fatalf("backend received record types %v, want only BeginRequest (%d) then EOF", types, BeginRequest)
	}
}

// recordTypes returns the type of each FastCGI record in data.
func recordTypes(t *testing.T, data []byte) []uint8 {
	t.Helper()

	var types []uint8
	for len(data) > 0 {
		if len(data) < 8 {
			t.Fatalf("truncated record header: %d bytes", len(data))
		}
		contentLength := int(data[4])<<8 | int(data[5])
		size := 8 + contentLength + int(data[6])
		if len(data) < size {
			t.Fatalf("truncated record: %d bytes, want %d", len(data), size)
		}
		types = append(types, data[1])
		data = data[size:]
	}
	return types
}
