package reverseproxy

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestCloneRequestClearsOpaqueTarget(t *testing.T) {
	for _, tc := range []struct {
		target, want string
	}{
		{"/public?x=1", "/public?x=1"},
		{"http://public.example/public?x=1", "/public?x=1"},
		{"http:http://private.example/secret", "/"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			original, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
				"GET " + tc.target + " HTTP/1.1\r\nHost: public.example\r\n\r\n")))
			if err != nil {
				t.Fatal(err)
			}
			defer original.Body.Close()
			originalURL := *original.URL
			cloned := cloneRequest(original)
			cloned.URL.Scheme = "http"
			cloned.URL.Host = "selected-upstream.example"
			var wire bytes.Buffer
			if err := cloned.Write(&wire); err != nil {
				t.Fatal(err)
			}
			want := "GET " + tc.want + " HTTP/1.1\r\n"
			if !strings.HasPrefix(wire.String(), want) {
				t.Fatalf("outbound target = %q, want prefix %q", wire.String(), want)
			}
			if *original.URL != originalURL {
				t.Fatal("original request URL was mutated")
			}
		})
	}
}
