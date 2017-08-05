package limits

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestBodySizeLimit(t *testing.T) {
	var (
		gotContent    []byte
		gotError      error
		expectContent = "hello"
	)
	l := Limit{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			gotContent, gotError = ioutil.ReadAll(r.Body)
			return 0, nil
		}),
		BodyLimits: []httpserver.PathLimit{{Path: "/", Limit: int64(len(expectContent))}},
	}

	r := httptest.NewRequest("GET", "/", strings.NewReader(expectContent+expectContent))
	l.ServeHTTP(httptest.NewRecorder(), r)
	if got := string(gotContent); got != expectContent {
		t.Errorf("expected content[%s], got[%s]", expectContent, got)
	}
	if gotError != httpserver.ErrMaxBytesExceeded {
		t.Errorf("expect error %v, got %v", httpserver.ErrMaxBytesExceeded, gotError)
	}
}
