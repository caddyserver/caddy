package gzip

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestGzipHandler(t *testing.T) {

	pathFilter := PathFilter{make(Set)}
	badPaths := []string{"/bad", "/nogzip", "/nongzip"}
	for _, p := range badPaths {
		pathFilter.IgnoredPaths.Add(p)
	}
	extFilter := ExtFilter{make(Set)}
	for _, e := range []string{".txt", ".html", ".css", ".md"} {
		extFilter.Exts.Add(e)
	}
	gz := Gzip{Configs: []Config{
		Config{Filters: []Filter{pathFilter, extFilter}},
	}}

	w := httptest.NewRecorder()
	gz.Next = nextFunc(true)
	var exts = []string{
		".html", ".css", ".md",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		r.Header.Set("Accept-Encoding", "gzip")
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}

	w = httptest.NewRecorder()
	gz.Next = nextFunc(false)
	for _, p := range badPaths {
		for _, e := range exts {
			url := p + "/file" + e
			r, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Error(err)
			}
			r.Header.Set("Accept-Encoding", "gzip")
			_, err = gz.ServeHTTP(w, r)
			if err != nil {
				t.Error(err)
			}
		}
	}

	w = httptest.NewRecorder()
	gz.Next = nextFunc(false)
	exts = []string{
		".htm1", ".abc", ".mdx",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		r.Header.Set("Accept-Encoding", "gzip")
		_, err = gz.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func nextFunc(shouldGzip bool) middleware.Handler {
	return middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		if shouldGzip {
			if r.Header.Get("Accept-Encoding") != "" {
				return 0, fmt.Errorf("Accept-Encoding header not expected")
			}
			if w.Header().Get("Content-Encoding") != "gzip" {
				return 0, fmt.Errorf("Content-Encoding must be gzip, found %v", r.Header.Get("Content-Encoding"))
			}
			if _, ok := w.(gzipResponseWriter); !ok {
				return 0, fmt.Errorf("ResponseWriter should be gzipResponseWriter, found %T", w)
			}
			return 0, nil
		}
		if r.Header.Get("Accept-Encoding") == "" {
			return 0, fmt.Errorf("Accept-Encoding header expected")
		}
		if w.Header().Get("Content-Encoding") == "gzip" {
			return 0, fmt.Errorf("Content-Encoding must not be gzip, found gzip")
		}
		if _, ok := w.(gzipResponseWriter); ok {
			return 0, fmt.Errorf("ResponseWriter should not be gzipResponseWriter")
		}
		return 0, nil
	})
}
