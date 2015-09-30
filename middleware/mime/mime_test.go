package mime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestMimeHandler(t *testing.T) {

	mimes := map[string]string{
		".html": "text/html",
		".txt":  "text/plain",
		".swf":  "application/x-shockwave-flash",
	}

	var configs []Config
	for ext, contentType := range mimes {
		configs = append(configs, Config{Ext: ext, ContentType: contentType})
	}

	m := Mime{Configs: configs}

	w := httptest.NewRecorder()
	exts := []string{
		".html", ".txt", ".swf",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		m.Next = nextFunc(true, mimes[e])
		_, err = m.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}

	w = httptest.NewRecorder()
	exts = []string{
		".htm1", ".abc", ".mdx",
	}
	for _, e := range exts {
		url := "/file" + e
		r, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		m.Next = nextFunc(false, "")
		_, err = m.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func nextFunc(shouldMime bool, contentType string) middleware.Handler {
	return middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		if shouldMime {
			if w.Header().Get("Content-Type") != contentType {
				return 0, fmt.Errorf("expected Content-Type: %v, found %v", contentType, r.Header.Get("Content-Type"))
			}
			return 0, nil
		}
		if w.Header().Get("Content-Type") != "" {
			return 0, fmt.Errorf("Content-Type header not expected")
		}
		return 0, nil
	})
}
