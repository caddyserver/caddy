package locale_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

func TestLocale(t *testing.T) {
	rootPath := os.TempDir()

	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.html")))
	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.en.html")))
	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.en-GB.html")))
	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.de.html")))

	tests := []struct {
		methods              []method.Method
		defaultLocale        string
		acceptLanguageHeader string
		expectedLocale       string
		expectedPath         string
	}{
		{[]method.Method{&method.Header{}}, "fr", "", "", "/test.html"},
		{[]method.Method{&method.Header{}}, "en", "", "en", "/test.en.html"},
		{[]method.Method{&method.Header{}}, "en-GB", "", "en-GB", "/test.en-GB.html"},
		{[]method.Method{&method.Header{}}, "en", "de,en;q=0.8,en-GB;q=0.6", "de", "/test.de.html"},
	}

	for index, test := range tests {
		locale := locale.Locale{
			Next:          middleware.HandlerFunc(contentHandler),
			RootPath:      rootPath,
			Methods:       test.methods,
			DefaultLocale: test.defaultLocale,
		}

		request, err := http.NewRequest("GET", "/test.html", nil)
		if err != nil {
			t.Fatalf("test %d: could not create HTTP request %v", index, err)
		}
		request.Header.Set("Accept-Language", test.acceptLanguageHeader)

		recorder := httptest.NewRecorder()
		if _, err = locale.ServeHTTP(recorder, request); err != nil {
			t.Fatalf("test %d: could not ServeHTTP %v", index, err)
		}

		if cl := recorder.Header().Get("Content-Language"); cl != test.expectedLocale {
			t.Fatalf("test %d: expected content language %s, got %s", index, test.expectedLocale, cl)
		}
		if path := request.URL.Path; path != test.expectedPath {
			t.Fatalf("test %d: expected path %s, got %s", index, test.expectedPath, path)
		}
	}
}

func contentHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return http.StatusOK, nil
}
