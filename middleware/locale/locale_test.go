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
)

func TestLocale(t *testing.T) {
	rootPath := os.TempDir()

	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.html")))
	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.en.html")))
	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.en-GB.html")))
	defer os.Remove(touchFile(t, filepath.Join(rootPath, "test.de.html")))

	tests := []struct {
		detectMethods        []locale.DetectMethod
		defaultLocale        string
		acceptLanguageHeader string
		expectedLocale       string
		expectedPath         string
	}{
		{[]locale.DetectMethod{locale.DetectMethodHeader}, "fr", "", "", "/test.html"},
		{[]locale.DetectMethod{locale.DetectMethodHeader}, "en", "", "en", "/test.en.html"},
		{[]locale.DetectMethod{locale.DetectMethodHeader}, "en-GB", "", "en-GB", "/test.en-GB.html"},
		{[]locale.DetectMethod{locale.DetectMethodHeader}, "en", "de,en;q=0.8,en-GB;q=0.6", "de", "/test.de.html"},
	}

	for _, test := range tests {
		locale := locale.Locale{
			Next:          middleware.HandlerFunc(contentHandler),
			RootPath:      rootPath,
			DetectMethods: test.detectMethods,
			DefaultLocale: test.defaultLocale,
		}

		request, err := http.NewRequest("GET", "/test.html", nil)
		if err != nil {
			t.Fatalf("could not create HTTP request %v", err)
		}
		request.Header.Set("Accept-Language", test.acceptLanguageHeader)

		recorder := httptest.NewRecorder()
		if _, err = locale.ServeHTTP(recorder, request); err != nil {
			t.Fatalf("could not ServeHTTP %v", err)
		}

		if cl := recorder.Header().Get("Content-Language"); cl != test.expectedLocale {
			t.Fatalf("expected content language %s, got %s", test.expectedLocale, cl)
		}
		if path := request.URL.Path; path != test.expectedPath {
			t.Fatalf("expected path %s, got %s", test.expectedPath, path)
		}
	}
}

func contentHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return http.StatusOK, nil
}
