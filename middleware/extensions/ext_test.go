package extensions

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestExtensions(t *testing.T) {
	rootDir := os.TempDir()

	// create a temporary page
	path := filepath.Join(rootDir, "extensions_test.html")
	_, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	for i, test := range []struct {
		path        string
		extensions  []string
		expectedURL string
	}{
		{"/extensions_test", []string{".html"}, "/extensions_test.html"},
		{"/extensions_test/", []string{".html"}, "/extensions_test/"},
		{"/extensions_test", []string{".json"}, "/extensions_test"},
		{"/another_test", []string{".html"}, "/another_test"},
	} {
		ex := Ext{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return 0, nil
			}),
			Root:       rootDir,
			Extensions: test.extensions,
		}

		req, err := http.NewRequest("GET", test.path, nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}

		rec := httptest.NewRecorder()

		ex.ServeHTTP(rec, req)

		if got := req.URL.String(); got != test.expectedURL {
			t.Fatalf("Test %d: Got unexpected request URL: %q, wanted %q", i, got, test.expectedURL)
		}
	}
}
