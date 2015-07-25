package templates

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func Test(t *testing.T) {
	tmpl := Templates{
		Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			Rule{
				Extensions: []string{".html"},
				IndexFiles: []string{"index.html"},
				Path:       "/photos",
			},
			Rule{
				Extensions: []string{".html", ".htm"},
				IndexFiles: []string{"index.html", "index.htm"},
				Path:       "/images",
			},
		},
		Root:    "./testdata",
		FileSys: http.Dir("./testdata"),
	}

	tmplroot := Templates{
		Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		}),
		Rules: []Rule{
			Rule{
				Extensions: []string{".html"},
				IndexFiles: []string{"index.html"},
				Path:       "/",
			},
		},
		Root:    "./testdata",
		FileSys: http.Dir("./testdata"),
	}

	/*
	* Test tmpl on /photos/test.html
	 */
	req, err := http.NewRequest("GET", "/photos/test.html", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}

	rec := httptest.NewRecorder()

	tmpl.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody := rec.Body.String()
	expectedBody := `<!DOCTYPE html><html><head><title>test page</title></head><body><h1>Header title</h1>
</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}

	/*
	* Test tmpl on /images/img.htm
	 */
	req, err = http.NewRequest("GET", "/images/img.htm", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	rec = httptest.NewRecorder()

	tmpl.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html><html><head><title>img</title></head><body><h1>Header title</h1>
</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}

	/*
	* Test tmplroot on /root.html
	 */
	req, err = http.NewRequest("GET", "/root.html", nil)
	if err != nil {
		t.Fatalf("Could not create HTTP request: %v", err)
	}

	rec = httptest.NewRecorder()

	tmplroot.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Test: Wrong response code: %d, should be %d", rec.Code, http.StatusOK)
	}

	respBody = rec.Body.String()
	expectedBody = `<!DOCTYPE html><html><head><title>root</title></head><body><h1>Header title</h1>
</body></html>
`

	if respBody != expectedBody {
		t.Fatalf("Test: the expected body %v is different from the response one: %v", expectedBody, respBody)
	}
}
