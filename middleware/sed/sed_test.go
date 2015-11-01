package sed

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
)

func TestSedpHandler(t *testing.T) {
	// Config Sed middleware
	patterns := []Pattern{
		Pattern{
			Find:    "may",
			Replace: "must",
		},
		Pattern{
			Find:    "This",
			Replace: "exmaple.com",
		},
		Pattern{
			Find:    "http://",
			Replace: "https://",
		},
	}
	sed := Sed{
		Rules: []Rule{
			Rule{
				Patterns: patterns,
				Url:      "/",
			},
		},
	}

	// Load gziped data.
	gzData, err := ioutil.ReadFile("data.gz")
	if err != nil {
		t.Fatal(err)
	}

	// Test with disabled gzip module. While it's turned off we can get
	// Content-Encoding header from proxy backend. We trust it.
	var tests = []struct {
		body     []byte // body test
		expected []byte // expected body
		ctt      string // Content-Type for response
		cte      string // Contetn-Encoding for response
		ae       string // Accept-Encoding for request
	}{
		{
			body:     []byte("This domain is established to be used for illustrative examples in documents. You may use this domain in examples without prior coordination or asking for permission."),
			expected: []byte("exmaple.com domain is established to be used for illustrative examples in documents. You must use this domain in examples without prior coordination or asking for permission."),
			ctt:      "text/html; utf-8",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     []byte("This domain is established to be used for illustrative examples in documents. You may use this domain in examples without prior coordination or asking for permission."),
			expected: []byte("This domain is established to be used for illustrative examples in documents. You may use this domain in examples without prior coordination or asking for permission."),
			ctt:      "",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     []byte(""),
			expected: []byte(""),
			ctt:      "",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     []byte(""),
			expected: []byte(""),
			ctt:      "text/html; utf-8",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     []byte("http://example.com http://example.net Test string"),
			expected: []byte("https://example.com https://example.net Test string"),
			ctt:      "text/html; utf-8",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     []byte("http://example.com http://example.net Test string"),
			expected: []byte("http://example.com http://example.net Test string"),
			ctt:      "",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     gzData,
			expected: []byte("gzip https://example.com https://example.net Test string"),
			ctt:      "text/html; utf-8",
			cte:      "gzip",
			ae:       "gzip",
		},
		{
			body:     gzData,
			expected: gzData,
			ctt:      "",
			cte:      "gzip",
			ae:       "gzip",
		},
		{
			body:     gzData,
			expected: gzData,
			ctt:      "text/html; utf-8",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     gzData,
			expected: gzData,
			ctt:      "",
			cte:      "",
			ae:       "gzip",
		},
		{
			body:     []byte("gzip http://example.com http://example.net Test string"),
			expected: []byte("gzip https://example.com https://example.net Test string"),
			ctt:      "text/html; utf-8",
			cte:      "gzip",
			ae:       "",
		},
		{
			body:     []byte("gzip http://example.com http://example.net Test string"),
			expected: []byte("gzip http://example.com http://example.net Test string"),
			ctt:      "",
			cte:      "gzip",
			ae:       "",
		},
		{
			body:     []byte("gzip http://example.com http://example.net Test string"),
			expected: []byte("gzip https://example.com https://example.net Test string"),
			ctt:      "text/html; utf-8",
			cte:      "",
			ae:       "",
		},
		{
			body:     []byte("gzip http://example.com http://example.net Test string"),
			expected: []byte("gzip http://example.com http://example.net Test string"),
			ctt:      "",
			cte:      "",
			ae:       "",
		},
	}

	for _, tt := range tests {
		w := httptest.NewRecorder()
		sed.Next = nextFunc(tt.body, tt.ctt, tt.cte)
		r, err := http.NewRequest("GET", "/", nil)
		if tt.ae != "" {
			r.Header.Set("Accept-Encoding", tt.ae)
		}
		if err != nil {
			t.Error(err)
		}
		_, err = sed.ServeHTTP(w, r)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(w.Body.Bytes(), tt.expected) {
			t.Errorf("Expected '%s' but got '%s' instead", tt.expected, w.Body.Bytes())
		}
	}
}

func nextFunc(body []byte, ctt, cte string) middleware.Handler {
	return middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
		if ctt != "" {
			w.Header().Set("Content-Type", ctt)
		}
		if cte != "" {
			w.Header().Set("Content-Encoding", cte)
		}
		w.Write(body)
		return 0, nil
	})
}
