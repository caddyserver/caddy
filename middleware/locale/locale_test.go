package locale_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

func TestLocale(t *testing.T) {
	tests := []struct {
		locales              []string
		methods              []method.Method
		acceptLanguageHeader string
		expectedLocale       string
	}{
		{[]string{"en"}, []method.Method{&method.Header{}}, "", "en"},
		{[]string{"en", "en-GB"}, []method.Method{&method.Header{}}, "en-GB,en", "en-GB"},
		{[]string{"en", "de"}, []method.Method{&method.Header{}}, "de,en;q=0.8,en-GB;q=0.6", "de"},
	}

	for index, test := range tests {
		locale := locale.Locale{
			Next:    middleware.HandlerFunc(contentHandler),
			Methods: test.methods,
			Locales: test.locales,
		}

		request, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatalf("test %d: could not create HTTP request %v", index, err)
		}
		request.Header.Set("Accept-Language", test.acceptLanguageHeader)

		recorder := httptest.NewRecorder()
		if _, err = locale.ServeHTTP(recorder, request); err != nil {
			t.Fatalf("test %d: could not ServeHTTP %v", index, err)
		}

		if cl := request.Header.Get("Detected-Locale"); cl != test.expectedLocale {
			t.Fatalf("test %d: expected detected locale %s, got %s", index, test.expectedLocale, cl)
		}
	}
}

func contentHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	fmt.Fprintf(w, r.URL.String())
	return http.StatusOK, nil
}
