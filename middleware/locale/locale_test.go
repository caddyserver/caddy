package locale_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

func TestLocale(t *testing.T) {
	tests := []struct {
		availableLocales     []string
		methods              []method.Method
		pathScope            string
		path                 string
		acceptLanguageHeader string
		expectedLocale       string
	}{
		{[]string{"en"}, []method.Method{method.Names["header"]}, "/", "/", "", "en"},
		{[]string{"en", "en-GB"}, []method.Method{method.Names["header"]}, "/", "/", "en-GB,en", "en-GB"},
		{[]string{"en", "de"}, []method.Method{method.Names["header"]}, "/", "/", "de,en;q=0.8,en-GB;q=0.6", "de"},
		{[]string{"en"}, []method.Method{method.Names["header"]}, "/test", "/other/path", "", ""},
	}

	for index, test := range tests {
		locale := locale.Locale{
			Next:             middleware.HandlerFunc(contentHandler),
			AvailableLocales: test.availableLocales,
			Methods:          test.methods,
			PathScope:        test.pathScope,
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

func contentHandler(_ http.ResponseWriter, _ *http.Request) (int, error) {
	return http.StatusOK, nil
}
