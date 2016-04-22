package method_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/locale/method"
)

func TestHeaderParsing(t *testing.T) {
	header := method.Names["header"]

	request, _ := http.NewRequest("GET", "/", nil)

	tests := []struct {
		header          string
		expectedLocales []string
	}{
		{"de,en;q=0.8,en-GB;q=0.6", []string{"de", "en", "en-GB"}},
		{"de;q=0.2,en;q=0.8,en-GB;q=0.6", []string{"en", "en-GB", "de"}},
		{"de,,en-GB;q=0.6", []string{"de", "en-GB"}},
	}

	for index, test := range tests {
		request.Header.Set("Accept-Language", test.header)

		locales := header(request, nil)
		if !reflect.DeepEqual(test.expectedLocales, locales) {
			t.Fatalf("test %d: expected locales %#v, got %#v", index, test.expectedLocales, locales)
		}
	}
}
