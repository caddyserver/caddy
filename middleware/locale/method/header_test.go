package method

import (
	"net/http"
	"reflect"
	"testing"
)

func TestHeaderParsing(t *testing.T) {
	header := Names["header"]

	request, _ := http.NewRequest("GET", "/", nil)

	tests := []struct {
		header          string
		expectedLocales []string
	}{
		{"de,en;q=0.8,en-GB;q=0.6", []string{"de", "en", "en-GB"}},
		{"de;q=0.2,en;q=0.8,en-GB;q=0.6", []string{"en", "en-GB", "de"}},
		{"de,,en-GB;q=0.6", []string{"de", "en-GB"}},
		{"en; q=0.8, de", []string{"de", "en"}},
	}

	for index, test := range tests {
		request.Header.Set("Accept-Language", test.header)

		locales := header(request, nil)
		if !reflect.DeepEqual(test.expectedLocales, locales) {
			t.Fatalf("test %d: expected locales %#v, got %#v", index, test.expectedLocales, locales)
		}
	}
}
