package method

import (
	"net/http"
	"reflect"
	"testing"
)

func TestCookieParsing(t *testing.T) {
	cookie := Names["cookie"]
	configuration := &Configuration{CookieName: "locale"}

	tests := []struct {
		name            string
		value           string
		expectedLocales []string
	}{
		{"", "", []string{}},
		{"locale", "en", []string{"en"}},
	}

	for index, test := range tests {
		request, _ := http.NewRequest("GET", "/", nil)
		if test.name != "" {
			request.Header.Set("Cookie", (&http.Cookie{Name: test.name, Value: test.value}).String())
		}

		locales := cookie(request, configuration)
		if !reflect.DeepEqual(test.expectedLocales, locales) {
			t.Fatalf("test %d: expected locales %#v, got %#v", index, test.expectedLocales, locales)
		}
	}
}
