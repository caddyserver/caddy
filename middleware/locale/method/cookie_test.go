package method_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/locale/method"
)

func TestCookieParsing(t *testing.T) {
	cookie := method.Names["cookie"]
	settings := &method.Settings{CookieName: "locale"}

	request, _ := http.NewRequest("GET", "/", nil)

	tests := []struct {
		name            string
		value           string
		expectedLocales []string
	}{
		{"locale", "en", []string{"en"}},
		{"locale", "de", []string{"de"}},
	}

	for index, test := range tests {
		request.Header.Set("Cookie", (&http.Cookie{Name: test.name, Value: test.value}).String())
		locales := cookie(request, settings)
		if !reflect.DeepEqual(test.expectedLocales, locales) {
			t.Fatalf("test %d: expected locales %#v, got %#v", index, test.expectedLocales, locales)
		}
	}
}
