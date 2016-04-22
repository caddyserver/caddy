package setup

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

func TestLocaleParsing(t *testing.T) {
	tests := []struct {
		input           string
		expectedLocales []string
		expectedMethods []method.Method
	}{
		{`locale en de`, []string{"en", "de"}, []method.Method{&method.Header{}}},
		{`locale en {
		    all de
		  }`, []string{"en", "de"}, []method.Method{&method.Header{}}},
		{`locale en de {
		    detect header
		  }`, []string{"en", "de"}, []method.Method{&method.Header{}}},
	}

	for _, test := range tests {
		controller := NewTestController(test.input)

		middleware, err := Locale(controller)
		if err != nil {
			t.Errorf("Expected no errors, but got: %v", err)
		}

		handler := middleware(EmptyNext)
		localeHandler, ok := handler.(*locale.Locale)
		if !ok {
			t.Fatalf("Expected handler to be type Locale, got: %#v", handler)
		}

		if !reflect.DeepEqual(localeHandler.Locales, test.expectedLocales) {
			t.Fatalf("Expected handler to have locales %#v, got: %#v",
				test.expectedLocales, localeHandler.Locales)
		}
		if !reflect.DeepEqual(localeHandler.Methods, test.expectedMethods) {
			t.Fatalf("Expected handler to have detect methods %#v, got: %#v",
				test.expectedMethods, localeHandler.Methods)
		}
	}
}
