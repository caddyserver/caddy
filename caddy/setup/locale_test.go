package setup

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

func TestLocaleParsing(t *testing.T) {
	tests := []struct {
		input                 string
		expectedLocales       []string
		expectedMethods       []method.Method
		expectedConfiguration *method.Configuration
	}{
		{`locale en de`, []string{"en", "de"}, []method.Method{method.Names["header"]}, &method.Configuration{}},
		{`locale en {
		    all de
		  }`, []string{"en", "de"}, []method.Method{method.Names["header"]}, &method.Configuration{}},
		{`locale en de {
		    detect cookie header
				cookie language
		  }`, []string{"en", "de"}, []method.Method{method.Names["cookie"], method.Names["header"]},
			&method.Configuration{CookieName: "language"}},
	}

	for index, test := range tests {
		controller := NewTestController(test.input)

		middleware, err := Locale(controller)
		if err != nil {
			t.Fatalf("test %d: expected no errors, but got: %v", index, err)
		}

		handler := middleware(EmptyNext)
		localeHandler, ok := handler.(*locale.Locale)
		if !ok {
			t.Fatalf("test %d: expected handler to be type Locale, got: %#v", index, handler)
		}

		if !reflect.DeepEqual(localeHandler.AvailableLocales, test.expectedLocales) {
			t.Errorf("test %d: expected handler to have available locales %#v, got: %#v", index,
				test.expectedLocales, localeHandler.AvailableLocales)
		}
		if len(localeHandler.Methods) != len(test.expectedMethods) {
			t.Errorf("test %d: expected handler to have %d detect methods, got: %d", index,
				len(test.expectedMethods), len(localeHandler.Methods))
		}
	}
}
