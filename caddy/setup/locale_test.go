package setup

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/locale"
	"github.com/mholt/caddy/middleware/locale/method"
)

func TestLocaleDetector(t *testing.T) {
	controller := NewTestController(`locale en`)

	middleware, err := Locale(controller)
	if err != nil {
		t.Errorf("Expected no errors, but got: %v", err)
	}
	if middleware == nil {
		t.Fatal("Expected middleware, was nil instead")
	}

	handler := middleware(EmptyNext)
	localeHandler, ok := handler.(*locale.Locale)
	if !ok {
		t.Fatalf("Expected handler to be type Locale, got: %#v", handler)
	}

	if !SameNext(localeHandler.Next, EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}

func TestLocaleParsing(t *testing.T) {
	tests := []struct {
		input                 string
		expectedMethods       []method.Method
		expectedDefaultLocale string
	}{
		{`locale en`, []method.Method{}, "en"},
		{`locale header de_DE`, []method.Method{&method.Header{}}, "de_DE"},
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

		if !reflect.DeepEqual(localeHandler.Methods, test.expectedMethods) {
			t.Fatalf("Expected handler to have detect methods %#v, got: %#v",
				test.expectedMethods, localeHandler.Methods)
		}

		if localeHandler.DefaultLocale != test.expectedDefaultLocale {
			t.Fatalf("Expected handler to have default locale %#v, got: %#v",
				test.expectedDefaultLocale, localeHandler.DefaultLocale)
		}
	}
}
