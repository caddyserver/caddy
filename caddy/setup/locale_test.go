package setup

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy/middleware/locale"
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
	localeHandler, ok := handler.(locale.Locale)
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
		expectedDetectMethods []locale.DetectMethod
		expectedDefaultLocale string
	}{
		{`locale en`, []locale.DetectMethod{}, "en"},
		{`locale header de_DE`, []locale.DetectMethod{locale.DetectMethodHeader}, "de_DE"},
	}

	for _, test := range tests {
		controller := NewTestController(test.input)

		middleware, err := Locale(controller)
		if err != nil {
			t.Errorf("Expected no errors, but got: %v", err)
		}

		handler := middleware(EmptyNext)
		localeHandler, ok := handler.(locale.Locale)
		if !ok {
			t.Fatalf("Expected handler to be type Locale, got: %#v", handler)
		}

		if !reflect.DeepEqual(localeHandler.DetectMethods, test.expectedDetectMethods) {
			t.Fatalf("Expected handler to have detect methods %#v, got: %#v",
				test.expectedDetectMethods, localeHandler.DetectMethods)
		}

		if localeHandler.DefaultLocale != test.expectedDefaultLocale {
			t.Fatalf("Expected handler to have default locale %#v, got: %#v",
				test.expectedDefaultLocale, localeHandler.DefaultLocale)
		}
	}
}
