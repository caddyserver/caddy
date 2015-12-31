package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewReplacer(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatal("Request Formation Failed\n")
	}
	replaceValues := NewReplacer(request, recordRequest, "")

	switch v := replaceValues.(type) {
	case replacer:

		if v.replacements["{host}"] != "localhost" {
			t.Error("Expected host to be localhost")
		}
		if v.replacements["{method}"] != "POST" {
			t.Error("Expected request method  to be POST")
		}
		if v.replacements["{status}"] != "200" {
			t.Error("Expected status to be 200")
		}

	default:
		t.Fatal("Return Value from New Replacer expected pass type assertion into a replacer type\n")
	}
}

func TestReplace(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatal("Request Formation Failed\n")
	}
	request.Header.Set("Custom", "foobarbaz")
	request.Header.Set("ShorterVal", "1")
	repl := NewReplacer(request, recordRequest, "-")

	if expected, actual := "This host is localhost.", repl.Replace("This host is {host}."); expected != actual {
		t.Errorf("{host} replacement: expected '%s', got '%s'", expected, actual)
	}
	if expected, actual := "This request method is POST.", repl.Replace("This request method is {method}."); expected != actual {
		t.Errorf("{method} replacement: expected '%s', got '%s'", expected, actual)
	}
	if expected, actual := "The response status is 200.", repl.Replace("The response status is {status}."); expected != actual {
		t.Errorf("{status} replacement: expected '%s', got '%s'", expected, actual)
	}
	if expected, actual := "The Custom header is foobarbaz.", repl.Replace("The Custom header is {>Custom}."); expected != actual {
		t.Errorf("{>Custom} replacement: expected '%s', got '%s'", expected, actual)
	}

	// Test header case-insensitivity
	if expected, actual := "The cUsToM header is foobarbaz...", repl.Replace("The cUsToM header is {>cUsToM}..."); expected != actual {
		t.Errorf("{>cUsToM} replacement: expected '%s', got '%s'", expected, actual)
	}

	// Test non-existent header/value
	if expected, actual := "The Non-Existent header is -.", repl.Replace("The Non-Existent header is {>Non-Existent}."); expected != actual {
		t.Errorf("{>Non-Existent} replacement: expected '%s', got '%s'", expected, actual)
	}

	// Test bad placeholder
	if expected, actual := "Bad {host placeholder...", repl.Replace("Bad {host placeholder..."); expected != actual {
		t.Errorf("bad placeholder: expected '%s', got '%s'", expected, actual)
	}

	// Test bad header placeholder
	if expected, actual := "Bad {>Custom placeholder", repl.Replace("Bad {>Custom placeholder"); expected != actual {
		t.Errorf("bad header placeholder: expected '%s', got '%s'", expected, actual)
	}

	// Test bad header placeholder with valid one later
	if expected, actual := "Bad -", repl.Replace("Bad {>Custom placeholder {>ShorterVal}"); expected != actual {
		t.Errorf("bad header placeholders: expected '%s', got '%s'", expected, actual)
	}

	// Test shorter header value with multiple placeholders
	if expected, actual := "Short value 1 then foobarbaz.", repl.Replace("Short value {>ShorterVal} then {>Custom}."); expected != actual {
		t.Errorf("short value: expected '%s', got '%s'", expected, actual)
	}
}

func TestSet(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatalf("Request Formation Failed \n")
	}
	repl := NewReplacer(request, recordRequest, "")

	repl.Set("host", "getcaddy.com")
	repl.Set("method", "GET")
	repl.Set("status", "201")
	repl.Set("variable", "value")

	if repl.Replace("This host is {host}") != "This host is getcaddy.com" {
		t.Error("Expected host replacement failed")
	}
	if repl.Replace("This request method is {method}") != "This request method is GET" {
		t.Error("Expected method replacement failed")
	}
	if repl.Replace("The response status is {status}") != "The response status is 201" {
		t.Error("Expected status replacement failed")
	}
	if repl.Replace("The value of variable is {variable}") != "The value of variable is value" {
		t.Error("Expected variable replacement failed")
	}
}
