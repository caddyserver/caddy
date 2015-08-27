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
	userJson := `{"username": "dennis"}`

	reader := strings.NewReader(userJson) //Convert string to reader

	request, err := http.NewRequest("POST", "http://caddyserver.com", reader) //Create request with JSON body
	if err != nil {
		t.Fatalf("Request Formation Failed \n")
	}
	replaceValues := NewReplacer(request, recordRequest, "")

	switch v := replaceValues.(type) {
	case replacer:
		if v.replacements["{host}"] != "caddyserver.com" {
			t.Errorf("Expected host to be caddyserver.com")
		}
		if v.replacements["{method}"] != "POST" {
			t.Errorf("Expected request method  to be POST")
		}
		if v.replacements["{status}"] != "200" {
			t.Errorf("Expected status to be 200")
		}

	default:
		t.Fatalf("Return Value from New Replacer expected pass type assertion into a replacer type   \n")
	}
}
