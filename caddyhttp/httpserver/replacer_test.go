package httpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewReplacer(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatal("Request Formation Failed\n")
	}
	rep := NewReplacer(request, recordRequest, "")

	switch v := rep.(type) {
	case *replacer:
		if v.getSubstitution("{host}") != "localhost" {
			t.Error("Expected host to be localhost")
		}
		if v.getSubstitution("{method}") != "POST" {
			t.Error("Expected request method  to be POST")
		}
	default:
		t.Fatalf("Expected *replacer underlying Replacer type, got: %#v", rep)
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
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal("Failed to determine hostname\n")
	}

	old := now
	now = func() time.Time {
		return time.Date(2006, 1, 2, 15, 4, 5, 02, time.FixedZone("hardcoded", -7))
	}
	defer func() {
		now = old
	}()
	testCases := []struct {
		template string
		expect   string
	}{
		{"This hostname is {hostname}", "This hostname is " + hostname},
		{"This host is {host}.", "This host is localhost."},
		{"This request method is {method}.", "This request method is POST."},
		{"The response status is {status}.", "The response status is 200."},
		{"{when}", "02/Jan/2006:15:04:05 +0000"},
		{"{when_iso}", "2006-01-02T15:04:12Z"},
		{"The Custom header is {>Custom}.", "The Custom header is foobarbaz."},
		{"The CustomAdd header is {>CustomAdd}.", "The CustomAdd header is caddy."},
		{"The request is {request}.", "The request is POST / HTTP/1.1\\r\\nHost: localhost\\r\\nCustom: foobarbaz\\r\\nCustomadd: caddy\\r\\nShorterval: 1\\r\\n\\r\\n."},
		{"The cUsToM header is {>cUsToM}...", "The cUsToM header is foobarbaz..."},
		{"The Non-Existent header is {>Non-Existent}.", "The Non-Existent header is -."},
		{"Bad {host placeholder...", "Bad {host placeholder..."},
		{"Bad {>Custom placeholder", "Bad {>Custom placeholder"},
		{"Bad {>Custom placeholder {>ShorterVal}", "Bad -"},
	}

	for _, c := range testCases {
		if expected, actual := c.expect, repl.Replace(c.template); expected != actual {
			t.Errorf("for template '%s', expected '%s', got '%s'", c.template, expected, actual)
		}
	}

	complexCases := []struct {
		template     string
		replacements map[string]string
		expect       string
	}{
		{
			"/a{1}/{2}",
			map[string]string{
				"{1}": "12",
				"{2}": "",
			},
			"/a12/"},
	}

	for _, c := range complexCases {
		repl := &replacer{
			customReplacements: c.replacements,
		}
		if expected, actual := c.expect, repl.Replace(c.template); expected != actual {
			t.Errorf("for template '%s', expected '%s', got '%s'", c.template, expected, actual)
		}
	}
}

func TestSet(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost", reader)
	if err != nil {
		t.Fatalf("Request Formation Failed: %s\n", err.Error())
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

func TestRound(t *testing.T) {
	var tests = map[time.Duration]time.Duration{
		// 599.935µs -> 560µs
		559935 * time.Nanosecond: 560 * time.Microsecond,
		// 1.55ms    -> 2ms
		1550 * time.Microsecond: 2 * time.Millisecond,
		// 1.5555s   -> 1.556s
		1555500 * time.Microsecond: 1556 * time.Millisecond,
		// 1m2.0035s -> 1m2.004s
		62003500 * time.Microsecond: 62004 * time.Millisecond,
	}

	for dur, expected := range tests {
		rounded := roundDuration(dur)
		if rounded != expected {
			t.Errorf("Expected %v, Got %v", expected, rounded)
		}
	}
}

func TestMillisecondConverstion(t *testing.T) {
	var testCases = map[time.Duration]int64{
		2 * time.Second:           2000,
		9039492 * time.Nanosecond: 9,
		1000 * time.Microsecond:   1,
		127 * time.Nanosecond:     0,
		0 * time.Millisecond:      0,
		255 * time.Millisecond:    255,
	}

	for dur, expected := range testCases {
		numMillisecond := convertToMilliseconds(dur)
		if numMillisecond != expected {
			t.Errorf("Expected %v. Got %v", expected, numMillisecond)
		}
	}
}
