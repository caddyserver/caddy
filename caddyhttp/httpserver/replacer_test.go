package httpserver

import (
	"bytes"
	"io/ioutil"
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
		if v.replacements["{host}"]() != "localhost" {
			t.Error("Expected host to be localhost")
		}
		if v.replacements["{method}"]() != "POST" {
			t.Error("Expected request method  to be POST")
		}

		// Response placeholders should only be set after call to Replace()
		got, want := "", ""
		if getReplacement, ok := v.replacements["{status}"]; ok {
			got = getReplacement()
		}
		if want := ""; got != want {
			t.Errorf("Expected status to NOT be set before Replace() is called; was: %s", got)
		}
		rep.Replace("{foobar}")
		if getReplacement, ok := v.replacements["{status}"]; ok {
			got = getReplacement()
		}
		if want = "200"; got != want {
			t.Errorf("Expected status to be %s, was: %s", want, got)
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

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal("Failed to determine hostname\n")
	}

	testCases := []struct {
		template string
		expect   string
	}{
		{"This hostname is {hostname}", "This hostname is " + hostname},
		{"This host is {host}.", "This host is localhost."},
		{"This request method is {method}.", "This request method is POST."},
		{"The response status is {status}.", "The response status is 200."},
		{"The Custom header is {>Custom}.", "The Custom header is foobarbaz."},
		{"The request is {request}.", "The request is POST / HTTP/1.1\\r\\nHost: localhost\\r\\nCustom: foobarbaz\\r\\nShorterval: 1\\r\\n\\r\\n."},
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
		replacements map[string]func() string
		expect       string
	}{
		{"/a{1}/{2}",
			map[string]func() string{
				"{1}": func() string { return "12" },
				"{2}": func() string { return "" }},
			"/a12/"},
	}

	for _, c := range complexCases {
		repl := &replacer{
			replacements: c.replacements,
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

func TestReadRequestBody(t *testing.T) {
	payload := []byte(`{ "foo": "bar" }`)
	var readSize int64 = 5
	r, err := http.NewRequest("POST", "/", bytes.NewReader(payload))
	if err != nil {
		t.Error(err)
	}
	defer r.Body.Close()

	logBody, err := readRequestBody(r, readSize)
	if err != nil {
		t.Error("readRequestBody failed", err)
	} else if !bytes.EqualFold(payload[0:readSize], logBody) {
		t.Error("Expected log comparison failed")
	}

	// Ensure the Request body is the same as the original.
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Error("Unable to read request body", err)
	} else if !bytes.EqualFold(payload, reqBody) {
		t.Error("Expected request body comparison failed")
	}
}
