// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mholt/caddy/caddytls"
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

	request, err := http.NewRequest("POST", "http://localhost.local/?foo=bar", reader)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, *request.URL)
	request = request.WithContext(ctx)

	request.Header.Set("Custom", "foobarbaz")
	request.Header.Set("ShorterVal", "1")
	repl := NewReplacer(request, recordRequest, "-")
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")
	request.Header.Set("Cookie", "foo=bar; taste=delicious")

	// add some response headers
	recordRequest.Header().Set("Custom", "CustomResponseHeader")

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to determine hostname: %v", err)
	}

	old := now
	now = func() time.Time {
		// Note that the `-7` is seconds, not hours.
		return time.Date(2006, 1, 2, 15, 4, 5, 99999999, time.FixedZone("hardcoded", -7))
	}
	defer func() {
		now = old
	}()
	testCases := []struct {
		template string
		expect   string
	}{
		{"This hostname is {hostname}", "This hostname is " + hostname},
		{"This host is {host}.", "This host is localhost.local."},
		{"This request method is {method}.", "This request method is POST."},
		{"The response status is {status}.", "The response status is 200."},
		{"{when}", "02/Jan/2006:15:04:05 +0000"},
		{"{when_iso}", "2006-01-02T15:04:12Z"},
		{"{when_iso_local}", "2006-01-02T15:04:05"},
		{"{when_unix}", "1136214252"},
		{"{when_unix_ms}", "1136214252099"},
		{"The Custom header is {>Custom}.", "The Custom header is foobarbaz."},
		{"The CustomAdd header is {>CustomAdd}.", "The CustomAdd header is caddy."},
		{"The Custom response header is {<Custom}.", "The Custom response header is CustomResponseHeader."},
		{"Bad {>Custom placeholder", "Bad {>Custom placeholder"},
		{"The request is {request}.", "The request is POST /?foo=bar HTTP/1.1\\r\\nHost: localhost.local\\r\\n" +
			"Cookie: foo=bar; taste=delicious\\r\\nCustom: foobarbaz\\r\\nCustomadd: caddy\\r\\n" +
			"Shorterval: 1\\r\\n\\r\\n."},
		{"The cUsToM header is {>cUsToM}...", "The cUsToM header is foobarbaz..."},
		{"The cUsToM response header is {<CuSTom}.", "The cUsToM response header is CustomResponseHeader."},
		{"The Non-Existent header is {>Non-Existent}.", "The Non-Existent header is -."},
		{"Bad {host placeholder...", "Bad {host placeholder..."},
		{"Bad {>Custom placeholder", "Bad {>Custom placeholder"},
		{"Bad {>Custom placeholder {>ShorterVal}", "Bad -"},
		{"Bad {}", "Bad -"},
		{"Cookies are {~taste}", "Cookies are delicious"},
		{"Missing cookie is {~missing}", "Missing cookie is -"},
		{"Query string is {query}", "Query string is foo=bar"},
		{"Query string value for foo is {?foo}", "Query string value for foo is bar"},
		{"Missing query string argument is {?missing}", "Missing query string argument is "},
		{"{label1} {label2} {label3} {label4}", "localhost local - -"},
		{"Label with missing number is {label} or {labelQQ}", "Label with missing number is - or -"},
		{"\\{ 'hostname': '{hostname}' \\}", "{ 'hostname': '" + hostname + "' }"},
		{"{server_port}", "80"},
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

func TestCustomServerPort(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost.local:8000/?foo=bar", reader)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, *request.URL)
	request = request.WithContext(ctx)

	repl := NewReplacer(request, recordRequest, "-")

	testCase := struct {
		template string
		expect   string
	}{
		template: "{server_port}",
		expect:   "8000",
	}

	if expected, actual := testCase.expect, repl.Replace(testCase.template); expected != actual {
		t.Errorf("for template '%s', expected '%s', got '%s'", testCase.template, expected, actual)
	}
}

func TestTlsReplace(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)

	clientCertText := []byte(`-----BEGIN CERTIFICATE-----
MIIB9jCCAV+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1DYWRk
eSBUZXN0IENBMB4XDTE4MDcyNDIxMzUwNVoXDTI4MDcyMTIxMzUwNVowHTEbMBkG
A1UEAwwSY2xpZW50LmxvY2FsZG9tYWluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDFDEpzF0ew68teT3xDzcUxVFaTII+jXH1ftHXxxP4BEYBU4q90qzeKFneF
z83I0nC0WAQ45ZwHfhLMYHFzHPdxr6+jkvKPASf0J2v2HDJuTM1bHBbik5Ls5eq+
fVZDP8o/VHKSBKxNs8Goc2NTsr5b07QTIpkRStQK+RJALk4x9QIDAQABo0swSTAJ
BgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8A
AAEwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADgYEANSjz2Sk+
eqp31wM9il1n+guTNyxJd+FzVAH+hCZE5K+tCgVDdVFUlDEHHbS/wqb2PSIoouLV
3Q9fgDkiUod+uIK0IynzIKvw+Cjg+3nx6NQ0IM0zo8c7v398RzB4apbXKZyeeqUH
9fNwfEi+OoXR6s+upSKobCmLGLGi9Na5s5g=
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(clientCertText)
	if block == nil {
		t.Fatalf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to decode PEM certificate: %v", err)
	}

	request := &http.Request{
		Method: "GET",
		Host:   "foo.com",
		URL: &url.URL{
			Scheme: "https",
			Path:   "/path/",
			Host:   "foo.com",
		},
		Header:     http.Header{},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RemoteAddr: "192.0.2.1:1234",
		RequestURI: "https://foo.com/path/",
		TLS: &tls.ConnectionState{
			Version:           tls.VersionTLS12,
			HandshakeComplete: true,
			ServerName:        "foo.com",
			CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			PeerCertificates:  []*x509.Certificate{cert},
		},
	}

	repl := NewReplacer(request, recordRequest, "-")

	now := time.Now().In(time.UTC)
	days := int64(cert.NotAfter.Sub(now).Seconds() / 86400)
	pemBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	protocol, _ := caddytls.GetSupportedProtocolName(request.TLS.Version)
	cipher, _ := caddytls.GetSupportedCipherName(request.TLS.CipherSuite)
	cEscapedCert := url.QueryEscape(string(pem.EncodeToMemory(&pemBlock)))
	cFingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	cIDn := cert.Issuer.String()
	cRawCert := string(cert.Raw)
	cSDn := cert.Subject.String()
	cSerial := fmt.Sprintf("%x", cert.SerialNumber)
	cVEnd := cert.NotAfter.In(time.UTC).Format("Jan 02 15:04:05 2006 MST")
	cVRemain := strconv.FormatInt(days, 10)
	cVStart := cert.NotBefore.Format("Jan 02 15:04:05 2006 MST")

	testCases := []struct {
		template string
		expect   string
	}{
		{"{tls_protocol}", protocol},
		{"{tls_cipher}", cipher},
		{"{tls_client_escaped_cert}", cEscapedCert},
		{"{tls_client_fingerprint}", cFingerprint},
		{"{tls_client_i_dn}", cIDn},
		{"{tls_client_raw_cert}", cRawCert},
		{"{tls_client_s_dn}", cSDn},
		{"{tls_client_serial}", cSerial},
		{"{tls_client_v_end}", cVEnd},
		{"{tls_client_v_remain}", cVRemain},
		{"{tls_client_v_start}", cVStart},
		{"{server_port}", "443"},
	}

	for _, c := range testCases {
		if expected, actual := c.expect, repl.Replace(c.template); expected != actual {
			t.Errorf("for template '%s', expected '%s', got '%s'", c.template, expected, actual)
		}
	}
}

func BenchmarkReplace(b *testing.B) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost/?foo=bar", reader)
	if err != nil {
		b.Fatalf("Failed to make request: %v", err)
	}
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, *request.URL)
	request = request.WithContext(ctx)

	request.Header.Set("Custom", "foobarbaz")
	request.Header.Set("ShorterVal", "1")
	repl := NewReplacer(request, recordRequest, "-")
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")
	request.Header.Set("Cookie", "foo=bar; taste=delicious")

	// add some response headers
	recordRequest.Header().Set("Custom", "CustomResponseHeader")

	now = func() time.Time {
		// Note that the `-7` is seconds, not hours.
		return time.Date(2006, 1, 2, 15, 4, 5, 02, time.FixedZone("hardcoded", -7))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		repl.Replace("This hostname is {hostname}")
	}
}

func BenchmarkReplaceEscaped(b *testing.B) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost/?foo=bar", reader)
	if err != nil {
		b.Fatalf("Failed to make request: %v", err)
	}
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, *request.URL)
	request = request.WithContext(ctx)

	request.Header.Set("Custom", "foobarbaz")
	request.Header.Set("ShorterVal", "1")
	repl := NewReplacer(request, recordRequest, "-")
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")
	request.Header.Set("Cookie", "foo=bar; taste=delicious")

	// add some response headers
	recordRequest.Header().Set("Custom", "CustomResponseHeader")

	now = func() time.Time {
		// Note that the `-7` is seconds, not hours.
		return time.Date(2006, 1, 2, 15, 4, 5, 02, time.FixedZone("hardcoded", -7))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		repl.Replace("\\{ 'hostname': '{hostname}' \\}")
	}
}

func TestResponseRecorderNil(t *testing.T) {

	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://localhost/?foo=bar", reader)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	request.Header.Set("Custom", "foobarbaz")
	repl := NewReplacer(request, nil, "-")
	// add some headers after creating replacer
	request.Header.Set("CustomAdd", "caddy")
	request.Header.Set("Cookie", "foo=bar; taste=delicious")

	old := now
	now = func() time.Time {
		// Note that the `-7` is seconds, not hours.
		return time.Date(2006, 1, 2, 15, 4, 5, 02, time.FixedZone("hardcoded", -7))
	}
	defer func() {
		now = old
	}()
	testCases := []struct {
		template string
		expect   string
	}{
		{"The Custom response header is {<Custom}.", "The Custom response header is -."},
	}

	for _, c := range testCases {
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

// Test function to test that various placeholders hold correct values after a rewrite
// has been performed.  The NewRequest actually contains the rewritten value.
func TestPathRewrite(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	reader := strings.NewReader(`{"username": "dennis"}`)

	request, err := http.NewRequest("POST", "http://getcaddy.com/index.php?key=value", reader)
	if err != nil {
		t.Fatalf("Request Formation Failed: %s\n", err.Error())
	}
	urlCopy := *request.URL
	urlCopy.Path = "a/custom/path.php"
	ctx := context.WithValue(request.Context(), OriginalURLCtxKey, urlCopy)
	request = request.WithContext(ctx)

	repl := NewReplacer(request, recordRequest, "")

	if got, want := repl.Replace("This path is '{path}'"), "This path is 'a/custom/path.php'"; got != want {
		t.Errorf("{path} replacement failed; got '%s', want '%s'", got, want)
	}

	if got, want := repl.Replace("This path is {rewrite_path}"), "This path is /index.php"; got != want {
		t.Errorf("{rewrite_path} replacement failed; got '%s', want '%s'", got, want)
	}
	if got, want := repl.Replace("This path is '{uri}'"), "This path is 'a/custom/path.php?key=value'"; got != want {
		t.Errorf("{uri} replacement failed; got '%s', want '%s'", got, want)
	}

	if got, want := repl.Replace("This path is {rewrite_uri}"), "This path is /index.php?key=value"; got != want {
		t.Errorf("{rewrite_uri} replacement failed; got '%s', want '%s'", got, want)
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

func TestMillisecondConversion(t *testing.T) {
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
