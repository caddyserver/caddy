package caddytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aryann/difflib"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// AssertLoadError will load a config and expect an error
func AssertLoadError(t *testing.T, rawConfig string, configType string, expectedError string) {
	tc := StartHarness(t)
	err := tc.tester.LoadConfig(rawConfig, configType)
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("expected error \"%s\" but got \"%s\"", expectedError, err.Error())
	}
}

// CompareAdapt adapts a config and then compares it against an expected result
func CompareAdapt(t testing.TB, filename, rawConfig string, adapterName string, expectedResponse string) bool {
	cfgAdapter := caddyconfig.GetAdapter(adapterName)
	if cfgAdapter == nil {
		t.Logf("unrecognized config adapter '%s'", adapterName)
		return false
	}

	options := make(map[string]any)

	result, warnings, err := cfgAdapter.Adapt([]byte(rawConfig), options)
	if err != nil {
		t.Logf("adapting config using %s adapter: %v", adapterName, err)
		return false
	}

	// prettify results to keep tests human-manageable
	var prettyBuf bytes.Buffer
	err = json.Indent(&prettyBuf, result, "", "\t")
	if err != nil {
		return false
	}
	result = prettyBuf.Bytes()

	if len(warnings) > 0 {
		for _, w := range warnings {
			t.Logf("warning: %s:%d: %s: %s", filename, w.Line, w.Directive, w.Message)
		}
	}

	diff := difflib.Diff(
		strings.Split(expectedResponse, "\n"),
		strings.Split(string(result), "\n"))

	// scan for failure
	failed := false
	for _, d := range diff {
		if d.Delta != difflib.Common {
			failed = true
			break
		}
	}

	if failed {
		for _, d := range diff {
			switch d.Delta {
			case difflib.Common:
				fmt.Printf("  %s\n", d.Payload)
			case difflib.LeftOnly:
				fmt.Printf(" - %s\n", d.Payload)
			case difflib.RightOnly:
				fmt.Printf(" + %s\n", d.Payload)
			}
		}
		return false
	}
	return true
}

// AssertAdapt adapts a config and then tests it against an expected result
func AssertAdapt(t testing.TB, rawConfig string, adapterName string, expectedResponse string) {
	ok := CompareAdapt(t, "Caddyfile", rawConfig, adapterName, expectedResponse)
	if !ok {
		t.Fail()
	}
}

// Generic request functions

func applyHeaders(t testing.TB, req *http.Request, requestHeaders []string) {
	requestContentType := ""
	for _, requestHeader := range requestHeaders {
		arr := strings.SplitAfterN(requestHeader, ":", 2)
		k := strings.TrimRight(arr[0], ":")
		v := strings.TrimSpace(arr[1])
		if k == "Content-Type" {
			requestContentType = v
		}
		t.Logf("Request header: %s => %s", k, v)
		req.Header.Set(k, v)
	}

	if requestContentType == "" {
		t.Logf("Content-Type header not provided")
	}
}
