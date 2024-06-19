package caddytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// use the convention to replace /[certificatename].[crt|key] with the full path
// this helps reduce the noise in test configurations and also allow this
// to run in any path
func prependCaddyFilePath(rawConfig string) string {
	r := matchKey.ReplaceAllString(rawConfig, getIntegrationDir()+"$1")
	r = matchCert.ReplaceAllString(r, getIntegrationDir()+"$1")
	return r
}

func getIntegrationDir() string {
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		panic("unable to determine the current file path")
	}

	return path.Dir(filename)
}

var (
	matchKey  = regexp.MustCompile(`(/[\w\d\.]+\.key)`)
	matchCert = regexp.MustCompile(`(/[\w\d\.]+\.crt)`)
)

type TestHarness struct {
	t testing.TB

	tester *Tester
}

// StartHarness creates and starts a test harness environment which spans the lifetime a single caddy instance
// This is used for the integration tests
func StartHarness(t *testing.T) *TestHarness {
	if testing.Short() {
		t.SkipNow()
		return nil
	}
	o := &TestHarness{t: t}
	o.init()
	return o
}

func (tc *TestHarness) Client() *http.Client {
	return tc.tester.Client
}

func (tc *TestHarness) LoadConfig(rawConfig, configType string) {
	rawConfig = prependCaddyFilePath(rawConfig)
	err := tc.tester.LoadConfig(rawConfig, configType)
	require.NoError(tc.t, err)
}

func (tc *TestHarness) init() {
	// start the server
	tester, err := NewTester()
	if err != nil {
		tc.t.Errorf("Failed to create caddy tester: %s", err)
		return
	}
	tc.tester = tester
	err = tc.tester.LaunchCaddy()
	if err != nil {
		tc.t.Errorf("Failed to launch caddy server: %s", err)
		tc.t.FailNow()
		return
	}
	// cleanup
	tc.t.Cleanup(func() {
		func() {
			if tc.t.Failed() {
				res, err := http.Get(fmt.Sprintf("http://localhost:%d/config/", Default.AdminPort))
				if err != nil {
					tc.t.Log("unable to read the current config")
					return
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)

				var out bytes.Buffer
				_ = json.Indent(&out, body, "", "  ")
				tc.t.Logf("----------- failed with config -----------\n%s", out.String())
			}
		}()
		// shutdown server after extracing the config
		err = tc.tester.CleanupCaddy()
		if err != nil {
			tc.t.Errorf("failed to clean up caddy instance: %s", err)
			tc.t.FailNow()
		}
	})
}

// AssertRedirect makes a request and asserts the redirection happens
func (tc *TestHarness) AssertRedirect(requestURI string, expectedToLocation string, expectedStatusCode int) *http.Response {
	redirectPolicyFunc := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// using the existing client, we override the check redirect policy for this test
	old := tc.tester.Client.CheckRedirect
	tc.tester.Client.CheckRedirect = redirectPolicyFunc
	defer func() { tc.tester.Client.CheckRedirect = old }()

	resp, err := tc.tester.Client.Get(requestURI)
	if err != nil {
		tc.t.Errorf("failed to call server %s", err)
		return nil
	}

	if expectedStatusCode != resp.StatusCode {
		tc.t.Errorf("requesting \"%s\" expected status code: %d but got %d", requestURI, expectedStatusCode, resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		tc.t.Errorf("requesting \"%s\" expected location: \"%s\" but got error: %s", requestURI, expectedToLocation, err)
	}
	if loc == nil && expectedToLocation != "" {
		tc.t.Errorf("requesting \"%s\" expected a Location header, but didn't get one", requestURI)
	}
	if loc != nil {
		if expectedToLocation != loc.String() {
			tc.t.Errorf("requesting \"%s\" expected location: \"%s\" but got \"%s\"", requestURI, expectedToLocation, loc.String())
		}
	}

	return resp
}

// AssertResponseCode will execute the request and verify the status code, returns a response for additional assertions
func (tc *TestHarness) AssertResponseCode(req *http.Request, expectedStatusCode int) *http.Response {
	resp, err := tc.tester.Client.Do(req)
	if err != nil {
		tc.t.Fatalf("failed to call server %s", err)
	}

	if expectedStatusCode != resp.StatusCode {
		tc.t.Errorf("requesting \"%s\" expected status code: %d but got %d", req.URL.RequestURI(), expectedStatusCode, resp.StatusCode)
	}

	return resp
}

// AssertResponse request a URI and assert the status code and the body contains a string
func (tc *TestHarness) AssertResponse(req *http.Request, expectedStatusCode int, expectedBody string) (*http.Response, string) {
	resp := tc.AssertResponseCode(req, expectedStatusCode)

	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		tc.t.Fatalf("unable to read the response body %s", err)
	}

	body := string(bytes)

	if body != expectedBody {
		tc.t.Errorf("requesting \"%s\" expected response body \"%s\" but got \"%s\"", req.RequestURI, expectedBody, body)
	}

	return resp, body
}

// Verb specific test functions

// AssertGetResponse GET a URI and expect a statusCode and body text
func (tc *TestHarness) AssertGetResponse(requestURI string, expectedStatusCode int, expectedBody string) (*http.Response, string) {
	req, err := http.NewRequest("GET", requestURI, nil)
	if err != nil {
		tc.t.Fatalf("unable to create request %s", err)
	}

	return tc.AssertResponse(req, expectedStatusCode, expectedBody)
}

// AssertDeleteResponse request a URI and expect a statusCode and body text
func (tc *TestHarness) AssertDeleteResponse(requestURI string, expectedStatusCode int, expectedBody string) (*http.Response, string) {
	req, err := http.NewRequest("DELETE", requestURI, nil)
	if err != nil {
		tc.t.Fatalf("unable to create request %s", err)
	}

	return tc.AssertResponse(req, expectedStatusCode, expectedBody)
}

// AssertPostResponseBody POST to a URI and assert the response code and body
func (tc *TestHarness) AssertPostResponseBody(requestURI string, requestHeaders []string, requestBody *bytes.Buffer, expectedStatusCode int, expectedBody string) (*http.Response, string) {
	req, err := http.NewRequest("POST", requestURI, requestBody)
	if err != nil {
		tc.t.Errorf("failed to create request %s", err)
		return nil, ""
	}

	applyHeaders(tc.t, req, requestHeaders)

	return tc.AssertResponse(req, expectedStatusCode, expectedBody)
}

// AssertPutResponseBody PUT to a URI and assert the response code and body
func (tc *TestHarness) AssertPutResponseBody(requestURI string, requestHeaders []string, requestBody *bytes.Buffer, expectedStatusCode int, expectedBody string) (*http.Response, string) {
	req, err := http.NewRequest("PUT", requestURI, requestBody)
	if err != nil {
		tc.t.Errorf("failed to create request %s", err)
		return nil, ""
	}

	applyHeaders(tc.t, req, requestHeaders)

	return tc.AssertResponse(req, expectedStatusCode, expectedBody)
}

// AssertPatchResponseBody PATCH to a URI and assert the response code and body
func (tc *TestHarness) AssertPatchResponseBody(requestURI string, requestHeaders []string, requestBody *bytes.Buffer, expectedStatusCode int, expectedBody string) (*http.Response, string) {
	req, err := http.NewRequest("PATCH", requestURI, requestBody)
	if err != nil {
		tc.t.Errorf("failed to create request %s", err)
		return nil, ""
	}

	applyHeaders(tc.t, req, requestHeaders)

	return tc.AssertResponse(req, expectedStatusCode, expectedBody)
}
