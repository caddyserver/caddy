package caddytest

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"
)

var internalHostnames = []string{"a.caddy.local", "b.caddy.local", "c.caddy.local"}

// TestContext stores the context of the testing process
type TestContext struct {
	t *testing.T
}

// Complete called to clean up the request free the mutex
func (tctx *TestContext) Complete() {
	if tctx.t.Failed() {
		res, err := http.Get("http://localhost:2019/config/")
		if err != nil {
			tctx.t.Log("unable to read the current config")
		}
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)

		var out bytes.Buffer
		json.Indent(&out, body, "", "  ")
		tctx.t.Logf("----------- failed with config -----------\n%s", out.String())
	}
}

// InitServer this will configure the server with a configurion of a specific
// type. The configType must be either "json" or the adapter type.
func InitServer(t *testing.T, rawConfig string, configType string) TestContext {

	tctx := TestContext{t: t}

	err := validateTestPrerequistes()
	if err != nil {
		t.Skipf("skipping tests as failed integration prerequites. %s", err)
		return tctx
	}

	rawConfig = prependCaddyFilePath(rawConfig)
	client := &http.Client{
		Timeout: time.Second * 2,
	}
	req, err := http.NewRequest("POST", "http://localhost:2019/load", strings.NewReader(rawConfig))
	if err != nil {
		t.Errorf("failed to create request. %s", err)
		return tctx
	}

	if configType == "json" {
		req.Header.Add("Content-Type", "application/json")
	} else {
		req.Header.Add("Content-Type", "texg/"+configType)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Errorf("unable to contact caddy server. %s", err)
		return tctx
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("unable to read response. %s", err)
		return tctx
	}

	if res.StatusCode != 200 {
		t.Logf("failed to load config:\n status code:%d \n %s", res.StatusCode, string(body))
		t.Fail()
	}
	return tctx
}

var hasValidated bool
var arePrerequisitesValid bool

func validateTestPrerequistes() error {

	if hasValidated {
		if !arePrerequisitesValid {
			return errors.New("caddy integration prerequistes failed. see first error")
		}
		return nil
	}

	hasValidated = true
	arePrerequisitesValid = false

	for _, host := range internalHostnames {
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("caddy integration prerequistes failed. missing dns host:%s. %s", host, err)
		}

		if len(ips) == 1 && !ips[0].IsLoopback() {
			return fmt.Errorf("caddy integration prerequisites failed. dns host (%s) should resolve to 127.0.0.1 found %s", host, ips[0])
		}
	}

	// check certificates are found
	if _, err := os.Stat(getIntegrationDir() + "/caddy.local.crt"); os.IsNotExist(err) {
		return errors.New("caddy integration test certificates not found")
	}
	if _, err := os.Stat(getIntegrationDir() + "/caddy.local.key"); os.IsNotExist(err) {
		return errors.New("caddy integration test certificates not found")
	}

	//TODO: assert that caddy is running

	arePrerequisitesValid = true
	return nil
}

func getIntegrationDir() string {

	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		panic("unable to determine the current file path")
	}

	return path.Dir(filename)
}

// use the convention to replace caddy.load.[crt|key] with the full path
// this helps reduce the noise in test configurations and also allow this
// to run in any path
func prependCaddyFilePath(rawConfig string) string {
	rawConfig = strings.Replace(rawConfig, "/caddy.local.crt", getIntegrationDir()+"/caddy.local.crt", -1)
	return strings.Replace(rawConfig, "/caddy.local.key", getIntegrationDir()+"/caddy.local.key", -1)
}

// AssertGetResponse request a URI and assert the status code and the body contains a string
func AssertGetResponse(t *testing.T, requestURI string, statusCode int, expectedBody string) (*http.Response, string) {
	resp, body := AssertGetResponseBody(t, requestURI, statusCode)
	if !strings.Contains(body, expectedBody) {
		t.Errorf("expected response body \"%s\" but got \"%s\"", expectedBody, body)
	}
	return resp, string(body)
}

// AssertGetResponseBody request a URI and assert the status code matches
func AssertGetResponseBody(t *testing.T, requestURI string, expectedStatusCode int) (*http.Response, string) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(requestURI)
	if err != nil {
		t.Errorf("failed to call server %s", err)
		return nil, ""
	}

	defer resp.Body.Close()

	if expectedStatusCode != resp.StatusCode {
		t.Errorf("expected status code: %d but got %d", expectedStatusCode, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("unable to read the response body %s", err)
		return nil, ""
	}

	return resp, string(body)
}

// AssertRedirect makes a request and asserts the redirection happens
func AssertRedirect(t *testing.T, requestURI string, expectedToLocation string, expectedStatusCode int) *http.Response {

	redirectPolicyFunc := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
		Transport:     tr,
	}

	resp, err := client.Get(requestURI)
	if err != nil {
		t.Errorf("failed to call server %s", err)
		return nil
	}

	if expectedStatusCode != resp.StatusCode {
		t.Errorf("expected status code: %d but got %d", expectedStatusCode, resp.StatusCode)
	}

	loc, err := resp.Location()
	if expectedToLocation != loc.String() {
		t.Errorf("expected location: \"%s\" but got \"%s\"", expectedToLocation, loc.String())
	}

	return resp
}
