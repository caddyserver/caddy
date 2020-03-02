package caddytest

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"
)

// InitServer this will configure the server with a configurion of a specific
// type. The configType must be either "json" or the adapter type.
func InitServer(t *testing.T, rawConfig string, configType string) {

	err := validateTestPrerequisites()
	if err != nil {
		t.Skipf("skipping tests as failed integration prerequisites. %s", err)
		return
	}

	t.Cleanup(func() {
		if t.Failed() {
			res, err := http.Get("http://localhost:2019/config/")
			if err != nil {
				t.Log("unable to read the current config")
			}
			defer res.Body.Close()
			body, err := ioutil.ReadAll(res.Body)

			var out bytes.Buffer
			json.Indent(&out, body, "", "  ")
			t.Logf("----------- failed with config -----------\n%s", out.String())
		}
	})

	rawConfig = prependCaddyFilePath(rawConfig)
	client := &http.Client{
		Timeout: time.Second * 2,
	}
	req, err := http.NewRequest("POST", "http://localhost:2019/load", strings.NewReader(rawConfig))
	if err != nil {
		t.Errorf("failed to create request. %s", err)
		return
	}

	if configType == "json" {
		req.Header.Add("Content-Type", "application/json")
	} else {
		req.Header.Add("Content-Type", "text/"+configType)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Errorf("unable to contact caddy server. %s", err)
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("unable to read response. %s", err)
		return
	}

	if res.StatusCode != 200 {
		t.Logf("failed to load config:\n status code:%d \n %s", res.StatusCode, string(body))
		t.Fail()
	}
}

var hasValidated bool
var arePrerequisitesValid bool

func validateTestPrerequisites() error {

	if hasValidated {
		if !arePrerequisitesValid {
			return errors.New("caddy integration prerequisites failed. see first error")
		}
		return nil
	}

	hasValidated = true
	arePrerequisitesValid = false

	// check certificates are found
	if _, err := os.Stat(getIntegrationDir() + "/caddy.localhost.crt"); os.IsNotExist(err) {
		return errors.New("caddy integration test certificates not found")
	}
	if _, err := os.Stat(getIntegrationDir() + "/caddy.localhost.key"); os.IsNotExist(err) {
		return errors.New("caddy integration test certificates not found")
	}

	// assert that caddy is running
	client := &http.Client{
		Timeout: time.Second * 2,
	}
	_, err := client.Get("http://localhost:2019/load")
	if err != nil {
		return errors.New("caddy integration test caddy server not running. Expected to be listening on localhost:2019")
	}

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
	rawConfig = strings.Replace(rawConfig, "/caddy.localhost.crt", getIntegrationDir()+"/caddy.localhost.crt", -1)
	return strings.Replace(rawConfig, "/caddy.localhost.key", getIntegrationDir()+"/caddy.localhost.key", -1)
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

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

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

	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
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
