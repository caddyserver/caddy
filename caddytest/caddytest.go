package caddytest

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"
)

// InitServer this will configure the server with a configurion of a specific
// type. The configType must be either "json" or the adapter type.
func InitServer(t *testing.T, rawConfig string, configType string) {

	err := validateTestPrerequistes()
	if err != nil {
		t.Skipf("skipping tests as failed integration prerequites. %s", err)
		return
	}

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
		req.Header.Add("Content-Type", "texg/"+configType)
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

func validateTestPrerequistes() error {

	//TODO: hostname assumptions
	// 127.0.0.1 a.caddy.local
	// 127.0.0.1 b.caddy.local
	// 127.0.0.1 c.caddy.local

	//TODO: certificate assumptions
	// have a caddy.local.crt and caddy.local.key in this path - see generate_key.sh

	// return errors.New("no certs")

	//TODO: assert that caddy is running

	return nil
}

// use the convention to replace caddy.load.[crt|key] with the full path
// this helps reduce the noise in test configurations and also allow this
// to run in any path
func prependCaddyFilePath(rawConfig string) string {

	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		panic("unable to determine the current file path")
	}

	dir := path.Dir(filename)
	rawConfig = strings.Replace(rawConfig, "/caddy.local.crt", dir+"/caddy.local.crt", -1)
	return strings.Replace(rawConfig, "/caddy.local.key", dir+"/caddy.local.key", -1)
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
