package caddytest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Defaults store any configuration required to make the tests run
type Defaults struct {
	// Port we expect caddy to listening on
	AdminPort int
	// Certificates we expect to be loaded before attempting to run the tests
	Certifcates []string
}

// Default testing values
var Default = Defaults{
	AdminPort:   2019,
	Certifcates: []string{"/caddy.localhost.crt", "/caddy.localhost.key"},
}

var (
	matchKey  = regexp.MustCompile(`(/[\w\d\.]+\.key)`)
	matchCert = regexp.MustCompile(`(/[\w\d\.]+\.crt)`)
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
			res, err := http.Get(fmt.Sprintf("http://localhost:%d/config/", Default.AdminPort))
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
	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/load", Default.AdminPort), strings.NewReader(rawConfig))
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
	for _, certName := range Default.Certifcates {
		if _, err := os.Stat(getIntegrationDir() + certName); os.IsNotExist(err) {
			return fmt.Errorf("caddy integration test certificates (%s) not found", certName)
		}
	}

	// assert that caddy is running
	client := &http.Client{
		Timeout: time.Second * 2,
	}
	_, err := client.Get(fmt.Sprintf("http://localhost:%d/config/", Default.AdminPort))
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

// use the convention to replace /[certificatename].[crt|key] with the full path
// this helps reduce the noise in test configurations and also allow this
// to run in any path
func prependCaddyFilePath(rawConfig string) string {
	r := matchKey.ReplaceAllString(rawConfig, getIntegrationDir()+"$1")
	r = matchCert.ReplaceAllString(r, getIntegrationDir()+"$1")
	return r
}

// creates a testing transport that forces call dialing connections to happen locally
func createTestingTransport() *http.Transport {

	dialer := net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 5 * time.Second,
		DualStack: true,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		parts := strings.Split(addr, ":")
		destAddr := fmt.Sprintf("127.0.0.1:%s", parts[1])
		log.Printf("caddytest: redirecting the dialer from %s to %s", addr, destAddr)
		return dialer.DialContext(ctx, network, destAddr)
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
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
		Transport: createTestingTransport(),
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
		Transport:     createTestingTransport(),
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
