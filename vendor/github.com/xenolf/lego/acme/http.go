package acme

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

var (
	// UserAgent (if non-empty) will be tacked onto the User-Agent string in requests.
	UserAgent string

	// HTTPClient is an HTTP client with a reasonable timeout value and
	// potentially a custom *x509.CertPool based on the caCertificatesEnvVar
	// environment variable (see the `initCertPool` function)
	HTTPClient = http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				ServerName: os.Getenv(caServerNameEnvVar),
				RootCAs:    initCertPool(),
			},
		},
	}
)

const (
	// defaultGoUserAgent is the Go HTTP package user agent string. Too
	// bad it isn't exported. If it changes, we should update it here, too.
	defaultGoUserAgent = "Go-http-client/1.1"

	// ourUserAgent is the User-Agent of this underlying library package.
	ourUserAgent = "xenolf-acme"

	// caCertificatesEnvVar is the environment variable name that can be used to
	// specify the path to PEM encoded CA Certificates that can be used to
	// authenticate an ACME server with a HTTPS certificate not issued by a CA in
	// the system-wide trusted root list.
	caCertificatesEnvVar = "LEGO_CA_CERTIFICATES"

	// caServerNameEnvVar is the environment variable name that can be used to
	// specify the CA server name that can be used to
	// authenticate an ACME server with a HTTPS certificate not issued by a CA in
	// the system-wide trusted root list.
	caServerNameEnvVar = "LEGO_CA_SERVER_NAME"
)

// initCertPool creates a *x509.CertPool populated with the PEM certificates
// found in the filepath specified in the caCertificatesEnvVar OS environment
// variable. If the caCertificatesEnvVar is not set then initCertPool will
// return nil. If there is an error creating a *x509.CertPool from the provided
// caCertificatesEnvVar value then initCertPool will panic.
func initCertPool() *x509.CertPool {
	if customCACertsPath := os.Getenv(caCertificatesEnvVar); customCACertsPath != "" {
		customCAs, err := ioutil.ReadFile(customCACertsPath)
		if err != nil {
			panic(fmt.Sprintf("error reading %s=%q: %v",
				caCertificatesEnvVar, customCACertsPath, err))
		}
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(customCAs); !ok {
			panic(fmt.Sprintf("error creating x509 cert pool from %s=%q: %v",
				caCertificatesEnvVar, customCACertsPath, err))
		}
		return certPool
	}
	return nil
}

// httpHead performs a HEAD request with a proper User-Agent string.
// The response body (resp.Body) is already closed when this function returns.
func httpHead(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to head %q: %v", url, err)
	}

	req.Header.Set("User-Agent", userAgent())

	resp, err = HTTPClient.Do(req)
	if err != nil {
		return resp, fmt.Errorf("failed to do head %q: %v", url, err)
	}
	resp.Body.Close()
	return resp, err
}

// httpPost performs a POST request with a proper User-Agent string.
// Callers should close resp.Body when done reading from it.
func httpPost(url string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to post %q: %v", url, err)
	}
	req.Header.Set("Content-Type", bodyType)
	req.Header.Set("User-Agent", userAgent())

	return HTTPClient.Do(req)
}

// httpGet performs a GET request with a proper User-Agent string.
// Callers should close resp.Body when done reading from it.
func httpGet(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get %q: %v", url, err)
	}
	req.Header.Set("User-Agent", userAgent())

	return HTTPClient.Do(req)
}

// getJSON performs an HTTP GET request and parses the response body
// as JSON, into the provided respBody object.
func getJSON(uri string, respBody interface{}) (http.Header, error) {
	resp, err := httpGet(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to get json %q: %v", uri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return resp.Header, handleHTTPError(resp)
	}

	return resp.Header, json.NewDecoder(resp.Body).Decode(respBody)
}

// postJSON performs an HTTP POST request and parses the response body
// as JSON, into the provided respBody object.
func postJSON(j *jws, uri string, reqBody, respBody interface{}) (http.Header, error) {
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.New("Failed to marshal network message")
	}

	resp, err := j.post(uri, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to post JWS message. -> %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {

		err := handleHTTPError(resp)

		switch err.(type) {

		case NonceError:

			// Retry once if the nonce was invalidated

			retryResp, err := j.post(uri, jsonBytes)
			if err != nil {
				return nil, fmt.Errorf("Failed to post JWS message. -> %v", err)
			}

			defer retryResp.Body.Close()

			if retryResp.StatusCode >= http.StatusBadRequest {
				return retryResp.Header, handleHTTPError(retryResp)
			}

			if respBody == nil {
				return retryResp.Header, nil
			}

			return retryResp.Header, json.NewDecoder(retryResp.Body).Decode(respBody)

		default:
			return resp.Header, err

		}

	}

	if respBody == nil {
		return resp.Header, nil
	}

	return resp.Header, json.NewDecoder(resp.Body).Decode(respBody)
}

// userAgent builds and returns the User-Agent string to use in requests.
func userAgent() string {
	ua := fmt.Sprintf("%s %s (%s; %s) %s", UserAgent, ourUserAgent, runtime.GOOS, runtime.GOARCH, defaultGoUserAgent)
	return strings.TrimSpace(ua)
}
