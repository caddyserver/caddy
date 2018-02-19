package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// UserAgent (if non-empty) will be tacked onto the User-Agent string in requests.
var UserAgent string

// HTTPClient is an HTTP client with a reasonable timeout value.
var HTTPClient = http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

const (
	// defaultGoUserAgent is the Go HTTP package user agent string. Too
	// bad it isn't exported. If it changes, we should update it here, too.
	defaultGoUserAgent = "Go-http-client/1.1"

	// ourUserAgent is the User-Agent of this underlying library package.
	ourUserAgent = "xenolf-acme"
)

// httpHead performs a HEAD request with a proper User-Agent string.
// The response body (resp.Body) is already closed when this function returns.
func httpHead(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
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
	req, err := http.NewRequest("POST", url, body)
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
	req, err := http.NewRequest("GET", url, nil)
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
		return nil, errors.New("Failed to marshal network message...")
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
	ua := fmt.Sprintf("%s (%s; %s) %s %s", defaultGoUserAgent, runtime.GOOS, runtime.GOARCH, ourUserAgent, UserAgent)
	return strings.TrimSpace(ua)
}
