package sender

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"

	"github.com/xenolf/lego/acme"
)

type RequestOption func(*http.Request) error

func contentType(ct string) RequestOption {
	return func(req *http.Request) error {
		req.Header.Set("Content-Type", ct)
		return nil
	}
}

type Doer struct {
	httpClient *http.Client
	userAgent  string
}

// NewDoer Creates a new Doer.
func NewDoer(client *http.Client, userAgent string) *Doer {
	return &Doer{
		httpClient: client,
		userAgent:  userAgent,
	}
}

// Get performs a GET request with a proper User-Agent string.
// If "response" is not provided, callers should close resp.Body when done reading from it.
func (d *Doer) Get(url string, response interface{}) (*http.Response, error) {
	req, err := d.newRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return d.do(req, response)
}

// Head performs a HEAD request with a proper User-Agent string.
// The response body (resp.Body) is already closed when this function returns.
func (d *Doer) Head(url string) (*http.Response, error) {
	req, err := d.newRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	return d.do(req, nil)
}

// Post performs a POST request with a proper User-Agent string.
// If "response" is not provided, callers should close resp.Body when done reading from it.
func (d *Doer) Post(url string, body io.Reader, bodyType string, response interface{}) (*http.Response, error) {
	req, err := d.newRequest(http.MethodPost, url, body, contentType(bodyType))
	if err != nil {
		return nil, err
	}

	return d.do(req, response)
}

func (d *Doer) newRequest(method, uri string, body io.Reader, opts ...RequestOption) (*http.Request, error) {
	req, err := http.NewRequest(method, uri, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", d.formatUserAgent())

	for _, opt := range opts {
		err = opt(req)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}
	}

	return req, nil
}

func (d *Doer) do(req *http.Request, response interface{}) (*http.Response, error) {
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if err = checkError(req, resp); err != nil {
		return resp, err
	}

	if response != nil {
		raw, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return resp, err
		}

		defer resp.Body.Close()

		err = json.Unmarshal(raw, response)
		if err != nil {
			return resp, fmt.Errorf("failed to unmarshal %q to type %T: %v", raw, response, err)
		}
	}

	return resp, nil
}

// formatUserAgent builds and returns the User-Agent string to use in requests.
func (d *Doer) formatUserAgent() string {
	ua := fmt.Sprintf("%s %s (%s; %s; %s)", d.userAgent, ourUserAgent, ourUserAgentComment, runtime.GOOS, runtime.GOARCH)
	return strings.TrimSpace(ua)
}

func checkError(req *http.Request, resp *http.Response) error {
	if resp.StatusCode >= http.StatusBadRequest {

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("%d :: %s :: %s :: %v", resp.StatusCode, req.Method, req.URL, err)
		}

		var errorDetails *acme.ProblemDetails
		err = json.Unmarshal(body, &errorDetails)
		if err != nil {
			return fmt.Errorf("%d ::%s :: %s :: %v :: %s", resp.StatusCode, req.Method, req.URL, err, string(body))
		}

		errorDetails.Method = req.Method
		errorDetails.URL = req.URL.String()

		// Check for errors we handle specifically
		if errorDetails.HTTPStatus == http.StatusBadRequest && errorDetails.Type == acme.BadNonceErr {
			return &acme.NonceError{ProblemDetails: errorDetails}
		}

		return errorDetails
	}
	return nil
}
