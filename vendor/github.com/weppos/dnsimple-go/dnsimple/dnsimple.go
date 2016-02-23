// Package dnsimple implements a client for the DNSimple API.
//
// In order to use this package you will need a DNSimple account and your API Token.
package dnsimple

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	libraryVersion = "0.1"
	baseURL        = "https://api.dnsimple.com/"
	userAgent      = "dnsimple-go/" + libraryVersion

	apiVersion = "v1"
)

type Client struct {
	// HTTP client used to communicate with the API.
	HttpClient *http.Client

	// Credentials used for accessing the DNSimple API
	Credentials Credentials

	// Base URL for API requests.
	// Defaults to the public DNSimple API, but can be set to a different endpoint (e.g. the sandbox).
	// BaseURL should always be specified with a trailing slash.
	BaseURL string

	// User agent used when communicating with the DNSimple API.
	UserAgent string

	// Services used for talking to different parts of the DNSimple API.
	Contacts  *ContactsService
	Domains   *DomainsService
	Registrar *RegistrarService
	Users     *UsersService
}

// NewClient returns a new DNSimple API client.
func NewClient(apiToken, email string) *Client {
	return NewAuthenticatedClient(NewApiTokenCredentials(email, apiToken))

}

// NewAuthenticatedClient returns a new DNSimple API client  using the given
// credentials.
func NewAuthenticatedClient(credentials Credentials) *Client {
	c := &Client{Credentials: credentials, HttpClient: &http.Client{}, BaseURL: baseURL, UserAgent: userAgent}
	c.Contacts = &ContactsService{client: c}
	c.Domains = &DomainsService{client: c}
	c.Registrar = &RegistrarService{client: c}
	c.Users = &UsersService{client: c}
	return c
}

// NewRequest creates an API request.
// The path is expected to be a relative path and will be resolved
// according to the BaseURL of the Client. Paths should always be specified without a preceding slash.
func (client *Client) NewRequest(method, path string, payload interface{}) (*http.Request, error) {
	url := client.BaseURL + fmt.Sprintf("%s/%s", apiVersion, path)

	body := new(bytes.Buffer)
	if payload != nil {
		err := json.NewEncoder(body).Encode(payload)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", client.UserAgent)
	req.Header.Add(client.Credentials.HttpHeader())

	return req, nil
}

func (c *Client) get(path string, v interface{}) (*Response, error) {
	return c.Do("GET", path, nil, v)
}

func (c *Client) post(path string, payload, v interface{}) (*Response, error) {
	return c.Do("POST", path, payload, v)
}

func (c *Client) put(path string, payload, v interface{}) (*Response, error) {
	return c.Do("PUT", path, payload, v)
}

func (c *Client) delete(path string, payload interface{}) (*Response, error) {
	return c.Do("DELETE", path, payload, nil)
}

// Do sends an API request and returns the API response.
// The API response is JSON decoded and stored in the value pointed by v,
// or returned as an error if an API error has occurred.
// If v implements the io.Writer interface, the raw response body will be written to v,
// without attempting to decode it.
func (c *Client) Do(method, path string, payload, v interface{}) (*Response, error) {
	req, err := c.NewRequest(method, path, payload)
	if err != nil {
		return nil, err
	}

	res, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	response := &Response{Response: res}

	err = CheckResponse(res)
	if err != nil {
		return response, err
	}

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			io.Copy(w, res.Body)
		} else {
			err = json.NewDecoder(res.Body).Decode(v)
		}
	}

	return response, err
}

// A Response represents an API response.
type Response struct {
	*http.Response
}

// An ErrorResponse represents an error caused by an API request.
type ErrorResponse struct {
	Response *http.Response // HTTP response that caused this error
	Message  string         `json:"message"` // human-readable message
}

// Error implements the error interface.
func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%v %v: %d %v",
		r.Response.Request.Method, r.Response.Request.URL,
		r.Response.StatusCode, r.Message)
}

// CheckResponse checks the API response for errors, and returns them if present.
// A response is considered an error if the status code is different than 2xx. Specific requests
// may have additional requirements, but this is sufficient in most of the cases.
func CheckResponse(r *http.Response) error {
	if code := r.StatusCode; 200 <= code && code <= 299 {
		return nil
	}

	errorResponse := &ErrorResponse{Response: r}
	err := json.NewDecoder(r.Body).Decode(errorResponse)
	if err != nil {
		return err
	}

	return errorResponse
}

// Date custom type.
type Date struct {
	time.Time
}

// UnmarshalJSON handles the deserialization of the custom Date type.
func (d *Date) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("date should be a string, got %s", data)
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("invalid date: %v", err)
	}
	d.Time = t
	return nil
}
