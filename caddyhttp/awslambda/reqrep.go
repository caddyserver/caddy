package awslambda

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Request represents a single HTTP request.  It will be serialized as JSON
// and sent to the AWS Lambda function as the function payload.
type Request struct {
	// Set to the constant "HTTPJSON-REQ"
	Type string `json:"type"`
	// Metadata about the HTTP request
	Meta *RequestMeta `json:"meta"`
	// HTTP request body (may be empty)
	Body string `json:"body"`
}

// RequestMeta represents HTTP metadata present on the request
type RequestMeta struct {
	// HTTP method used by client (e.g. GET or POST)
	Method string `json:"method"`

	// Path portion of URL without the query string
	Path string `json:"path"`

	// Query string (without '?')
	Query string `json:"query"`

	// Host field from net/http Request, which may be of the form host:port
	Host string `json:"host"`

	// Proto field from net/http Request, for example "HTTP/1.1"
	Proto string `json:"proto"`

	// HTTP request headers
	Headers map[string][]string `json:"headers"`
}

// NewRequest returns a new Request based on the HTTP request.
// Returns an error if the HTTP request body cannot be read.
func NewRequest(r *http.Request) (*Request, error) {
	// TODO: possibly use buf.Grow() based on content-length header (if present)?
	// Not sure if that will speed things up in the common case
	buf := &bytes.Buffer{}
	if r.Body != nil {
		_, err := io.Copy(buf, r.Body)
		if err != nil {
			return nil, err
		}
	}

	return &Request{
		Type: "HTTPJSON-REQ",
		Meta: newRequestMeta(r),
		Body: buf.String(),
	}, nil
}

// newRequestMeta returns a new RequestMeta based on the HTTP request
func newRequestMeta(r *http.Request) *RequestMeta {
	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = v
	}
	return &RequestMeta{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		Host:    r.Host,
		Proto:   r.Proto,
		Headers: headers,
	}
}

// Reply encapsulates the response from a Lambda invocation.
// AWS Lambda functions should return a JSON object that matches this format.
type Reply struct {
	// Must be set to the constant "HTTPJSON-REP"
	Type string `json:"type"`
	// Reply metadata. If omitted, a default 200 status with empty headers will be used.
	Meta *ReplyMeta `json:"meta"`
	// Response body
	Body string `json:"body"`
}

// ReplyMeta encapsulates HTTP response metadata that the lambda function wishes
// Caddy to set on the HTTP response.
//
// *NOTE* that header values must be encoded as string arrays
type ReplyMeta struct {
	// HTTP status code (e.g. 200 or 404)
	Status int `json:"status"`
	// HTTP response headers
	Headers map[string][]string `json:"headers"`
}

// ParseReply unpacks the Lambda response data into a Reply.
// If the reply is a JSON object with a 'type' field equal to 'HTTPJSON-REP', then
// data will be unmarshaled directly as a Reply struct.
//
// If data is not a JSON object, or the object's type field is omitted or set to
// a string other than 'HTTPJSON-REP', then data will be set as the Reply.body
// and Reply.meta will contain a default struct with a 200 status and
// a content-type header of 'application/json'.
func ParseReply(data []byte) (*Reply, error) {
	if len(data) > 0 && data[0] == '{' {
		var rep Reply
		err := json.Unmarshal(data, &rep)
		if err == nil && rep.Type == "HTTPJSON-REP" {
			if rep.Meta == nil {
				rep.Meta = &defaultMeta
			}
			return &rep, nil
		}
	}

	return &Reply{
		Type: "HTTPJSON-REP",
		Meta: &defaultMeta,
		Body: string(data),
	}, nil
}

var defaultMeta = ReplyMeta{
	Status: 200,
	Headers: map[string][]string{
		"content-type": []string{"application/json"},
	},
}
