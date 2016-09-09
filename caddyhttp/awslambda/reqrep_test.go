package awslambda

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestNewRequest(t *testing.T) {
	for i, test := range []struct {
		method   string
		url      string
		body     string
		headers  map[string][]string
		expected Request
	}{
		{
			"GET", "http://example.com/foo?a=b&c=1", "", nil,
			Request{
				Type: "HTTPJSON-REQ",
				Meta: &RequestMeta{
					Method:  "GET",
					Path:    "/foo",
					Query:   "a=b&c=1",
					Headers: map[string][]string{},
				},
			},
		},
		{
			"POST", "https://www.example.org/cat/dog/bird", "post-body-here",
			map[string][]string{
				"x-header-1":   []string{"1-val"},
				"content-type": []string{"image/jpeg"},
			},
			Request{
				Type: "HTTPJSON-REQ",
				Meta: &RequestMeta{
					Method:  "POST",
					Path:    "/cat/dog/bird",
					Headers: map[string][]string{},
				},
			},
		},
	} {
		u, err := url.Parse(test.url)
		if err != nil {
			t.Errorf("Unable to parse url: %s", test.url)
		}

		httpReq := &http.Request{
			Method: test.method,
			URL:    u,
			Header: http.Header(test.headers),
		}

		if test.body != "" {
			httpReq.Body = newBufCloser(test.body)
			test.expected.Body = test.body
		}

		if test.headers != nil {
			test.expected.Meta.Headers = test.headers
		}

		actual, err := NewRequest(httpReq)
		if err != nil {
			t.Errorf("\nTest %d returned non-nil err: %v", i, err)
		} else if actual == nil {
			t.Errorf("\nTest %d returned nil request", i)
		} else {
			eqOrErr(test.expected, *actual, i, t)
		}
	}
}

func TestParseReply(t *testing.T) {
	for i, test := range []struct {
		data          []byte
		expectDefault bool
		expected      Reply
	}{
		{[]byte("hello"), true, Reply{}},
		{nil, true, Reply{}},
		{[]byte(`{"type":"other", "meta": "stuff"}`), true, Reply{}},
		{[]byte(`{"type":"HTTPJSON-REP", "meta": { "status": 404 }, "body": "1234" }`), false,
			Reply{
				Meta: &ReplyMeta{
					Status: 404,
				},
				Body: "1234",
			}},
		{[]byte(`{"type":"HTTPJSON-REP", "body": "zzzz" }`), false,
			Reply{
				Meta: &defaultMeta,
				Body: "zzzz",
			}},
	} {
		if test.expectDefault {
			test.expected = Reply{
				Meta: &defaultMeta,
				Body: string(test.data),
			}
		}

		test.expected.Type = "HTTPJSON-REP"

		actual, err := ParseReply(test.data)
		if err != nil {
			t.Errorf("\nTest %d returned err: %v", i, err)
		} else if actual == nil {
			t.Errorf("Test %d returned nil", i)
		} else {
			eqOrErr(test.expected, *actual, i, t)
		}
	}
}

/////////////////////

func newBufCloser(s string) *BufCloser {
	return &BufCloser{
		bytes.NewBufferString(s),
	}
}

type BufCloser struct {
	*bytes.Buffer
}

func (b *BufCloser) Close() error {
	return nil
}

func eqOrErr(expected, actual interface{}, num int, t *testing.T) bool {
	if !reflect.DeepEqual(expected, actual) {
		ex, err := json.Marshal(expected)
		ac, err2 := json.Marshal(actual)
		if err != nil || err2 != nil {
			t.Errorf("\nTest %d\nExpected: %+v\n  Actual: %+v", num, expected, actual)
			return false
		} else {
			t.Errorf("\nTest %d\nExpected: %s\n  Actual: %s", num, ex, ac)
			return false
		}
	}
	return true
}
