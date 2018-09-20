package h2quic

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
)

// copied from net/http2/transport.go

var errResponseHeaderListSize = errors.New("http2: response header list larger than advertised limit")
var noBody = ioutil.NopCloser(bytes.NewReader(nil))

// from the handleResponse function
func responseFromHeaders(f *http2.MetaHeadersFrame) (*http.Response, error) {
	if f.Truncated {
		return nil, errResponseHeaderListSize
	}

	status := f.PseudoValue("status")
	if status == "" {
		return nil, errors.New("missing status pseudo header")
	}
	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, errors.New("malformed non-numeric status pseudo header")
	}

	// TODO: handle statusCode == 100

	header := make(http.Header)
	res := &http.Response{
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	for _, hf := range f.RegularFields() {
		key := http.CanonicalHeaderKey(hf.Name)
		if key == "Trailer" {
			t := res.Trailer
			if t == nil {
				t = make(http.Header)
				res.Trailer = t
			}
			foreachHeaderElement(hf.Value, func(v string) {
				t[http.CanonicalHeaderKey(v)] = nil
			})
		} else {
			header[key] = append(header[key], hf.Value)
		}
	}

	return res, nil
}

// continuation of the handleResponse function
func setLength(res *http.Response, isHead, streamEnded bool) *http.Response {
	if !streamEnded || isHead {
		res.ContentLength = -1
		if clens := res.Header["Content-Length"]; len(clens) == 1 {
			if clen64, err := strconv.ParseInt(clens[0], 10, 64); err == nil {
				res.ContentLength = clen64
			}
		}
	}
	return res
}

// copied from net/http/server.go

// foreachHeaderElement splits v according to the "#rule" construction
// in RFC 2616 section 2.1 and calls fn for each non-empty element.
func foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for _, f := range strings.Split(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}
