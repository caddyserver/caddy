package h2quic

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

func requestFromHeaders(headers []hpack.HeaderField) (*http.Request, error) {
	var path, authority, method, contentLengthStr string
	httpHeaders := http.Header{}

	for _, h := range headers {
		switch h.Name {
		case ":path":
			path = h.Value
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		case "content-length":
			contentLengthStr = h.Value
		default:
			if !h.IsPseudo() {
				httpHeaders.Add(h.Name, h.Value)
			}
		}
	}

	// concatenate cookie headers, see https://tools.ietf.org/html/rfc6265#section-5.4
	if len(httpHeaders["Cookie"]) > 0 {
		httpHeaders.Set("Cookie", strings.Join(httpHeaders["Cookie"], "; "))
	}

	if len(path) == 0 || len(authority) == 0 || len(method) == 0 {
		return nil, errors.New(":path, :authority and :method must not be empty")
	}

	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	var contentLength int64
	if len(contentLengthStr) > 0 {
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	return &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        httpHeaders,
		Body:          nil,
		ContentLength: contentLength,
		Host:          authority,
		RequestURI:    path,
		TLS:           &tls.ConnectionState{},
	}, nil
}

func hostnameFromRequest(req *http.Request) string {
	if len(req.Host) > 0 {
		return req.Host
	}
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}
