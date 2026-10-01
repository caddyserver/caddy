// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intercept

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	originBody      = "I'm a teapot"
	replacementBody = "I'm a combined coffee/tea pot that is temporarily out of coffee"
)

// originResponse declares its own Content-Length, the way reverse_proxy and
// file_server do.
var originResponse caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Length", strconv.Itoa(len(originBody)))
	_, err := io.WriteString(w, originBody)
	return err
})

// replacementHandler starts the replacement response with before, then writes
// the body.
type replacementHandler struct {
	before func(w http.ResponseWriter) error
}

func (h replacementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if err := h.before(w); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	_, err := io.WriteString(w, replacementBody)
	return err
}

// A replacement response that opens with a flush or an empty write still has to
// drop the original Content-Length, or net/http aborts the body it frames.
func TestInterceptReplacementBodyAfterPartialWrite(t *testing.T) {
	for i, tc := range []struct {
		name   string
		before func(w http.ResponseWriter) error
	}{
		{
			name: "flush before the body",
			before: func(w http.ResponseWriter) error {
				return http.NewResponseController(w).Flush()
			},
		},
		{
			name: "empty write before the body",
			before: func(w http.ResponseWriter) error {
				_, err := w.Write(nil)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			route := caddyhttp.Route{
				Handlers: []caddyhttp.MiddlewareHandler{replacementHandler{before: tc.before}},
			}
			if err := route.ProvisionHandlers(ctx, nil); err != nil {
				t.Fatalf("Test %d: provisioning the response handler: %v", i, err)
			}

			ir := Intercept{
				HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
			}
			ir.logger = zap.NewNop()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
				if err := ir.ServeHTTP(w, r, originResponse); err != nil {
					t.Errorf("Test %d: serving: %v", i, err)
				}
			}))
			defer srv.Close()

			resp, err := srv.Client().Get(srv.URL)
			if err != nil {
				t.Fatalf("Test %d: request failed: %v", i, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Test %d: reading the replacement body: %v", i, err)
			}
			if string(body) != replacementBody {
				t.Errorf("Test %d: expected body %q, got %q", i, replacementBody, string(body))
			}
		})
	}
}

type writerCaps struct {
	flusher       bool
	hijacker      bool
	readerFrom    bool
	pusher        bool
	writeDeadline bool
}

func probeCaps(w http.ResponseWriter) writerCaps {
	_, flusher := w.(http.Flusher)
	_, hijacker := w.(http.Hijacker)
	_, readerFrom := w.(io.ReaderFrom)
	_, pusher := w.(http.Pusher)
	writeDeadline := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute)) == nil
	return writerCaps{
		flusher:       flusher,
		hijacker:      hijacker,
		readerFrom:    readerFrom,
		pusher:        pusher,
		writeDeadline: writeDeadline,
	}
}

var plainOrigin caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	_, err := io.WriteString(w, originBody)
	return err
})

type capsHandler struct {
	caps *writerCaps
}

func (h capsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	*h.caps = probeCaps(w)
	_, err := io.WriteString(w, "capability ok")
	return err
}

func TestInterceptWriterCapabilities(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	var realCaps, routeCaps writerCaps

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{capsHandler{caps: &routeCaps}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realCaps = probeCaps(w)
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, plainOrigin); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	// the routes may gain delegating wrappers, but they must not lose a
	// capability the real writer has
	lost := writerCaps{
		flusher:       realCaps.flusher && !routeCaps.flusher,
		hijacker:      realCaps.hijacker && !routeCaps.hijacker,
		readerFrom:    realCaps.readerFrom && !routeCaps.readerFrom,
		pusher:        realCaps.pusher && !routeCaps.pusher,
		writeDeadline: realCaps.writeDeadline && !routeCaps.writeDeadline,
	}
	if lost != (writerCaps{}) {
		t.Errorf("route writer lost capabilities of the real writer: %+v (real %+v, route %+v)", lost, realCaps, routeCaps)
	}
	if string(body) != "capability ok" {
		t.Errorf("expected body %q, got %q", "capability ok", string(body))
	}
}

type noSniffHandler struct{}

func (noSniffHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.Header()["Content-Type"] = nil
	_, err := io.WriteString(w, "<b>hi</b>")
	return err
}

// A nil Content-Type is the deliberate no-sniff marker, not inherited
// metadata, so a replacement keeps it and Go does not sniff.
func TestInterceptReplacementKeepsNoSniffContentType(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{noSniffHandler{}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, plainOrigin); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if string(body) != "<b>hi</b>" {
		t.Errorf("expected body %q, got %q", "<b>hi</b>", string(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "" {
		t.Errorf("expected no Content-Type (sniffing suppressed), got %q", got)
	}
}

type hijackHandler struct{}

func (hijackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	return err
}

func TestInterceptHijackWithoutOutput(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{hijackHandler{}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, originResponse); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the hijacked body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if string(body) != "hello" {
		t.Errorf("expected body %q, got %q", "hello", string(body))
	}
}

type switchingProtocolsHandler struct{}

func (switchingProtocolsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.Header().Set("Upgrade", "example")
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return err
	}
	// flushing after the hijack must not touch the hijacked connection
	_ = http.NewResponseController(w).Flush()
	_, err = conn.Write([]byte("switched"))
	return err
}

// 101 owns the response: the route's status and headers are committed and
// the hijacked connection carries the raw bytes.
func TestInterceptSwitchingProtocols(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{switchingProtocolsHandler{}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, originResponse); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	addr, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("resolving the server address: %v", err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("dialing the server: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting the read deadline: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "example")
	if err := req.Write(conn); err != nil {
		t.Fatalf("writing the upgrade request: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("reading the upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected status %d, got %d", http.StatusSwitchingProtocols, resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); got != "example" {
		t.Errorf("expected the route's Upgrade header %q, got %q", "example", got)
	}

	// the route's raw bytes must be the first thing after the 101, so the
	// intercepted body cannot have been written before them
	raw := make([]byte, len("switched"))
	if _, err := io.ReadFull(br, raw); err != nil {
		t.Fatalf("reading the hijacked bytes: %v", err)
	}
	if string(raw) != "switched" {
		t.Errorf("expected the hijacked bytes %q, got %q", "switched", string(raw))
	}
}

var trailerOrigin caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Trailer", "X-Trailer")
	if _, err := io.WriteString(w, originBody); err != nil {
		return err
	}
	w.Header().Set("X-Trailer", "trailer-value")
	return nil
})

type headerOnlyHandler struct{}

func (headerOnlyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.Header().Set("X-Added", "yes")
	return nil
}

func TestInterceptTrailers(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{headerOnlyHandler{}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, trailerOrigin); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if string(body) != originBody {
		t.Errorf("expected body %q, got %q", originBody, string(body))
	}
	if got := resp.Header.Get("X-Added"); got != "yes" {
		t.Errorf("expected the route's X-Added header %q, got %q", "yes", got)
	}
	if got := resp.Trailer.Get("X-Trailer"); got != "trailer-value" {
		t.Errorf("expected trailer %q, got %q", "trailer-value", got)
	}
}

type earlyHintsHandler struct{}

func (earlyHintsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.Header().Set("Link", "</style.css>; rel=preload")
	w.WriteHeader(http.StatusEarlyHints)
	_, err := io.WriteString(w, "final")
	return err
}

func TestInterceptEarlyHintsDoNotOwnResponse(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{earlyHintsHandler{}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, plainOrigin); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	var got103 bool
	var hintHeaders textproto.MIMEHeader
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			if code == http.StatusEarlyHints {
				got103 = true
				hintHeaders = header
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if !got103 {
		t.Errorf("expected to receive status 103")
	}
	if got := hintHeaders.Get("Link"); got != "</style.css>; rel=preload" {
		t.Errorf("expected the route's Link header on the 103, got %q", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected final status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if string(body) != "final" {
		t.Errorf("expected body %q, got %q", "final", string(body))
	}
}

type writeThenNextHandler struct{}

func (writeThenNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	w.WriteHeader(http.StatusCreated)
	if _, err := io.WriteString(w, "new"); err != nil {
		return err
	}
	return next.ServeHTTP(w, r)
}

// a route already committed the response, so reaching the fallback afterwards
// must not append the intercepted body
func TestInterceptFallbackAfterCommitWritesNothing(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	route := caddyhttp.Route{
		Handlers: []caddyhttp.MiddlewareHandler{writeThenNextHandler{}},
	}
	if err := route.ProvisionHandlers(ctx, nil); err != nil {
		t.Fatalf("provisioning the response handler: %v", err)
	}

	ir := Intercept{
		HandleResponse: []caddyhttp.ResponseHandler{{Routes: caddyhttp.RouteList{route}}},
	}
	ir.logger = zap.NewNop()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := ir.ServeHTTP(w, r, originResponse); err != nil {
			t.Errorf("serving: %v", err)
		}
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}
	if string(body) != "new" {
		t.Errorf("expected body %q, got %q", "new", string(body))
	}
}
