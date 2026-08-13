package requestbody

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestRequestBodyCaddyModule(t *testing.T) {
	rb := RequestBody{}
	info := rb.CaddyModule()
	if info.ID != "http.handlers.request_body" {
		t.Errorf("CaddyModule().ID = %v, want 'http.handlers.request_body'", info.ID)
	}
	if info.New == nil {
		t.Fatal("CaddyModule().New is nil")
	}
}

func TestErrorWrapperMaxBytesError(t *testing.T) {
	body := strings.NewReader("this body exceeds the limit")
	w := httptest.NewRecorder()
	limitedReader := http.MaxBytesReader(w, io.NopCloser(body), 5)
	ew := errorWrapper{limitedReader}

	buf := make([]byte, 100)
	totalRead := 0
	for {
		n, err := ew.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			httpErr, ok := err.(caddyhttp.HandlerError)
			if !ok {
				t.Fatalf("error should be caddyhttp.HandlerError, got %T: %v", err, err)
			}
			if httpErr.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("status code = %d, want %d", httpErr.StatusCode, http.StatusRequestEntityTooLarge)
			}
			break
		}
	}
}

func TestErrorWrapperNormalRead(t *testing.T) {
	body := strings.NewReader("hello")
	w := httptest.NewRecorder()
	limitedReader := http.MaxBytesReader(w, io.NopCloser(body), 1000)
	ew := errorWrapper{limitedReader}

	buf := make([]byte, 100)
	n, err := ew.Read(buf)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Read() = %q, want %q", string(buf[:n]), "hello")
	}
}

func TestServeHTTPMaxSize(t *testing.T) {
	rb := RequestBody{MaxSize: 5}
	body := io.NopCloser(strings.NewReader("this body is definitely longer than five bytes"))
	r := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	var calledNext bool
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		_ = data
		return nil
	})

	err := rb.ServeHTTP(w, r, nextHandler)
	if !calledNext {
		t.Error("next handler should have been called")
	}
	if err == nil {
		t.Error("expected error due to MaxSize exceeded")
	}
}

func TestServeHTTPNilBody(t *testing.T) {
	rb := RequestBody{MaxSize: 100}
	r := httptest.NewRequest("GET", "/", nil)
	r.Body = nil
	w := httptest.NewRecorder()

	var calledNext bool
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		return nil
	})

	err := rb.ServeHTTP(w, r, nextHandler)
	if err != nil {
		t.Fatalf("ServeHTTP() error: %v", err)
	}
	if !calledNext {
		t.Error("next handler should have been called")
	}
}

func TestServeHTTPZeroMaxSize(t *testing.T) {
	rb := RequestBody{MaxSize: 0}
	body := io.NopCloser(strings.NewReader("some body"))
	r := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	var bodyContent string
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		bodyContent = string(data)
		return nil
	})

	err := rb.ServeHTTP(w, r, nextHandler)
	if err != nil {
		t.Fatalf("ServeHTTP() error: %v", err)
	}
	if bodyContent != "some body" {
		t.Errorf("body = %q, want %q", bodyContent, "some body")
	}
}
