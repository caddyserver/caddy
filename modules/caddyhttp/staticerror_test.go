package caddyhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestStaticErrorCaddyModule(t *testing.T) {
	se := StaticError{}
	info := se.CaddyModule()
	if info.ID != "http.handlers.error" {
		t.Errorf("CaddyModule().ID = %q, want 'http.handlers.error'", info.ID)
	}
}

func TestStaticErrorServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		staticErr      StaticError
		wantStatusCode int
		wantMessage    string
	}{
		{
			name:           "default status code 500",
			staticErr:      StaticError{},
			wantStatusCode: 500,
		},
		{
			name:           "custom status code",
			staticErr:      StaticError{StatusCode: "404"},
			wantStatusCode: 404,
		},
		{
			name:           "custom error message",
			staticErr:      StaticError{Error: "custom error", StatusCode: "503"},
			wantStatusCode: 503,
			wantMessage:    "custom error",
		},
		{
			name:           "status code only",
			staticErr:      StaticError{StatusCode: "403"},
			wantStatusCode: 403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repl := caddy.NewReplacer()
			ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)

			req, _ := http.NewRequest("GET", "http://example.com/", nil)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			err := tt.staticErr.ServeHTTP(w, req, nil)
			if err == nil {
				t.Fatal("ServeHTTP() should return an error")
			}

			var he HandlerError
			if !errors.As(err, &he) {
				t.Fatal("ServeHTTP() error should be HandlerError")
			}

			if he.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d, want %d", he.StatusCode, tt.wantStatusCode)
			}

			if tt.wantMessage != "" && he.Err != nil {
				if he.Err.Error() != tt.wantMessage {
					t.Errorf("Err.Error() = %q, want %q", he.Err.Error(), tt.wantMessage)
				}
			}
		})
	}
}

func TestStaticErrorServeHTTPInvalidStatusCode(t *testing.T) {
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	se := StaticError{StatusCode: "not_a_number"}
	err := se.ServeHTTP(w, req, nil)
	if err == nil {
		t.Fatal("ServeHTTP() should return error for invalid status code")
	}

	var he HandlerError
	if !errors.As(err, &he) {
		t.Fatal("error should be HandlerError")
	}
	// Invalid status code should return 500
	if he.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500 for invalid status code", he.StatusCode)
	}
}

func TestStaticErrorUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantStatus string
		wantMsg    string
	}{
		{
			name:       "status code only",
			input:      `error 404`,
			wantStatus: "404",
		},
		{
			name:    "message only (non-3-digit)",
			input:   `error "Page not found"`,
			wantMsg: "Page not found",
		},
		{
			name:       "message and status code",
			input:      `error "Page not found" 404`,
			wantStatus: "404",
			wantMsg:    "Page not found",
		},
		{
			name:    "no args",
			input:   `error`,
			wantErr: true,
		},
		{
			name:    "too many args",
			input:   `error "msg" 404 extra`,
			wantErr: true,
		},
		{
			name:       "status in block",
			input:      "error 500 {\n    message \"server error\"\n}",
			wantStatus: "500",
			wantMsg:    "server error",
		},
		{
			name:    "two-digit number is treated as message",
			input:   `error 42`,
			wantMsg: "42",
		},
		{
			name:    "four-digit number is treated as message",
			input:   `error 1234`,
			wantMsg: "1234",
		},
		{
			name:       "three-digit is status code",
			input:      `error 503`,
			wantStatus: "503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			se := &StaticError{}
			err := se.UnmarshalCaddyfile(d)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if tt.wantStatus != "" && string(se.StatusCode) != tt.wantStatus {
				t.Errorf("StatusCode = %q, want %q", se.StatusCode, tt.wantStatus)
			}
			if tt.wantMsg != "" && se.Error != tt.wantMsg {
				t.Errorf("Error = %q, want %q", se.Error, tt.wantMsg)
			}
		})
	}
}

func TestStaticErrorUnmarshalCaddyfileDuplicateMessage(t *testing.T) {
	input := "error \"first message\" 500 {\n    message \"second message\"\n}"
	d := caddyfile.NewTestDispenser(input)
	se := &StaticError{}
	err := se.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("expected error when message is specified both inline and in block")
	}
}
