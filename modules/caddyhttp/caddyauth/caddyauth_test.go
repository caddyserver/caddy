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

package caddyauth

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type mockProvider struct {
	Status   int
	Authed   bool
	Header   map[string]string
	Response []byte
	User     User
	Error    error
}

func (p *mockProvider) Authenticate(w http.ResponseWriter, r *http.Request) (User, bool, error) {
	if p.Error != nil {
		return User{}, false, p.Error
	}
	for k, v := range p.Header {
		w.Header().Add(k, v)
	}
	w.WriteHeader(p.Status)
	if _, err := w.Write(p.Response); err != nil {
		return User{}, false, err
	}
	return p.User, p.Authed, nil
}

type mockHandler struct {
	Called bool
}

func (h *mockHandler) ServeHTTP(_ http.ResponseWriter, _ *http.Request) error {
	h.Called = true
	return nil
}

func TestAuthenticationServeHTTP(t *testing.T) {
	tests := []struct {
		name          string
		providers     map[string]Authenticator
		validStatuses []int
		validReplies  [][]byte
		expectAuthed  bool
		expectError   bool
	}{
		{
			name: "single provider authenticates",
			providers: map[string]Authenticator{
				"http_basic": &mockProvider{
					Status: 200,
					Authed: true,
					User:   User{ID: "test"},
				},
			},
			expectAuthed: true,
		},
		{
			name: "multi provider, one succeeds",
			providers: map[string]Authenticator{
				"http_basic": &mockProvider{
					Status: 200,
					Authed: true,
					User:   User{ID: "test"},
				},
				"other": &mockProvider{
					Status: 401,
					Authed: false,
				},
				"erroring": &mockProvider{
					Error: errors.New("test error"),
				},
			},
			expectAuthed: true,
		},
		{
			name: "all failing, none redirecting",
			providers: map[string]Authenticator{
				"http_basic": &mockProvider{
					Status:   402,
					Response: []byte("http_basic"),
				},
				"other": &mockProvider{
					Status:   401,
					Response: []byte("other"),
				},
			},
			validStatuses: []int{401, 402},
			validReplies:  [][]byte{[]byte("other"), []byte("http_basic")},
			expectError:   true,
		},
		{
			name: "all failing, one redirecting",
			providers: map[string]Authenticator{
				"http_basic": &mockProvider{
					Status:   402,
					Response: []byte("http_basic"),
				},
				"other": &mockProvider{
					Status:   301,
					Response: []byte("oauth"),
					Header: map[string]string{
						"Location": "https://example.org/redirect",
					},
				},
			},
			validStatuses: []int{301},
			validReplies:  [][]byte{[]byte("oauth")},
			expectError:   true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			a := Authentication{
				Providers: test.providers,
				logger:    caddy.Log(),
			}
			r, err := http.NewRequest("GET", "/test", new(bytes.Buffer))
			if err != nil {
				t.Errorf("Failed to create request: %v", err)
			}
			w := httptest.NewRecorder()
			r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, nil)
			next := &mockHandler{}
			err = a.ServeHTTP(w, r, next)
			switch {
			case err != nil && test.expectError:
				// we expected an error and there is one, now check the
				// statuses:
				statusOk := false
				for _, vs := range test.validStatuses {
					statusOk = statusOk || vs == w.Code
				}
				if !statusOk {
					t.Errorf("status was %d, expected one of: %v", w.Code, test.validStatuses)
				}
				replyOk := false
				for _, vr := range test.validReplies {
					replyOk = replyOk || bytes.Equal(vr, w.Body.Bytes())
				}
				if !replyOk {
					t.Errorf("reply was '%s' expected on of: %v", w.Body.Bytes(), test.validReplies)
				}
			case err == nil && test.expectError:
				t.Error("expected an error got none.")
			case err != nil && !test.expectError:
				t.Errorf("expected no error, got: %v", err)
			case err == nil && !test.expectError:
				// no error, none expected. Check nothing modified the writer.
				if w.Code != 200 {
					t.Errorf("expected 200 code, got: %d", w.Code)
				}
				if len(w.Body.Bytes()) > 0 {
					t.Errorf("no body expected, got: %s", w.Body.Bytes())
				}
			}
			switch {
			case test.expectAuthed && !next.Called:
				t.Error("next handler was not called for authorized user.")
			case !test.expectAuthed && next.Called:
				t.Error("next handler was called for unauthorized user.")
			}
		})
	}
}
