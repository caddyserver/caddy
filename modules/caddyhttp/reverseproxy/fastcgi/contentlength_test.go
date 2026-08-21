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

package fastcgi

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TestDoRejectsUnusableContentLength pins what the client does with a
// CONTENT_LENGTH it cannot use, and which of those cases carries which message.
//
// Only "-1" is reachable through Transport.RoundTrip, which is the shape a
// chunked request takes: Get/Head/Options/Post all set CONTENT_LENGTH before
// Do sees it, from the r.ContentLength that net/http reports as -1 when it has
// no length. The absent and empty cases guard Do's own contract for any future
// caller; an absent key was the one that used to return a 411 with no error at
// all, while an empty value carried strconv's syntax error, true but useless
// to an operator. TestPostRejectsUnknownLengthWithRemedy covers the reachable
// path end to end.
func TestDoRejectsUnusableContentLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		wantErr error
	}{
		{
			name:    "absent",
			env:     map[string]string{},
			wantErr: errNoContentLength,
		},
		{
			name:    "empty",
			env:     map[string]string{"CONTENT_LENGTH": ""},
			wantErr: errNoContentLength,
		},
		{
			// The reported case: what a chunked request becomes by the time it
			// reaches here, and the only one production can produce.
			name:    "negative, as a chunked request arrives",
			env:     map[string]string{"CONTENT_LENGTH": "-1"},
			wantErr: errNoContentLength,
		},
		{
			name:    "not a number",
			env:     map[string]string{"CONTENT_LENGTH": "banana"},
			wantErr: errBadContentLength,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &client{}
			_, err := c.Do(tc.env, strings.NewReader("body"))
			if err == nil {
				t.Fatal("expected an error")
			}

			var handlerErr caddyhttp.HandlerError
			if !errors.As(err, &handlerErr) {
				t.Fatalf("error %v is not a caddyhttp.HandlerError", err)
			}
			if handlerErr.StatusCode != http.StatusLengthRequired {
				t.Errorf("status = %d, want %d", handlerErr.StatusCode, http.StatusLengthRequired)
			}
			// The status alone is what sent people hunting through their
			// backend logs, so the cause has to travel with it.
			if handlerErr.Err == nil {
				t.Fatal("the 411 carries no error to explain it")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestNoContentLengthErrorNamesTheRemedy keeps the message actionable: the
// operator has to learn that buffering is what supplies the missing length.
func TestNoContentLengthErrorNamesTheRemedy(t *testing.T) {
	t.Parallel()

	if !strings.Contains(errNoContentLength.Error(), "request_buffers") {
		t.Errorf("error %q does not name request_buffers as the remedy", errNoContentLength)
	}
}

// TestPostRejectsUnknownLengthWithRemedy goes through the entry point RoundTrip
// actually uses. Transport.RoundTrip passes r.ContentLength straight to Post,
// and net/http reports -1 for a chunked body, so this is the exact call the
// reporter of #7386 made. Asserting it only against Do would let the message
// rot on a branch production never reaches.
func TestPostRejectsUnknownLengthWithRemedy(t *testing.T) {
	t.Parallel()

	c := &client{}
	env := map[string]string{}

	_, err := c.Post(env, http.MethodPost, "application/octet-stream", strings.NewReader("body"), -1)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, errNoContentLength) {
		t.Errorf("error %v does not wrap errNoContentLength", err)
	}
	if !strings.Contains(err.Error(), "request_buffers") {
		t.Errorf("the error operators see, %q, does not name the remedy", err)
	}

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusLengthRequired {
		t.Errorf("error %v is not a 411 HandlerError", err)
	}
}
