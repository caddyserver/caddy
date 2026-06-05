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

package logging

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// extractExtraFields reads the unexported `fields` slice of ExtraLogFields
// via reflect + unsafe, so tests can verify what addLogField added.
func extractExtraFields(t *testing.T, e *caddyhttp.ExtraLogFields) []zapcore.Field {
	t.Helper()
	v := reflect.ValueOf(e).Elem().FieldByName("fields")
	if !v.IsValid() {
		t.Fatalf("ExtraLogFields.fields not found via reflection")
	}
	v = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	return v.Interface().([]zapcore.Field)
}

// fieldValue runs the field through a MapObjectEncoder and returns the
// resulting concrete value keyed under the field's Key, which abstracts
// over the underlying zapcore.FieldType.
func fieldValue(t *testing.T, f zapcore.Field) any {
	t.Helper()
	enc := zapcore.NewMapObjectEncoder()
	f.AddTo(enc)
	return enc.Fields[f.Key]
}

// newTestRequest builds a *http.Request carrying a context with the three
// values addLogField reads: vars, replacer, extra log fields.
func newTestRequest(vars map[string]any, repl *caddy.Replacer, extra *caddyhttp.ExtraLogFields) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := req.Context()
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, extra)
	return req.WithContext(ctx)
}

func TestAddLogFieldResponseBodyPlaceholder(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		bufData   []byte
		nilBuf    bool
		wantValue any
	}{
		{
			name:      "response body captured when buf has data",
			value:     "{http.response.body}",
			bufData:   []byte("hello world"),
			wantValue: "hello world",
		},
		{
			name:      "response body empty string when buf is nil",
			value:     "{http.response.body}",
			nilBuf:    true,
			wantValue: "",
		},
		{
			name:      "response body base64 encoded when buf has data",
			value:     "{http.response.body_base64}",
			bufData:   []byte("hello world"),
			wantValue: base64.StdEncoding.EncodeToString([]byte("hello world")),
		},
		{
			name:      "response body base64 empty string when buf is nil",
			value:     "{http.response.body_base64}",
			nilBuf:    true,
			wantValue: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extra := new(caddyhttp.ExtraLogFields)
			req := newTestRequest(map[string]any{}, caddy.NewReplacer(), extra)

			handler := LogAppend{Key: "field", Value: tc.value}
			var buf *bytes.Buffer
			if !tc.nilBuf {
				buf = bytes.NewBuffer(tc.bufData)
			}
			handler.addLogField(req, buf)

			fields := extractExtraFields(t, extra)
			if len(fields) != 1 {
				t.Fatalf("expected 1 field added, got %d", len(fields))
			}
			if fields[0].Key != "field" {
				t.Errorf("field key: got %q, want %q", fields[0].Key, "field")
			}
			got := fieldValue(t, fields[0])
			if got != tc.wantValue {
				t.Errorf("field value: got %v (%T), want %v (%T)", got, got, tc.wantValue, tc.wantValue)
			}
		})
	}
}

func TestAddLogFieldPlaceholderResolution(t *testing.T) {
	repl := caddy.NewReplacer()
	repl.Set("my.var", "resolved")
	repl.Set("count", 42)

	vars := map[string]any{
		"foo":    "bar",
		"answer": 42,
	}

	tests := []struct {
		name      string
		value     string
		wantValue any
	}{
		{
			name:      "single placeholder resolves via replacer (string)",
			value:     "{my.var}",
			wantValue: "resolved",
		},
		{
			name:      "single placeholder resolves via replacer (int)",
			value:     "{count}",
			wantValue: int64(42),
		},
		{
			name:      "vars-key match returns vars value (string)",
			value:     "foo",
			wantValue: "bar",
		},
		{
			name:      "vars-key match returns vars value (int)",
			value:     "answer",
			wantValue: int64(42),
		},
		{
			name:      "constant string passes through when not a placeholder or vars key",
			value:     "literal value",
			wantValue: "literal value",
		},
		{
			name: "placeholder with no matching variable returns nil",
			// repl.Get returns (nil, false); addLogField ignores ok and uses nil
			value:     "{nonexistent}",
			wantValue: nil,
		},
		{
			name: "value with single brace pair but extra text is NOT treated as placeholder",
			// Has one '{' but doesn't start with '{', so falls through to vars/constant path.
			value:     "prefix-{x}",
			wantValue: "prefix-{x}",
		},
		{
			name: "value with two placeholders is NOT treated as single placeholder",
			// strings.Count(value, "{") == 2 disqualifies the fast path; value falls
			// through to the vars/constant branches and is treated as a constant.
			value:     "{a}{b}",
			wantValue: "{a}{b}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extra := new(caddyhttp.ExtraLogFields)
			req := newTestRequest(vars, repl, extra)

			handler := LogAppend{Key: "k", Value: tc.value}
			handler.addLogField(req, nil)

			fields := extractExtraFields(t, extra)
			if len(fields) != 1 {
				t.Fatalf("expected 1 field added, got %d", len(fields))
			}
			got := fieldValue(t, fields[0])
			if got != tc.wantValue {
				t.Errorf("field value: got %v (%T), want %v (%T)", got, got, tc.wantValue, tc.wantValue)
			}
		})
	}
}

// TestAddLogFieldVarsPriorityOverConstant verifies that when the value
// matches a vars key, the vars value wins over treating it as a constant.
func TestAddLogFieldVarsPriorityOverConstant(t *testing.T) {
	vars := map[string]any{"colliding": "from-vars"}
	extra := new(caddyhttp.ExtraLogFields)
	req := newTestRequest(vars, caddy.NewReplacer(), extra)

	handler := LogAppend{Key: "k", Value: "colliding"}
	handler.addLogField(req, nil)

	fields := extractExtraFields(t, extra)
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if got := fieldValue(t, fields[0]); got != "from-vars" {
		t.Errorf("vars value should take priority over constant fallback: got %v, want %q", got, "from-vars")
	}
}

func TestLogAppendCaddyModule(t *testing.T) {
	info := LogAppend{}.CaddyModule()
	if info.ID != "http.handlers.log_append" {
		t.Errorf("module ID: got %q, want %q", info.ID, "http.handlers.log_append")
	}
	if info.New == nil {
		t.Fatal("module New func is nil")
	}
	if _, ok := info.New().(*LogAppend); !ok {
		t.Errorf("New() returned wrong type: got %T", info.New())
	}
}
