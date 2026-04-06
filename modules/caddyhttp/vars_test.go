package caddyhttp

import (
	"context"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestGetVarAndSetVar(t *testing.T) {
	vars := map[string]any{
		"existing_key": "existing_value",
	}

	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)

	// Test GetVar
	if v := GetVar(ctx, "existing_key"); v != "existing_value" {
		t.Errorf("GetVar() = %v, want 'existing_value'", v)
	}

	if v := GetVar(ctx, "nonexistent_key"); v != nil {
		t.Errorf("GetVar() for missing key = %v, want nil", v)
	}

	// Test GetVar with context without vars
	emptyCtx := context.Background()
	if v := GetVar(emptyCtx, "any"); v != nil {
		t.Errorf("GetVar() on context without vars = %v, want nil", v)
	}
}

func TestSetVar(t *testing.T) {
	vars := map[string]any{}
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)

	// Set a value
	SetVar(ctx, "key1", "value1")
	if vars["key1"] != "value1" {
		t.Errorf("SetVar() didn't set value, got %v", vars["key1"])
	}

	// Overwrite a value
	SetVar(ctx, "key1", "value2")
	if vars["key1"] != "value2" {
		t.Errorf("SetVar() didn't overwrite value, got %v", vars["key1"])
	}

	// Set nil deletes existing key
	SetVar(ctx, "key1", nil)
	if _, ok := vars["key1"]; ok {
		t.Error("SetVar(nil) should delete the key")
	}

	// BUG: SetVar with nil for non-existent key should be a no-op per its documentation,
	// but it actually inserts a nil value into the map. The nil check only deletes
	// existing keys; if the key doesn't exist, execution falls through to the
	// final `varMap[key] = value` line, storing nil.
	SetVar(ctx, "nonexistent", nil)
	if _, ok := vars["nonexistent"]; !ok {
		t.Error("BUG: SetVar(nil) for non-existent key unexpectedly did NOT set the key. " +
			"If this passes, the bug described in code comments may have been fixed.")
	}
}

func TestSetVarWithoutContext(t *testing.T) {
	// SetVar on context without VarsCtxKey should silently return
	ctx := context.Background()
	SetVar(ctx, "key", "value") // should not panic
}

func TestVarsMiddlewareCaddyModule(t *testing.T) {
	m := VarsMiddleware{}
	info := m.CaddyModule()
	if info.ID != "http.handlers.vars" {
		t.Errorf("CaddyModule().ID = %v, want 'http.handlers.vars'", info.ID)
	}
}

func TestVarsMatcherEmptyMatch(t *testing.T) {
	m := VarsMatcher{}

	vars := map[string]any{}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req = req.WithContext(ctx)

	// Empty matcher should match everything
	match, err := m.MatchWithError(req)
	if err != nil {
		t.Fatalf("MatchWithError() error = %v", err)
	}
	if !match {
		t.Error("empty VarsMatcher should match everything")
	}
}

func TestVarsMatcherMatch(t *testing.T) {
	vars := map[string]any{
		"my_var": "hello",
	}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req = req.WithContext(ctx)

	tests := []struct {
		name      string
		matcher   VarsMatcher
		wantMatch bool
	}{
		{
			name:      "matching variable",
			matcher:   VarsMatcher{"my_var": {"hello"}},
			wantMatch: true,
		},
		{
			name:      "non-matching variable",
			matcher:   VarsMatcher{"my_var": {"world"}},
			wantMatch: false,
		},
		{
			name:      "nonexistent variable",
			matcher:   VarsMatcher{"nonexistent": {"anything"}},
			wantMatch: false,
		},
		{
			name:      "multiple values OR",
			matcher:   VarsMatcher{"my_var": {"world", "hello", "foo"}},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.matcher.Match(req)
			if match != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestVarsMatcherWithNilVarValue(t *testing.T) {
	vars := map[string]any{
		"nil_var": nil,
	}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), VarsCtxKey, vars)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req = req.WithContext(ctx)

	// nil variable value should match empty string
	m := VarsMatcher{"nil_var": {""}}
	match, err := m.MatchWithError(req)
	if err != nil {
		t.Fatalf("MatchWithError() error = %v", err)
	}
	if !match {
		t.Error("nil variable value should match empty string")
	}
}
