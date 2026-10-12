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

package caddyhttp

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/caddyserver/caddy/v2"
)

func TestCELLiteralReviewMapCollision(t *testing.T) {
	value := types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{
		types.String("same"): types.String("configured"),
		&celMatcherLiteralString{String: types.String("same")}: types.String("evaluated"),
	})
	if _, err := CELMatcherStringMap(value); err == nil {
		t.Fatal("identical map keys with different provenance must be rejected")
	}
}

func TestCELLiteralReviewTemplateRoundTrip(t *testing.T) {
	repl := caddy.NewReplacer()
	repl.Set("secret", "expanded-secret")
	for _, input := range []string{
		"{secret}", `\{secret}`, `{secret\}`, `\\{secret}`, "{}{}", "{unclosed", "closed}",
	} {
		value := CELMatcherString{Value: input, Literal: true}
		if got := repl.ReplaceAll(value.Template(), ""); got != input {
			t.Errorf("literal %q replaced to %q", input, got)
		}
	}
}

// A placeholder can return a collection instead of a scalar string. Its leaves
// are evaluated data, just as if the placeholder had returned one string.
func TestCELLiteralReviewEvaluatedList(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `header({'X-Value': {values}})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	for _, input := range []any{[]string{"{secret}"}, []any{"{secret}"}} {
		for _, want := range []struct {
			header  string
			matches bool
		}{{"{secret}", true}, {"expanded-secret", false}} {
			req := httptest.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("X-Value", want.header)
			repl := caddy.NewReplacer()
			repl.Set("values", input)
			repl.Set("secret", "expanded-secret")
			req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
			matched, err := matcher.MatchWithError(req)
			if err != nil || matched != want.matches {
				t.Errorf("input %T header %q: matched=%v error=%v; want %v", input, want.header, matched, err, want.matches)
			}
		}
	}
}

func TestCELLiteralReviewQueryTemplateCollision(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `query({'\\{key\\}': ['expected'], {dynamic_key}: ['other']})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://example.com/?%7Bkey%7D=expected", nil)
	repl := caddy.NewReplacer()
	repl.Set("dynamic_key", "{key}")
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	if matched, err := matcher.MatchWithError(req); err == nil {
		t.Fatalf("ambiguous query keys must return an error, matched=%v expanded expression=%s", matched, matcher.expandedExpr)
	}
}

func TestCELLiteralReviewConcurrentConcat(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `header({'X-Value': '\{secret}' + {suffix}})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				secret := fmt.Sprintf("request-%d-%d", i, j)
				req := httptest.NewRequest("GET", "https://example.com/", nil)
				req.Header.Set("X-Value", secret+"{secret}")
				repl := caddy.NewReplacer()
				repl.Set("secret", secret)
				repl.Set("suffix", "{secret}")
				req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
				if matched, err := matcher.MatchWithError(req); err != nil || !matched {
					t.Errorf("request %s: matched=%v error=%v", secret, matched, err)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestCELLiteralReviewUnsupportedCycles(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	matcher := MatchExpression{Expr: `header({'X-Value': {values}})`}
	if err := matcher.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	cycle := make([]any, 2)
	cycle[0], cycle[1] = cycle, cycle
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	repl := caddy.NewReplacer()
	repl.Set("values", cycle)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	if matched, err := matcher.MatchWithError(req); err == nil || matched {
		t.Fatalf("unsupported cyclic input must be rejected: matched=%v error=%v", matched, err)
	}
}
