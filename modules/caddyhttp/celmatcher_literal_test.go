package caddyhttp

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"

	"github.com/caddyserver/caddy/v2"
)

func TestCELMatcherRuntimeLiterals(t *testing.T) {
	t.Setenv("CADDY_CEL_TEST", "secret")
	private := filepath.Join(t.TempDir(), "synthetic.txt")
	if err := os.WriteFile(private, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, expr, input, actual string
		want                      bool
	}{
		{"header placeholder", `header({'Field': {input}})`, "{env.CADDY_CEL_TEST}", "secret", false},
		{"header file placeholder", `header({'Field': {input}})`, "{file." + private + "}", "secret", false},
		{"header literal placeholder", `header({'Field': {input}})`, "{env.CADDY_CEL_TEST}", "{env.CADDY_CEL_TEST}", true},
		{"header literal backslash", `header({'Field': {input}})`, `\{env.CADDY_CEL_TEST}`, `\{env.CADDY_CEL_TEST}`, true},
		{"header wildcard", `header({'Field': {input}})`, "*", "secret", false},
		{"header literal wildcard", `header({'Field': {input}})`, "*", "*", true},
		{"header mixed list", `header({'Field': [{input}, '*']})`, "{env.CADDY_CEL_TEST}", "secret", true},
		{"header mixed map", `header({'Field': {input}, 'Other': '*'})`, "*", "secret", false},
		{"header empty static list", `header({'Field': [], 'Other': {input}})`, "secret", "secret", true},
		{"header static template", `header({'Field': '\{env.CADDY_CEL_TEST}'})`, "", "secret", true},
		{"header concat", `header({'Field': {input} + 'ret'})`, "sec", "secret", true},
		{"header concat is literal", `header({'Field': {input} + '*'})`, "sec", "secret", false},
		{"static concat is template", `header({'Field': '{' + 'env.CADDY_CEL_TEST}'})`, "", "secret", true},
		{"query placeholder", `query({'token': {input}})`, "{env.CADDY_CEL_TEST}", "secret", false},
		{"query wildcard", `query({'token': {input}})`, "*", "secret", false},
		{"query literal wildcard", `query({'token': {input}})`, "*", "*", true},
		{"query static template", `query({'token': '\{env.CADDY_CEL_TEST}'})`, "", "secret", true},
		{"query mixed list", `query({'token': [{input}, '*']})`, "missing", "secret", true},
		{"query runtime key", `query({{input}: 'secret'})`, "{env.CADDY_CEL_TEST}", "secret", true},
		{"vars placeholder", `vars({'foo': {input}})`, "{env.CADDY_CEL_TEST}", "secret", false},
		{"vars literal placeholder", `vars({'foo': {input}})`, "{env.CADDY_CEL_TEST}", "{env.CADDY_CEL_TEST}", true},
		{"vars literal backslash", `vars({'foo': {input}})`, `\{env.CADDY_CEL_TEST}`, `\{env.CADDY_CEL_TEST}`, true},
		{"vars static template", `vars({'foo': '\{env.CADDY_CEL_TEST}'})`, "", "secret", true},
		{"vars runtime key", `vars({{input}: 'literal-key-value'})`, "{env.CADDY_CEL_TEST}", "secret", true},
		{"vars regexp runtime key", `vars_regexp({input}, '^literal-key-value$')`, "{env.CADDY_CEL_TEST}", "secret", true},
		{"vars regexp no placeholder lookup", `vars_regexp({input}, '^secret$')`, "{env.CADDY_CEL_TEST}", "secret", false},
		{"path placeholder", `path({input})`, "/{env.CADDY_CEL_TEST}", "secret", false},
		{"path wildcard", `path({input})`, "/s*", "secret", false},
		{"path brackets", `path({input})`, "/[s]afe", "secret", false},
		{"path literal", `path({input})`, "/SAFE", "secret", true},
		{"path concat is literal", `path({input} + '*')`, "/s", "secret", false},
		{"path static template", `path('\{http.request.uri.path}')`, "", "secret", true},
		{"path static wildcard", `path('/s*')`, "", "secret", true},
		{"path mixed list", `path({input}, '/s*')`, "/missing", "secret", true},
		{"host wildcard", `host({input})`, "*.test", "secret", false},
		{"host literal", `host({input})`, "EXAMPLE.TEST", "secret", true},
		{"host static wildcard", `host('*.test')`, "", "secret", true},
		{"host mixed list", `host({input}, '*.test')`, "other.test", "secret", true},
		{"host static template", `host('\{http.request.host}')`, "", "secret", true},
		{"method runtime", `method({input})`, "GET", "secret", true},
		{"tls runtime", `tls({input})`, "any", "secret", false},
		{"regexp runtime unchanged", `path_regexp({input})`, "^/s.*", "secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			m := MatchExpression{Expr: tc.expr}
			if err := m.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "http://example.test/safe", nil)
			req.URL.RawQuery = url.Values{"token": {tc.actual}, "{env.CADDY_CEL_TEST}": {"secret"}}.Encode()
			req.Header.Set("Field", tc.actual)
			req.Header.Set("Other", tc.actual)
			req = req.WithContext(context.WithValue(req.Context(), VarsCtxKey, make(map[string]any)))
			repl := NewTestReplacer(req)
			repl.Set("input", tc.input)
			SetVar(req.Context(), "foo", tc.actual)
			SetVar(req.Context(), "{env.CADDY_CEL_TEST}", "literal-key-value")
			got, err := m.MatchWithError(req)
			if err != nil || got != tc.want {
				t.Fatalf("matched=%v, error=%v; want %v", got, err, tc.want)
			}

		})
	}
}

func TestCELMatcherFactoryCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, expr string
		dataType   *cel.Type
		calls      int
	}{
		{"static caching", `custom('{env.CADDY_CEL_TEST}')`, cel.StringType, 1},
		{"runtime string", `custom(ph(req, 'input'))`, cel.StringType, 3},
		{"runtime list", `custom(ph(req, 'input'))`, cel.ListType(cel.StringType), 3},
		{"runtime map", `custom({'Field': ph(req, 'input')})`, CELTypeJSON, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			library, err := CELMatcherImpl("custom", "custom_request_data", []*cel.Type{tc.dataType},
				func(data ref.Val) (RequestMatcherWithError, error) {
					calls++
					switch v := data.(type) {
					case traits.Lister:
						data = v.Get(types.Int(0))
					case traits.Mapper:
						data = v.Get(types.String("Field"))
					}

					s, ok := data.(types.String)
					if !ok || s != "{env.CADDY_CEL_TEST}" {
						t.Errorf("plugin received %T(%v), not the original CEL string", data, data)
					}
					return MatchMethod{"GET"}, nil
				})
			if err != nil {
				t.Fatal(err)
			}
			env, err := cel.NewEnv(cel.Lib(library),
				cel.Variable(CELRequestVarName, httpRequestCELType),
				cel.Function(CELPlaceholderFuncName,
					cel.Overload("ph_test", []*cel.Type{httpRequestCELType, cel.StringType}, cel.StringType),
					cel.SingletonBinaryBinding(func(_, _ ref.Val) ref.Val { return types.String("{env.CADDY_CEL_TEST}") })))
			if err != nil {
				t.Fatal(err)
			}
			checked, issues := env.Compile(tc.expr)
			if err := issues.Err(); err != nil {
				t.Fatal(err)
			}
			program, err := env.Program(checked)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/", nil)
			for range 3 {
				result, _, err := program.Eval(celHTTPRequest{req})
				if err != nil || result != types.True {
					t.Fatalf("result=%v, error=%v", result, err)
				}
			}
			if calls != tc.calls {
				t.Fatalf("factory called %d times, want %d", calls, tc.calls)
			}
		})
	}
}

func TestCELMatcherLiteralErrors(t *testing.T) {
	for _, tc := range []struct {
		expr  string
		input any
	}{
		{`header({'Field': {input}})`, true},
		{`query({'token': 'secret', {input}: 'other'})`, "token"},
		{`path_regexp({input})`, "["},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			m := MatchExpression{Expr: tc.expr}
			if err := m.Provision(ctx); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/", nil)
			repl := NewTestReplacer(req)
			repl.Set("input", tc.input)
			if _, err := m.MatchWithError(req); err == nil {
				t.Fatal("expected runtime error")
			}
		})
	}
}

func TestCELMatcherConcurrentLiterals(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	m := MatchExpression{Expr: `header({'Field': {input}}) && path('/safe*')`}
	if err := m.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for _, input := range []string{"*", "{env.CADDY_CEL_TEST}", "literal"} {
				req := httptest.NewRequest("GET", "/safe", nil)
				repl := NewTestReplacer(req)
				repl.Set("input", input)
				req.Header.Set("Field", input)
				if matched, err := m.MatchWithError(req); err != nil || !matched {
					t.Errorf("matched=%v, error=%v", matched, err)
				}
			}
		})
	}
	wg.Wait()
}
