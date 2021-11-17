package logging

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap/zapcore"
)

func TestQueryFilter(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{replaceAction, "foo", "REDACTED"},
		{replaceAction, "notexist", "REDACTED"},
		{deleteAction, "bar", ""},
		{deleteAction, "notexist", ""},
	}}

	if f.Validate() != nil {
		t.Fatalf("the filter must be valid")
	}

	out := f.Filter(zapcore.Field{String: "/path?foo=a&foo=b&bar=c&bar=d&baz=e"})
	if out.String != "/path?baz=e&foo=REDACTED&foo=REDACTED" {
		t.Fatalf("query parameters have not been filtered: %s", out.String)
	}
}

func TestValidateQueryFilter(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{},
	}}
	if f.Validate() == nil {
		t.Fatalf("empty action type must be invalid")
	}

	f = QueryFilter{[]queryFilterAction{
		{Type: "foo"},
	}}
	if f.Validate() == nil {
		t.Fatalf("unknown action type must be invalid")
	}
}

func TestCookieFilter(t *testing.T) {
	f := CookieFilter{[]cookieFilterAction{
		{replaceAction, "foo", "REDACTED"},
		{deleteAction, "bar", ""},
	}}

	out := f.Filter(zapcore.Field{String: "foo=a; foo=b; bar=c; bar=d; baz=e"})
	if out.String != "foo=REDACTED; foo=REDACTED; baz=e" {
		t.Fatalf("cookies have not been filtered: %s", out.String)
	}
}

func TestValidateCookieFilter(t *testing.T) {
	f := CookieFilter{[]cookieFilterAction{
		{},
	}}
	if f.Validate() == nil {
		t.Fatalf("empty action type must be invalid")
	}

	f = CookieFilter{[]cookieFilterAction{
		{Type: "foo"},
	}}
	if f.Validate() == nil {
		t.Fatalf("unknown action type must be invalid")
	}
}

func TestRegexpFilter(t *testing.T) {
	f := RegexpFilter{RawRegexp: `secret`, Value: "REDACTED"}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "foo-secret-bar"})
	if out.String != "foo-REDACTED-bar" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}
