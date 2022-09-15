package logging

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zapcore"
)

func TestQueryFilter(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{replaceAction, "foo", "REDACTED"},
		{replaceAction, "notexist", "REDACTED"},
		{deleteAction, "bar", ""},
		{deleteAction, "notexist", ""},
		{hashAction, "hash", ""},
	}}

	if f.Validate() != nil {
		t.Fatalf("the filter must be valid")
	}

	out := f.Filter(zapcore.Field{String: "/path?foo=a&foo=b&bar=c&bar=d&baz=e&hash=hashed"})
	if out.String != "/path?baz=e&foo=REDACTED&foo=REDACTED&hash=e3b0c442" {
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
		{hashAction, "hash", ""},
	}}

	out := f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{
		"foo=a; foo=b; bar=c; bar=d; baz=e; hash=hashed",
	}})
	outval := out.Interface.(caddyhttp.LoggableStringArray)
	expected := caddyhttp.LoggableStringArray{
		"foo=REDACTED; foo=REDACTED; baz=e; hash=1a06df82",
	}
	if outval[0] != expected[0] {
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

func TestHashFilter(t *testing.T) {
	f := HashFilter{}

	out := f.Filter(zapcore.Field{String: "foo"})
	if out.String != "2c26b46b" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}
