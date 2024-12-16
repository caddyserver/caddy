package logging

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zapcore"
)

func TestIPMaskSingleValue(t *testing.T) {
	f := IPMaskFilter{IPv4MaskRaw: 16, IPv6MaskRaw: 32}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "255.255.255.255"})
	if out.String != "255.255.0.0" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"})
	if out.String != "ffff:ffff::" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "not-an-ip"})
	if out.String != "not-an-ip" {
		t.Fatalf("field has been filtered: %s", out.String)
	}
}

func TestIPMaskCommaValue(t *testing.T) {
	f := IPMaskFilter{IPv4MaskRaw: 16, IPv6MaskRaw: 32}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "255.255.255.255, 244.244.244.244"})
	if out.String != "255.255.0.0, 244.244.0.0" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"})
	if out.String != "ffff:ffff::, ff00:ffff::" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}

	out = f.Filter(zapcore.Field{String: "not-an-ip, 255.255.255.255"})
	if out.String != "not-an-ip, 255.255.0.0" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestIPMaskMultiValue(t *testing.T) {
	f := IPMaskFilter{IPv4MaskRaw: 16, IPv6MaskRaw: 32}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{
		"255.255.255.255",
		"244.244.244.244",
	}})
	arr, ok := out.Interface.(caddyhttp.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "255.255.0.0" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "244.244.0.0" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}

	out = f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}})
	arr, ok = out.Interface.(caddyhttp.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "ffff:ffff::" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "ff00:ffff::" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestQueryFilterSingleValue(t *testing.T) {
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

func TestQueryFilterMultiValue(t *testing.T) {
	f := QueryFilter{
		Actions: []queryFilterAction{
			{Type: replaceAction, Parameter: "foo", Value: "REDACTED"},
			{Type: replaceAction, Parameter: "notexist", Value: "REDACTED"},
			{Type: deleteAction, Parameter: "bar"},
			{Type: deleteAction, Parameter: "notexist"},
			{Type: hashAction, Parameter: "hash"},
		},
	}

	if f.Validate() != nil {
		t.Fatalf("the filter must be valid")
	}

	out := f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{
		"/path1?foo=a&foo=b&bar=c&bar=d&baz=e&hash=hashed",
		"/path2?foo=c&foo=d&bar=e&bar=f&baz=g&hash=hashed",
	}})
	arr, ok := out.Interface.(caddyhttp.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Interface)
	}

	expected1 := "/path1?baz=e&foo=REDACTED&foo=REDACTED&hash=e3b0c442"
	expected2 := "/path2?baz=g&foo=REDACTED&foo=REDACTED&hash=e3b0c442"
	if arr[0] != expected1 {
		t.Fatalf("query parameters in entry 0 have not been filtered correctly: got %s, expected %s", arr[0], expected1)
	}
	if arr[1] != expected2 {
		t.Fatalf("query parameters in entry 1 have not been filtered correctly: got %s, expected %s", arr[1], expected2)
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

func TestRegexpFilterSingleValue(t *testing.T) {
	f := RegexpFilter{RawRegexp: `secret`, Value: "REDACTED"}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{String: "foo-secret-bar"})
	if out.String != "foo-REDACTED-bar" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestRegexpFilterMultiValue(t *testing.T) {
	f := RegexpFilter{RawRegexp: `secret`, Value: "REDACTED"}
	f.Provision(caddy.Context{})

	out := f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{"foo-secret-bar", "bar-secret-foo"}})
	arr, ok := out.Interface.(caddyhttp.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "foo-REDACTED-bar" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "bar-REDACTED-foo" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestHashFilterSingleValue(t *testing.T) {
	f := HashFilter{}

	out := f.Filter(zapcore.Field{String: "foo"})
	if out.String != "2c26b46b" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestHashFilterMultiValue(t *testing.T) {
	f := HashFilter{}

	out := f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{"foo", "bar"}})
	arr, ok := out.Interface.(caddyhttp.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Integer)
	}
	if arr[0] != "2c26b46b" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "fcde2b2e" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}
