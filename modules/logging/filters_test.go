package logging

import (
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

func TestMultiRegexpFilterSingleOperation(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret`, Value: "REDACTED"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	out := f.Filter(zapcore.Field{String: "foo-secret-bar"})
	if out.String != "foo-REDACTED-bar" {
		t.Fatalf("field has not been filtered: %s", out.String)
	}
}

func TestMultiRegexpFilterMultipleOperations(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret`, Value: "REDACTED"},
			{RawRegexp: `password`, Value: "HIDDEN"},
			{RawRegexp: `token`, Value: "XXX"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	// Test sequential application
	out := f.Filter(zapcore.Field{String: "my-secret-password-token-data"})
	expected := "my-REDACTED-HIDDEN-XXX-data"
	if out.String != expected {
		t.Fatalf("field has not been filtered correctly: got %s, expected %s", out.String, expected)
	}
}

func TestMultiRegexpFilterMultiValue(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret`, Value: "REDACTED"},
			{RawRegexp: `\d+`, Value: "NUM"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	out := f.Filter(zapcore.Field{Interface: caddyhttp.LoggableStringArray{
		"foo-secret-123",
		"bar-secret-456",
	}})
	arr, ok := out.Interface.(caddyhttp.LoggableStringArray)
	if !ok {
		t.Fatalf("field is wrong type: %T", out.Interface)
	}
	if arr[0] != "foo-REDACTED-NUM" {
		t.Fatalf("field entry 0 has not been filtered: %s", arr[0])
	}
	if arr[1] != "bar-REDACTED-NUM" {
		t.Fatalf("field entry 1 has not been filtered: %s", arr[1])
	}
}

func TestMultiRegexpFilterAddOperation(t *testing.T) {
	f := MultiRegexpFilter{}
	err := f.AddOperation("secret", "REDACTED")
	if err != nil {
		t.Fatalf("unexpected error adding operation: %v", err)
	}
	err = f.AddOperation("password", "HIDDEN")
	if err != nil {
		t.Fatalf("unexpected error adding operation: %v", err)
	}
	err = f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	if len(f.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(f.Operations))
	}

	out := f.Filter(zapcore.Field{String: "my-secret-password"})
	expected := "my-REDACTED-HIDDEN"
	if out.String != expected {
		t.Fatalf("field has not been filtered correctly: got %s, expected %s", out.String, expected)
	}
}

func TestMultiRegexpFilterSecurityLimits(t *testing.T) {
	f := MultiRegexpFilter{}

	// Test maximum operations limit
	for i := 0; i < 51; i++ {
		err := f.AddOperation(fmt.Sprintf("pattern%d", i), "replacement")
		if i < 50 {
			if err != nil {
				t.Fatalf("unexpected error adding operation %d: %v", i, err)
			}
		} else {
			if err == nil {
				t.Fatalf("expected error when adding operation %d (exceeds limit)", i)
			}
		}
	}

	// Test empty pattern validation
	f2 := MultiRegexpFilter{}
	err := f2.AddOperation("", "replacement")
	if err == nil {
		t.Fatalf("expected error for empty pattern")
	}

	// Test pattern length limit
	f3 := MultiRegexpFilter{}
	longPattern := strings.Repeat("a", 1001)
	err = f3.AddOperation(longPattern, "replacement")
	if err == nil {
		t.Fatalf("expected error for pattern exceeding length limit")
	}
}

func TestMultiRegexpFilterValidation(t *testing.T) {
	// Test validation with empty operations
	f := MultiRegexpFilter{}
	err := f.Validate()
	if err == nil {
		t.Fatalf("expected validation error for empty operations")
	}

	// Test validation with valid operations
	err = f.AddOperation("valid", "replacement")
	if err != nil {
		t.Fatalf("unexpected error adding operation: %v", err)
	}
	err = f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}
	err = f.Validate()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestMultiRegexpFilterInputSizeLimit(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `test`, Value: "REPLACED"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	// Test with very large input (should be truncated)
	largeInput := strings.Repeat("test", 300000) // Creates ~1.2MB string
	out := f.Filter(zapcore.Field{String: largeInput})

	// The input should be truncated to 1MB and still processed
	if len(out.String) > 1000000 {
		t.Fatalf("output string not truncated: length %d", len(out.String))
	}

	// Should still contain replacements within the truncated portion
	if !strings.Contains(out.String, "REPLACED") {
		t.Fatalf("replacements not applied to truncated input")
	}
}

func TestMultiRegexpFilterOverlappingPatterns(t *testing.T) {
	f := MultiRegexpFilter{
		Operations: []regexpFilterOperation{
			{RawRegexp: `secret.*password`, Value: "SENSITIVE"},
			{RawRegexp: `password`, Value: "HIDDEN"},
		},
	}
	err := f.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("unexpected error provisioning: %v", err)
	}

	// The first pattern should match and replace the entire "secret...password" portion
	// Then the second pattern should not find "password" anymore since it was already replaced
	out := f.Filter(zapcore.Field{String: "my-secret-data-password-end"})
	expected := "my-SENSITIVE-end"
	if out.String != expected {
		t.Fatalf("field has not been filtered correctly: got %s, expected %s", out.String, expected)
	}
}
