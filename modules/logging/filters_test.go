package logging

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestQueryFilter(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{ReplaceType, "foo", "REDACTED"},
		{ReplaceType, "notexist", "REDACTED"},
		{DeleteType, "bar", ""},
		{DeleteType, "notexist", ""},
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
