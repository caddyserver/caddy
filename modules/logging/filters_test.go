package logging

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestQueryFilter(t *testing.T) {
	f := QueryFilter{[]queryFilterAction{
		{ReplaceType, "foo", "REDACTED"},
		{DeleteType, "bar", ""},
	}}

	out := f.Filter(zapcore.Field{String: "/path?foo=a&foo=b&bar=c&bar=d&baz=e"})
	if out.String != "/path?baz=e&foo=REDACTED" {
		t.Fatalf("query parameters have not been filtered: %s", out.String)
	}
}
