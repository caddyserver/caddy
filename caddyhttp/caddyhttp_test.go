package caddyhttp

import (
	"strings"
	"testing"

	"github.com/mholt/caddy"
)

// TODO: this test could be improved; the purpose is to
// ensure that the standard plugins are in fact plugged in
// and registered properly; this is a quick/naive way to do it.
func TestStandardPlugins(t *testing.T) {
	numStandardPlugins := 31 // importing caddyhttp plugs in this many plugins
	s := caddy.DescribePlugins()
	if got, want := strings.Count(s, "\n"), numStandardPlugins+5; got != want {
		t.Errorf("Expected all standard plugins to be plugged in, got:\n%s", s)
	}
}
