package awslambda

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestSetup(t *testing.T) {
	input := "awslambda /foo"
	c := caddy.NewTestController("http", input)
	err := setup(c)
	if err != nil {
		t.Errorf("setup() returned err: %v", err)
	}

	mids := httpserver.GetConfig(c).Middleware()
	mid := mids[len(mids)-1]
	handler := mid(nil).(Handler)

	expected := []*Config{
		&Config{
			Path:    "/foo",
			Include: []string{},
			Exclude: []string{},
		},
	}
	handler.Configs[0].invoker = nil
	eqOrErr(expected, handler.Configs, 0, t)
}
