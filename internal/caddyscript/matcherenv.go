package caddyscript

import (
	"net/http"

	caddyscript "bitbucket.org/lightcodelabs/caddy2/internal/caddyscript/lib"
	"go.starlark.net/starlark"
)

// MatcherEnv sets up the global context for the matcher caddyscript environment.
func MatcherEnv(r *http.Request) starlark.StringDict {
	env := make(starlark.StringDict)
	env["req"] = caddyscript.HTTPRequest{Req: r}
	env["time"] = caddyscript.Time{}
	env["regexp"] = caddyscript.Regexp{}

	return env
}
