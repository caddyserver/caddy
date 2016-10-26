package push

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type Middleware struct {
	Next  httpserver.Handler
	Rules []Rule
}

type (
	Rule struct {
		Path     string
		Resource PushResource
	}

	PushResource struct {
		Path   string
		Method string
		Header http.Header
	}
)
