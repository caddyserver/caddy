package push

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type (
	// Rule describes conditions on which resources will be pushed
	Rule struct {
		Path      string
		Resources []Resource
	}

	// Resource describes resource to be pushed
	Resource struct {
		Path   string
		Method string
		Header http.Header
	}

	// Middleware supports pushing resources to clients
	Middleware struct {
		Next  httpserver.Handler
		Rules []Rule
		Root  http.FileSystem
	}

	ruleOp func([]Resource)
)
