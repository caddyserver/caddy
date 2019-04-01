package staticfiles

import (
	"net/http"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.static_files",
		New:  func() (interface{}, error) { return &StaticFiles{}, nil },
	})
}

// StaticFiles implements a static file server responder for Caddy.
type StaticFiles struct {
	Root string
}

func (sf StaticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	http.FileServer(http.Dir(sf.Root)).ServeHTTP(w, r)
	return nil
}

// Interface guard
var _ caddyhttp.Handler = StaticFiles{}
