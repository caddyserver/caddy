package starlarkmw

import (
	"context"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/starlarkmw/internal/lib"
	caddyscript "github.com/caddyserver/caddy/v2/pkg/caddyscript/lib"
	"github.com/starlight-go/starlight/convert"
	"go.starlark.net/starlark"
)

func init() {
	caddy.RegisterModule(StarlarkMW{})
}

// StarlarkMW represents a middleware responder written in starlark
type StarlarkMW struct {
	Script         string `json:"script"`
	serveHTTP      *starlark.Function
	setup          *starlark.Function
	thread         *starlark.Thread
	loadMiddleware *lib.LoadMiddleware
	execute        *lib.Execute
	globals        *starlark.StringDict
	gctx           caddy.Context
	rctx           caddy.Context
	rcancel        context.CancelFunc
}

// CaddyModule returns the Caddy module information.
func (StarlarkMW) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.starlark",
		New: func() caddy.Module { return new(StarlarkMW) },
	}
}

// ServeHTTP responds to an http request with starlark.
func (s *StarlarkMW) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	var mwcancel context.CancelFunc
	var mwctx caddy.Context

	// call setup() to prepare the middleware chain if it is defined
	if s.setup != nil {
		mwctx, mwcancel = caddy.NewContext(s.gctx)
		defer mwcancel()

		s.loadMiddleware.Ctx = mwctx
		args := starlark.Tuple{caddyscript.HTTPRequest{Req: r}}

		_, err := starlark.Call(new(starlark.Thread), s.setup, args, nil)
		if err != nil {
			return fmt.Errorf("starlark setup(), %v", err)
		}
	}

	// dynamically build middleware chain for each request
	stack := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		wr, err := convert.ToValue(w)
		if err != nil {
			return fmt.Errorf("cannot convert response writer to starlark value")
		}

		args := starlark.Tuple{wr, caddyscript.HTTPRequest{Req: r}}
		v, err := starlark.Call(new(starlark.Thread), s.serveHTTP, args, nil)
		if err != nil {
			return fmt.Errorf("starlark serveHTTP(), %v", err)
		}

		// if a responder type was returned from starlark we should run it otherwise it
		// is expected to handle the request
		if resp, ok := v.(lib.ResponderModule); ok {
			return resp.Instance.ServeHTTP(w, r)
		}

		return nil
	})

	// TODO :- make middlewareResponseWriter exported and wrap w with that
	var mid []caddyhttp.Middleware
	for _, m := range s.execute.Modules {
		mid = append(mid, func(next caddyhttp.HandlerFunc) caddyhttp.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) error {
				return m.Instance.ServeHTTP(w, r, next)
			}
		})
	}

	for i := len(mid) - 1; i >= 0; i-- {
		stack = mid[i](stack)
	}

	s.execute.Modules = nil

	return stack(w, r)
}

// Cleanup cleans up any modules loaded during the creation of a starlark route.
func (s *StarlarkMW) Cleanup() error {
	s.rcancel()
	return nil
}

// Provision sets up the starlark env.
func (s *StarlarkMW) Provision(ctx caddy.Context) error {
	// store global context
	s.gctx = ctx

	// setup context for cleaning up any modules loaded during starlark script parsing phase
	rctx, cancel := caddy.NewContext(ctx)
	s.rcancel = cancel

	// setup starlark global env
	env := make(starlark.StringDict)
	loadMiddleware := lib.LoadMiddleware{}
	loadResponder := lib.LoadResponder{
		Ctx: rctx,
	}
	execute := lib.Execute{}

	lr := starlark.NewBuiltin("loadResponder", loadResponder.Run)
	lr = lr.BindReceiver(&loadResponder)
	env["loadResponder"] = lr

	lm := starlark.NewBuiltin("loadMiddleware", loadMiddleware.Run)
	lm = lm.BindReceiver(&loadMiddleware)
	env["loadMiddleware"] = lm

	ex := starlark.NewBuiltin("execute", execute.Run)
	ex = ex.BindReceiver(&execute)
	env["execute"] = ex

	// import caddyscript lib
	env["time"] = caddyscript.Time{}
	env["regexp"] = caddyscript.Regexp{}

	// configure starlark
	thread := new(starlark.Thread)
	s.thread = thread

	// run starlark script
	globals, err := starlark.ExecFile(thread, "", s.Script, env)
	if err != nil {
		return fmt.Errorf("starlark exec file: %v", err.Error())
	}

	// extract defined methods to setup middleware chain and responder, setup is not required
	var setup *starlark.Function
	if _, ok := globals["setup"]; ok {
		setup, ok = globals["setup"].(*starlark.Function)
		if !ok {
			return fmt.Errorf("setup function not defined in starlark script")
		}
	}

	serveHTTP, ok := globals["serveHTTP"].(*starlark.Function)
	if !ok {
		return fmt.Errorf("serveHTTP function not defined in starlark script")
	}

	s.setup = setup
	s.serveHTTP = serveHTTP
	s.loadMiddleware = &loadMiddleware
	s.execute = &execute
	s.globals = &globals

	return nil
}
