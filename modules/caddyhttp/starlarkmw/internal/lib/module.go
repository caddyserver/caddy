package lib

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/caddyserver/caddy/v2"
	"go.starlark.net/starlark"
)

// ResponderModule represents a module that satisfies the caddyhttp handler.
type ResponderModule struct {
	Name     string
	Cfg      json.RawMessage
	Instance caddyhttp.Handler
}

func (r ResponderModule) Freeze()               {}
func (r ResponderModule) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: responder module") }
func (r ResponderModule) String() string        { return "responder module" }
func (r ResponderModule) Type() string          { return "responder module" }
func (r ResponderModule) Truth() starlark.Bool  { return true }

// Middleware represents a module that satisfies the starlark Value interface.
type Middleware struct {
	Name     string
	Cfg      json.RawMessage
	Instance caddyhttp.MiddlewareHandler
}

func (r Middleware) Freeze()               {}
func (r Middleware) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: middleware") }
func (r Middleware) String() string        { return "middleware" }
func (r Middleware) Type() string          { return "middleware" }
func (r Middleware) Truth() starlark.Bool  { return true }

// LoadMiddleware represents the method exposed to starlark to load a Caddy module.
type LoadMiddleware struct {
	Middleware Middleware
	Ctx        caddy.Context
}

func (r LoadMiddleware) Freeze()               {}
func (r LoadMiddleware) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: loadMiddleware") }
func (r LoadMiddleware) String() string        { return "loadMiddleware" }
func (r LoadMiddleware) Type() string          { return "function: loadMiddleware" }
func (r LoadMiddleware) Truth() starlark.Bool  { return true }

// Run is the method bound to the starlark loadMiddleware function.
func (r *LoadMiddleware) Run(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var cfg *starlark.Dict
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &name, &cfg)
	if err != nil {
		return starlark.None, fmt.Errorf("unpacking arguments: %v", err.Error())
	}

	js := json.RawMessage(cfg.String())

	if strings.Index(name, "http.handlers.") == -1 {
		name = fmt.Sprintf("http.handlers.%s", name)
	}

	inst, err := r.Ctx.LoadModuleByID(name, js)
	if err != nil {
		return starlark.None, err
	}

	mid, ok := inst.(caddyhttp.MiddlewareHandler)
	if !ok {
		return starlark.None, fmt.Errorf("could not assert as middleware handler")
	}

	m := Middleware{
		Name:     name,
		Cfg:      js,
		Instance: mid,
	}

	r.Middleware = m

	return m, nil
}

// LoadResponder represents the method exposed to starlark to load a Caddy middleware responder.
type LoadResponder struct {
	Module ResponderModule
	Ctx    caddy.Context
}

func (r LoadResponder) Freeze()               {}
func (r LoadResponder) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: loadModule") }
func (r LoadResponder) String() string        { return "loadModule" }
func (r LoadResponder) Type() string          { return "function: loadModule" }
func (r LoadResponder) Truth() starlark.Bool  { return true }

// Run is the method bound to the starlark loadResponder function.
func (r *LoadResponder) Run(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var cfg *starlark.Dict
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &name, &cfg)
	if err != nil {
		return starlark.None, fmt.Errorf("unpacking arguments: %v", err.Error())
	}

	js := json.RawMessage(cfg.String())

	if strings.Index(name, "http.handlers.") == -1 {
		name = fmt.Sprintf("http.handlers.%s", name)
	}

	inst, err := r.Ctx.LoadModuleByID(name, js)
	if err != nil {
		return starlark.None, err
	}

	res, ok := inst.(caddyhttp.Handler)
	if !ok {
		return starlark.None, fmt.Errorf("could not assert as responder")
	}

	m := ResponderModule{
		Name:     name,
		Cfg:      js,
		Instance: res,
	}

	r.Module = m

	return m, nil
}

// Execute represents the method exposed to starlark to build a middleware chain.
type Execute struct {
	Modules []Middleware
}

func (r Execute) Freeze()               {}
func (r Execute) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: execute") }
func (r Execute) String() string        { return "execute" }
func (r Execute) Type() string          { return "function: execute" }
func (r Execute) Truth() starlark.Bool  { return true }

// Run is the method bound to the starlark execute function.
func (r *Execute) Run(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var mids *starlark.List
	err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &mids)
	if err != nil {
		return starlark.None, fmt.Errorf("unpacking arguments: %v", err.Error())
	}

	for i := 0; i < mids.Len(); i++ {
		val, ok := mids.Index(i).(Middleware)
		if !ok {
			return starlark.None, fmt.Errorf("cannot get module from execute")
		}

		r.Modules = append(r.Modules, val)
	}

	return starlark.None, nil
}
