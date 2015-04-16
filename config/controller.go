package config

import "github.com/mholt/caddy/middleware"

// controller is a dispenser of tokens and also
// facilitates setup with the server by providing
// access to its configuration. It implements
// the middleware.Controller interface.
type controller struct {
	dispenser
	parser    *parser
	pathScope string
}

// newController returns a new controller.
func newController(p *parser) *controller {
	return &controller{
		dispenser: dispenser{
			cursor:   -1,
			filename: p.filename,
		},
		parser: p,
	}
}

// Startup registers a function to execute when the server starts.
func (c *controller) Startup(fn func() error) {
	c.parser.cfg.Startup = append(c.parser.cfg.Startup, fn)
}

// Shutdown registers a function to execute when the server exits.
func (c *controller) Shutdown(fn func() error) {
	c.parser.cfg.Shutdown = append(c.parser.cfg.Shutdown, fn)
}

// Root returns the server root file path.
func (c *controller) Root() string {
	if c.parser.cfg.Root == "" {
		return "."
	} else {
		return c.parser.cfg.Root
	}
}

// Context returns the path scope that the Controller is in.
func (c *controller) Context() middleware.Path {
	return middleware.Path(c.pathScope)
}
