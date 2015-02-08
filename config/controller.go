package config

// controller is a dispenser of tokens and also
// facilitates setup with the server by providing
// access to its configuration. It implements
// the middleware.Controller interface.
type controller struct {
	dispenser
	parser *parser
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

// Root returns the server root file path.
func (c *controller) Root() string {
	if c.parser.cfg.Root == "" {
		return "."
	} else {
		return c.parser.cfg.Root
	}
}

// Host returns the hostname the server is bound to.
func (c *controller) Host() string {
	return c.parser.cfg.Host
}

// Port returns the port that the server is listening on.
func (c *controller) Port() string {
	return c.parser.cfg.Port
}
