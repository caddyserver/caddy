package caddy

import (
	"strings"

	"github.com/mholt/caddy/caddyfile"
)

// Controller is given to the setup function of directives which
// gives them access to be able to read tokens and do whatever
// they need to do.
type Controller struct {
	caddyfile.Dispenser

	// The instance in which the setup is occurring
	instance *Instance

	// Key is the key from the top of the server block, usually
	// an address, hostname, or identifier of some sort.
	Key string

	// OncePerServerBlock is a function that executes f
	// exactly once per server block, no matter how many
	// hosts are associated with it. If it is the first
	// time, the function f is executed immediately
	// (not deferred) and may return an error which is
	// returned by OncePerServerBlock.
	OncePerServerBlock func(f func() error) error

	// ServerBlockIndex is the 0-based index of the
	// server block as it appeared in the input.
	ServerBlockIndex int

	// ServerBlockKeyIndex is the 0-based index of this
	// key as it appeared in the input at the head of the
	// server block.
	ServerBlockKeyIndex int

	// ServerBlockKeys is a list of keys that are
	// associated with this server block. All these
	// keys, consequently, share the same tokens.
	ServerBlockKeys []string

	// ServerBlockStorage is used by a directive's
	// setup function to persist state between all
	// the keys on a server block.
	ServerBlockStorage interface{}
}

// ServerType gets the name of the server type that is being set up.
func (c *Controller) ServerType() string {
	return c.instance.serverType
}

// OnStartup adds fn to the list of callback functions to execute
// when the server is about to be started.
func (c *Controller) OnStartup(fn func() error) {
	c.instance.onStartup = append(c.instance.onStartup, fn)
}

// OnRestart adds fn to the list of callback functions to execute
// when the server is about to be restarted.
func (c *Controller) OnRestart(fn func() error) {
	c.instance.onRestart = append(c.instance.onRestart, fn)
}

// OnShutdown adds fn to the list of callback functions to execute
// when the server is about to be shut down..
func (c *Controller) OnShutdown(fn func() error) {
	c.instance.onShutdown = append(c.instance.onShutdown, fn)
}

// Context gets the context associated with the instance associated with c.
func (c *Controller) Context() Context {
	return c.instance.context
}

// NewTestController creates a new Controller for
// the input specified, with a filename of "Testfile".
// The Config is bare, consisting only of a Root of cwd.
//
// Used primarily for testing but needs to be exported so
// add-ons can use this as a convenience. Does not initialize
// the server-block-related fields.
func NewTestController(serverType, input string) *Controller {
	stype, _ := getServerType(serverType)
	return &Controller{
		instance:           &Instance{serverType: serverType, context: stype.NewContext()},
		Dispenser:          caddyfile.NewDispenser("Testfile", strings.NewReader(input)),
		OncePerServerBlock: func(f func() error) error { return f() },
	}
}
