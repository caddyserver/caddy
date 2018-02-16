// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"strings"

	"github.com/mholt/caddy/caddyfile"
)

// Controller is given to the setup function of directives which
// gives them access to be able to read tokens with which to
// configure themselves. It also stores state for the setup
// functions, can get the current context, and can be used to
// identify a particular server block using the Key field.
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

// OnFirstStartup adds fn to the list of callback functions to execute
// when the server is about to be started NOT as part of a restart.
func (c *Controller) OnFirstStartup(fn func() error) {
	c.instance.onFirstStartup = append(c.instance.onFirstStartup, fn)
}

// OnStartup adds fn to the list of callback functions to execute
// when the server is about to be started (including restarts).
func (c *Controller) OnStartup(fn func() error) {
	c.instance.onStartup = append(c.instance.onStartup, fn)
}

// OnRestart adds fn to the list of callback functions to execute
// when the server is about to be restarted.
func (c *Controller) OnRestart(fn func() error) {
	c.instance.onRestart = append(c.instance.onRestart, fn)
}

// OnShutdown adds fn to the list of callback functions to execute
// when the server is about to be shut down (including restarts).
func (c *Controller) OnShutdown(fn func() error) {
	c.instance.onShutdown = append(c.instance.onShutdown, fn)
}

// OnFinalShutdown adds fn to the list of callback functions to execute
// when the server is about to be shut down NOT as part of a restart.
func (c *Controller) OnFinalShutdown(fn func() error) {
	c.instance.onFinalShutdown = append(c.instance.onFinalShutdown, fn)
}

// Context gets the context associated with the instance associated with c.
func (c *Controller) Context() Context {
	return c.instance.context
}

// Get safely gets a value from the Instance's storage.
func (c *Controller) Get(key interface{}) interface{} {
	c.instance.StorageMu.RLock()
	defer c.instance.StorageMu.RUnlock()
	return c.instance.Storage[key]
}

// Set safely sets a value on the Instance's storage.
func (c *Controller) Set(key, val interface{}) {
	c.instance.StorageMu.Lock()
	c.instance.Storage[key] = val
	c.instance.StorageMu.Unlock()
}

// NewTestController creates a new Controller for
// the server type and input specified. The filename
// is "Testfile". If the server type is not empty and
// is plugged in, a context will be created so that
// the results of setup functions can be checked for
// correctness.
//
// Used only for testing, but exported so plugins can
// use this for convenience.
func NewTestController(serverType, input string) *Controller {
	testInst := &Instance{serverType: serverType, Storage: make(map[interface{}]interface{})}
	if stype, err := getServerType(serverType); err == nil {
		testInst.context = stype.NewContext(testInst)
	}
	return &Controller{
		instance:           testInst,
		Dispenser:          caddyfile.NewDispenser("Testfile", strings.NewReader(input)),
		OncePerServerBlock: func(f func() error) error { return f() },
	}
}
