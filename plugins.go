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
	"fmt"
	"log"
	"net"
	"sort"
	"sync"

	"github.com/mholt/caddy/caddyfile"
)

// These are all the registered plugins.
var (
	// serverTypes is a map of registered server types.
	serverTypes = make(map[string]ServerType)

	// plugins is a map of server type to map of plugin name to
	// Plugin. These are the "general" plugins that may or may
	// not be associated with a specific server type. If it's
	// applicable to multiple server types or the server type is
	// irrelevant, the key is empty string (""). But all plugins
	// must have a name.
	plugins = make(map[string]map[string]Plugin)

	// eventHooks is a map of hook name to Hook. All hooks plugins
	// must have a name.
	eventHooks = sync.Map{}

	// parsingCallbacks maps server type to map of directive
	// to list of callback functions. These aren't really
	// plugins on their own, but are often registered from
	// plugins.
	parsingCallbacks = make(map[string]map[string][]ParsingCallback)

	// caddyfileLoaders is the list of all Caddyfile loaders
	// in registration order.
	caddyfileLoaders []caddyfileLoader
)

// DescribePlugins returns a string describing the registered plugins.
func DescribePlugins() string {
	str := "Server types:\n"
	for name := range serverTypes {
		str += "  " + name + "\n"
	}

	// List the loaders in registration order
	str += "\nCaddyfile loaders:\n"
	for _, loader := range caddyfileLoaders {
		str += "  " + loader.name + "\n"
	}
	if defaultCaddyfileLoader.name != "" {
		str += "  " + defaultCaddyfileLoader.name + "\n"
	}

	// List the event hook plugins
	hooks := ""
	eventHooks.Range(func(k, _ interface{}) bool {
		hooks += "  hook." + k.(string) + "\n"
		return true
	})
	if hooks != "" {
		str += "\nEvent hook plugins:\n"
		str += hooks
	}

	// Let's alphabetize the rest of these...
	var others []string
	for stype, stypePlugins := range plugins {
		for name := range stypePlugins {
			var s string
			if stype != "" {
				s = stype + "."
			}
			s += name
			others = append(others, s)
		}
	}

	sort.Strings(others)
	str += "\nOther plugins:\n"
	for _, name := range others {
		str += "  " + name + "\n"
	}

	return str
}

// ValidDirectives returns the list of all directives that are
// recognized for the server type serverType. However, not all
// directives may be installed. This makes it possible to give
// more helpful error messages, like "did you mean ..." or
// "maybe you need to plug in ...".
func ValidDirectives(serverType string) []string {
	stype, err := getServerType(serverType)
	if err != nil {
		return nil
	}
	return stype.Directives()
}

// ServerListener pairs a server to its listener and/or packetconn.
type ServerListener struct {
	server   Server
	listener net.Listener
	packet   net.PacketConn
}

// LocalAddr returns the local network address of the packetconn. It returns
// nil when it is not set.
func (s ServerListener) LocalAddr() net.Addr {
	if s.packet == nil {
		return nil
	}
	return s.packet.LocalAddr()
}

// Addr returns the listener's network address. It returns nil when it is
// not set.
func (s ServerListener) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Context is a type which carries a server type through
// the load and setup phase; it maintains the state
// between loading the Caddyfile, then executing its
// directives, then making the servers for Caddy to
// manage. Typically, such state involves configuration
// structs, etc.
type Context interface {
	// Called after the Caddyfile is parsed into server
	// blocks but before the directives are executed,
	// this method gives you an opportunity to inspect
	// the server blocks and prepare for the execution
	// of directives. Return the server blocks (which
	// you may modify, if desired) and an error, if any.
	// The first argument is the name or path to the
	// configuration file (Caddyfile).
	//
	// This function can be a no-op and simply return its
	// input if there is nothing to do here.
	InspectServerBlocks(string, []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error)

	// This is what Caddy calls to make server instances.
	// By this time, all directives have been executed and,
	// presumably, the context has enough state to produce
	// server instances for Caddy to start.
	MakeServers() ([]Server, error)
}

// RegisterServerType registers a server type srv by its
// name, typeName.
func RegisterServerType(typeName string, srv ServerType) {
	if _, ok := serverTypes[typeName]; ok {
		panic("server type already registered")
	}
	serverTypes[typeName] = srv
}

// ServerType contains information about a server type.
type ServerType struct {
	// Function that returns the list of directives, in
	// execution order, that are valid for this server
	// type. Directives should be one word if possible
	// and lower-cased.
	Directives func() []string

	// DefaultInput returns a default config input if none
	// is otherwise loaded. This is optional, but highly
	// recommended, otherwise a blank Caddyfile will be
	// used.
	DefaultInput func() Input

	// The function that produces a new server type context.
	// This will be called when a new Caddyfile is being
	// loaded, parsed, and executed independently of any
	// startup phases before this one. It's a way to keep
	// each set of server instances separate and to reduce
	// the amount of global state you need.
	NewContext func(inst *Instance) Context
}

// Plugin is a type which holds information about a plugin.
type Plugin struct {
	// ServerType is the type of server this plugin is for.
	// Can be empty if not applicable, or if the plugin
	// can associate with any server type.
	ServerType string

	// Action is the plugin's setup function, if associated
	// with a directive in the Caddyfile.
	Action SetupFunc
}

// RegisterPlugin plugs in plugin. All plugins should register
// themselves, even if they do not perform an action associated
// with a directive. It is important for the process to know
// which plugins are available.
//
// The plugin MUST have a name: lower case and one word.
// If this plugin has an action, it must be the name of
// the directive that invokes it. A name is always required
// and must be unique for the server type.
func RegisterPlugin(name string, plugin Plugin) {
	if name == "" {
		panic("plugin must have a name")
	}
	if _, ok := plugins[plugin.ServerType]; !ok {
		plugins[plugin.ServerType] = make(map[string]Plugin)
	}
	if _, dup := plugins[plugin.ServerType][name]; dup {
		panic("plugin named " + name + " already registered for server type " + plugin.ServerType)
	}
	plugins[plugin.ServerType][name] = plugin
}

// EventName represents the name of an event used with event hooks.
type EventName string

// Define names for the various events
const (
	StartupEvent         EventName = "startup"
	ShutdownEvent        EventName = "shutdown"
	CertRenewEvent       EventName = "certrenew"
	InstanceStartupEvent EventName = "instancestartup"
)

// EventHook is a type which holds information about a startup hook plugin.
type EventHook func(eventType EventName, eventInfo interface{}) error

// RegisterEventHook plugs in hook. All the hooks should register themselves
// and they must have a name.
func RegisterEventHook(name string, hook EventHook) {
	if name == "" {
		panic("event hook must have a name")
	}
	_, dup := eventHooks.LoadOrStore(name, hook)
	if dup {
		panic("hook named " + name + " already registered")
	}
}

// EmitEvent executes the different hooks passing the EventType as an
// argument. This is a blocking function. Hook developers should
// use 'go' keyword if they don't want to block Caddy.
func EmitEvent(event EventName, info interface{}) {
	eventHooks.Range(func(k, v interface{}) bool {
		err := v.(EventHook)(event, info)
		if err != nil {
			log.Printf("error on '%s' hook: %v", k.(string), err)
		}
		return true
	})
}

// ParsingCallback is a function that is called after
// a directive's setup functions have been executed
// for all the server blocks.
type ParsingCallback func(Context) error

// RegisterParsingCallback registers callback to be called after
// executing the directive afterDir for server type serverType.
func RegisterParsingCallback(serverType, afterDir string, callback ParsingCallback) {
	if _, ok := parsingCallbacks[serverType]; !ok {
		parsingCallbacks[serverType] = make(map[string][]ParsingCallback)
	}
	parsingCallbacks[serverType][afterDir] = append(parsingCallbacks[serverType][afterDir], callback)
}

// SetupFunc is used to set up a plugin, or in other words,
// execute a directive. It will be called once per key for
// each server block it appears in.
type SetupFunc func(c *Controller) error

// DirectiveAction gets the action for directive dir of
// server type serverType.
func DirectiveAction(serverType, dir string) (SetupFunc, error) {
	if stypePlugins, ok := plugins[serverType]; ok {
		if plugin, ok := stypePlugins[dir]; ok {
			return plugin.Action, nil
		}
	}
	if genericPlugins, ok := plugins[""]; ok {
		if plugin, ok := genericPlugins[dir]; ok {
			return plugin.Action, nil
		}
	}
	return nil, fmt.Errorf("no action found for directive '%s' with server type '%s' (missing a plugin?)",
		dir, serverType)
}

// Loader is a type that can load a Caddyfile.
// It is passed the name of the server type.
// It returns an error only if something went
// wrong, not simply if there is no Caddyfile
// for this loader to load.
//
// A Loader should only load the Caddyfile if
// a certain condition or requirement is met,
// as returning a non-nil Input value along with
// another Loader will result in an error.
// In other words, loading the Caddyfile must
// be deliberate & deterministic, not haphazard.
//
// The exception is the default Caddyfile loader,
// which will be called only if no other Caddyfile
// loaders return a non-nil Input. The default
// loader may always return an Input value.
type Loader interface {
	Load(serverType string) (Input, error)
}

// LoaderFunc is a convenience type similar to http.HandlerFunc
// that allows you to use a plain function as a Load() method.
type LoaderFunc func(serverType string) (Input, error)

// Load loads a Caddyfile.
func (lf LoaderFunc) Load(serverType string) (Input, error) {
	return lf(serverType)
}

// RegisterCaddyfileLoader registers loader named name.
func RegisterCaddyfileLoader(name string, loader Loader) {
	caddyfileLoaders = append(caddyfileLoaders, caddyfileLoader{name: name, loader: loader})
}

// SetDefaultCaddyfileLoader registers loader by name
// as the default Caddyfile loader if no others produce
// a Caddyfile. If another Caddyfile loader has already
// been set as the default, this replaces it.
//
// Do not call RegisterCaddyfileLoader on the same
// loader; that would be redundant.
func SetDefaultCaddyfileLoader(name string, loader Loader) {
	defaultCaddyfileLoader = caddyfileLoader{name: name, loader: loader}
}

// loadCaddyfileInput iterates the registered Caddyfile loaders
// and, if needed, calls the default loader, to load a Caddyfile.
// It is an error if any of the loaders return an error or if
// more than one loader returns a Caddyfile.
func loadCaddyfileInput(serverType string) (Input, error) {
	var loadedBy string
	var caddyfileToUse Input
	for _, l := range caddyfileLoaders {
		cdyfile, err := l.loader.Load(serverType)
		if err != nil {
			return nil, fmt.Errorf("loading Caddyfile via %s: %v", l.name, err)
		}
		if cdyfile != nil {
			if caddyfileToUse != nil {
				return nil, fmt.Errorf("Caddyfile loaded multiple times; first by %s, then by %s", loadedBy, l.name)
			}
			loaderUsed = l
			caddyfileToUse = cdyfile
			loadedBy = l.name
		}
	}
	if caddyfileToUse == nil && defaultCaddyfileLoader.loader != nil {
		cdyfile, err := defaultCaddyfileLoader.loader.Load(serverType)
		if err != nil {
			return nil, err
		}
		if cdyfile != nil {
			loaderUsed = defaultCaddyfileLoader
			caddyfileToUse = cdyfile
		}
	}
	return caddyfileToUse, nil
}

// OnProcessExit is a list of functions to run when the process
// exits -- they are ONLY for cleanup and should not block,
// return errors, or do anything fancy. They will be run with
// every signal, even if "shutdown callbacks" are not executed.
// This variable must only be modified in the main goroutine
// from init() functions.
var OnProcessExit []func()

// caddyfileLoader pairs the name of a loader to the loader.
type caddyfileLoader struct {
	name   string
	loader Loader
}

var (
	defaultCaddyfileLoader caddyfileLoader // the default loader if all else fail
	loaderUsed             caddyfileLoader // the loader that was used (relevant for reloads)
)
