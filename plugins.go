package caddy

import (
	"fmt"
	"net"

	"github.com/mholt/caddy2/caddyfile"
)

// Directive has a name and a package import path.
// The package path is required for performing
// custom builds of Caddy.
type Directive struct {
	Name, Package string
}

// ValidDirectives returns the list of all directives that are
// recognized for the server type serverType. However, not all
// directives may be installed. This makes it possible to give
// more helpful error messages, like "did you mean ..." or
// "maybe you need to plug in ...".
func ValidDirectives(serverType string) []string {
	var dirs []string
	stype, err := getServerType(serverType)
	if err != nil {
		return dirs
	}
	for _, d := range stype.Directives {
		dirs = append(dirs, d.Name)
	}
	return dirs
}

// serverListener pairs a server to its listener.
type serverListener struct {
	server   Server
	listener net.Listener
}

// Context is a type that carries a server type through
// the load and setup phase; it maintains the state
// between loading the Caddyfile, then executing its
// directives, then making the servers for Caddy to
// manage. Typically, such state involves configuration
// structs, etc.
type Context interface {
	InspectServerBlocks(string, []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error)
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

// serverTypes is a map of registered server types.
var serverTypes = make(map[string]ServerType)

// ServerType contains information about a server type.
type ServerType struct {
	// List of directives, in execution order, that are
	// valid for this server type.
	Directives []Directive

	// InspectServerBlocks is an optional callback that is
	// executed after loading the tokens for each server
	// block but before executing the directives in them.
	// This func may modify the server blocks and return
	// new ones to be used.
	InspectServerBlocks func(sourceFile string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error)

	// MakeServers is a callback that makes the server
	// instances.
	MakeServers func() ([]Server, error)

	// DefaultInput returns a default config input if none
	// is otherwise loaded.
	DefaultInput func() Input

	NewContext func() Context
}

// plugins is a map of server type to map of plugin name to Plugin.
var plugins = make(map[string]map[string]Plugin)

// Plugin is a type which holds information about a plugin.
type Plugin struct {
	// The plugin must have a name: lower case and one word.
	// If this plugin has an action, it must be the name of
	// the directive to attach to. A name is always required.
	Name string

	// ServerType is the type of server this plugin is for.
	// Can be empty if not associated with any particular
	// server type.
	ServerType string

	// Action is the plugin's setup function, if associated
	// with a directive in the Caddyfile.
	Action SetupFunc
}

// RegisterPlugin plugs in plugin.
func RegisterPlugin(plugin Plugin) {
	if plugin.Name == "" {
		panic("plugin must have a name")
	}

	if _, ok := plugins[plugin.ServerType]; !ok {
		plugins[plugin.ServerType] = make(map[string]Plugin)
	}
	if _, dup := plugins[plugin.ServerType][plugin.Name]; dup {
		panic("plugin named " + plugin.Name + " already registered for server type " + plugin.ServerType)
	}
	plugins[plugin.ServerType][plugin.Name] = plugin
}

// parsingCallbacks maps server type to map of directive to list of callback functions.
var parsingCallbacks = make(map[string]map[string][]func() error)

// RegisterParsingCallback registers callback to be called after
// executing the directive afterDir for server type serverType.
func RegisterParsingCallback(serverType, afterDir string, callback func() error) {
	if _, ok := parsingCallbacks[serverType]; !ok {
		parsingCallbacks[serverType] = make(map[string][]func() error)
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
	return nil, fmt.Errorf("no action found for directive '%s' with server type '%s'",
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
// loaders returned a non-nil Input. The default
// loader may always return an Input value.
type Loader interface {
	Load(string) (Input, error)
}

// LoaderFunc is a convenience type similar to http.HandlerFunc
// that allows you to use a plain function as a Load() method.
type LoaderFunc func(string) (Input, error)

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
		if cdyfile, err := l.loader.Load(serverType); cdyfile != nil {
			if caddyfileToUse != nil {
				return nil, fmt.Errorf("Caddyfile loaded multiple times; first by %s, then by %s", loadedBy, l.name)
			}
			if err != nil {
				return nil, err
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

// caddyfileLoader pairs the name of a loader to the loader.
type caddyfileLoader struct {
	name   string
	loader Loader
}

var (
	caddyfileLoaders       []caddyfileLoader // all loaders in registration order
	defaultCaddyfileLoader caddyfileLoader   // the default loader if all else fail
	loaderUsed             caddyfileLoader   // the loader that was used (relevant for reloads)
)
