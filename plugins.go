package caddy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/mholt/caddy2/caddyfile"
)

// TODO: We could probably just make a single map[string]ServerTypeInfo
// where ServerTypeInfo contains plugins, parsing callbacks, etc...

type Directive struct {
	Name, Package string
}

// ValidDirectives returns the list of all directives that are
// recognized. However, not all directives may be installed.
// This makes it possible to give more helpful error messages,
// like "did you mean ..." or "maybe you need to plug in ..."
// TODO: Limit this to a particular server type...?
func ValidDirectives() []string {
	var dirs []string
	for _, st := range serverTypes {
		for _, d := range st.Directives {
			dirs = append(dirs, d.Name)
		}
	}
	return dirs
}

// serverTypes is a map of registered server types.
var serverTypes = make(map[string]ServerType)

// serverListener pairs a
// server to its listener.
type serverListener struct {
	server   Server
	listener net.Listener
}

// servers is the list of servers we know to be running.
var servers []serverListener

// serversMu protects the servers slice during changes
var serversMu sync.Mutex

func SaveServer(s Server, ln net.Listener) {
	serversMu.Lock()
	servers = append(servers, serverListener{server: s, listener: ln})
	serversMu.Unlock()
}

func AddServerType(typeName string, srv ServerType) {
	if _, ok := serverTypes[typeName]; ok {
		panic("server type already registered")
	}
	if srv.MakeServers == nil {
		panic("MakeServers function is required")
	}
	serverTypes[typeName] = srv
}

type ServerType struct {
	Directives          []Directive
	InspectServerBlocks func(sourceFile string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error)
	MakeServers         func() ([]Server, error)
	DefaultInput        func() Input
}

// plugins is a map of server type to map of plugin name to Plugin.
var plugins = make(map[string]map[string]Plugin)

// Plugin is a type which holds information about a plugin.
type Plugin struct {
	// The plugin must have a name: lower case and one word.
	// If this plugin has an Action, it must be the name of
	// the directive to attach to. A name is always required.
	Name string

	// ServerType is the type of server this plugin is for.
	// Can be empty if not associated with any particular
	// server type.
	ServerType string

	// Action is the plugin's setup function, if associated
	// with a directive in the Caddyfile.
	Action SetupFunc

	// CaddyfileLoader is a function that loads the contents of
	// the Caddyfile
	//CaddyfileLoader func() ([]byte, error)

	// TODO...
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func RegisterPlugin(plugin Plugin) {
	if plugin.Name == "" {
		panic("plugin must have a name")
	}

	// TODO
	// if plugin.GetCertificate != nil {
	// 	getCertificates = append(getCertificates, plugin.GetCertificate)
	// }

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

func ParsingCallback(serverType, afterDir string, callback func() error) {
	if _, ok := parsingCallbacks[serverType]; !ok {
		parsingCallbacks[serverType] = make(map[string][]func() error)
	}
	parsingCallbacks[serverType][afterDir] = append(parsingCallbacks[serverType][afterDir], callback)
}

// SetupFunc is used to set up a plugin, or in other words,
// execute a directive. It will be called once per key for
// each server block it appears in.
type SetupFunc func(c *Controller) error

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

type caddyfileLoader struct {
	name   string
	loader Loader
}

var caddyfileLoaders []caddyfileLoader

var loaderUsed caddyfileLoader

//var loaderMu sync.Mutex //TODO: NEEDED? to protect usedCaddyfileLoader

type Loader interface {
	Load() (Input, error)
}

func AddCaddyfileLoader(name string, loader Loader) {
	caddyfileLoaders = append(caddyfileLoaders, caddyfileLoader{name: name, loader: loader})
}

func loadCaddyfileInput() (Input, error) {
	var loadedBy string
	var caddyfileToUse Input
	for _, l := range caddyfileLoaders {
		if cdyfile, err := l.loader.Load(); cdyfile != nil {
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
	return caddyfileToUse, nil
}
