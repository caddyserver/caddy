package caddy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/mholt/caddy/caddy/https"
	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/server"
)

const (
	// DefaultConfigFile is the name of the configuration file that is loaded
	// by default if no other file is specified.
	DefaultConfigFile = "Caddyfile"
)

// loadConfigsUpToIncludingTLS loads the configs from input with name filename and returns them,
// the parsed server blocks, the index of the last directive it processed, and an error (if any).
func loadConfigsUpToIncludingTLS(filename string, input io.Reader) ([]server.Config, []parse.ServerBlock, int, error) {
	var configs []server.Config

	// Each server block represents similar hosts/addresses, since they
	// were grouped together in the Caddyfile.
	serverBlocks, err := parse.ServerBlocks(filename, input, true)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(serverBlocks) == 0 {
		newInput := DefaultInput()
		serverBlocks, err = parse.ServerBlocks(newInput.Path(), bytes.NewReader(newInput.Body()), true)
		if err != nil {
			return nil, nil, 0, err
		}
	}

	var lastDirectiveIndex int // we set up directives in two parts; this stores where we left off

	// Iterate each server block and make a config for each one,
	// executing the directives that were parsed in order up to the tls
	// directive; this is because we must activate Let's Encrypt.
	for i, sb := range serverBlocks {
		onces := makeOnces()
		storages := makeStorages()

		for j, addr := range sb.Addresses {
			config := server.Config{
				Host:       addr.Host,
				Port:       addr.Port,
				Scheme:     addr.Scheme,
				Root:       Root,
				ConfigFile: filename,
				AppName:    AppName,
				AppVersion: AppVersion,
			}

			// It is crucial that directives are executed in the proper order.
			for k, dir := range directiveOrder {
				// Execute directive if it is in the server block
				if tokens, ok := sb.Tokens[dir.name]; ok {
					// Each setup function gets a controller, from which setup functions
					// get access to the config, tokens, and other state information useful
					// to set up its own host only.
					controller := &setup.Controller{
						Config:    &config,
						Dispenser: parse.NewDispenserTokens(filename, tokens),
						OncePerServerBlock: func(f func() error) error {
							var err error
							onces[dir.name].Do(func() {
								err = f()
							})
							return err
						},
						ServerBlockIndex:     i,
						ServerBlockHostIndex: j,
						ServerBlockHosts:     sb.HostList(),
						ServerBlockStorage:   storages[dir.name],
					}
					// execute setup function and append middleware handler, if any
					midware, err := dir.setup(controller)
					if err != nil {
						return nil, nil, lastDirectiveIndex, err
					}
					if midware != nil {
						config.Middleware = append(config.Middleware, midware)
					}
					storages[dir.name] = controller.ServerBlockStorage // persist for this server block
				}

				// Stop after TLS setup, since we need to activate Let's Encrypt before continuing;
				// it makes some changes to the configs that middlewares might want to know about.
				if dir.name == "tls" {
					lastDirectiveIndex = k
					break
				}
			}

			configs = append(configs, config)
		}
	}

	return configs, serverBlocks, lastDirectiveIndex, nil
}

// loadConfigs reads input (named filename) and parses it, returning the
// server configurations in the order they appeared in the input. As part
// of this, it activates Let's Encrypt for the configs that are produced.
// Thus, the returned configs are already optimally configured for HTTPS.
func loadConfigs(filename string, input io.Reader) ([]server.Config, error) {
	configs, serverBlocks, lastDirectiveIndex, err := loadConfigsUpToIncludingTLS(filename, input)
	if err != nil {
		return nil, err
	}

	// Now we have all the configs, but they have only been set up to the
	// point of tls. We need to activate Let's Encrypt before setting up
	// the rest of the middlewares so they have correct information regarding
	// TLS configuration, if necessary. (this only appends, so our iterations
	// over server blocks below shouldn't be affected)
	if !IsRestart() && !Quiet {
		fmt.Print("Activating privacy features...")
	}
	configs, err = https.Activate(configs)
	if err != nil {
		return nil, err
	} else if !IsRestart() && !Quiet {
		fmt.Println(" done.")
	}

	// Finish setting up the rest of the directives, now that TLS is
	// optimally configured. These loops are similar to above except
	// we don't iterate all the directives from the beginning and we
	// don't create new configs.
	configIndex := -1
	for i, sb := range serverBlocks {
		onces := makeOnces()
		storages := makeStorages()

		for j := range sb.Addresses {
			configIndex++

			for k := lastDirectiveIndex + 1; k < len(directiveOrder); k++ {
				dir := directiveOrder[k]

				if tokens, ok := sb.Tokens[dir.name]; ok {
					controller := &setup.Controller{
						Config:    &configs[configIndex],
						Dispenser: parse.NewDispenserTokens(filename, tokens),
						OncePerServerBlock: func(f func() error) error {
							var err error
							onces[dir.name].Do(func() {
								err = f()
							})
							return err
						},
						ServerBlockIndex:     i,
						ServerBlockHostIndex: j,
						ServerBlockHosts:     sb.HostList(),
						ServerBlockStorage:   storages[dir.name],
					}
					midware, err := dir.setup(controller)
					if err != nil {
						return nil, err
					}
					if midware != nil {
						configs[configIndex].Middleware = append(configs[configIndex].Middleware, midware)
					}
					storages[dir.name] = controller.ServerBlockStorage // persist for this server block
				}
			}
		}
	}

	return configs, nil
}

// makeOnces makes a map of directive name to sync.Once
// instance. This is intended to be called once per server
// block when setting up configs so that Setup functions
// for each directive can perform a task just once per
// server block, even if there are multiple hosts on the block.
//
// We need one Once per directive, otherwise the first
// directive to use it would exclude other directives from
// using it at all, which would be a bug.
func makeOnces() map[string]*sync.Once {
	onces := make(map[string]*sync.Once)
	for _, dir := range directiveOrder {
		onces[dir.name] = new(sync.Once)
	}
	return onces
}

// makeStorages makes a map of directive name to interface{}
// so that directives' setup functions can persist state
// between different hosts on the same server block during the
// setup phase.
func makeStorages() map[string]interface{} {
	storages := make(map[string]interface{})
	for _, dir := range directiveOrder {
		storages[dir.name] = nil
	}
	return storages
}

// arrangeBindings groups configurations by their bind address. For example,
// a server that should listen on localhost and another on 127.0.0.1 will
// be grouped into the same address: 127.0.0.1. It will return an error
// if an address is malformed or a TLS listener is configured on the
// same address as a plaintext HTTP listener. The return value is a map of
// bind address to list of configs that would become VirtualHosts on that
// server. Use the keys of the returned map to create listeners, and use
// the associated values to set up the virtualhosts.
func arrangeBindings(allConfigs []server.Config) (bindingGroup, error) {
	var groupings bindingGroup

	// Group configs by bind address
	for _, conf := range allConfigs {
		// use default port if none is specified
		if conf.Port == "" {
			conf.Port = Port
		}

		bindAddr, warnErr, fatalErr := resolveAddr(conf)
		if fatalErr != nil {
			return groupings, fatalErr
		}
		if warnErr != nil {
			log.Printf("[WARNING] Resolving bind address for %s: %v", conf.Address(), warnErr)
		}

		// Make sure to compare the string representation of the address,
		// not the pointer, since a new *TCPAddr is created each time.
		var existing bool
		for i := 0; i < len(groupings); i++ {
			if groupings[i].BindAddr.String() == bindAddr.String() {
				groupings[i].Configs = append(groupings[i].Configs, conf)
				existing = true
				break
			}
		}
		if !existing {
			groupings = append(groupings, bindingMapping{
				BindAddr: bindAddr,
				Configs:  []server.Config{conf},
			})
		}
	}

	// Don't allow HTTP and HTTPS to be served on the same address
	for _, group := range groupings {
		isTLS := group.Configs[0].TLS.Enabled
		for _, config := range group.Configs {
			if config.TLS.Enabled != isTLS {
				thisConfigProto, otherConfigProto := "HTTP", "HTTP"
				if config.TLS.Enabled {
					thisConfigProto = "HTTPS"
				}
				if group.Configs[0].TLS.Enabled {
					otherConfigProto = "HTTPS"
				}
				return groupings, fmt.Errorf("configuration error: Cannot multiplex %s (%s) and %s (%s) on same address",
					group.Configs[0].Address(), otherConfigProto, config.Address(), thisConfigProto)
			}
		}
	}

	return groupings, nil
}

// resolveAddr determines the address (host and port) that a config will
// bind to. The returned address, resolvAddr, should be used to bind the
// listener or group the config with other configs using the same address.
// The first error, if not nil, is just a warning and should be reported
// but execution may continue. The second error, if not nil, is a real
// problem and the server should not be started.
//
// This function does not handle edge cases like port "http" or "https" if
// they are not known to the system. It does, however, serve on the wildcard
// host if resolving the address of the specific hostname fails.
func resolveAddr(conf server.Config) (resolvAddr *net.TCPAddr, warnErr, fatalErr error) {
	resolvAddr, warnErr = net.ResolveTCPAddr("tcp", net.JoinHostPort(conf.BindHost, conf.Port))
	if warnErr != nil {
		// the hostname probably couldn't be resolved, just bind to wildcard then
		resolvAddr, fatalErr = net.ResolveTCPAddr("tcp", net.JoinHostPort("", conf.Port))
		if fatalErr != nil {
			return
		}
	}

	return
}

// validDirective returns true if d is a valid
// directive; false otherwise.
func validDirective(d string) bool {
	for _, dir := range directiveOrder {
		if dir.name == d {
			return true
		}
	}
	return false
}

// DefaultInput returns the default Caddyfile input
// to use when it is otherwise empty or missing.
// It uses the default host and port (depends on
// host, e.g. localhost is 2015, otherwise 443) and
// root.
func DefaultInput() CaddyfileInput {
	port := Port
	if https.HostQualifies(Host) && port == DefaultPort {
		port = "443"
	}
	return CaddyfileInput{
		Contents: []byte(fmt.Sprintf("%s:%s\nroot %s", Host, port, Root)),
	}
}

// These defaults are configurable through the command line
var (
	// Root is the site root
	Root = DefaultRoot

	// Host is the site host
	Host = DefaultHost

	// Port is the site port
	Port = DefaultPort
)

// bindingMapping maps a network address to configurations
// that will bind to it. The order of the configs is important.
type bindingMapping struct {
	BindAddr *net.TCPAddr
	Configs  []server.Config
}

// bindingGroup maps network addresses to their configurations.
// Preserving the order of the groupings is important
// (related to graceful shutdown and restart)
// so this is a slice, not a literal map.
type bindingGroup []bindingMapping
