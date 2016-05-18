package caddy

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy2/caddyfile"
)

// Configurable application parameters
var (
	// AppName is the name of the application.
	AppName string

	// AppVersion is the version of the application.
	AppVersion string

	// Quiet when set to true, will not show any informative output on initialization.
	Quiet bool

	// HTTP2 indicates whether HTTP2 is enabled or not.
	HTTP2 bool

	// PidFile is the path to the pidfile to create.
	PidFile string

	// GracefulTimeout is the maximum duration of a graceful shutdown.
	GracefulTimeout time.Duration
)

var (
	// startedServerType is the server type that was (last) started.
	// Note that this package currently does not support starting
	// multiple server types at a time in the same process.
	startedServerType string

	// caddyfileInput is the input configuration text used for this process
	caddyfileInput Input

	// caddyfileMu protects caddyfileInput during changes
	caddyfileInputMu sync.Mutex

	// restartFds keeps the servers' sockets for graceful in-process restart
	restartFds = make(map[string]*os.File)

	// wg is used to wait for all servers to shut down
	wg sync.WaitGroup

	// startedBefore should be set to true if caddy has been started
	// at least once (does not indicate whether currently running).
	startedBefore bool
)

// Server is a type that can listen and serve. A Server
// should only associate with zero or one listeners.
type Server interface {
	// Listen starts listening by creating a new listener
	// and returning it. It does not start accepting
	// connections.
	Listen() (net.Listener, error)

	// Serve starts serving using the provided listener.
	// Serve must start the server loop nearly immediately,
	// or at least not return any errors before the server
	// loop begins. Serve blocks indefinitely, or in other
	// words, until the server is stopped.
	Serve(net.Listener) error
}

// Stopper is a type that can stop serving. The stop
// does not necessarily have to be graceful.
type Stopper interface {
	// Stop stops the server. It blocks until the
	// server is completely stopped.
	Stop() error
}

// GracefulServer is a Server and Stopper, the stopping
// of which is graceful (whatever that means for the kind
// of server being implemented). It must be able to return
// the address it is configured to listen on so that its
// listener can be paired with it upon graceful restarts.
type GracefulServer interface {
	Server
	Stopper

	// Address returns the address the server should
	// listen on; it is used to pair the server to
	// its listener during a graceful/zero-downtime
	// restart. Thus when implementing this method,
	// you must not access a listener to get the
	// address; you must store the address the
	// server is to serve on some other way.
	Address() string
}

// Listener is a net.Listener with an underlying file descriptor.
// A server's listener should implement this interface if it is
// to support zero-downtime reloads.
type Listener interface {
	net.Listener
	File() (*os.File, error)
}

// LoadCaddyfile loads a Caddyfile by calling the user's loader function,
// and if that returns nil, then this function resorts to the default
// configuration. Thus, if there are no other errors, this function
// always returns at least the default Caddyfile.
func LoadCaddyfile() (cdyfile Input, err error) {
	// Ask plugins for a Caddyfile
	cdyfile, err = loadCaddyfileInput()
	if err != nil {
		return nil, err
	}

	// Otherwise revert to default
	// TODO.
	if cdyfile == nil {
		//	cdyfile = DefaultInput()
	}

	return
}

func Wait() {
	wg.Wait()
}

// CaddyfileFromPipe loads the Caddyfile input from f if f is
// not interactive input. f is assumed to be a pipe or stream,
// such as os.Stdin. If f is not a pipe, no error is returned
// but the Input value will be nil. An error is only returned
// if there was an error reading the pipe, even if the length
// of what was read is 0.
func CaddyfileFromPipe(f *os.File) (Input, error) {
	fi, err := f.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		// Note that a non-nil error is not a problem. Windows
		// will not create a stdin if there is no pipe, which
		// produces an error when calling Stat(). But Unix will
		// make one either way, which is why we also check that
		// bitmask.
		// BUG: Reading from stdin after this fails (e.g. for the let's encrypt email address) (OS X)
		confBody, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}
		return CaddyfileInput{
			Contents: confBody,
			Filepath: f.Name(),
		}, nil
	}

	// not having input from the pipe is not itself an error,
	// just means no input to return.
	return nil, nil
}

// Caddyfile returns the current Caddyfile
func Caddyfile() Input {
	caddyfileInputMu.Lock()
	defer caddyfileInputMu.Unlock()
	return caddyfileInput
}

// Start starts Caddy with the given Caddyfile. If cdyfile
// is nil, the LoadCaddyfile function will be called to get
// one.
//
// This function blocks until all the servers are listening.
//
// Do not call Start() with more than one server type per
// process; the behavior is currently undefined. We may look
// into changing this in the future.
func Start(serverType string, cdyfile Input) (err error) {
	startedServerType = serverType

	stype, err := getServerType(serverType)
	if err != nil {
		return err
	}

	// Input must never be nil; try to load something
	// TODO: This may still result in nil caddyfile? Just use an "empty" one otherwise?
	if cdyfile == nil {
		cdyfile, err = LoadCaddyfile()
		if err != nil {
			return err
		}
	}

	caddyfileInputMu.Lock()
	caddyfileInput = cdyfile
	caddyfileInputMu.Unlock()

	sblocks, err := loadServerBlocks(serverType, path.Base(cdyfile.Path()), bytes.NewReader(cdyfile.Body()))
	if err != nil {
		return err
	}

	if stype.InspectServerBlocks != nil {
		sblocks, err = stype.InspectServerBlocks(cdyfile.Path(), sblocks)
		if err != nil {
			return err
		}
	}

	err = executeDirectives(serverType, cdyfile.Path(), stype.Directives, sblocks)
	if err != nil {
		return err
	}

	// TODO: Make it possible to just require []Server instead of []GracefulServer?
	var serverList []Server
	if stype.MakeServers != nil {
		slist, err := stype.MakeServers()
		if err != nil {
			return err
		}
		serverList = append(serverList, slist...)
	}

	// TODO: Run startup callbacks...
	// run startup functions that should only execute when
	// the original parent process is starting.
	// TODO... move into server package? Also, is startedBefore necessary?
	// if !startedBefore { { //&& !startedBefore {
	// 	err := s.RunFirstStartupFuncs()
	// 	if err != nil {
	// 		errChan <- err
	// 		return
	// 	}
	// }

	err = startServers(serverList)
	if err != nil {
		return err
	}

	startedBefore = true
	// TODO ^ needed?

	// showInitializationOutput(groupings)

	return nil
}

func executeDirectives(serverType, filename string,
	directives []Directive, sblocks []caddyfile.ServerBlock) error {

	// map of server block ID to map of directive name to whatever.
	storages := make(map[int]map[string]interface{})

	// It is crucial that directives are executed in the proper order.
	for _, dir := range directives {
		for i, sb := range sblocks {
			var once sync.Once
			if _, ok := storages[i]; !ok {
				storages[i] = make(map[string]interface{})
			}

			// TODO...
			// config := server.Config{
			// 	Host:       addr.Host,
			// 	Port:       addr.Port,
			// 	Scheme:     addr.Scheme,
			// 	Root:       Config.Defaults.Root,
			// 	ConfigFile: filename,
			// 	AppName:    Config.AppName,
			// 	AppVersion: Config.AppVersion,
			// }

			for j, key := range sb.Keys {
				// Execute directive if it is in the server block
				if tokens, ok := sb.Tokens[dir.Name]; ok {
					controller := &Controller{
						ServerType: serverType,
						Key:        key,
						Dispenser:  caddyfile.NewDispenserTokens(filename, tokens),
						OncePerServerBlock: func(f func() error) error {
							var err error
							once.Do(func() {
								err = f()
							})
							return err
						},
						ServerBlockIndex:     i,
						ServerBlockHostIndex: j, // TODO: Rename these fields to be more generic
						ServerBlockHosts:     sb.Keys,
						ServerBlockStorage:   storages[i][dir.Name],
					}

					setup, err := DirectiveAction(serverType, dir.Name)
					if err != nil {
						return err
					}

					err = setup(controller)
					if err != nil {
						return err
					}

					storages[i][dir.Name] = controller.ServerBlockStorage // persist for this server block
				}

				// Stop after TLS setup, since we need to activate Let's Encrypt before continuing;
				// it makes some changes to the configs that middlewares might want to know about.
				// if dir == "tls" {
				// 	lastDirectiveIndex = k
				// 	break
				// }
			}
		}

		// See if there are any callbacks to execute after this directive
		if allCallbacks, ok := parsingCallbacks[serverType]; ok {
			callbacks := allCallbacks[dir.Name]
			for _, callback := range callbacks {
				if err := callback(); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func startServers(serverList []Server) error {
	errChan := make(chan error, len(serverList))

	for _, s := range serverList {
		var ln net.Listener
		var err error

		// If this is a reload and s is a GracefulServer,
		// TODO -- why is being a GracefulServer a requirement?? Should work anyway, right?
		// we can probably inherit its listener from earlier.
		if gs, ok := s.(GracefulServer); ok && len(restartFds) > 0 {
			addr := gs.Address()
			fmt.Println("Is a graceful server... addr:", addr)
			if file, ok := restartFds[addr]; ok {
				ln, err = net.FileListener(file)
				if err != nil {
					return err
				}
				fmt.Println("Inherited listener:", ln)

				file.Close()
				delete(restartFds, addr)
			}
		}

		if ln == nil {
			ln, err = s.Listen()
			if err != nil {
				return err
			}
		}

		wg.Add(1)
		go func(s Server, ln net.Listener) {
			defer wg.Done()
			errChan <- s.Serve(ln)
		}(s, ln)

		SaveServer(s, ln)
	}

	// Close the remaining (unused) file descriptors to free up resources
	if len(restartFds) > 0 {
		for key, file := range restartFds {
			file.Close()
			delete(restartFds, key)
		}
	}

	// Log errors that may be returned from Serve() calls,
	// these errors should only be occurring in the server loop.
	go func() {
		for err := range errChan {
			if err == nil {
				continue
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				// this error is normal when closing the listener
				continue
			}
			log.Println(err)
		}
	}()

	return nil
}

func getServerType(serverType string) (ServerType, error) {
	stype, ok := serverTypes[serverType]
	if ok {
		return stype, nil
	}
	if serverType == "" {
		if len(serverTypes) == 1 {
			for _, stype := range serverTypes {
				return stype, nil
			}
		}
		return ServerType{}, fmt.Errorf("multiple server types available; must choose one")
	}
	if len(serverTypes) == 0 {
		return ServerType{}, fmt.Errorf("no server types plugged in")
	}
	return ServerType{}, fmt.Errorf("unknown server type '%s'", serverType)
}

func loadServerBlocks(serverType, filename string, input io.Reader) ([]caddyfile.ServerBlock, error) {
	validDirectives := ValidDirectives()
	serverBlocks, err := caddyfile.ServerBlocks(filename, input, validDirectives)
	if err != nil {
		return nil, err
	}
	if len(serverBlocks) == 0 && serverTypes[serverType].DefaultInput != nil {
		newInput := serverTypes[serverType].DefaultInput()
		serverBlocks, err = caddyfile.ServerBlocks(newInput.Path(),
			bytes.NewReader(newInput.Body()), validDirectives)
		if err != nil {
			return nil, err
		}
	}
	return serverBlocks, nil
}

// writePidFile writes the process ID to the file at
// Config.Process.PidFile, if specified.
func writePidFile() error {
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	return ioutil.WriteFile(PidFile, pid, 0644)
}

// Stop stops all servers. It blocks until they are all stopped.
// It does NOT execute shutdown callbacks that may have been
// configured by middleware (they must be executed separately).
func Stop() error {
	// TODO
	//https.Deactivate()

	serversMu.Lock()
	for _, s := range servers {
		if gs, ok := s.server.(GracefulServer); ok {
			if err := gs.Stop(); err != nil {
				log.Printf("[ERROR] Stopping %s: %v", gs.Address(), err)
			}
		}
	}
	servers = []serverListener{} // don't reuse servers
	serversMu.Unlock()

	return nil
}

// IsRestart returns whether the servers have been
// restarted - TODO: This doesn't mesh well with the new 0.9 changes
func IsRestart() bool {
	return startedBefore
}

// CaddyfileInput represents a Caddyfile as input
// and is simply a convenient way to implement
// the Input interface.
type CaddyfileInput struct {
	Filepath string
	Contents []byte
	//ServerType string // TODO - Necessary?
}

// Body returns c.Contents.
func (c CaddyfileInput) Body() []byte { return c.Contents }

// Path returns c.Filepath.
func (c CaddyfileInput) Path() string { return c.Filepath }

// Input represents a Caddyfile; its contents and file path
// (which should include the file name at the end of the path).
// If path does not apply (e.g. piped input) you may use
// any understandable value. The path is mainly used for logging,
// error messages, and debugging.
type Input interface {
	// Gets the Caddyfile contents
	Body() []byte

	// Gets the path to the origin file
	Path() string
}

// DefaultInput returns the default Caddyfile input
// to use when it is otherwise empty or missing.
// It uses the default host and port (depends on
// host, e.g. localhost is 2015, otherwise 443) and
// root.
func DefaultInput(serverType string) Input {
	// port := Config.Defaults.Port
	// if https.HostQualifies(Config.Defaults.Host) && port == DefaultPort {
	// 	port = "443"
	// }
	// return CaddyfileInput{
	// 	Contents: []byte(fmt.Sprintf("%s:%s\nroot %s", Config.Defaults.Host, port, Config.Defaults.Root)),
	// }
	if _, ok := serverTypes[serverType]; !ok {
		return CaddyfileInput{}
	}
	if serverTypes[serverType].DefaultInput == nil {
		return CaddyfileInput{}
	}
	return serverTypes[serverType].DefaultInput()
}

// IsLoopback returns true if host looks explicitly like a loopback address.
func IsLoopback(host string) bool {
	return host == "localhost" ||
		host == "::1" ||
		strings.HasPrefix(host, "127.")
}

const (
	// DefaultConfigFile is the name of the configuration file that is loaded
	// by default if no other file is specified.
	DefaultConfigFile = "Caddyfile"
)
