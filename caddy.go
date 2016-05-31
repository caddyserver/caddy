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

	// Quiet mode will not show any informative output on initialization.
	Quiet bool

	// PidFile is the path to the pidfile to create.
	PidFile string

	// GracefulTimeout is the maximum duration of a graceful shutdown.
	GracefulTimeout time.Duration
)

// Instance contains the state of servers created as a result of
// calling Start and can be used to access or control those servers.
type Instance struct {
	// serverType is the server type that was (last) started.
	// Note that this package currently does not support starting
	// multiple server types at a time in the same process.
	serverType string

	// caddyfileInput is the input configuration text used for this process
	caddyfileInput Input

	// wg is used to wait for all servers to shut down
	wg sync.WaitGroup

	// servers is the list of servers with their listeners...
	servers []serverListener
}

// Stop stops all servers contained in i.
func (i *Instance) Stop() error {
	for _, s := range i.servers {
		if gs, ok := s.server.(GracefulServer); ok {
			if err := gs.Stop(); err != nil {
				log.Printf("[ERROR] Stopping %s: %v", gs.Address(), err)
			}
		}
	}
	for j, other := range instances {
		if other == i {
			instances = append(instances[:j], instances[j+1:]...)
			break
		}
	}
	return nil
}

// Restart replaces the servers in i with new servers created from
// executing the newCaddyfile. Upon success, it returns the new
// instance to replace i. Upon failure, i will not be replaced.
func (i *Instance) Restart(newCaddyfile Input) (*Instance, error) {
	log.Println("[INFO] Reloading")

	if newCaddyfile == nil {
		newCaddyfile = i.caddyfileInput
	}

	// Add file descriptors of all the sockets that are capable of it
	restartFds := make(map[string]restartPair)
	for _, s := range i.servers {
		gs, srvOk := s.server.(GracefulServer)
		ln, lnOk := s.listener.(Listener)
		if srvOk && lnOk {
			restartFds[gs.Address()] = restartPair{server: gs, listener: ln}
		}
	}

	// create new instance; if the restart fails, it is simply discarded
	newInst := &Instance{serverType: newCaddyfile.ServerType()}

	// attempt to start new instance
	err := startWithListenerFds(newCaddyfile, newInst, restartFds)
	if err != nil {
		return i, err
	}

	// success! bump the old instance out so it will be garbage-collected
	instancesMu.Lock()
	for j, other := range instances {
		if other == i {
			instances = append(instances[:j], instances[j+1:]...)
			break
		}
	}
	instancesMu.Unlock()

	log.Println("[INFO] Reloading complete")

	return newInst, nil
}

// SaveServer adds s and its associated listener ln to the
// internally-kept list of servers that is running. For
// saved servers, graceful restarts will be provided.
func (i *Instance) SaveServer(s Server, ln net.Listener) {
	i.servers = append(i.servers, serverListener{server: s, listener: ln})
}

// HasListenerWithAddress returns whether this package is
// tracking a server using a listener with the address
// addr.
func HasListenerWithAddress(addr string) bool {
	instancesMu.Lock()
	defer instancesMu.Unlock()
	for _, inst := range instances {
		for _, sln := range inst.servers {
			if listenerAddrEqual(sln.listener, addr) {
				return true
			}
		}
	}
	return false
}

// listenerAddrEqual compares a listener's address with
// addr. Extra care is taken to match addresses with an
// empty hostname portion, as listeners tend to report
// [::]:80, for example, when the matching address that
// created the listener might be simply :80.
func listenerAddrEqual(ln net.Listener, addr string) bool {
	lnAddr := ln.Addr().String()
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil || hostname != "" {
		return lnAddr == addr
	}
	if lnAddr == net.JoinHostPort("::", port) {
		return true
	}
	if lnAddr == net.JoinHostPort("0.0.0.0", port) {
		return true
	}
	return false
}

/*
// TODO: We should be able to support UDP servers... I'm considering this pattern.

type UDPListener struct {
	*net.UDPConn
}

func (u UDPListener) Accept() (net.Conn, error) {
	return u.UDPConn, nil
}

func (u UDPListener) Close() error {
	return u.UDPConn.Close()
}

func (u UDPListener) Addr() net.Addr {
	return u.UDPConn.LocalAddr()
}

var _ net.Listener = UDPListener{}
*/

// Server is a type that can listen and serve. A Server
// must associate with exactly zero or one listeners.
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
// The net.Listener that a GracefulServer creates must
// implement the Listener interface for restarts to be
// graceful (assuming the listener is for TCP).
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

// LoadCaddyfile loads a Caddyfile by calling the plugged in
// Caddyfile loader methods. An error is returned if more than
// one loader returns a non-nil Caddyfile input. If no loaders
// load a Caddyfile, the default loader is used. If no default
// loader is registered or it returns nil, the server type's
// default Caddyfile is loaded. If the server type does not
// specify any default Caddyfile value, then an empty Caddyfile
// is returned. Consequently, this function never returns a nil
// value as long as there are no errors.
func LoadCaddyfile(serverType string) (Input, error) {
	// Ask plugged-in loaders for a Caddyfile
	cdyfile, err := loadCaddyfileInput(serverType)
	if err != nil {
		return nil, err
	}

	// Otherwise revert to default
	if cdyfile == nil {
		cdyfile = DefaultInput(serverType)
	}

	// Still nil? Geez.
	if cdyfile == nil {
		cdyfile = CaddyfileInput{ServerTypeName: serverType}
	}

	return cdyfile, nil
}

// Wait blocks until all of i's servers have stopped.
func (i *Instance) Wait() {
	i.wg.Wait()
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
		// NOTE: Reading from stdin after this fails (e.g. for the let's encrypt email address) (OS X)
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

// Caddyfile returns the Caddyfile used to create i.
func (i *Instance) Caddyfile() Input {
	return i.caddyfileInput
}

// Start starts Caddy with the given Caddyfile.
//
// This function blocks until all the servers are listening.
func Start(cdyfile Input) (*Instance, error) {
	inst := &Instance{serverType: cdyfile.ServerType()}
	return inst, startWithListenerFds(cdyfile, inst, nil)
}

func startWithListenerFds(cdyfile Input, inst *Instance, restartFds map[string]restartPair) error {
	if cdyfile == nil {
		cdyfile = CaddyfileInput{}
	}

	stypeName := cdyfile.ServerType()

	stype, err := getServerType(stypeName)
	if err != nil {
		return err
	}

	inst.caddyfileInput = cdyfile

	sblocks, err := loadServerBlocks(stypeName, path.Base(cdyfile.Path()), bytes.NewReader(cdyfile.Body()))
	if err != nil {
		return err
	}

	ctx := stype.NewContext()

	sblocks, err = ctx.InspectServerBlocks(cdyfile.Path(), sblocks)
	if err != nil {
		return err
	}

	err = executeDirectives(stypeName, cdyfile.Path(), stype.Directives, sblocks)
	if err != nil {
		return err
	}

	slist, err := ctx.MakeServers()
	if err != nil {
		return err
	}

	// TODO: Run startup callbacks...
	// run startup functions that should only execute when
	// the original parent process is starting,
	// in other words, when currentRunContext loads as nil
	// TODO... move into server package? Also, is startedBefore necessary?
	// if !startedBefore { { //&& !startedBefore {
	// 	err := s.RunFirstStartupFuncs()
	// 	if err != nil {
	// 		errChan <- err
	// 		return
	// 	}
	// }

	err = startServers(slist, inst, restartFds)
	if err != nil {
		return err
	}

	instancesMu.Lock()
	instances = append(instances, inst)
	instancesMu.Unlock()

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

func startServers(serverList []Server, inst *Instance, restartFds map[string]restartPair) error {
	errChan := make(chan error, len(serverList))

	for _, s := range serverList {
		var ln net.Listener
		var err error

		// If this is a reload and s is a GracefulServer,
		// reuse the listener for a graceful restart.
		if gs, ok := s.(GracefulServer); ok && restartFds != nil {
			addr := gs.Address()
			if old, ok := restartFds[addr]; ok {
				file, err := old.listener.File()
				if err != nil {
					return err
				}
				ln, err = net.FileListener(file)
				if err != nil {
					return err
				}
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

		inst.wg.Add(1)
		go func(s Server, ln net.Listener, inst *Instance) {
			defer inst.wg.Done()
			errChan <- s.Serve(ln)
		}(s, ln, inst)

		inst.servers = append(inst.servers, serverListener{server: s, listener: ln})
	}

	// Close the remaining (unused) file descriptors to free up resources
	// and stop old servers that aren't used anymore
	for key, old := range restartFds {
		if err := old.server.Stop(); err != nil {
			log.Printf("[ERROR] Stopping %s: %v", old.server.Address(), err)
		}
		delete(restartFds, key)
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
	validDirectives := ValidDirectives(serverType)
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

// Upgrade re-launches the process, preserving the listeners
// for a graceful restart. It does NOT load new configuration,
// merely starts the process with a newly-upgraded binary.
// TODO: This is not yet implemented
func Upgrade() error {
	return fmt.Errorf("not implemented")
}

// IsRestart returns whether the servers have been
// restarted - TODO: This doesn't mesh well with the new 0.9 changes
// More like, this tells whether servers have been started before
// TODO... maybe change to IsStarted() or something?
func IsRestart() bool {
	//return currentRunContext.Load() != nil
	return false
}

// CaddyfileInput represents a Caddyfile as input
// and is simply a convenient way to implement
// the Input interface.
type CaddyfileInput struct {
	Filepath       string
	Contents       []byte
	ServerTypeName string
}

// Body returns c.Contents.
func (c CaddyfileInput) Body() []byte { return c.Contents }

// Path returns c.Filepath.
func (c CaddyfileInput) Path() string { return c.Filepath }

// ServerType returns c.ServerType.
func (c CaddyfileInput) ServerType() string { return c.ServerTypeName }

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

	// The type of server this input is intended for
	ServerType() string
}

// DefaultInput returns the default Caddyfile input
// to use when it is otherwise empty or missing.
// It uses the default host and port (depends on
// host, e.g. localhost is 2015, otherwise 443) and
// root.
func DefaultInput(serverType string) Input {
	if _, ok := serverTypes[serverType]; !ok {
		return nil
	}
	if serverTypes[serverType].DefaultInput == nil {
		return nil
	}
	return serverTypes[serverType].DefaultInput()
}

// IsLoopback returns true if host looks explicitly like a loopback address.
func IsLoopback(host string) bool {
	return host == "localhost" ||
		host == "::1" ||
		strings.HasPrefix(host, "127.")
}

type restartPair struct {
	server   GracefulServer
	listener Listener
}

var (
	// instances is the list of running Instances.
	instances []*Instance

	// instancesMu protects instances.
	instancesMu sync.Mutex
)

const (
	// DefaultConfigFile is the name of the configuration file that is loaded
	// by default if no other file is specified.
	DefaultConfigFile = "Caddyfile"
)
