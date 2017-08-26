// Package caddy implements the Caddy server manager.
//
// To use this package:
//
//   1. Set the AppName and AppVersion variables.
//   2. Call LoadCaddyfile() to get the Caddyfile.
//      Pass in the name of the server type (like "http").
//      Make sure the server type's package is imported
//      (import _ "github.com/mholt/caddy/caddyhttp").
//   3. Call caddy.Start() to start Caddy. You get back
//      an Instance, on which you can call Restart() to
//      restart it or Stop() to stop it.
//
// You should call Wait() on your instance to wait for
// all servers to quit before your process exits.
package caddy

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/caddyfile"
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

	// isUpgrade will be set to true if this process
	// was started as part of an upgrade, where a parent
	// Caddy process started this one.
	isUpgrade = os.Getenv("CADDY__UPGRADE") == "1"

	// started will be set to true when the first
	// instance is started; it never gets set to
	// false after that.
	started bool

	// mu protects the variables 'isUpgrade' and 'started'.
	mu sync.Mutex
)

// Instance contains the state of servers created as a result of
// calling Start and can be used to access or control those servers.
type Instance struct {
	// serverType is the name of the instance's server type
	serverType string

	// caddyfileInput is the input configuration text used for this process
	caddyfileInput Input

	// wg is used to wait for all servers to shut down
	wg *sync.WaitGroup

	// context is the context created for this instance.
	context Context

	// servers is the list of servers with their listeners.
	servers []ServerListener

	// these callbacks execute when certain events occur
	onFirstStartup  []func() error // starting, not as part of a restart
	onStartup       []func() error // starting, even as part of a restart
	onRestart       []func() error // before restart commences
	onShutdown      []func() error // stopping, even as part of a restart
	onFinalShutdown []func() error // stopping, not as part of a restart
}

// Servers returns the ServerListeners in i.
func (i *Instance) Servers() []ServerListener { return i.servers }

// Stop stops all servers contained in i. It does NOT
// execute shutdown callbacks.
func (i *Instance) Stop() error {
	// stop the servers
	for _, s := range i.servers {
		if gs, ok := s.server.(GracefulServer); ok {
			if err := gs.Stop(); err != nil {
				log.Printf("[ERROR] Stopping %s: %v", gs.Address(), err)
			}
		}
	}

	// splice i out of instance list, causing it to be garbage-collected
	instancesMu.Lock()
	for j, other := range instances {
		if other == i {
			instances = append(instances[:j], instances[j+1:]...)
			break
		}
	}
	instancesMu.Unlock()

	return nil
}

// ShutdownCallbacks executes all the shutdown callbacks of i,
// including ones that are scheduled only for the final shutdown
// of i. An error returned from one does not stop execution of
// the rest. All the non-nil errors will be returned.
func (i *Instance) ShutdownCallbacks() []error {
	var errs []error
	for _, shutdownFunc := range i.onShutdown {
		err := shutdownFunc()
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, finalShutdownFunc := range i.onFinalShutdown {
		err := finalShutdownFunc()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Restart replaces the servers in i with new servers created from
// executing the newCaddyfile. Upon success, it returns the new
// instance to replace i. Upon failure, i will not be replaced.
func (i *Instance) Restart(newCaddyfile Input) (*Instance, error) {
	log.Println("[INFO] Reloading")

	i.wg.Add(1)
	defer i.wg.Done()

	// run restart callbacks
	for _, fn := range i.onRestart {
		err := fn()
		if err != nil {
			return i, err
		}
	}

	if newCaddyfile == nil {
		newCaddyfile = i.caddyfileInput
	}

	// Add file descriptors of all the sockets that are capable of it
	restartFds := make(map[string]restartTriple)
	for _, s := range i.servers {
		gs, srvOk := s.server.(GracefulServer)
		ln, lnOk := s.listener.(Listener)
		pc, pcOk := s.packet.(PacketConn)
		if srvOk {
			if lnOk && pcOk {
				restartFds[gs.Address()] = restartTriple{server: gs, listener: ln, packet: pc}
				continue
			}
			if lnOk {
				restartFds[gs.Address()] = restartTriple{server: gs, listener: ln}
				continue
			}
			if pcOk {
				restartFds[gs.Address()] = restartTriple{server: gs, packet: pc}
				continue
			}
		}
	}

	// create new instance; if the restart fails, it is simply discarded
	newInst := &Instance{serverType: newCaddyfile.ServerType(), wg: i.wg}

	// attempt to start new instance
	err := startWithListenerFds(newCaddyfile, newInst, restartFds)
	if err != nil {
		return i, err
	}

	// success! stop the old instance
	for _, shutdownFunc := range i.onShutdown {
		err := shutdownFunc()
		if err != nil {
			return i, err
		}
	}
	i.Stop()

	log.Println("[INFO] Reloading complete")

	return newInst, nil
}

// SaveServer adds s and its associated listener ln to the
// internally-kept list of servers that is running. For
// saved servers, graceful restarts will be provided.
func (i *Instance) SaveServer(s Server, ln net.Listener) {
	i.servers = append(i.servers, ServerListener{server: s, listener: ln})
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
	if err != nil {
		return lnAddr == addr
	}
	if lnAddr == net.JoinHostPort("::", port) {
		return true
	}
	if lnAddr == net.JoinHostPort("0.0.0.0", port) {
		return true
	}
	return hostname != "" && lnAddr == addr
}

// TCPServer is a type that can listen and serve connections.
// A TCPServer must associate with exactly zero or one net.Listeners.
type TCPServer interface {
	// Listen starts listening by creating a new listener
	// and returning it. It does not start accepting
	// connections. For UDP-only servers, this method
	// can be a no-op that returns (nil, nil).
	Listen() (net.Listener, error)

	// Serve starts serving using the provided listener.
	// Serve must start the server loop nearly immediately,
	// or at least not return any errors before the server
	// loop begins. Serve blocks indefinitely, or in other
	// words, until the server is stopped. For UDP-only
	// servers, this method can be a no-op that returns nil.
	Serve(net.Listener) error
}

// UDPServer is a type that can listen and serve packets.
// A UDPServer must associate with exactly zero or one net.PacketConns.
type UDPServer interface {
	// ListenPacket starts listening by creating a new packetconn
	// and returning it. It does not start accepting connections.
	// TCP-only servers may leave this method blank and return
	// (nil, nil).
	ListenPacket() (net.PacketConn, error)

	// ServePacket starts serving using the provided packetconn.
	// ServePacket must start the server loop nearly immediately,
	// or at least not return any errors before the server
	// loop begins. ServePacket blocks indefinitely, or in other
	// words, until the server is stopped. For TCP-only servers,
	// this method can be a no-op that returns nil.
	ServePacket(net.PacketConn) error
}

// Server is a type that can listen and serve. It supports both
// TCP and UDP, although the UDPServer interface can be used
// for more than just UDP.
//
// If the server uses TCP, it should implement TCPServer completely.
// If it uses UDP or some other protocol, it should implement
// UDPServer completely. If it uses both, both interfaces should be
// fully implemented. Any unimplemented methods should be made as
// no-ops that simply return nil values.
type Server interface {
	TCPServer
	UDPServer
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

// PacketConn is a net.PacketConn with an underlying file descriptor.
// A server's packetconn should implement this interface if it is
// to support zero-downtime reloads (in sofar this holds true for datagram
// connections).
type PacketConn interface {
	net.PacketConn
	File() (*os.File, error)
}

// AfterStartup is an interface that can be implemented
// by a server type that wants to run some code after all
// servers for the same Instance have started.
type AfterStartup interface {
	OnStartupComplete()
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
	// If we are finishing an upgrade, we must obtain the Caddyfile
	// from our parent process, regardless of configured loaders.
	if IsUpgrade() {
		err := gob.NewDecoder(os.Stdin).Decode(&loadedGob)
		if err != nil {
			return nil, err
		}
		return loadedGob.Caddyfile, nil
	}

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
func CaddyfileFromPipe(f *os.File, serverType string) (Input, error) {
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
			Contents:       confBody,
			Filepath:       f.Name(),
			ServerTypeName: serverType,
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
	inst := &Instance{serverType: cdyfile.ServerType(), wg: new(sync.WaitGroup)}
	err := startWithListenerFds(cdyfile, inst, nil)
	if err != nil {
		return inst, err
	}
	signalSuccessToParent()
	if pidErr := writePidFile(); pidErr != nil {
		log.Printf("[ERROR] Could not write pidfile: %v", pidErr)
	}
	return inst, nil
}

func startWithListenerFds(cdyfile Input, inst *Instance, restartFds map[string]restartTriple) error {
	if cdyfile == nil {
		cdyfile = CaddyfileInput{}
	}

	err := ValidateAndExecuteDirectives(cdyfile, inst, false)
	if err != nil {
		return err
	}

	slist, err := inst.context.MakeServers()
	if err != nil {
		return err
	}

	// run startup callbacks
	if !IsUpgrade() && restartFds == nil {
		// first startup means not a restart or upgrade
		for _, firstStartupFunc := range inst.onFirstStartup {
			err := firstStartupFunc()
			if err != nil {
				return err
			}
		}
	}
	for _, startupFunc := range inst.onStartup {
		err := startupFunc()
		if err != nil {
			return err
		}
	}

	err = startServers(slist, inst, restartFds)
	if err != nil {
		return err
	}

	instancesMu.Lock()
	instances = append(instances, inst)
	instancesMu.Unlock()

	// run any AfterStartup callbacks if this is not
	// part of a restart; then show file descriptor notice
	if restartFds == nil {
		for _, srvln := range inst.servers {
			if srv, ok := srvln.server.(AfterStartup); ok {
				srv.OnStartupComplete()
			}
		}
		if !Quiet {
			for _, srvln := range inst.servers {
				if !IsLoopback(srvln.listener.Addr().String()) {
					checkFdlimit()
					break
				}
			}
		}
	}

	mu.Lock()
	started = true
	mu.Unlock()

	return nil
}

// ValidateAndExecuteDirectives will load the server blocks from cdyfile
// by parsing it, then execute the directives configured by it and store
// the resulting server blocks into inst. If justValidate is true, parse
// callbacks will not be executed between directives, since the purpose
// is only to check the input for valid syntax.
func ValidateAndExecuteDirectives(cdyfile Input, inst *Instance, justValidate bool) error {
	// If parsing only inst will be nil, create an instance for this function call only.
	if justValidate {
		inst = &Instance{serverType: cdyfile.ServerType(), wg: new(sync.WaitGroup)}
	}

	stypeName := cdyfile.ServerType()

	stype, err := getServerType(stypeName)
	if err != nil {
		return err
	}

	inst.caddyfileInput = cdyfile

	sblocks, err := loadServerBlocks(stypeName, cdyfile.Path(), bytes.NewReader(cdyfile.Body()))
	if err != nil {
		return err
	}

	inst.context = stype.NewContext()
	if inst.context == nil {
		return fmt.Errorf("server type %s produced a nil Context", stypeName)
	}

	sblocks, err = inst.context.InspectServerBlocks(cdyfile.Path(), sblocks)
	if err != nil {
		return err
	}

	err = executeDirectives(inst, cdyfile.Path(), stype.Directives(), sblocks, justValidate)
	if err != nil {
		return err
	}

	return nil
}

func executeDirectives(inst *Instance, filename string,
	directives []string, sblocks []caddyfile.ServerBlock, justValidate bool) error {
	// map of server block ID to map of directive name to whatever.
	storages := make(map[int]map[string]interface{})

	// It is crucial that directives are executed in the proper order.
	// We loop with the directives on the outer loop so we execute
	// a directive for all server blocks before going to the next directive.
	// This is important mainly due to the parsing callbacks (below).
	for _, dir := range directives {
		for i, sb := range sblocks {
			var once sync.Once
			if _, ok := storages[i]; !ok {
				storages[i] = make(map[string]interface{})
			}

			for j, key := range sb.Keys {
				// Execute directive if it is in the server block
				if tokens, ok := sb.Tokens[dir]; ok {
					controller := &Controller{
						instance:  inst,
						Key:       key,
						Dispenser: caddyfile.NewDispenserTokens(filename, tokens),
						OncePerServerBlock: func(f func() error) error {
							var err error
							once.Do(func() {
								err = f()
							})
							return err
						},
						ServerBlockIndex:    i,
						ServerBlockKeyIndex: j,
						ServerBlockKeys:     sb.Keys,
						ServerBlockStorage:  storages[i][dir],
					}

					setup, err := DirectiveAction(inst.serverType, dir)
					if err != nil {
						return err
					}

					err = setup(controller)
					if err != nil {
						return err
					}

					storages[i][dir] = controller.ServerBlockStorage // persist for this server block
				}
			}
		}

		if !justValidate {
			// See if there are any callbacks to execute after this directive
			if allCallbacks, ok := parsingCallbacks[inst.serverType]; ok {
				callbacks := allCallbacks[dir]
				for _, callback := range callbacks {
					if err := callback(inst.context); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func startServers(serverList []Server, inst *Instance, restartFds map[string]restartTriple) error {
	errChan := make(chan error, len(serverList))

	for _, s := range serverList {
		var (
			ln  net.Listener
			pc  net.PacketConn
			err error
		)

		// if performing an upgrade, obtain listener file descriptors
		// from parent process
		if IsUpgrade() {
			if gs, ok := s.(GracefulServer); ok {
				addr := gs.Address()
				if fdIndex, ok := loadedGob.ListenerFds["tcp"+addr]; ok {
					file := os.NewFile(fdIndex, "")
					ln, err = net.FileListener(file)
					file.Close()
					if err != nil {
						return err
					}
				}
				if fdIndex, ok := loadedGob.ListenerFds["udp"+addr]; ok {
					file := os.NewFile(fdIndex, "")
					pc, err = net.FilePacketConn(file)
					file.Close()
					if err != nil {
						return err
					}
				}
			}
		}

		// If this is a reload and s is a GracefulServer,
		// reuse the listener for a graceful restart.
		if gs, ok := s.(GracefulServer); ok && restartFds != nil {
			addr := gs.Address()
			if old, ok := restartFds[addr]; ok {
				// listener
				if old.listener != nil {
					file, err := old.listener.File()
					if err != nil {
						return err
					}
					ln, err = net.FileListener(file)
					if err != nil {
						return err
					}
					file.Close()
				}
				// packetconn
				if old.packet != nil {
					file, err := old.packet.File()
					if err != nil {
						return err
					}
					pc, err = net.FilePacketConn(file)
					if err != nil {
						return err
					}
					file.Close()
				}
			}
		}

		if ln == nil {
			ln, err = s.Listen()
			if err != nil {
				return err
			}
		}
		if pc == nil {
			pc, err = s.ListenPacket()
			if err != nil {
				return err
			}
		}

		inst.wg.Add(2)
		go func(s Server, ln net.Listener, pc net.PacketConn, inst *Instance) {
			defer inst.wg.Done()

			go func() {
				errChan <- s.Serve(ln)
				defer inst.wg.Done()
			}()
			errChan <- s.ServePacket(pc)
		}(s, ln, pc, inst)

		inst.servers = append(inst.servers, ServerListener{server: s, listener: ln, packet: pc})
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
	if len(serverTypes) == 0 {
		return ServerType{}, fmt.Errorf("no server types plugged in")
	}
	if serverType == "" {
		if len(serverTypes) == 1 {
			for _, stype := range serverTypes {
				return stype, nil
			}
		}
		return ServerType{}, fmt.Errorf("multiple server types available; must choose one")
	}
	return ServerType{}, fmt.Errorf("unknown server type '%s'", serverType)
}

func loadServerBlocks(serverType, filename string, input io.Reader) ([]caddyfile.ServerBlock, error) {
	validDirectives := ValidDirectives(serverType)
	serverBlocks, err := caddyfile.Parse(filename, input, validDirectives)
	if err != nil {
		return nil, err
	}
	if len(serverBlocks) == 0 && serverTypes[serverType].DefaultInput != nil {
		newInput := serverTypes[serverType].DefaultInput()
		serverBlocks, err = caddyfile.Parse(newInput.Path(),
			bytes.NewReader(newInput.Body()), validDirectives)
		if err != nil {
			return nil, err
		}
	}
	return serverBlocks, nil
}

// Stop stops ALL servers. It blocks until they are all stopped.
// It does NOT execute shutdown callbacks, and it deletes all
// instances after stopping is completed. Do not re-use any
// references to old instances after calling Stop.
func Stop() error {
	// This awkward for loop is to avoid a deadlock since
	// inst.Stop() also acquires the instancesMu lock.
	for {
		instancesMu.Lock()
		if len(instances) == 0 {
			break
		}
		inst := instances[0]
		instancesMu.Unlock()
		if err := inst.Stop(); err != nil {
			log.Printf("[ERROR] Stopping %s: %v", inst.serverType, err)
		}
	}
	return nil
}

// IsLoopback returns true if the hostname of addr looks
// explicitly like a common local hostname. addr must only
// be a host or a host:port combination.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // happens if the addr is just a hostname
	}
	return host == "localhost" ||
		strings.Trim(host, "[]") == "::1" ||
		strings.HasPrefix(host, "127.")
}

// IsInternal returns true if the IP of addr
// belongs to a private network IP range. addr must only
// be an IP or an IP:port combination.
// Loopback addresses are considered false.
func IsInternal(addr string) bool {
	privateNetworks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // happens if the addr is just a hostname, missing port
		// if we encounter an error, the brackets need to be stripped
		// because SplitHostPort didn't do it for us
		host = strings.Trim(host, "[]")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, privateNetwork := range privateNetworks {
		_, ipnet, _ := net.ParseCIDR(privateNetwork)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// Started returns true if at least one instance has been
// started by this package. It never gets reset to false
// once it is set to true.
func Started() bool {
	mu.Lock()
	defer mu.Unlock()
	return started
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

// writePidFile writes the process ID to the file at PidFile.
// It does nothing if PidFile is not set.
func writePidFile() error {
	if PidFile == "" {
		return nil
	}
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	return ioutil.WriteFile(PidFile, pid, 0644)
}

type restartTriple struct {
	server   GracefulServer
	listener Listener
	packet   PacketConn
}

var (
	// instances is the list of running Instances.
	instances []*Instance

	// instancesMu protects instances.
	instancesMu sync.Mutex
)

var (
	// DefaultConfigFile is the name of the configuration file that is loaded
	// by default if no other file is specified.
	DefaultConfigFile = "Caddyfile"
)

// CtxKey is a value type for use with context.WithValue.
type CtxKey string
