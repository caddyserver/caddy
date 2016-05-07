// Package caddy implements the Caddy web server as a service
// in your own Go programs.
//
// To use this package, follow a few simple steps:
//
//   1. Set the AppName and AppVersion variables.
//   2. Call LoadCaddyfile() to get the Caddyfile.
//      You should pass in your own Caddyfile loader.
//   3. Call caddy.Start() to start Caddy, caddy.Stop()
//      to stop it, or caddy.Restart() to restart it.
//
// You should use caddy.Wait() to wait for all Caddy servers
// to quit before your process exits.
package caddy

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/caddy/https"
	"github.com/mholt/caddy/server"
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
	// caddyfile is the input configuration text used for this process
	caddyfile Input

	// caddyfileMu protects caddyfile during changes
	caddyfileMu sync.Mutex

	// servers is a list of all the currently-listening servers
	servers []*server.Server

	// serversMu protects the servers slice during changes
	serversMu sync.Mutex

	// wg is used to wait for all servers to shut down
	wg sync.WaitGroup

	// restartFds keeps the servers' sockets for graceful in-process restart
	restartFds = make(map[string]*os.File)

	// startedBefore should be set to true if caddy has been started
	// at least once (does not indicate whether currently running).
	startedBefore bool
)

const (
	// DefaultHost is the default host.
	DefaultHost = ""
	// DefaultPort is the default port.
	DefaultPort = "2015"
	// DefaultRoot is the default root folder.
	DefaultRoot = "."
)

// Start starts Caddy with the given Caddyfile. If cdyfile
// is nil, the LoadCaddyfile function will be called to get
// one.
//
// This function blocks until all the servers are listening.
func Start(cdyfile Input) (err error) {
	// Input must never be nil; try to load something
	if cdyfile == nil {
		cdyfile, err = LoadCaddyfile(nil)
		if err != nil {
			return err
		}
	}

	caddyfileMu.Lock()
	caddyfile = cdyfile
	caddyfileMu.Unlock()

	// load the server configs (activates Let's Encrypt)
	configs, err := loadConfigs(path.Base(cdyfile.Path()), bytes.NewReader(cdyfile.Body()))
	if err != nil {
		return err
	}

	// group virtualhosts by address
	groupings, err := arrangeBindings(configs)
	if err != nil {
		return err
	}

	// Start each server with its one or more configurations
	err = startServers(groupings)
	if err != nil {
		return err
	}

	showInitializationOutput(groupings)

	startedBefore = true

	return nil
}

// showInitializationOutput just outputs some basic information about
// what is being served to stdout, as well as any applicable, non-essential
// warnings for the user.
func showInitializationOutput(groupings bindingGroup) {
	// Show initialization output
	if !Quiet && !IsRestart() {
		var checkedFdLimit bool
		for _, group := range groupings {
			for _, conf := range group.Configs {
				// Print address of site
				fmt.Println(conf.Address())

				// Note if non-localhost site resolves to loopback interface
				if group.BindAddr.IP.IsLoopback() && !isLocalhost(conf.Host) {
					fmt.Printf("Notice: %s is only accessible on this machine (%s)\n",
						conf.Host, group.BindAddr.IP.String())
				}
				if !checkedFdLimit && !group.BindAddr.IP.IsLoopback() && !isLocalhost(conf.Host) {
					checkFdlimit()
					checkedFdLimit = true
				}
			}
		}
	}
}

// startServers starts all the servers in groupings,
// taking into account whether or not this process is
// from a graceful restart or not. It blocks until
// the servers are listening.
func startServers(groupings bindingGroup) error {
	var startupWg sync.WaitGroup
	errChan := make(chan error, len(groupings)) // must be buffered to allow Serve functions below to return if stopped later

	for _, group := range groupings {
		s, err := server.New(group.BindAddr.String(), group.Configs, GracefulTimeout)
		if err != nil {
			return err
		}
		s.HTTP2 = HTTP2
		s.ReqCallback = https.RequestCallback // ensures we can solve ACME challenges while running
		if s.OnDemandTLS {
			s.TLSConfig.GetCertificate = https.GetOrObtainCertificate // TLS on demand -- awesome!
		} else {
			s.TLSConfig.GetCertificate = https.GetCertificate
		}

		var ln server.ListenerFile
		if len(restartFds) > 0 {
			// Reuse the listeners for in-process restart
			if file, ok := restartFds[s.Addr]; ok {
				fln, err := net.FileListener(file)
				if err != nil {
					return err
				}

				ln, ok = fln.(server.ListenerFile)
				if !ok {
					return errors.New("listener for " + s.Addr + " was not a ListenerFile")
				}

				file.Close()
				delete(restartFds, s.Addr)
			}
		}

		wg.Add(1)
		go func(s *server.Server, ln server.ListenerFile) {
			defer wg.Done()

			// run startup functions that should only execute when
			// the original parent process is starting.
			if !startedBefore {
				err := s.RunFirstStartupFuncs()
				if err != nil {
					errChan <- err
					return
				}
			}

			// start the server
			if ln != nil {
				errChan <- s.Serve(ln)
			} else {
				errChan <- s.ListenAndServe()
			}
		}(s, ln)

		startupWg.Add(1)
		go func(s *server.Server) {
			defer startupWg.Done()
			s.WaitUntilStarted()
		}(s)

		serversMu.Lock()
		servers = append(servers, s)
		serversMu.Unlock()
	}

	// Close the remaining (unused) file descriptors to free up resources
	if len(restartFds) > 0 {
		for key, file := range restartFds {
			file.Close()
			delete(restartFds, key)
		}
	}

	// Wait for all servers to finish starting
	startupWg.Wait()

	// Return the first error, if any
	select {
	case err := <-errChan:
		// "use of closed network connection" is normal if it was a graceful shutdown
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			return err
		}
	default:
	}

	return nil
}

// Stop stops all servers. It blocks until they are all stopped.
// It does NOT execute shutdown callbacks that may have been
// configured by middleware (they must be executed separately).
func Stop() error {
	https.Deactivate()

	serversMu.Lock()
	for _, s := range servers {
		if err := s.Stop(); err != nil {
			log.Printf("[ERROR] Stopping %s: %v", s.Addr, err)
		}
	}
	servers = []*server.Server{} // don't reuse servers
	serversMu.Unlock()

	return nil
}

// Wait blocks until all servers are stopped.
func Wait() {
	wg.Wait()
}

// LoadCaddyfile loads a Caddyfile by calling the user's loader function,
// and if that returns nil, then this function resorts to the default
// configuration. Thus, if there are no other errors, this function
// always returns at least the default Caddyfile.
func LoadCaddyfile(loader func() (Input, error)) (cdyfile Input, err error) {
	// Try user's loader
	if cdyfile == nil && loader != nil {
		cdyfile, err = loader()
	}

	// Otherwise revert to default
	if cdyfile == nil {
		cdyfile = DefaultInput()
	}

	return
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
	caddyfileMu.Lock()
	defer caddyfileMu.Unlock()
	return caddyfile
}

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

	// IsFile returns true if the original input was a file on the file system
	// that could be loaded again later if requested.
	IsFile() bool
}
