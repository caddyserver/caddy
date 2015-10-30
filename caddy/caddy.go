// Package caddy implements the Caddy web server as a service.
//
// To use this package, follow a few simple steps:
//
//   1. Set the AppName and AppVersion variables.
//   2. Call LoadCaddyfile() to get the Caddyfile (it
//      might have been piped in as part of a restart).
//      You should pass in your own Caddyfile loader.
//   3. Call caddy.Start() to start Caddy, caddy.Stop()
//      to stop it, or caddy.Restart() to restart it.
//
// You should use caddy.Wait() to wait for all Caddy servers
// to quit before your process exits.
//
// Importing this package has the side-effect of trapping
// SIGINT on all platforms and SIGUSR1 on not-Windows systems.
// It has to do this in order to perform shutdowns or reloads.
package caddy

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/mholt/caddy/caddy/letsencrypt"
	"github.com/mholt/caddy/server"
)

// Configurable application parameters
var (
	// The name and version of the application.
	AppName, AppVersion string

	// If true, initialization will not show any output.
	Quiet bool

	// DefaultInput is the default configuration to use when config input is empty or missing.
	DefaultInput = CaddyfileInput{
		Contents: []byte(fmt.Sprintf("%s:%s\nroot %s", DefaultHost, DefaultPort, DefaultRoot)),
	}

	// HTTP2 indicates whether HTTP2 is enabled or not
	HTTP2 bool // TODO: temporary flag until http2 is standard
)

var (
	// caddyfile is the input configuration text used for this process
	caddyfile Input

	// caddyfileMu protects caddyfile during changes
	caddyfileMu sync.Mutex

	// incompleteRestartErr occurs if this process is a fork
	// of the parent but no Caddyfile was piped in
	incompleteRestartErr = errors.New("cannot finish restart successfully")

	// servers is a list of all the currently-listening servers
	servers []*server.Server

	// serversMu protects the servers slice during changes
	serversMu sync.Mutex

	// wg is used to wait for all servers to shut down
	wg sync.WaitGroup

	// loadedGob is used if this is a child process as part of
	// a graceful restart; it is used to map listeners to their
	// index in the list of inherited file descriptors. This
	// variable is not safe for concurrent access.
	loadedGob caddyfileGob
)

const (
	DefaultHost = "0.0.0.0"
	DefaultPort = "2015"
	DefaultRoot = "."
)

// Start starts Caddy with the given Caddyfile. If cdyfile
// is nil or the process is forked from a parent as part of
// a graceful restart, Caddy will check to see if Caddyfile
// was piped from stdin and use that. It blocks until all the
// servers are listening.
//
// If this process is a fork and no Caddyfile was piped in,
// an error will be returned (the Restart() function does this
// for you automatically). If this process is NOT a fork and
// cdyfile is nil, a default configuration will be assumed.
// In any case, an error is returned if Caddy could not be
// started.
func Start(cdyfile Input) error {
	// TODO: What if already started -- is that an error?

	var err error

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

	// load the server configs
	configs, err := load(path.Base(cdyfile.Path()), bytes.NewReader(cdyfile.Body()))
	if err != nil {
		return err
	}

	// secure all the things
	configs, err = letsencrypt.Activate(configs)
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

	// Close remaining file descriptors we may have inherited that we don't need
	if isRestart() {
		for _, fdIndex := range loadedGob.ListenerFds {
			file := os.NewFile(fdIndex, "")
			fln, err := net.FileListener(file)
			if err == nil {
				fln.Close()
			}
		}
	}

	// Show initialization output
	if !Quiet && !isRestart() {
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

	// Tell parent process that we got this
	if isRestart() {
		ppipe := os.NewFile(3, "") // parent is listening on pipe at index 3
		ppipe.Write([]byte("success"))
		ppipe.Close()
	}

	return nil
}

// startServers starts all the servers in groupings,
// taking into account whether or not this process is
// a child from a graceful restart or not. It blocks
// until the servers are listening.
func startServers(groupings Group) error {
	var startupWg sync.WaitGroup

	for _, group := range groupings {
		s, err := server.New(group.BindAddr.String(), group.Configs)
		if err != nil {
			log.Fatal(err)
		}
		s.HTTP2 = HTTP2 // TODO: This setting is temporary

		var ln server.ListenerFile
		if isRestart() {
			// Look up this server's listener in the map of inherited file descriptors;
			// if we don't have one, we must make a new one.
			if fdIndex, ok := loadedGob.ListenerFds[s.Addr]; ok {
				file := os.NewFile(fdIndex, "")

				fln, err := net.FileListener(file)
				if err != nil {
					log.Fatal(err)
				}

				ln, ok = fln.(server.ListenerFile)
				if !ok {
					log.Fatal("listener was not a ListenerFile")
				}

				delete(loadedGob.ListenerFds, s.Addr) // mark it as used
			}
		}

		wg.Add(1)
		go func(s *server.Server, ln server.ListenerFile) {
			defer wg.Done()

			if ln != nil {
				err = s.Serve(ln)
			} else {
				err = s.ListenAndServe()
			}

			// "use of closed network connection" is normal if doing graceful shutdown...
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				if isRestart() {
					log.Fatal(err)
				} else {
					log.Println(err)
				}
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

	startupWg.Wait()

	return nil
}

// Stop stops all servers. It blocks until they are all stopped.
// It does NOT execute shutdown callbacks that may have been
// configured by middleware (they are executed on SIGINT).
func Stop() error {
	letsencrypt.Deactivate()

	serversMu.Lock()
	for _, s := range servers {
		s.Stop() // TODO: error checking/reporting?
	}
	servers = []*server.Server{} // don't reuse servers
	serversMu.Unlock()

	return nil
}

// Wait blocks until all servers are stopped.
func Wait() {
	wg.Wait()
}

// LoadCaddyfile loads a Caddyfile in a way that prioritizes
// reading from stdin pipe; otherwise it calls loader to load
// the Caddyfile. If loader does not return a Caddyfile, the
// default one will be returned. Thus, if there are no other
// errors, this function always returns at least the default
// Caddyfile (not the previously-used Caddyfile).
func LoadCaddyfile(loader func() (Input, error)) (cdyfile Input, err error) {
	// If we are a fork, finishing the restart is highest priority;
	// piped input is required in this case.
	if isRestart() {
		err := gob.NewDecoder(os.Stdin).Decode(&loadedGob)
		if err != nil {
			return nil, err
		}
		cdyfile = loadedGob.Caddyfile
	}

	// Otherwise, we first try to get from stdin pipe
	if cdyfile == nil {
		cdyfile, err = CaddyfileFromPipe(os.Stdin)
		if err != nil {
			return nil, err
		}
	}

	// No piped input, so try the user's loader instead
	if cdyfile == nil && loader != nil {
		cdyfile, err = loader()
	}

	// Otherwise revert to default
	if cdyfile == nil {
		cdyfile = DefaultInput
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
