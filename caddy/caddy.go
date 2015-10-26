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
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

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

// caddyfileGob maps bind address to index of the file descriptor
// in the Files array passed to the child process. It also contains
// the caddyfile contents.
type caddyfileGob struct {
	ListenerFds map[string]uintptr
	Caddyfile   []byte
}

// Start starts Caddy with the given Caddyfile. If cdyfile
// is nil or the process is forked from a parent as part of
// a graceful restart, Caddy will check to see if Caddyfile
// was piped from stdin and use that.
//
// If this process is a fork and no Caddyfile was piped in,
// an error will be returned. If this process is NOT a fork
// and cdyfile is nil, a default configuration will be assumed.
// In any case, an error is returned if Caddy could not be
// started.
func Start(cdyfile Input) error {
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

	groupings, err := Load(path.Base(cdyfile.Path()), bytes.NewReader(cdyfile.Body()))
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
		file := os.NewFile(3, "")
		file.Write([]byte("success"))
		file.Close()
	}

	return nil
}

// startServers starts all the servers in groupings,
// taking into account whether or not this process is
// a child from a graceful restart or not.
func startServers(groupings Group) error {
	for i, group := range groupings {
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
		go func(s *server.Server, i int, ln server.ListenerFile) {
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
		}(s, i, ln)

		serversMu.Lock()
		servers = append(servers, s)
		serversMu.Unlock()
	}
	return nil
}

// isLocalhost returns true if the string looks explicitly like a localhost address.
func isLocalhost(s string) bool {
	return s == "localhost" || s == "::1" || strings.HasPrefix(s, "127.")
}

// checkFdlimit issues a warning if the OS max file descriptors is below a recommended minimum.
func checkFdlimit() {
	const min = 4096

	// Warn if ulimit is too low for production sites
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		out, err := exec.Command("sh", "-c", "ulimit -n").Output() // use sh because ulimit isn't in Linux $PATH
		if err == nil {
			// Note that an error here need not be reported
			lim, err := strconv.Atoi(string(bytes.TrimSpace(out)))
			if err == nil && lim < min {
				fmt.Printf("Warning: File descriptor limit %d is too low for production sites. At least %d is recommended. Set with \"ulimit -n %d\".\n", lim, min, min)
			}
		}
	}
}

func Stop() error {
	serversMu.Lock()
	for _, s := range servers {
		s.Stop() // TODO: error checking/reporting?
	}
	serversMu.Unlock()
	return nil
}

// Restart restarts the entire application; gracefully with zero
// downtime if on a POSIX-compatible system, or forcefully if on
// Windows but with imperceptibly-short downtime.
//
// The restarted application will use newCaddyfile as its input
// configuration. If newCaddyfile is nil, the current (existing)
// Caddyfile configuration will be used.
func Restart(newCaddyfile Input) error {
	if newCaddyfile == nil {
		caddyfileMu.Lock()
		newCaddyfile = caddyfile
		caddyfileMu.Unlock()
	}

	if runtime.GOOS == "windows" {
		err := Stop()
		if err != nil {
			return err
		}
		err = Start(newCaddyfile)
		if err != nil {
			return err
		}
		return nil
	}

	if len(os.Args) == 0 { // this should never happen, but just in case...
		os.Args = []string{""}
	}

	// Tell the child that it's a restart
	os.Setenv("CADDY_RESTART", "true")

	// Prepare our payload to the child process
	cdyfileGob := caddyfileGob{
		ListenerFds: make(map[string]uintptr),
		Caddyfile:   newCaddyfile.Body(),
	}

	// Prepare a pipe to the fork's stdin so it can get the Caddyfile
	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return err
	}

	// Prepare a pipe that the child process will use to communicate
	// its success or failure with us, the parent
	sigrpipe, sigwpipe, err := os.Pipe()
	if err != nil {
		return err
	}

	// Pass along current environment and file descriptors to child.
	// Ordering here is very important: stdin, stdout, stderr, sigpipe,
	// and then the listener file descriptors (in order).
	fds := []uintptr{rpipe.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), sigwpipe.Fd()}

	// Now add file descriptors of the sockets
	serversMu.Lock()
	for i, s := range servers {
		fds = append(fds, s.ListenerFd())
		cdyfileGob.ListenerFds[s.Addr] = uintptr(4 + i) // 4 fds come before any of the listeners
	}
	serversMu.Unlock()

	// Fork the process with the current environment and file descriptors
	execSpec := &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: fds,
	}
	_, err = syscall.ForkExec(os.Args[0], os.Args, execSpec)
	if err != nil {
		return err
	}

	// Feed it the Caddyfile
	err = gob.NewEncoder(wpipe).Encode(cdyfileGob)
	if err != nil {
		return err
	}
	wpipe.Close()

	// Wait for child process to signal success or fail
	sigwpipe.Close() // close our copy of the write end of the pipe
	answer, err := ioutil.ReadAll(sigrpipe)
	if err != nil || len(answer) == 0 {
		log.Println("restart: child failed to answer; changes not applied")
		return incompleteRestartErr
	}

	// Child process is listening now; we can stop all our servers here.
	return Stop()
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
// Caddyfile.
func LoadCaddyfile(loader func() (Input, error)) (cdyfile Input, err error) {
	// If we are a fork, finishing the restart is highest priority;
	// piped input is required in this case.
	if isRestart() {
		err := gob.NewDecoder(os.Stdin).Decode(&loadedGob)
		if err != nil {
			return nil, err
		}
		cdyfile = CaddyfileInput{
			Filepath: os.Stdin.Name(),
			Contents: loadedGob.Caddyfile,
		}
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

// Caddyfile returns the current Caddyfile
func Caddyfile() Input {
	caddyfileMu.Lock()
	defer caddyfileMu.Unlock()
	return caddyfile
}

// isRestart returns whether this process is, according
// to env variables, a fork as part of a graceful restart.
func isRestart() bool {
	return os.Getenv("CADDY_RESTART") == "true"
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

// CaddyfileInput represents a Caddyfile as input
// and is simply a convenient way to implement
// the Input interface.
type CaddyfileInput struct {
	Filepath string
	Contents []byte
}

// Body returns c.Contents.
func (c CaddyfileInput) Body() []byte { return c.Contents }

// Path returns c.Filepath.
func (c CaddyfileInput) Path() string { return c.Filepath }

func init() {
	letsencrypt.OnRenew = func() error { return Restart(nil) }

	// Trap signals
	go func() {
		shutdown, reload := make(chan os.Signal, 1), make(chan os.Signal, 1)
		signal.Notify(shutdown, os.Interrupt, os.Kill) // quit the process
		signal.Notify(reload, syscall.SIGUSR1)         // reload configuration

		for {
			select {
			case <-shutdown:
				var exitCode int

				serversMu.Lock()
				errs := server.ShutdownCallbacks(servers)
				serversMu.Unlock()
				if len(errs) > 0 {
					for _, err := range errs {
						log.Println(err)
					}
					exitCode = 1
				}
				os.Exit(exitCode)

			case <-reload:
				err := Restart(nil)
				if err != nil {
					log.Println(err)
				}
			}
		}
	}()
}
