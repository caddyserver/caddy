// Package app holds application-global state to make it accessible
// by other packages in the application.
//
// This package differs from config in that the things in app aren't
// really related to server configuration.
package app

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/mholt/caddy/server"
)

const (
	// Name is the program name
	Name = "Caddy"

	// Version is the program version
	Version = "0.7.6"
)

var (
	// Servers is a list of all the currently-listening servers
	Servers []*server.Server

	// ServersMutex protects the Servers slice during changes
	ServersMutex sync.Mutex

	// Wg is used to wait for all servers to shut down
	Wg sync.WaitGroup

	// HTTP2 indicates whether HTTP2 is enabled or not
	HTTP2 bool // TODO: temporary flag until http2 is standard

	// Quiet mode hides non-error initialization output
	Quiet bool
)

func init() {
	go func() {
		// Wait for signal
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, os.Kill) // TODO: syscall.SIGTERM? Or that should not run callbacks...
		<-interrupt

		// Run shutdown callbacks
		var exitCode int
		ServersMutex.Lock()
		errs := server.ShutdownCallbacks(Servers)
		ServersMutex.Unlock()
		if len(errs) > 0 {
			for _, err := range errs {
				log.Println(err)
			}
			exitCode = 1
		}
		os.Exit(exitCode)
	}()
}

// Restart restarts the entire application; gracefully with zero
// downtime if on a POSIX-compatible system, or forcefully if on
// Windows but with imperceptibly-short downtime.
//
// The restarted application will use caddyfile as its input
// configuration; it will not look elsewhere for the config
// to use.
func Restart(caddyfile []byte) error {
	// TODO: This is POSIX-only right now; also, os.Args[0] is required!
	// TODO: Pipe the Caddyfile to stdin of child!
	// TODO: Before stopping this process, verify child started successfully (valid Caddyfile, etc)

	// Tell the child that it's a restart
	os.Setenv("CADDY_RESTART", "true")

	// Pass along current environment and file descriptors to child.
	// We pass along the file descriptors explicitly to ensure proper
	// order, since losing the original order will break the child.
	fds := []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()}

	// Now add file descriptors of the sockets
	ServersMutex.Lock()
	for _, s := range Servers {
		fds = append(fds, s.ListenerFd())
	}
	ServersMutex.Unlock()

	// Fork the process with the current environment and file descriptors
	execSpec := &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: fds,
	}
	fork, err := syscall.ForkExec(os.Args[0], os.Args, execSpec)
	if err != nil {
		log.Println("FORK ERR:", err, fork)
	}

	// Child process is listening now; we can stop all our servers here.
	ServersMutex.Lock()
	for _, s := range Servers {
		go s.Stop() // TODO: error checking/reporting
	}
	ServersMutex.Unlock()

	return err
}

// SetCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
func SetCPU(cpu string) error {
	var numCPU int

	availCPU := runtime.NumCPU()

	if strings.HasSuffix(cpu, "%") {
		// Percent
		var percent float32
		pctStr := cpu[:len(cpu)-1]
		pctInt, err := strconv.Atoi(pctStr)
		if err != nil || pctInt < 1 || pctInt > 100 {
			return errors.New("invalid CPU value: percentage must be between 1-100")
		}
		percent = float32(pctInt) / 100
		numCPU = int(float32(availCPU) * percent)
	} else {
		// Number
		num, err := strconv.Atoi(cpu)
		if err != nil || num < 1 {
			return errors.New("invalid CPU value: provide a number or percent greater than 0")
		}
		numCPU = num
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	runtime.GOMAXPROCS(numCPU)
	return nil
}

// DataFolder returns the path to the folder
// where the application may store data. This
// currently resolves to ~/.caddy
func DataFolder() string {
	return filepath.Join(userHomeDir(), ".caddy")
}

// userHomeDir returns the user's home directory according to
// environment variables.
//
// Credit: http://stackoverflow.com/a/7922977/1048862
func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}
