// +build !windows

package caddy

import (
	"encoding/gob"
	"io/ioutil"
	"log"
	"os"
	"syscall"
)

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
