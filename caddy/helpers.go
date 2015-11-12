package caddy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/mholt/caddy/caddy/letsencrypt"
)

func init() {
	letsencrypt.OnChange = func() error { return Restart(nil) }
}

// isLocalhost returns true if host looks explicitly like a localhost address.
func isLocalhost(host string) bool {
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
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

// signalParent tells the parent our status using pipe at index 3.
// If this process is not a restart, this function does nothing.
// Calling this is vital so that the parent process can unblock and
// either continue running or kill itself.
func signalParent(success bool) {
	if IsRestart() {
		ppipe := os.NewFile(3, "") // parent is listening on pipe at index 3
		if success {
			// Tell parent process that we're OK so it can quit now
			ppipe.Write([]byte("success"))
		}
		ppipe.Close()
	}
}

// caddyfileGob maps bind address to index of the file descriptor
// in the Files array passed to the child process. It also contains
// the caddyfile contents. Used only during graceful restarts.
type caddyfileGob struct {
	ListenerFds map[string]uintptr
	Caddyfile   Input
}

// IsRestart returns whether this process is, according
// to env variables, a fork as part of a graceful restart.
func IsRestart() bool {
	return os.Getenv("CADDY_RESTART") == "true"
}

// writePidFile writes the process ID to the file at PidFile, if specified.
func writePidFile() error {
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	return ioutil.WriteFile(PidFile, pid, 0644)
}

// CaddyfileInput represents a Caddyfile as input
// and is simply a convenient way to implement
// the Input interface.
type CaddyfileInput struct {
	Filepath string
	Contents []byte
	RealFile bool
}

// Body returns c.Contents.
func (c CaddyfileInput) Body() []byte { return c.Contents }

// Path returns c.Filepath.
func (c CaddyfileInput) Path() string { return c.Filepath }

// IsFile returns true if the original input was a real file on the file system.
func (c CaddyfileInput) IsFile() bool { return c.RealFile }
