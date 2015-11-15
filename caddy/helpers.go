package caddy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

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

// signalSuccessToParent tells the parent our status using pipe at index 3.
// If this process is not a restart, this function does nothing.
// Calling this function once this process has successfully initialized
// is vital so that the parent process can unblock and kill itself.
// This function is idempotent; it executes at most once per process.
func signalSuccessToParent() {
	signalParentOnce.Do(func() {
		if IsRestart() {
			ppipe := os.NewFile(3, "")               // parent is reading from pipe at index 3
			_, err := ppipe.Write([]byte("success")) // we must send some bytes to the parent
			if err != nil {
				log.Printf("[ERROR] Communicating successful init to parent: %v", err)
			}
			ppipe.Close()
		}
	})
}

// signalParentOnce is used to make sure that the parent is only
// signaled once; doing so more than once breaks whatever socket is
// at fd 4 (the reason for this is still unclear - to reproduce,
// call Stop() and Start() in succession at least once after a
// restart, then try loading first host of Caddyfile in the browser).
// Do not use this directly - call signalSuccessToParent instead.
var signalParentOnce sync.Once

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
