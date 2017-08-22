// +build !windows,!plan9,!nacl

package caddy

import (
	"fmt"
	"syscall"
)

// checkFdlimit issues a warning if the OS limit for
// max file descriptors is below a recommended minimum.
func checkFdlimit() {
	const min = 8192

	// Warn if ulimit is too low for production sites
	rlimit := &syscall.Rlimit{}
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rlimit)
	if err == nil && rlimit.Cur < min {
		fmt.Printf("WARNING: File descriptor limit %d is too low for production servers. "+
			"At least %d is recommended. Fix with \"ulimit -n %d\".\n", rlimit.Cur, min, min)
	}

}
