// +build !windows,!plan9,!nacl

package caddy

import (
	"fmt"
	"os"
	"syscall"
)

// SetRlimitOpenFiles set rlimit for NOFILE
// setcap cap_sys_resource+ep for the caddy binary is needed
// if it is executed as non-root user
func SetRlimitOpenFiles(limit uint64) {
	rlimit := &syscall.Rlimit{}

	rlimit.Max = limit
	rlimit.Cur = limit

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, rlimit); err != nil {
		if os.Getuid() != 0 {
			fmt.Printf("Failed to set NOFILE rlimit. Capability not set. Please ")
			fmt.Println("execute: sudo setcap cap_sys_resource+ep caddy")
			return
		}

		fmt.Printf("WARNING !! Setting NOFILE rlimit failed with error: %s\n", err)
	}
}
