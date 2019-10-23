package caddy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// pledge invokes the pledge system call with the associated promises. It passes `NULL` to the
// `execpromises` argument.
func pledge() {
	const (
		// Allows things such as read, write, and socket operations.
		io = "stdio"
		// Allows setting up a socket to listen.
		net = "inet"
		// Allows calling `setrlimit`.
		limit = "proc"
	)

	promises := strings.Join([]string{io, net, limit}, " ")
	err := unix.PledgePromises(promises)
	if err != nil {
		fmt.Printf("WARNING: Error calling pledge: %s", err)
	}
}
