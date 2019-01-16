// Command aesnicheck queries the CPU for AES-NI support. If AES-NI is supported,
// aesnicheck will print "supported" and exit with a status of 0. If AES-NI is
// not supported, aesnicheck will print "unsupported" and exit with a status of
// -1.
package main

import (
	"fmt"
	"os"

	"github.com/codahale/aesnicheck"
)

func main() {
	if aesnicheck.HasAESNI() {
		fmt.Println("supported")
		os.Exit(0)
	} else {
		fmt.Println("unsupported")
		os.Exit(-1)
	}
}
