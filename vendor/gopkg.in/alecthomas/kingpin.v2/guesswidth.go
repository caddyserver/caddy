// +build appengine !linux,!freebsd,!darwin,!dragonfly,!netbsd,!openbsd

package kingpin

import "io"

func guessWidth(w io.Writer) int {
	return 80
}
