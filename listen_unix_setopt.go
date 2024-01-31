//go:build unix && !freebsd && !solaris

package caddy

import "golang.org/x/sys/unix"

const unixSOREUSEPORT = unix.SO_REUSEPORT
