// +build !appengine,linux freebsd darwin dragonfly netbsd openbsd

package kingpin

import (
	"io"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func guessWidth(w io.Writer) int {
	// check if COLUMNS env is set to comply with
	// http://pubs.opengroup.org/onlinepubs/009604499/basedefs/xbd_chap08.html
	colsStr := os.Getenv("COLUMNS")
	if colsStr != "" {
		if cols, err := strconv.Atoi(colsStr); err == nil {
			return cols
		}
	}

	if t, ok := w.(*os.File); ok {
		fd := t.Fd()
		var dimensions [4]uint16

		if _, _, err := syscall.Syscall6(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(syscall.TIOCGWINSZ),
			uintptr(unsafe.Pointer(&dimensions)),
			0, 0, 0,
		); err == 0 {
			return int(dimensions[1])
		}
	}
	return 80
}
