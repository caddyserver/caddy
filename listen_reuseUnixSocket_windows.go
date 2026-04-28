//go:build windows

package caddy

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

func reuseUnixSocket(network, addr string) (any, error) {
	if !IsUnixNetwork(network) {
		return nil, nil
	}

	//Note: This is here mainly for proper compatibility, because Unix sockets with abstract names are in an interesting limbo state on Windows:
	//Golang already translates `@` characters to `\0` for Windows: https://github.com/golang/go/blob/65d5c5f6dd8aa7b221cff6ec3f5101ea2e5f3efa/src/syscall/syscall_windows.go#L910
	//...but there still is an open issue about the fact that this is not properly supported: https://github.com/microsoft/WSL/issues/4240#issuecomment-620805115
	//The main issue is that the original announcement proclaimed support for this feature, but it was (apparently) never implemented: https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
	isAbstractUnixSocket := strings.HasPrefix(addr, "@")

	if isAbstractUnixSocket {
		//Abstract Unix sockets do not require us to remove stale socket files.
		return nil, nil
	}

	//On Windows, we're using the `fakeCloseListener` wrappers around a single, ever-living listener.
	//So, if there's an active listener entry in the pool, we're the current owner of the Unix socket file.
	_, socketBelongsToCurrentProcess := listenerPool.References(listenerKey(network, addr))

	if socketBelongsToCurrentProcess {
		//Reuse/cleanup is entirely handled by the refcounting mechanism in `listenerPool`.
		return nil, nil
	}

	//Another process created this socket file; try to delete it so we can bind to it later.
	//This allows us to start up even after a crash (that left an orphaned socket file behind).
	err := os.Remove(addr)

	if err == nil {
		return nil, nil
	} else if errors.Is(err, fs.ErrNotExist) {
		//Either the file didn't exist in the first place, or it was deleted before we were able to.
		return nil, nil
	} else {
		//We failed to delete the file. Likely, it belongs to another (active) process.
		return nil, err
	}
}
