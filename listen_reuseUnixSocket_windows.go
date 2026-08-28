// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package caddy

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

var errUnixSocketAlreadyInUse = errors.New("unix socket is already in use by another process")

func reuseUnixSocket(network, addr string) (any, error) {
	if !IsUnixNetwork(network) {
		return nil, nil
	}

	// Note: This is here mainly for proper compatibility, because Unix sockets with abstract names are in an interesting limbo state on Windows:
	// Go already translates `@` characters to `\0` for Windows: https://github.com/golang/go/blob/65d5c5f6dd8aa7b221cff6ec3f5101ea2e5f3efa/src/syscall/syscall_windows.go#L910
	// ...but there still is an open issue about the fact that this is not properly supported: https://github.com/microsoft/WSL/issues/4240#issuecomment-620805115
	// The main issue is that the original announcement proclaimed support for this feature, but it was (apparently) never implemented: https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
	isAbstractUnixSocket := strings.HasPrefix(addr, "@")

	if isAbstractUnixSocket {
		// Abstract Unix sockets do not require us to remove stale socket files.
		return nil, nil
	}

	// On Windows, we're using the `fakeCloseListener` wrappers around a single, ever-living listener.
	// So, if there's an active listener entry in the pool, we're the current owner of the Unix socket file.
	_, socketBelongsToCurrentProcess := listenerPool.References(listenerKey(network, addr))

	if socketBelongsToCurrentProcess {
		// Reuse/cleanup is entirely handled by the refcounting mechanism in `listenerPool`.
		return nil, nil
	}

	// If the socket file does not exist or has no backing server process, this will fail instantly.
	connection, err := net.DialTimeout("unix", addr, 10*time.Millisecond)

	if err == nil {
		connection.Close()
		return nil, fmt.Errorf("cannot reuse socket %v: %w", addr, errUnixSocketAlreadyInUse)
	}

	// Windows returns this error code both if the socket file does not exist and if it isn't backed by a server process anymore.
	// See: https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2#wsaeconnrefused
	const WSAECONNREFUSED syscall.Errno = 10061

	var errno syscall.Errno
	hasNoListeningServerProcess := errors.As(err, &errno) && errno == WSAECONNREFUSED

	if !hasNoListeningServerProcess {
		return nil, fmt.Errorf("cannot reuse socket %v: %w", addr, errUnixSocketAlreadyInUse)
	}

	// If the socket file exists, it hasn't been created by our process, and it seemingly
	// isn't backed by a server process anymore. Try to delete it so we can bind to it later.
	err = os.Remove(addr)

	if err == nil {
		return nil, nil
	} else if errors.Is(err, fs.ErrNotExist) {
		// Either the file didn't exist in the first place, or it was deleted before we were able to.
		return nil, nil
	} else {
		// We failed to delete the file. Likely, it belongs to another (active) process.
		return nil, err
	}
}
