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

package internal

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// SplitUnixSocketPermissionsBits takes a unix socket address in the
// unusual "path|bits" format (e.g. /run/caddy.sock|0222) and tries
// to split it into socket path (host) and permissions bits (port).
// Colons (":") can't be used as separator, as socket paths on Windows
// may include a drive letter (e.g. `unix/c:\absolute\path.sock`).
// Permission bits will default to 0200 if none are specified.
// Throws an error, if the first carrying bit does not
// include write perms (e.g. `0422` or `022`).
// Symbolic permission representation (e.g. `u=w,g=w,o=w`)
// is not supported and will throw an error for now!
func SplitUnixSocketPermissionsBits(addr string) (path string, fileMode fs.FileMode, err error) {
	addrSplit := strings.SplitN(addr, "|", 2)

	if len(addrSplit) == 2 {
		// parse octal permission bit string as uint32
		fileModeUInt64, err := strconv.ParseUint(addrSplit[1], 8, 32)
		if err != nil {
			return "", 0, fmt.Errorf("could not parse octal permission bits in %s: %v", addr, err)
		}
		fileMode = fs.FileMode(fileModeUInt64)

		// FileMode.String() returns a string like `-rwxr-xr--` for `u=rwx,g=rx,o=r` (`0754`)
		if string(fileMode.String()[2]) != "w" {
			return "", 0, fmt.Errorf("owner of the socket requires '-w-' (write, octal: '2') permissions at least; got '%s' in %s", fileMode.String()[1:4], addr)
		}

		return addrSplit[0], fileMode, nil
	}

	// default to 0200 (symbolic: `u=w,g=,o=`)
	// if no permission bits are specified
	return addr, 0o200, nil
}
