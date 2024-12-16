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

package caddycmd

import (
	"os"
	"path/filepath"
	"syscall"
)

// removeCaddyBinary removes the Caddy binary at the given path.
//
// On Windows, this uses a syscall to indirectly remove the file,
// because otherwise we get an "Access is denied." error when trying
// to delete the binary while Caddy is still running and performing
// the upgrade. "cmd.exe /C" executes a command specified by the
// following arguments, i.e. "del" which will run as a separate process,
// which avoids the "Access is denied." error.
func removeCaddyBinary(path string) error {
	var sI syscall.StartupInfo
	var pI syscall.ProcessInformation
	argv, err := syscall.UTF16PtrFromString(filepath.Join(os.Getenv("windir"), "system32", "cmd.exe") + " /C del " + path)
	if err != nil {
		return err
	}
	return syscall.CreateProcess(nil, argv, nil, nil, true, 0, nil, nil, &sI, &pI)
}
