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

//go:build !windows

package caddy

import (
	"os"
	"path/filepath"
)

// FastAbs is an optimized version of filepath.Abs for Unix systems,
// since we don't expect the working directory to ever change once
// Caddy is running. Avoid the os.Getwd() syscall overhead.
// It's overall the same as stdlib's implementation, the difference
// being cached working directory.
func FastAbs(path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	if wderr != nil {
		return "", wderr
	}
	return filepath.Join(wd, path), nil
}

var wd, wderr = os.Getwd()
