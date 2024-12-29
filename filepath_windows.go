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

package caddy

import (
	"path/filepath"
)

// FastAbs can't be optimized on Windows because there
// are special file paths that require the use of syscall.FullPath
// to handle correctly.
// Just call stdlib's implementation which uses that function.
func FastAbs(path string) (string, error) {
	return filepath.Abs(path)
}
