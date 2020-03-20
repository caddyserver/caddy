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

// +build gofuzz
// +build gofuzz_libfuzzer

package caddyfile

func FuzzParseCaddyfile(data []byte) (score int) {
	sb, err := Parse("Caddyfile", data)
	if err != nil {
		// if both an error is received and some ServerBlocks,
		// then the parse was able to parse partially. Mark this
		// result as interesting to push the fuzzer further through the parser.
		if sb != nil && len(sb) > 0 {
			return 1
		}
		return 0
	}
	return 1
}
