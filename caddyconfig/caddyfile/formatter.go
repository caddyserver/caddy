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

package caddyfile

import (
	"bytes"
	"io"
	"unicode"
)

// Format formats a Caddyfile to conventional standards.
func Format(body []byte) []byte {
	reader := bytes.NewReader(body)
	result := new(bytes.Buffer)

	var (
		commented,
		quoted,
		escaped,
		environ,
		lineBegin bool

		firstIteration = true

		indentation = 0

		prev,
		curr,
		next rune

		err error
	)

	insertTabs := func(num int) {
		for tabs := num; tabs > 0; tabs-- {
			result.WriteRune('\t')
		}
	}

	for {
		prev = curr
		curr = next

		if curr < 0 {
			break
		}

		next, _, err = reader.ReadRune()
		if err != nil {
			if err == io.EOF {
				next = -1
			} else {
				panic(err)
			}
		}

		if firstIteration {
			firstIteration = false
			lineBegin = true
			continue
		}

		if quoted {
			if escaped {
				escaped = false
			} else {
				if curr == '\\' {
					escaped = true
				}
				if curr == '"' {
					quoted = false
				}
			}
			if curr == '\n' {
				quoted = false
			}
		} else if commented {
			if curr == '\n' {
				commented = false
			}
		} else {
			if curr == '"' {
				quoted = true
			}
			if curr == '#' {
				commented = true
			}
			if curr == '}' {
				if environ {
					environ = false
				} else if indentation > 0 {
					indentation--
				}
			}
			if curr == '{' {
				if unicode.IsSpace(next) {
					indentation++

					if !unicode.IsSpace(prev) && !lineBegin {
						result.WriteRune(' ')
					}
				} else {
					environ = true
				}
			}
			if lineBegin {
				if curr == ' ' || curr == '\t' {
					continue
				} else {
					lineBegin = false
					if curr == '{' && unicode.IsSpace(next) {
						// If the block is global, i.e., starts with '{'
						// One less indentation for these blocks.
						insertTabs(indentation - 1)
					} else {
						insertTabs(indentation)
					}
				}
			} else {
				if prev == '{' &&
					(curr == ' ' || curr == '\t') &&
					(next != '\n' && next != '\r') {
					curr = '\n'
				}
			}
		}

		if curr == '\n' {
			lineBegin = true
		}

		result.WriteRune(curr)
	}

	return result.Bytes()
}
