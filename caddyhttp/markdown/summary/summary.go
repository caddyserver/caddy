// Copyright 2015 Light Code Labs, LLC
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

package summary

import (
	"bytes"

	"github.com/russross/blackfriday"
)

// Markdown formats input using a plain-text renderer, and
// then returns up to the first `wordcount` words as a summary.
func Markdown(input []byte, wordcount int) []byte {
	words := bytes.Fields(blackfriday.Markdown(input, renderer{}, 0))
	if wordcount > len(words) {
		wordcount = len(words)
	}
	return bytes.Join(words[0:wordcount], []byte{' '})
}
