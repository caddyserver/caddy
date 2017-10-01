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

package metadata

import (
	"bytes"

	"github.com/naoina/toml"
)

// TOMLParser is the Parser for TOML
type TOMLParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

// Type returns the kind of parser this struct is.
func (t *TOMLParser) Type() string {
	return "TOML"
}

// Init prepares and parses the metadata and markdown file itself
func (t *TOMLParser) Init(b *bytes.Buffer) bool {
	meta, data := splitBuffer(b, "+++")
	if meta == nil || data == nil {
		return false
	}
	t.markdown = data

	m := make(map[string]interface{})
	if err := toml.Unmarshal(meta.Bytes(), &m); err != nil {
		return false
	}
	t.metadata = NewMetadata(m)

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (t *TOMLParser) Metadata() Metadata {
	return t.metadata
}

// Markdown returns parser markdown.  It should be called only after a call to Parse returns without error.
func (t *TOMLParser) Markdown() []byte {
	return t.markdown.Bytes()
}
