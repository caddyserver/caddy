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

	"gopkg.in/yaml.v2"
)

// YAMLParser is the Parser for YAML
type YAMLParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

// Type returns the kind of metadata parser.
func (y *YAMLParser) Type() string {
	return "YAML"
}

// Init prepares the metadata parser for parsing.
func (y *YAMLParser) Init(b *bytes.Buffer) bool {
	meta, data := splitBuffer(b, "---")
	if meta == nil || data == nil {
		return false
	}
	y.markdown = data

	m := make(map[string]interface{})
	if err := yaml.Unmarshal(meta.Bytes(), &m); err != nil {
		return false
	}
	y.metadata = NewMetadata(m)

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (y *YAMLParser) Metadata() Metadata {
	return y.metadata
}

// Markdown renders the text as a byte array
func (y *YAMLParser) Markdown() []byte {
	return y.markdown.Bytes()
}
