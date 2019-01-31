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
)

// NoneParser is the parser for plaintext markdown with no metadata.
type NoneParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

// Type returns the kind of parser this struct is.
func (n *NoneParser) Type() string {
	return "None"
}

// Init preparses and parses the metadata and markdown file
func (n *NoneParser) Init(b *bytes.Buffer) bool {
	m := make(map[string]interface{})
	n.metadata = NewMetadata(m)
	n.markdown = bytes.NewBuffer(b.Bytes())

	return true
}

// Parse the metadata
func (n *NoneParser) Parse(b []byte) ([]byte, error) {
	return nil, nil
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (n *NoneParser) Metadata() Metadata {
	return n.metadata
}

// Markdown returns parsed markdown.  It should be called
// only after a call to Parse returns without error.
func (n *NoneParser) Markdown() []byte {
	return n.markdown.Bytes()
}
