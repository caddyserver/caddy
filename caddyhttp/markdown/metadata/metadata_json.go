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
	"encoding/json"
)

// JSONParser is the MetadataParser for JSON
type JSONParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

// Type returns the kind of metadata parser implemented by this struct.
func (j *JSONParser) Type() string {
	return "JSON"
}

// Init prepares the metadata metadata/markdown file and parses it
func (j *JSONParser) Init(b *bytes.Buffer) bool {
	m := make(map[string]interface{})

	err := json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		var offset int

		jerr, ok := err.(*json.SyntaxError)
		if !ok {
			return false
		}

		offset = int(jerr.Offset)

		m = make(map[string]interface{})
		err = json.Unmarshal(b.Next(offset-1), &m)
		if err != nil {
			return false
		}
	}

	j.metadata = NewMetadata(m)
	j.markdown = bytes.NewBuffer(b.Bytes())

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (j *JSONParser) Metadata() Metadata {
	return j.metadata
}

// Markdown returns the markdown text.  It should be called only after a call to Parse returns without error.
func (j *JSONParser) Markdown() []byte {
	return j.markdown.Bytes()
}
