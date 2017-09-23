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
	"bufio"
	"bytes"
	"time"
)

var (
	// Date format YYYY-MM-DD HH:MM:SS or YYYY-MM-DD
	timeLayout = []string{
		`2006-01-02 15:04:05-0700`,
		`2006-01-02 15:04:05`,
		`2006-01-02`,
	}
)

// Metadata stores a page's metadata
type Metadata struct {
	// Page title
	Title string

	// Page template
	Template string

	// Publish date
	Date time.Time

	// Variables to be used with Template
	Variables map[string]interface{}
}

// NewMetadata returns a new Metadata struct, loaded with the given map
func NewMetadata(parsedMap map[string]interface{}) Metadata {
	md := Metadata{
		Variables: make(map[string]interface{}),
	}
	md.load(parsedMap)

	return md
}

// load loads parsed values in parsedMap into Metadata
func (m *Metadata) load(parsedMap map[string]interface{}) {

	// Pull top level things out
	if title, ok := parsedMap["title"]; ok {
		m.Title, _ = title.(string)
	}
	if template, ok := parsedMap["template"]; ok {
		m.Template, _ = template.(string)
	}
	if date, ok := parsedMap["date"].(string); ok {
		for _, layout := range timeLayout {
			if t, err := time.Parse(layout, date); err == nil {
				m.Date = t
				break
			}
		}
	}

	m.Variables = parsedMap
}

// Parser is a an interface that must be satisfied by each parser
type Parser interface {
	// Initialize a parser
	Init(b *bytes.Buffer) bool

	// Type of metadata
	Type() string

	// Parsed metadata.
	Metadata() Metadata

	// Raw markdown.
	Markdown() []byte
}

// GetParser returns a parser for the given data
func GetParser(buf []byte) Parser {
	for _, p := range parsers() {
		b := bytes.NewBuffer(buf)
		if p.Init(b) {
			return p
		}
	}

	return nil
}

// parsers returns all available parsers
func parsers() []Parser {
	return []Parser{
		&TOMLParser{},
		&YAMLParser{},
		&JSONParser{},

		// This one must be last
		&NoneParser{},
	}
}

// Split out prefixed/suffixed metadata with given delimiter
func splitBuffer(b *bytes.Buffer, delim string) (*bytes.Buffer, *bytes.Buffer) {
	scanner := bufio.NewScanner(b)

	// Read and check first line
	if !scanner.Scan() {
		return nil, nil
	}
	if string(bytes.TrimSpace(scanner.Bytes())) != delim {
		return nil, nil
	}

	// Accumulate metadata, until delimiter
	meta := bytes.NewBuffer(nil)
	for scanner.Scan() {
		if string(bytes.TrimSpace(scanner.Bytes())) == delim {
			break
		}
		if _, err := meta.Write(scanner.Bytes()); err != nil {
			return nil, nil
		}
		if _, err := meta.WriteRune('\n'); err != nil {
			return nil, nil
		}
	}
	// Make sure we saw closing delimiter
	if string(bytes.TrimSpace(scanner.Bytes())) != delim {
		return nil, nil
	}

	// The rest is markdown
	markdown := new(bytes.Buffer)
	for scanner.Scan() {
		if _, err := markdown.Write(scanner.Bytes()); err != nil {
			return nil, nil
		}
		if _, err := markdown.WriteRune('\n'); err != nil {
			return nil, nil
		}
	}

	return meta, markdown
}
