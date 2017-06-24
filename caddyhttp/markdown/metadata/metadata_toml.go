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
