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

// Init prepases and parses the metadata and markdown file
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
