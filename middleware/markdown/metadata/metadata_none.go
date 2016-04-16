package metadata

import (
	"bytes"
)

// TOMLMetadataParser is the MetadataParser for TOML
type NoneMetadataParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

func (n *NoneMetadataParser) Type() string {
	return "None"
}

// Parse metadata/markdown file
func (n *NoneMetadataParser) Init(b *bytes.Buffer) bool {
	m := make(map[string]interface{})
	n.metadata = NewMetadata()
	n.metadata.load(m)
	n.markdown = bytes.NewBuffer(b.Bytes())

	return true
}

// Parse the metadata
func (n *NoneMetadataParser) Parse(b []byte) ([]byte, error) {
	return nil, nil
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (n *NoneMetadataParser) Metadata() Metadata {
	return n.metadata
}

func (n *NoneMetadataParser) Markdown() []byte {
	return n.markdown.Bytes()
}
