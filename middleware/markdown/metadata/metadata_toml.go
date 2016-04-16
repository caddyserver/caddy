package metadata

import (
	"bytes"

	"github.com/BurntSushi/toml"
)

// TOMLMetadataParser is the MetadataParser for TOML
type TOMLMetadataParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

func (t *TOMLMetadataParser) Type() string {
	return "TOML"
}

// Parse metadata/markdown file
func (t *TOMLMetadataParser) Init(b *bytes.Buffer) bool {
	meta, data := splitBuffer(b, "+++")
	if meta == nil || data == nil {
		return false
	}
	t.markdown = data

	m := make(map[string]interface{})
	if err := toml.Unmarshal(meta.Bytes(), &m); err != nil {
		return false
	}
	t.metadata = NewMetadata()
	t.metadata.load(m)

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (t *TOMLMetadataParser) Metadata() Metadata {
	return t.metadata
}

func (t *TOMLMetadataParser) Markdown() []byte {
	return t.markdown.Bytes()
}
