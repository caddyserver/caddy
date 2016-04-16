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

// Parse the metadata
func (t *TOMLMetadataParser) Parse(b []byte) ([]byte, error) {
	b, markdown, err := extractMetadata(t, b)
	if err != nil {
		return markdown, err
	}

	m := make(map[string]interface{})
	if err := toml.Unmarshal(b, &m); err != nil {
		return markdown, err
	}
	t.metadata.load(m)
	return markdown, nil
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (t *TOMLMetadataParser) Metadata() Metadata {
	return t.metadata
}

func (t *TOMLMetadataParser) Markdown() []byte {
	return t.markdown.Bytes()
}

// Opening returns the opening identifier TOML metadata
func (t *TOMLMetadataParser) Opening() []byte {
	return []byte("+++")
}

// Closing returns the closing identifier TOML metadata
func (t *TOMLMetadataParser) Closing() []byte {
	return []byte("+++")
}
