package markdown

import (
	"github.com/BurntSushi/toml"
)

// TOMLMetadataParser is the MetadataParser for TOML
type TOMLMetadataParser struct {
	metadata Metadata
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

// Opening returns the opening identifier TOML metadata
func (t *TOMLMetadataParser) Opening() []byte {
	return []byte("+++")
}

// Closing returns the closing identifier TOML metadata
func (t *TOMLMetadataParser) Closing() []byte {
	return []byte("+++")
}
