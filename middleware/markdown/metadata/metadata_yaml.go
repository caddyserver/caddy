package metadata

import (
	"bytes"

	"gopkg.in/yaml.v2"
)

// YAMLMetadataParser is the MetadataParser for YAML
type YAMLMetadataParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

func (y *YAMLMetadataParser) Type() string {
	return "YAML"
}

func (y *YAMLMetadataParser) Init(b *bytes.Buffer) bool {
	meta, data := splitBuffer(b, "---")
	if meta == nil || data == nil {
		return false
	}
	y.markdown = data

	m := make(map[string]interface{})
	if err := yaml.Unmarshal(meta.Bytes(), &m); err != nil {
		return false
	}
	y.metadata = NewMetadata()
	y.metadata.load(m)

	return true
}

// Parse the metadata
func (y *YAMLMetadataParser) Parse(b []byte) ([]byte, error) {
	b, markdown, err := extractMetadata(y, b)
	if err != nil {
		return markdown, err
	}

	m := make(map[string]interface{})
	if err := yaml.Unmarshal(b, &m); err != nil {
		return markdown, err
	}
	y.metadata.load(m)
	return markdown, nil
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (y *YAMLMetadataParser) Metadata() Metadata {
	return y.metadata
}

func (y *YAMLMetadataParser) Markdown() []byte {
	return y.markdown.Bytes()
}

// Opening returns the opening identifier YAML metadata
func (y *YAMLMetadataParser) Opening() []byte {
	return []byte("---")
}

// Closing returns the closing identifier YAML metadata
func (y *YAMLMetadataParser) Closing() []byte {
	return []byte("---")
}
