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
	y.metadata = NewMetadata(m)

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (y *YAMLMetadataParser) Metadata() Metadata {
	return y.metadata
}

func (y *YAMLMetadataParser) Markdown() []byte {
	return y.markdown.Bytes()
}
