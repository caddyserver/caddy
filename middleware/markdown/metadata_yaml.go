package markdown

import (
	"gopkg.in/yaml.v2"
)

// YAMLMetadataParser is the MetadataParser for YAML
type YAMLMetadataParser struct {
	metadata Metadata
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

// Opening returns the opening identifier YAML metadata
func (y *YAMLMetadataParser) Opening() []byte {
	return []byte("---")
}

// Closing returns the closing identifier YAML metadata
func (y *YAMLMetadataParser) Closing() []byte {
	return []byte("---")
}
