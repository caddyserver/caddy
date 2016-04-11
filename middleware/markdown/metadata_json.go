package markdown

import (
	"bytes"
	"encoding/json"
)

// JSONMetadataParser is the MetadataParser for JSON
type JSONMetadataParser struct {
	metadata Metadata
}

// Parse the metadata
func (j *JSONMetadataParser) Parse(b []byte) ([]byte, error) {
	b, markdown, err := extractMetadata(j, b)
	if err != nil {
		return markdown, err
	}
	m := make(map[string]interface{})

	// Read the preceding JSON object
	decoder := json.NewDecoder(bytes.NewReader(b))
	if err := decoder.Decode(&m); err != nil {
		return markdown, err
	}
	j.metadata.load(m)

	return markdown, nil
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (j *JSONMetadataParser) Metadata() Metadata {
	return j.metadata
}

// Opening returns the opening identifier JSON metadata
func (j *JSONMetadataParser) Opening() []byte {
	return []byte("{")
}

// Closing returns the closing identifier JSON metadata
func (j *JSONMetadataParser) Closing() []byte {
	return []byte("}")
}
