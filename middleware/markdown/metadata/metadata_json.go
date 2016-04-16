package metadata

import (
	"bytes"
	"encoding/json"
)

// JSONMetadataParser is the MetadataParser for JSON
type JSONMetadataParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

func (j *JSONMetadataParser) Type() string {
	return "JSON"
}

// Parse metadata/markdown file
func (j *JSONMetadataParser) Init(b *bytes.Buffer) bool {
	m := make(map[string]interface{})

	err := json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		var offset int

		if jerr, ok := err.(*json.SyntaxError); !ok {
			return false
		} else {
			offset = int(jerr.Offset)
		}

		m = make(map[string]interface{})
		err = json.Unmarshal(b.Next(offset-1), &m)
		if err != nil {
			return false
		}
	}

	j.metadata = NewMetadata()
	j.metadata.load(m)
	j.markdown = bytes.NewBuffer(b.Bytes())

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (j *JSONMetadataParser) Metadata() Metadata {
	return j.metadata
}

func (j *JSONMetadataParser) Markdown() []byte {
	return j.markdown.Bytes()
}
