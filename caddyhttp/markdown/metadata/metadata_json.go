package metadata

import (
	"bytes"
	"encoding/json"
)

// JSONParser is the MetadataParser for JSON
type JSONParser struct {
	metadata Metadata
	markdown *bytes.Buffer
}

// Type returns the kind of metadata parser implemented by this struct.
func (j *JSONParser) Type() string {
	return "JSON"
}

// Init prepares the metadata metadata/markdown file and parses it
func (j *JSONParser) Init(b *bytes.Buffer) bool {
	m := make(map[string]interface{})

	err := json.Unmarshal(b.Bytes(), &m)
	if err != nil {
		var offset int

		jerr, ok := err.(*json.SyntaxError)
		if !ok {
			return false
		}

		offset = int(jerr.Offset)

		m = make(map[string]interface{})
		err = json.Unmarshal(b.Next(offset-1), &m)
		if err != nil {
			return false
		}
	}

	j.metadata = NewMetadata(m)
	j.markdown = bytes.NewBuffer(b.Bytes())

	return true
}

// Metadata returns parsed metadata.  It should be called
// only after a call to Parse returns without error.
func (j *JSONParser) Metadata() Metadata {
	return j.metadata
}

// Markdown returns the markdown text.  It should be called only after a call to Parse returns without error.
func (j *JSONParser) Markdown() []byte {
	return j.markdown.Bytes()
}
