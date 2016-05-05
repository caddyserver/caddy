package markdown

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v2"
)

// Metadata stores a page's metadata
type Metadata struct {
	// Page title
	Title string

	// Page template
	Template string

	// Publish date
	Date time.Time

	// Variables to be used with Template
	Variables map[string]string

	// Flags to be used with Template
	Flags map[string]bool
}

// load loads parsed values in parsedMap into Metadata
func (m *Metadata) load(parsedMap map[string]interface{}) {
	if title, ok := parsedMap["title"]; ok {
		m.Title, _ = title.(string)
	}
	if template, ok := parsedMap["template"]; ok {
		m.Template, _ = template.(string)
	}
	if date, ok := parsedMap["date"].(string); ok {
		if t, err := time.Parse(timeLayout, date); err == nil {
			m.Date = t
		}
	}
	// store everything as a variable
	for key, val := range parsedMap {
		switch v := val.(type) {
		case string:
			m.Variables[key] = v
		case bool:
			m.Flags[key] = v
		}
	}
}

// MetadataParser is a an interface that must be satisfied by each parser
type MetadataParser interface {
	// Opening identifier
	Opening() []byte

	// Closing identifier
	Closing() []byte

	// Parse the metadata.
	// Returns the remaining page contents (Markdown)
	// after extracting metadata
	Parse([]byte) ([]byte, error)

	// Parsed metadata.
	// Should be called after a call to Parse returns no error
	Metadata() Metadata
}

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

// extractMetadata separates metadata content from from markdown content in b.
// It returns the metadata, the remaining bytes (markdown), and an error, if any.
func extractMetadata(parser MetadataParser, b []byte) (metadata []byte, markdown []byte, err error) {
	b = bytes.TrimSpace(b)
	openingLine := parser.Opening()
	closingLine := parser.Closing()
	if !bytes.HasPrefix(b, openingLine) {
		return nil, b, fmt.Errorf("first line missing expected metadata identifier")
	}
	metaStart := len(openingLine)
	if _, ok := parser.(*JSONMetadataParser); ok {
		metaStart = 0
	}
	metaEnd := bytes.Index(b[metaStart:], closingLine)
	if metaEnd == -1 {
		return nil, nil, fmt.Errorf("metadata not closed ('%s' not found)", parser.Closing())
	}
	metaEnd += metaStart
	if _, ok := parser.(*JSONMetadataParser); ok {
		metaEnd += len(closingLine)
	}
	metadata = b[metaStart:metaEnd]
	markdown = b[metaEnd:]
	if _, ok := parser.(*JSONMetadataParser); !ok {
		markdown = b[metaEnd+len(closingLine):]
	}
	return metadata, markdown, nil
}

// findParser finds the parser using line that contains opening identifier
func findParser(b []byte) MetadataParser {
	var line []byte
	// Read first line
	if _, err := fmt.Fscanln(bytes.NewReader(b), &line); err != nil {
		return nil
	}
	line = bytes.TrimSpace(line)
	for _, parser := range parsers() {
		if bytes.Equal(parser.Opening(), line) {
			return parser
		}
	}
	return nil
}

func newMetadata() Metadata {
	return Metadata{
		Variables: make(map[string]string),
		Flags:     make(map[string]bool),
	}
}

// parsers returns all available parsers
func parsers() []MetadataParser {
	return []MetadataParser{
		&JSONMetadataParser{metadata: newMetadata()},
		&TOMLMetadataParser{metadata: newMetadata()},
		&YAMLMetadataParser{metadata: newMetadata()},
	}
}
