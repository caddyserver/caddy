package markdown

import (
	"bytes"
	"fmt"
	"time"
)

var (
	// Date format YYYY-MM-DD HH:MM:SS or YYYY-MM-DD
	timeLayout = []string{
		`2006-01-02 15:04:05`,
		`2006-01-02`,
	}
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

	// Pull top level things out
	if title, ok := parsedMap["title"]; ok {
		m.Title, _ = title.(string)
	}
	if template, ok := parsedMap["template"]; ok {
		m.Template, _ = template.(string)
	}
	if date, ok := parsedMap["date"].(string); ok {
		for _, layout := range timeLayout {
			if t, err := time.Parse(layout, date); err == nil {
				m.Date = t
				break
			}
		}
	}

	// Store everything as a flag or variable
	for key, val := range parsedMap {
		switch v := val.(type) {
		case bool:
			m.Flags[key] = v
		case string:
			m.Variables[key] = v
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
