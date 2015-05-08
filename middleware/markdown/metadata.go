package markdown

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v2"
)

var (
	parsers = []MetadataParser{
		&JSONMetadataParser{},
		&TOMLMetadataParser{},
		&YAMLMetadataParser{},
	}
)

// Metadata stores a page's metadata
type Metadata struct {
	// Page title
	Title string

	// Page template
	Template string

	// Variables to be used with Template
	Variables map[string]interface{}
}

// load loads parsed values in parsedMap into Metadata
func (m *Metadata) load(parsedMap map[string]interface{}) {
	if template, ok := parsedMap["title"]; ok {
		m.Title, _ = template.(string)
	}
	if template, ok := parsedMap["template"]; ok {
		m.Template, _ = template.(string)
	}
	if variables, ok := parsedMap["variables"]; ok {
		m.Variables, _ = variables.(map[string]interface{})
	}
}

// MetadataParser is a an interface that must be satisfied by each parser
type MetadataParser interface {
	// Opening identifier
	Opening() []byte

	// Closing identifier
	Closing() []byte

	// Parse the metadata
	Parse([]byte) error

	// Parsed metadata.
	// Should be called after a call to Parse returns no error
	Metadata() Metadata
}

// JSONMetadataParser is the MetdataParser for JSON
type JSONMetadataParser struct {
	metadata Metadata
}

// Parse the metadata
func (j *JSONMetadataParser) Parse(b []byte) error {
	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	j.metadata.load(m)
	return nil
}

// Parsed metadata.
// Should be called after a call to Parse returns no error
func (j *JSONMetadataParser) Metadata() Metadata {
	return j.metadata
}

// Opening returns the opening identifier JSON metadata
func (j *JSONMetadataParser) Opening() []byte {
	return []byte(":::")
}

// Closing returns the closing identifier JSON metadata
func (j *JSONMetadataParser) Closing() []byte {
	return []byte(":::")
}

// TOMLMetadataParser is the MetadataParser for TOML
type TOMLMetadataParser struct {
	metadata Metadata
}

// Parse the metadata
func (t *TOMLMetadataParser) Parse(b []byte) error {
	m := make(map[string]interface{})
	if err := toml.Unmarshal(b, &m); err != nil {
		return err
	}
	t.metadata.load(m)
	return nil
}

// Parsed metadata.
// Should be called after a call to Parse returns no error
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
func (y *YAMLMetadataParser) Parse(b []byte) error {
	m := make(map[string]interface{})
	if err := yaml.Unmarshal(b, &m); err != nil {
		return err
	}
	y.metadata.load(m)
	return nil
}

// Parsed metadata.
// Should be called after a call to Parse returns no error
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

// extractMetadata extracts metadata content from a page.
// it returns the metadata, the remaining bytes (markdown),
// and an error if any
func extractMetadata(b []byte) (metadata Metadata, markdown []byte, err error) {
	b = bytes.TrimSpace(b)
	reader := bytes.NewBuffer(b)
	scanner := bufio.NewScanner(reader)
	var parser MetadataParser

	// Read first line
	if !scanner.Scan() {
		// if no line is read,
		// assume metadata not present
		return metadata, b, nil
	}

	line := scanner.Bytes()
	parser = findParser(line)
	// if no parser found,
	// assume metadata not present
	if parser == nil {
		return metadata, b, nil
	}

	// buffer for metadata contents
	buf := bytes.Buffer{}

	// Read remaining lines until closing identifier is found
	for scanner.Scan() {
		line := scanner.Bytes()

		// if closing identifier found
		if bytes.Equal(bytes.TrimSpace(line), parser.Closing()) {
			// parse the metadata
			err := parser.Parse(buf.Bytes())
			if err != nil {
				return metadata, nil, err
			}
			// get the scanner to return remaining bytes
			scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
				return len(data), data, nil
			})
			// scan the remaining bytes
			scanner.Scan()

			return parser.Metadata(), scanner.Bytes(), nil
		}
		buf.Write(line)
		buf.WriteString("\r\n")
	}

	// closing identifier not found
	return metadata, nil, fmt.Errorf("Metadata not closed. '%v' not found", string(parser.Closing()))
}

// findParser finds the parser using line that contains opening identifier
func findParser(line []byte) MetadataParser {
	line = bytes.TrimSpace(line)
	for _, parser := range parsers {
		if bytes.Equal(parser.Opening(), line) {
			return parser
		}
	}
	return nil
}
