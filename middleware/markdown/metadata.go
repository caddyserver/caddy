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
		&JSONMetadataParser{metadata: Metadata{Variables: make(map[string]interface{})}},
		&TOMLMetadataParser{metadata: Metadata{Variables: make(map[string]interface{})}},
		&YAMLMetadataParser{metadata: Metadata{Variables: make(map[string]interface{})}},
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

	// Parse the metadata.
	// Returns the remaining page contents (Markdown)
	// after extracting metadata
	Parse([]byte) ([]byte, error)

	// Parsed metadata.
	// Should be called after a call to Parse returns no error
	Metadata() Metadata
}

// JSONMetadataParser is the MetdataParser for JSON
type JSONMetadataParser struct {
	metadata Metadata
}

// Parse the metadata
func (j *JSONMetadataParser) Parse(b []byte) ([]byte, error) {
	m := make(map[string]interface{})

	// Read the preceding JSON object
	decoder := json.NewDecoder(bytes.NewReader(b))
	if err := decoder.Decode(&m); err != nil {
		return b, err
	}

	j.metadata.load(m)

	// Retrieve remaining bytes after decoding
	buf := make([]byte, len(b))
	n, err := decoder.Buffered().Read(buf)
	if err != nil {
		return b, err
	}

	return buf[:n], nil
}

// Parsed metadata.
// Should be called after a call to Parse returns no error
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
func (y *YAMLMetadataParser) Parse(b []byte) ([]byte, error) {
	b, markdown, err := extractMetadata(y, b)
	if err != nil {
		return markdown, err
	}
	m := make(map[string]interface{})
	if err := yaml.Unmarshal(b, &m); err != nil {
		return markdown, err
	}

	// convert variables (if present) to map[string]interface{}
	// to match expected type
	if vars, ok := m["variables"].(map[interface{}]interface{}); ok {
		vars1 := make(map[string]interface{})
		for k, v := range vars {
			if key, ok := k.(string); ok {
				vars1[key] = v
			}
		}
		m["variables"] = vars1
	}

	y.metadata.load(m)
	return markdown, nil
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
// and an error if any.
// Useful for MetadataParser with defined identifiers (YAML, TOML)
func extractMetadata(parser MetadataParser, b []byte) (metadata []byte, markdown []byte, err error) {
	b = bytes.TrimSpace(b)
	reader := bytes.NewBuffer(b)
	scanner := bufio.NewScanner(reader)

	// Read first line
	if !scanner.Scan() {
		// if no line is read,
		// assume metadata not present
		return nil, b, nil
	}

	line := bytes.TrimSpace(scanner.Bytes())
	if !bytes.Equal(line, parser.Opening()) {
		return nil, b, fmt.Errorf("Wrong identifier")
	}

	// buffer for metadata contents
	buf := bytes.Buffer{}

	// Read remaining lines until closing identifier is found
	for scanner.Scan() {
		line := scanner.Bytes()

		// if closing identifier found
		if bytes.Equal(bytes.TrimSpace(line), parser.Closing()) {

			// get the scanner to return remaining bytes
			scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
				return len(data), data, nil
			})
			// scan the remaining bytes
			scanner.Scan()

			return buf.Bytes(), scanner.Bytes(), nil
		}
		buf.Write(line)
		buf.WriteString("\r\n")
	}

	// closing identifier not found
	return buf.Bytes(), nil, fmt.Errorf("Metadata not closed. '%v' not found", string(parser.Closing()))
}

// findParser finds the parser using line that contains opening identifier
func findParser(b []byte) MetadataParser {
	var line []byte
	// Read first line
	if _, err := fmt.Fscanln(bytes.NewReader(b), &line); err != nil {
		return nil
	}
	line = bytes.TrimSpace(line)
	for _, parser := range parsers {
		if bytes.Equal(parser.Opening(), line) {
			return parser
		}
	}
	return nil
}
