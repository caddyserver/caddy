package markdown

import (
	"encoding/json"

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
	Title     string
	Template  string
	Variables map[string]interface{}
}

// Load loads parsed metadata into m
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

// MetadataParser parses the page metadata
// into Metadata
type MetadataParser interface {
	// Identifiers
	Opening() []byte
	Closing() []byte

	Parse([]byte) error
	Metadata() Metadata
}

// JSONMetadataParser is the MetdataParser for JSON
type JSONMetadataParser struct {
	metadata Metadata
}

// Parse parses b into metadata
func (j *JSONMetadataParser) Parse(b []byte) error {
	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	j.metadata.load(m)
	return nil
}

// Metadata returns the metadata parsed by this parser
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

// Parse parses b into metadata
func (t *TOMLMetadataParser) Parse(b []byte) error {
	m := make(map[string]interface{})
	if err := toml.Unmarshal(b, &m); err != nil {
		return err
	}
	t.metadata.load(m)
	return nil
}

// Metadata returns the metadata parsed by this parser
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

// YAMLMetadataParser is the MetdataParser for YAML
type YAMLMetadataParser struct {
	metadata Metadata
}

// Parse parses b into metadata
func (y *YAMLMetadataParser) Parse(b []byte) error {
	m := make(map[string]interface{})
	if err := yaml.Unmarshal(b, &m); err != nil {
		return err
	}
	y.metadata.load(m)
	return nil
}

// Metadata returns the metadata parsed by this parser
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
