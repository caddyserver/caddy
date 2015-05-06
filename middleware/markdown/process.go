package markdown

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"text/template"
)

// Process the contents of a page.
// It parses the metadata if any and uses the template if found
func Process(c Config, b []byte) ([]byte, error) {
	metadata, markdown, err := extractMetadata(b)
	if err != nil {
		return nil, err
	}
	// if metadata template is included
	var tmpl []byte
	if metadata.Template != "" {
		if t, ok := c.Templates[metadata.Template]; ok {
			tmpl, err = loadTemplate(t)
		}
		if err != nil {
			return nil, err
		}
	}

	// if no template loaded
	// use default template
	if tmpl == nil {
		tmpl = []byte(htmlTemplate)
	}

	// process markdown
	if markdown, err = processMarkdown(markdown, metadata.Variables); err != nil {
		return nil, err
	}

	tmpl = bytes.Replace(tmpl, []byte("{{body}}"), markdown, 1)

	return tmpl, nil
}

// extractMetadata extracts metadata content from a page.
// it returns the metadata, the remaining bytes (markdown),
// and an error if any
func extractMetadata(b []byte) (metadata Metadata, markdown []byte, err error) {
	b = bytes.TrimSpace(b)
	reader := bytes.NewBuffer(b)
	scanner := bufio.NewScanner(reader)
	var parser MetadataParser
	//	if scanner.Scan() &&
	// Read first line
	if scanner.Scan() {
		line := scanner.Bytes()
		parser = findParser(line)
		// if no parser found
		// assume metadata not present
		if parser == nil {
			return metadata, b, nil
		}
	}

	// buffer for metadata contents
	buf := bytes.Buffer{}

	// Read remaining lines until closing identifier is found
	for scanner.Scan() {
		line := scanner.Bytes()
		// closing identifier found
		if bytes.Equal(bytes.TrimSpace(line), parser.Closing()) {
			if err := parser.Parse(buf.Bytes()); err != nil {
				return metadata, nil, err
			}
			return parser.Metadata(), reader.Bytes(), nil
		}
		buf.Write(line)
	}
	return metadata, nil, fmt.Errorf("Metadata not closed. '%v' not found", string(parser.Closing()))
}

// findParser locates the parser for an opening identifier
func findParser(line []byte) MetadataParser {
	line = bytes.TrimSpace(line)
	for _, parser := range parsers {
		if bytes.Equal(parser.Opening(), line) {
			return parser
		}
	}
	return nil
}

func loadTemplate(tmpl string) ([]byte, error) {
	b, err := ioutil.ReadFile(tmpl)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(b, []byte("{{body}}")) {
		return nil, fmt.Errorf("template missing {{body}}")
	}
	return b, nil
}

func processMarkdown(b []byte, vars map[string]interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}
	t, err := template.New("markdown").Parse(string(b))
	if err != nil {
		return nil, err
	}
	if err := t.Execute(buf, vars); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
