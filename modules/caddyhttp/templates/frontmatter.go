package templates

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/naoina/toml"
	"gopkg.in/yaml.v2"
)

func extractFrontMatter(input string) (map[string]interface{}, string, error) {
	// get the bounds of the first non-empty line
	var firstLineStart, firstLineEnd int
	lineEmpty := true
	for i, b := range input {
		if b == '\n' {
			firstLineStart = firstLineEnd
			if firstLineStart > 0 {
				firstLineStart++ // skip newline character
			}
			firstLineEnd = i
			if !lineEmpty {
				break
			}
			continue
		}
		lineEmpty = lineEmpty && unicode.IsSpace(b)
	}
	firstLine := input[firstLineStart:firstLineEnd]

	// ensure residue windows carriage return byte is removed
	firstLine = strings.TrimSpace(firstLine)

	// see what kind of front matter there is, if any
	var closingFence string
	var fmParser func([]byte) (map[string]interface{}, error)
	switch firstLine {
	case yamlFrontMatterFenceOpen:
		fmParser = yamlFrontMatter
		closingFence = yamlFrontMatterFenceClose
	case tomlFrontMatterFenceOpen:
		fmParser = tomlFrontMatter
		closingFence = tomlFrontMatterFenceClose
	case jsonFrontMatterFenceOpen:
		fmParser = jsonFrontMatter
		closingFence = jsonFrontMatterFenceClose
	default:
		// no recognized front matter; whole document is body
		return nil, input, nil
	}

	// find end of front matter
	fmEndFenceStart := strings.Index(input[firstLineEnd:], "\n"+closingFence)
	if fmEndFenceStart < 0 {
		return nil, "", fmt.Errorf("unterminated front matter")
	}
	fmEndFenceStart += firstLineEnd + 1 // add 1 to account for newline

	// extract and parse front matter
	frontMatter := input[firstLineEnd:fmEndFenceStart]
	fm, err := fmParser([]byte(frontMatter))
	if err != nil {
		return nil, "", err
	}

	// the rest is the body
	body := input[fmEndFenceStart+len(closingFence):]

	return fm, body, nil
}

func yamlFrontMatter(input []byte) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := yaml.Unmarshal(input, &m)
	return m, err
}

func tomlFrontMatter(input []byte) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := toml.Unmarshal(input, &m)
	return m, err
}

func jsonFrontMatter(input []byte) (map[string]interface{}, error) {
	input = append([]byte{'{'}, input...)
	input = append(input, '}')
	m := make(map[string]interface{})
	err := json.Unmarshal(input, &m)
	return m, err
}

type parsedMarkdownDoc struct {
	Meta map[string]interface{} `json:"meta,omitempty"`
	Body string                 `json:"body,omitempty"`
}

const (
	yamlFrontMatterFenceOpen, yamlFrontMatterFenceClose = "---", "---"
	tomlFrontMatterFenceOpen, tomlFrontMatterFenceClose = "+++", "+++"
	jsonFrontMatterFenceOpen, jsonFrontMatterFenceClose = "{", "}"
)
