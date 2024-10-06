package templates

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

func extractFrontMatter(input string) (map[string]any, string, error) {
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
	var closingFence []string
	var fmParser func([]byte) (map[string]any, error)
	for _, fmType := range supportedFrontMatterTypes {
		if firstLine == fmType.FenceOpen {
			closingFence = fmType.FenceClose
			fmParser = fmType.ParseFunc
			break
		}
	}

	if fmParser == nil {
		// no recognized front matter; whole document is body
		return nil, input, nil
	}

	// find end of front matter
	var fmEndFence string
	fmEndFenceStart := -1
	for _, fence := range closingFence {
		index := strings.Index(input[firstLineEnd:], "\n"+fence)
		if index >= 0 {
			fmEndFenceStart = index
			fmEndFence = fence
			break
		}
	}
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
	body := input[fmEndFenceStart+len(fmEndFence):]

	return fm, body, nil
}

func yamlFrontMatter(input []byte) (map[string]any, error) {
	m := make(map[string]any)
	err := yaml.Unmarshal(input, &m)
	return m, err
}

func tomlFrontMatter(input []byte) (map[string]any, error) {
	m := make(map[string]any)
	err := toml.Unmarshal(input, &m)
	return m, err
}

func jsonFrontMatter(input []byte) (map[string]any, error) {
	input = append([]byte{'{'}, input...)
	input = append(input, '}')
	m := make(map[string]any)
	err := json.Unmarshal(input, &m)
	return m, err
}

type parsedMarkdownDoc struct {
	Meta map[string]any `json:"meta,omitempty"`
	Body string         `json:"body,omitempty"`
}

type frontMatterType struct {
	FenceOpen  string
	FenceClose []string
	ParseFunc  func(input []byte) (map[string]any, error)
}

var supportedFrontMatterTypes = []frontMatterType{
	{
		FenceOpen:  "---",
		FenceClose: []string{"---", "..."},
		ParseFunc:  yamlFrontMatter,
	},
	{
		FenceOpen:  "+++",
		FenceClose: []string{"+++"},
		ParseFunc:  tomlFrontMatter,
	},
	{
		FenceOpen:  "{",
		FenceClose: []string{"}"},
		ParseFunc:  jsonFrontMatter,
	},
}
