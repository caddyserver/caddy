package markdown

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var TOML = [4]string{`
title = "A title"
template = "default"
name = "value"
`,
	`+++
title = "A title"
template = "default"
name = "value"
+++
Page content
`,
	`+++
title = "A title"
template = "default"
name = "value"
	`,
	`title = "A title" template = "default" [variables] name = "value"`,
}

var YAML = [4]string{`
title : A title
template : default
name : value
`,
	`---
title : A title
template : default
name : value
---
Page content
`,
	`---
title : A title
template : default
name : value
`,
	`title : A title template : default variables : name : value`,
}
var JSON = [4]string{`
	"title" : "A title",
	"template" : "default",
	"name" : "value"
`,
	`{
	"title" : "A title",
	"template" : "default",
	"name" : "value"
}
Page content
`,
	`
{
	"title" : "A title",
	"template" : "default",
	"name" : "value"
`,
	`
{{
	"title" : "A title",
	"template" : "default",
	"name" : "value"
}
	`,
}

func check(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsers(t *testing.T) {
	expected := Metadata{
		Title:    "A title",
		Template: "default",
		Variables: map[string]string{
			"name":     "value",
			"title":    "A title",
			"template": "default",
		},
	}
	compare := func(m Metadata) bool {
		if m.Title != expected.Title {
			return false
		}
		if m.Template != expected.Template {
			return false
		}
		for k, v := range m.Variables {
			if v != expected.Variables[k] {
				return false
			}
		}
		return len(m.Variables) == len(expected.Variables)
	}

	data := []struct {
		parser   MetadataParser
		testData [4]string
		name     string
	}{
		{&JSONMetadataParser{metadata: Metadata{Variables: make(map[string]string)}}, JSON, "json"},
		{&YAMLMetadataParser{metadata: Metadata{Variables: make(map[string]string)}}, YAML, "yaml"},
		{&TOMLMetadataParser{metadata: Metadata{Variables: make(map[string]string)}}, TOML, "toml"},
	}

	for _, v := range data {
		// metadata without identifiers
		if _, err := v.parser.Parse([]byte(v.testData[0])); err == nil {
			t.Fatalf("Expected error for invalid metadata for %v", v.name)
		}

		// metadata with identifiers
		md, err := v.parser.Parse([]byte(v.testData[1]))
		check(t, err)
		if !compare(v.parser.Metadata()) {
			t.Fatalf("Expected %v, found %v for %v", expected, v.parser.Metadata(), v.name)
		}
		if "Page content" != strings.TrimSpace(string(md)) {
			t.Fatalf("Expected %v, found %v for %v", "Page content", string(md), v.name)
		}

		var line []byte
		fmt.Fscanln(bytes.NewReader([]byte(v.testData[1])), &line)
		if parser := findParser(line); parser == nil {
			t.Fatalf("Parser must be found for %v", v.name)
		} else {
			if reflect.TypeOf(parser) != reflect.TypeOf(v.parser) {
				t.Fatalf("parsers not equal. %v != %v", reflect.TypeOf(parser), reflect.TypeOf(v.parser))
			}
		}

		// metadata without closing identifier
		if _, err := v.parser.Parse([]byte(v.testData[2])); err == nil {
			t.Fatalf("Expected error for missing closing identifier for %v", v.name)
		}

		// invalid metadata
		if md, err = v.parser.Parse([]byte(v.testData[3])); err == nil {
			t.Fatalf("Expected error for invalid metadata for %v", v.name)
		}
	}

}
