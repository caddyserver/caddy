package markdown

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

var TOML = [4]string{`
title = "A title"
template = "default"
[variables]
name = "value"
`,
	`+++
title = "A title"
template = "default"
[variables]
name = "value"
+++
`,
	`+++
title = "A title"
template = "default"
[variables]
name = "value"
	`,
	`title = "A title" template = "default" [variables] name = "value"`,
}

var YAML = [4]string{`
title : A title
template : default
variables :
- name : value
`,
	`---
title : A title
template : default
variables :
- name : value
---
`,
	`---
title : A title
template : default
variables :
- name : value
`,
	`title : A title template : default variables : name : value`,
}
var JSON = [4]string{`
{
	"title" : "A title",
	"template" : "default",
	"variables" : {
		"name" : "value"
	}
}
`,
	`:::
{
	"title" : "A title",
	"template" : "default",
	"variables" : {
		"name" : "value"
	}
}
:::`,
	`:::
{
	"title" : "A title",
	"template" : "default",
	"variables" : {
		"name" : "value"
	}
}
`,
	`
	:::
{{
	"title" : "A title",
	"template" : "default",
	"variables" : {
		"name" : "value"
	}
}
:::
	`,
}

func check(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsers(t *testing.T) {
	expected := Metadata{
		Title:     "A title",
		Template:  "default",
		Variables: map[string]interface{}{"name": "value"},
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
		return true
	}

	data := []struct {
		parser   MetadataParser
		testData [4]string
		name     string
	}{
		{&JSONMetadataParser{}, JSON, "json"},
		{&YAMLMetadataParser{}, YAML, "yaml"},
		{&TOMLMetadataParser{}, TOML, "toml"},
	}

	for _, v := range data {
		// metadata without identifiers
		err := v.parser.Parse([]byte(v.testData[0]))
		check(t, err)
		if !compare(v.parser.Metadata()) {
			t.Fatalf("Expected %v, found %v for %v", expected, v.parser.Metadata().Variables, v.name)
		}

		// metadata with identifiers
		metadata, _, err := extractMetadata([]byte(v.testData[1]))
		check(t, err)
		if !compare(metadata) {
			t.Fatalf("Expected %v, found %v for %v", expected, metadata.Variables, v.name)
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
		if _, _, err := extractMetadata([]byte(v.testData[2])); err == nil {
			t.Fatalf("Expected error for missing closing identifier for %v", v.name)
		}

		// invalid metadata
		if err := v.parser.Parse([]byte(v.testData[3])); err == nil {
			t.Fatalf("Expected error for invalid metadata for %v", v.name)
		}
	}

}
