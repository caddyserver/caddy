// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyfile

import "testing"

var tests = []struct {
	caddyfile, json string
}{
	{ // 0
		caddyfile: `foo {
	root /bar
}`,
		json: `[{"keys":["foo"],"body":[["root","/bar"]]}]`,
	},
	{ // 1
		caddyfile: `host1, host2 {
	dir {
		def
	}
}`,
		json: `[{"keys":["host1","host2"],"body":[["dir",[["def"]]]]}]`,
	},
	{ // 2
		caddyfile: `host1, host2 {
	dir abc {
		def ghi
		jkl
	}
}`,
		json: `[{"keys":["host1","host2"],"body":[["dir","abc",[["def","ghi"],["jkl"]]]]}]`,
	},
	{ // 3
		caddyfile: `host1:1234, host2:5678 {
	dir abc {
	}
}`,
		json: `[{"keys":["host1:1234","host2:5678"],"body":[["dir","abc",[]]]}]`,
	},
	{ // 4
		caddyfile: `host {
	foo "bar baz"
}`,
		json: `[{"keys":["host"],"body":[["foo","bar baz"]]}]`,
	},
	{ // 5
		caddyfile: `host, host:80 {
	foo "bar \"baz\""
}`,
		json: `[{"keys":["host","host:80"],"body":[["foo","bar \"baz\""]]}]`,
	},
	{ // 6
		caddyfile: `host {
	foo "bar
baz"
}`,
		json: `[{"keys":["host"],"body":[["foo","bar\nbaz"]]}]`,
	},
	{ // 7
		caddyfile: `host {
	dir 123 4.56 true
}`,
		json: `[{"keys":["host"],"body":[["dir","123","4.56","true"]]}]`, // NOTE: I guess we assume numbers and booleans should be encoded as strings...?
	},
	{ // 8
		caddyfile: `http://host, https://host {
}`,
		json: `[{"keys":["http://host","https://host"],"body":[]}]`, // hosts in JSON are always host:port format (if port is specified), for consistency
	},
	{ // 9
		caddyfile: `host {
	dir1 a b
	dir2 c d
}`,
		json: `[{"keys":["host"],"body":[["dir1","a","b"],["dir2","c","d"]]}]`,
	},
	{ // 10
		caddyfile: `host {
	dir a b
	dir c d
}`,
		json: `[{"keys":["host"],"body":[["dir","a","b"],["dir","c","d"]]}]`,
	},
	{ // 11
		caddyfile: `host {
	dir1 a b
	dir2 {
		c
		d
	}
}`,
		json: `[{"keys":["host"],"body":[["dir1","a","b"],["dir2",[["c"],["d"]]]]}]`,
	},
	{ // 12
		caddyfile: `host1 {
	dir1
}

host2 {
	dir2
}`,
		json: `[{"keys":["host1"],"body":[["dir1"]]},{"keys":["host2"],"body":[["dir2"]]}]`,
	},
}

func TestToJSON(t *testing.T) {
	for i, test := range tests {
		output, err := ToJSON([]byte(test.caddyfile))
		if err != nil {
			t.Errorf("Test %d: %v", i, err)
		}
		if string(output) != test.json {
			t.Errorf("Test %d\nExpected:\n'%s'\nActual:\n'%s'", i, test.json, string(output))
		}
	}
}

func TestFromJSON(t *testing.T) {
	for i, test := range tests {
		output, err := FromJSON([]byte(test.json))
		if err != nil {
			t.Errorf("Test %d: %v", i, err)
		}
		if string(output) != test.caddyfile {
			t.Errorf("Test %d\nExpected:\n'%s'\nActual:\n'%s'", i, test.caddyfile, string(output))
		}
	}
}

// TODO: Will these tests come in handy somewhere else?
/*
func TestStandardizeAddress(t *testing.T) {
	// host:https should be converted to https://host
	output, err := ToJSON([]byte(`host:https`))
	if err != nil {
		t.Fatal(err)
	}
	if expected, actual := `[{"keys":["https://host"],"body":[]}]`, string(output); expected != actual {
		t.Errorf("Expected:\n'%s'\nActual:\n'%s'", expected, actual)
	}

	output, err = FromJSON([]byte(`[{"keys":["https://host"],"body":[]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if expected, actual := "https://host {\n}", string(output); expected != actual {
		t.Errorf("Expected:\n'%s'\nActual:\n'%s'", expected, actual)
	}

	// host: should be converted to just host
	output, err = ToJSON([]byte(`host:`))
	if err != nil {
		t.Fatal(err)
	}
	if expected, actual := `[{"keys":["host"],"body":[]}]`, string(output); expected != actual {
		t.Errorf("Expected:\n'%s'\nActual:\n'%s'", expected, actual)
	}
	output, err = FromJSON([]byte(`[{"keys":["host:"],"body":[]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if expected, actual := "host {\n}", string(output); expected != actual {
		t.Errorf("Expected:\n'%s'\nActual:\n'%s'", expected, actual)
	}
}
*/
