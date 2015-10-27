package caddyfile

import "testing"

var tests = []struct {
	caddyfile, json string
}{
	{ // 0
		caddyfile: `foo: {
	root /bar
}`,
		json: `[{"hosts":["foo:"],"body":{"root":["/bar"]}}]`,
	},
	{ // 1
		caddyfile: `host1:, host2: {
	dir {
		def
	}
}`,
		json: `[{"hosts":["host1:","host2:"],"body":{"dir":[{"def":null}]}}]`,
	},
	{ // 2
		caddyfile: `host1:, host2: {
	dir abc {
		def ghi
	}
}`,
		json: `[{"hosts":["host1:","host2:"],"body":{"dir":["abc",{"def":["ghi"]}]}}]`,
	},
	{ // 3
		caddyfile: `host1:1234, host2:5678 {
	dir abc {
	}
}`,
		json: `[{"hosts":["host1:1234","host2:5678"],"body":{"dir":["abc",{}]}}]`,
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
