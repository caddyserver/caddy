package caddy

import (
	"reflect"
	"testing"
)

func TestGetModules(t *testing.T) {
	modulesMu.Lock()
	modules = map[string]Module{
		"a":      {Name: "a"},
		"a.b":    {Name: "a.b"},
		"a.b.c":  {Name: "a.b.c"},
		"a.b.cd": {Name: "a.b.cd"},
		"a.c":    {Name: "a.c"},
		"a.d":    {Name: "a.d"},
		"b":      {Name: "b"},
		"b.a":    {Name: "b.a"},
		"b.b":    {Name: "b.b"},
		"b.a.c":  {Name: "b.a.c"},
		"c":      {Name: "c"},
	}
	modulesMu.Unlock()

	for i, tc := range []struct {
		input  string
		expect []Module
	}{
		{
			input: "",
			expect: []Module{
				{Name: "a"},
				{Name: "b"},
				{Name: "c"},
			},
		},
		{
			input: "a",
			expect: []Module{
				{Name: "a.b"},
				{Name: "a.c"},
				{Name: "a.d"},
			},
		},
		{
			input: "a.b",
			expect: []Module{
				{Name: "a.b.c"},
				{Name: "a.b.cd"},
			},
		},
		{
			input: "a.b.c",
		},
		{
			input: "b",
			expect: []Module{
				{Name: "b.a"},
				{Name: "b.b"},
			},
		},
		{
			input: "asdf",
		},
	} {
		actual := GetModules(tc.input)
		if !reflect.DeepEqual(actual, tc.expect) {
			t.Errorf("Test %d: Expected %v but got %v", i, tc.expect, actual)
		}
	}
}
