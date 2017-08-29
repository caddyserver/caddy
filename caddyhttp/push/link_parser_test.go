package push

import (
	"reflect"
	"testing"
)

func TestDifferentParserInputs(t *testing.T) {
	testCases := []struct {
		header            string
		expectedResources []linkResource
	}{
		{
			header:            "</resource>; as=script",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{"as": "script"}}},
		},
		{
			header:            "</resource>",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{}}},
		},
		{
			header:            "</resource>; nopush",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{"nopush": "nopush"}}},
		},
		{
			header:            "</resource>;nopush;rel=next",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{"nopush": "nopush", "rel": "next"}}},
		},
		{
			header: "</resource>;nopush;rel=next,</resource2>;nopush",
			expectedResources: []linkResource{
				{uri: "/resource", params: map[string]string{"nopush": "nopush", "rel": "next"}},
				{uri: "/resource2", params: map[string]string{"nopush": "nopush"}},
			},
		},
		{
			header: "</resource>,</resource2>",
			expectedResources: []linkResource{
				{uri: "/resource", params: map[string]string{}},
				{uri: "/resource2", params: map[string]string{}},
			},
		},
		{
			header:            "malformed",
			expectedResources: []linkResource{},
		},
		{
			header:            "<malformed",
			expectedResources: []linkResource{},
		},
		{
			header:            ",",
			expectedResources: []linkResource{},
		},
		{
			header:            ";",
			expectedResources: []linkResource{},
		},
		{
			header:            "</resource> ; ",
			expectedResources: []linkResource{{uri: "/resource", params: map[string]string{}}},
		},
	}

	for i, test := range testCases {

		actualResources := parseLinkHeader(test.header)

		if !reflect.DeepEqual(actualResources, test.expectedResources) {
			t.Errorf("Test %d (header: %s) - expected resources %v, got %v", i, test.header, test.expectedResources, actualResources)
		}
	}
}
