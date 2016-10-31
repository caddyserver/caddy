package maxrequestbody

import (
	"reflect"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

const (
	KB = 1024
	MB = 1024 * 1024
	GB = 1024 * 1024 * 1024
)

func TestParseArguments(t *testing.T) {
	cases := []struct {
		arguments []pathLimitUnparsed
		expected  []httpserver.PathLimit
		hasError  bool
	}{
		// Parse errors
		{arguments: []pathLimitUnparsed{{"/", "123.5"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "200LB"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "path:999MB"}}, expected: []httpserver.PathLimit{}, hasError: true},
		{arguments: []pathLimitUnparsed{{"/", "1_234_567"}}, expected: []httpserver.PathLimit{}, hasError: true},

		// Valid results
		{arguments: []pathLimitUnparsed{}, expected: []httpserver.PathLimit{}, hasError: false},
		{
			arguments: []pathLimitUnparsed{{"/", "100"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/", "100KB"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100 * KB}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/", "100MB"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100 * MB}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/", "100GB"}},
			expected:  []httpserver.PathLimit{{Path: "/", Limit: 100 * GB}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"index", "100"}},
			expected:  []httpserver.PathLimit{{Path: "/index", Limit: 100}},
			hasError:  false,
		},
		{
			arguments: []pathLimitUnparsed{{"/home", "100MB"}, {"/upload/images", "500GB"}},
			expected: []httpserver.PathLimit{
				{Path: "/home", Limit: 100 * MB},
				{Path: "/upload/images", Limit: 500 * GB},
			},
			hasError: false},
		{
			arguments: []pathLimitUnparsed{{"/", "999"}, {"/home", "12345MB"}},
			expected: []httpserver.PathLimit{
				{Path: "/", Limit: 999},
				{Path: "/home", Limit: 12345 * MB},
			},
			hasError: false,
		},

		// Duplicates
		{
			arguments: []pathLimitUnparsed{{"/home", "999"}, {"/home", "12345MB"}},
			expected: []httpserver.PathLimit{
				{Path: "/home", Limit: 12345 * MB},
			},
			hasError: false,
		},
	}

	for caseNum, c := range cases {
		output, err := parseArguments(c.arguments)
		if c.hasError && (err == nil) {
			t.Errorf("Expecting error for case %v but none encountered", caseNum)
		}
		if !c.hasError && (err != nil) {
			t.Errorf("Expecting no error for case %v but encountered %v", caseNum, err)
		}

		if !reflect.DeepEqual(c.expected, output) {
			t.Errorf("Case %v is expecting: %v, actual %v", caseNum, c.expected, output)
		}
	}
}

func TestSortPathLimits(t *testing.T) {
	cases := []struct {
		arguments []httpserver.PathLimit
		expected  []httpserver.PathLimit
	}{
		// Parse errors
		{arguments: []httpserver.PathLimit{}, expected: []httpserver.PathLimit{}},
		{
			arguments: []httpserver.PathLimit{{Path: "/index", Limit: 100}},
			expected:  []httpserver.PathLimit{{Path: "/index", Limit: 100}},
		},
		{
			arguments: []httpserver.PathLimit{
				{Path: "/static", Limit: 1},
				{Path: "/static/images", Limit: 100},
				{Path: "/index", Limit: 200},
			},
			expected: []httpserver.PathLimit{
				{Path: "/static/images", Limit: 100},
				{Path: "/static", Limit: 1},
				{Path: "/index", Limit: 200}},
		},
	}

	for caseNum, c := range cases {
		output := append([]httpserver.PathLimit{}, c.arguments...)
		SortPathLimits(output)
		if !reflect.DeepEqual(c.expected, output) {
			t.Errorf("Case %v is expecting: %v, actual %v", caseNum, c.expected, output)
		}
	}
}
