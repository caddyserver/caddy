package httpcaddyfile

import (
	"reflect"
	"sort"
	"testing"
)

func TestHostsFromKeys(t *testing.T) {
	for i, tc := range []struct {
		keys             []Address
		expectNormalMode []string
		expectLoggerMode []string
	}{
		{
			[]Address{
				Address{Original: "foo", Host: "foo"},
			},
			[]string{"foo"},
			[]string{"foo"},
		},
		{
			[]Address{
				Address{Original: "foo", Host: "foo"},
				Address{Original: "bar", Host: "bar"},
			},
			[]string{"bar", "foo"},
			[]string{"bar", "foo"},
		},
		{
			[]Address{
				Address{Original: ":2015", Port: "2015"},
			},
			[]string{}, []string{},
		},
		{
			[]Address{
				Address{Original: ":443", Port: "443"},
			},
			[]string{}, []string{},
		},
		{
			[]Address{
				Address{Original: "foo", Host: "foo"},
				Address{Original: ":2015", Port: "2015"},
			},
			[]string{}, []string{"foo"},
		},
		{
			[]Address{
				Address{Original: "example.com:2015", Host: "example.com", Port: "2015"},
			},
			[]string{"example.com"},
			[]string{"example.com:2015"},
		},
		{
			[]Address{
				Address{Original: "example.com:80", Host: "example.com", Port: "80"},
			},
			[]string{"example.com"},
			[]string{"example.com"},
		},
		{
			[]Address{
				Address{Original: "https://:2015/foo", Scheme: "https", Port: "2015", Path: "/foo"},
			},
			[]string{},
			[]string{},
		},
		{
			[]Address{
				Address{Original: "https://example.com:2015/foo", Scheme: "https", Host: "example.com", Port: "2015", Path: "/foo"},
			},
			[]string{"example.com"},
			[]string{"example.com:2015"},
		},
	} {
		sb := serverBlock{keys: tc.keys}

		// test in normal mode
		actual := sb.hostsFromKeys(false)
		sort.Strings(actual)
		if !reflect.DeepEqual(tc.expectNormalMode, actual) {
			t.Errorf("Test %d (loggerMode=false): Expected: %v Actual: %v", i, tc.expectNormalMode, actual)
		}

		// test in logger mode
		actual = sb.hostsFromKeys(true)
		sort.Strings(actual)
		if !reflect.DeepEqual(tc.expectLoggerMode, actual) {
			t.Errorf("Test %d (loggerMode=true): Expected: %v Actual: %v", i, tc.expectLoggerMode, actual)
		}
	}
}
