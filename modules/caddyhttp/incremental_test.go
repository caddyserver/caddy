package caddyhttp

import (
	"net/http"
	"testing"
)

func TestIsIncremental(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent"},
		{name: "true", values: []string{"?1"}, want: true},
		{name: "false", values: []string{"?0"}},
		{name: "surrounding space", values: []string{" ?1 "}, want: true},
		{name: "unknown parameter", values: []string{"?1;q=0.5"}, want: true},
		{name: "empty parameter", values: []string{"?1;"}},
		{name: "trailing garbage", values: []string{"?1 junk"}},
		{name: "integer", values: []string{"1"}},
		{name: "token", values: []string{"true"}},
		{name: "string", values: []string{`"?1"`}},
		{name: "invalid boolean", values: []string{"?2"}},
		{name: "empty value", values: []string{""}},
		{name: "repeated field", values: []string{"?1", "?0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := http.Header{}
			for _, v := range tc.values {
				hdr.Add(incrementalHeader, v)
			}
			if got := IsIncremental(hdr); got != tc.want {
				t.Errorf("IsIncremental(%q) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

func BenchmarkIsIncremental(b *testing.B) {
	for _, bc := range []struct {
		name  string
		value string
	}{
		{name: "absent"},
		{name: "true", value: "?1"},
		{name: "false", value: "?0"},
		{name: "true with param", value: "?1;q=0.5"},
	} {
		hdr := http.Header{}
		if bc.value != "" {
			hdr.Set(incrementalHeader, bc.value)
		}
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				IsIncremental(hdr)
			}
		})
	}
}
