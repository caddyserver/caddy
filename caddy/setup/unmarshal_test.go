package setup

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

type TestStruct struct {
	A string            // a foo
	B int               // b 42
	C bool              // c
	D []string          // d foo (allowed multiple times)
	E []int             // e 13 (allowed multiple times)
	G net.IP            // g 1.2.3.4
	H []net.IP          // h 1.2.3.4 (multiple)
	I net.Addr          // i 1.2.3.0\16
	J []net.Addr        // multiple cidrs
	K map[string]string // k key1 val1 \n k key2 val2
	L [][]string        // each line is one slice. All args are included
	Z string            `caddy:"m"`
}

func TestUnmarshal(t *testing.T) {
	_, c1, _ := net.ParseCIDR("1.2.3.0/0")
	_, c2, _ := net.ParseCIDR("2.2.3.0/0")
	tsts := []struct {
		input    []string
		expected *TestStruct
	}{
		{[]string{"a foo"}, &TestStruct{A: "foo"}},
		{[]string{"b 42"}, &TestStruct{B: 42}},
		{[]string{"C"}, &TestStruct{C: true}},
		{[]string{"C true"}, &TestStruct{C: true}},
		{[]string{"c false"}, &TestStruct{C: false}},
		{[]string{"d foo", "d bar"}, &TestStruct{D: []string{"foo", "bar"}}},
		{[]string{"E 17", "e -42"}, &TestStruct{E: []int{17, -42}}},
		{[]string{"g 1.2.3.4"}, &TestStruct{G: net.ParseIP("1.2.3.4")}},
		{[]string{"h 1.2.3.4", "h 2.3.4.5"}, &TestStruct{H: []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("2.3.4.5")}}},
		{[]string{"i 1.2.3.0/0"}, &TestStruct{I: c1}},
		{[]string{"j 1.2.3.0/0", "j 1.2.3.0/0"}, &TestStruct{J: []net.Addr{c1, c2}}},
		{[]string{"k a boo", `k foo "a b c d e"`}, &TestStruct{K: map[string]string{"a": "boo", "foo": "a b c d e"}}},
		{[]string{"l a b c", "l d e f g h"}, &TestStruct{L: [][]string{[]string{"a", "b", "c"}, []string{"d", "e", "f", "g", "h"}}}},
		{[]string{"m foo"}, &TestStruct{Z: "foo"}},
	}
	for i, tst := range tsts {
		input := fmt.Sprintf("{\n  %s\n}", strings.Join(tst.input, "\n  "))
		c := NewTestController(input)
		ts := &TestStruct{}
		err := c.Unmarshal(ts)
		if err != nil {
			t.Error(err)
			continue
		}
		if !reflect.DeepEqual(ts, tst.expected) {
			t.Errorf("Test %d: structs don't match", i)
		}
	}
}
