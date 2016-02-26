package caddy

import (
	"reflect"
	"testing"
)

func TestRegister(t *testing.T) {
	directives := []Directive{
		{"dummy", nil, "", ""},
		{"dummy2", nil, "", ""},
	}
	directiveOrder = directives
	RegisterDirective("foo", nil, "dummy")
	if len(directiveOrder) != 3 {
		t.Fatal("Should have 3 directives now")
	}
	getNames := func() (s []string) {
		for _, d := range directiveOrder {
			s = append(s, d.Name)
		}
		return s
	}
	if !reflect.DeepEqual(getNames(), []string{"dummy", "foo", "dummy2"}) {
		t.Fatalf("directive order doesn't match: %s", getNames())
	}
	RegisterDirective("bar", nil, "ASDASD")
	if !reflect.DeepEqual(getNames(), []string{"dummy", "foo", "dummy2", "bar"}) {
		t.Fatalf("directive order doesn't match: %s", getNames())
	}
}
