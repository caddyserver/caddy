package syntax

import (
	"testing"
)

func TestTagParsing(t *testing.T) {
	opts := parseTag("=x,head=2,min=3,max=60000,unknown")
	if len(opts) != 3 {
		t.Fatalf("Failed to parse all fields")
	}
	if opts["head"] != 2 || opts["min"] != 3 || opts["max"] != 60000 {
		t.Fatalf("Parsed fields incorrectly")
	}
}
