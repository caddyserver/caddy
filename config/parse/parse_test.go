package parse

import (
	"strings"
	"testing"
)

func TestAllTokens(t *testing.T) {
	input := strings.NewReader("a b c\nd e")
	expected := []string{"a", "b", "c", "d", "e"}
	tokens := allTokens(input)

	if len(tokens) != len(expected) {
		t.Fatalf("Expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, val := range expected {
		if tokens[i].text != val {
			t.Errorf("Token %d should be '%s' but was '%s'", i, val, tokens[i].text)
		}
	}
}
