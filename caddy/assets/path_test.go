package assets

import (
	"strings"
	"testing"
)

func TestPath(t *testing.T) {
	if actual := Path(); !strings.HasSuffix(actual, ".caddy") {
		t.Errorf("Expected path to be a .caddy folder, got: %v", actual)
	}
}
