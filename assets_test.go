package caddy

import (
	"strings"
	"testing"
)

func TestAssetsPath(t *testing.T) {
	if actual := AssetsPath(); !strings.HasSuffix(actual, ".caddy") {
		t.Errorf("Expected path to be a .caddy folder, got: %v", actual)
	}
}
