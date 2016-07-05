package caddy

import (
	"os"
	"strings"
	"testing"
)

func TestAssetsPath(t *testing.T) {
	if actual := AssetsPath(); !strings.HasSuffix(actual, ".caddy") {
		t.Errorf("Expected path to be a .caddy folder, got: %v", actual)
	}

	os.Setenv("CADDYPATH", "testpath")
	if actual, expected := AssetsPath(), "testpath"; actual != expected {
		t.Errorf("Expected path to be %v, got: %v", expected, actual)
	}
	os.Setenv("CADDYPATH", "")
}
