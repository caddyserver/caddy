// +build !go1.8

package push

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestPushUnavailableOnGolangPre18(t *testing.T) {
	err := setup(caddy.NewTestController("http", "push /index.html /index.css"))

	if err != ErrNotSupported {
		t.Fatalf("Expected setup error")
	}
}
