package app_test

import (
	"runtime"
	"testing"

	"github.com/mholt/caddy/app"
)

func TestSetCPU(t *testing.T) {
	currentCPU := runtime.GOMAXPROCS(-1)
	maxCPU := runtime.NumCPU()
	for i, test := range []struct {
		input     string
		output    int
		shouldErr bool
	}{
		{"1", 1, false},
		{"-1", currentCPU, true},
		{"0", currentCPU, true},
		{"100%", maxCPU, false},
		{"50%", int(0.5 * float32(maxCPU)), false},
		{"110%", currentCPU, true},
		{"-10%", currentCPU, true},
		{"invalid input", currentCPU, true},
		{"invalid input%", currentCPU, true},
		{"9999", maxCPU, false}, // over available CPU
	} {
		err := app.SetCPU(test.input)
		if test.shouldErr && err == nil {
			t.Errorf("Test %d: Expected error, but there wasn't any", i)
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: Expected no error, but there was one: %v", i, err)
		}
		if actual, expected := runtime.GOMAXPROCS(-1), test.output; actual != expected {
			t.Errorf("Test %d: GOMAXPROCS was %d but expected %d", i, actual, expected)
		}
		// teardown
		runtime.GOMAXPROCS(currentCPU)
	}
}
