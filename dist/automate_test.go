package main

import (
	"runtime"
	"testing"
)

func TestNumProcs(t *testing.T) {
	num := runtime.NumCPU()
	n := numProcs()
	if n > num || n < 1 {
		t.Errorf("Expected numProcs() to return max(NumCPU-1, 1) or at least some "+
			"reasonable value (depending on CI environment), but got n=%d (NumCPU=%d)", n, num)
	}
}
