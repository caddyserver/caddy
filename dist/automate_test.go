package main

import (
	"runtime"
	"testing"
)

func TestNumProcs(t *testing.T) {
	num := runtime.NumCPU()
	n := numProcs()
	if num > 1 && n != num-1 {
		t.Errorf("Expected numProcs to return max(NumCPU-1, 0) but got %d (NumCPU=%d)", n, num)
	}
}
