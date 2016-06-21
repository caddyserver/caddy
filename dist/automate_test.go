package main

import (
	"runtime"
	"testing"
)

func TestNumProcs(t *testing.T) {
	n := numProcs()
	if n != runtime.NumCPU()-1 {
		t.Errorf("Expected numProcs to return NumCPU-1, got %d", n)
	}
}
