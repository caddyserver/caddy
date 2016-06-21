package main

import "testing"

// This works because it does not have the same signature as the
// conventional "TestMain" function described in the testing package
// godoc.
func TestMain(t *testing.T) {
	var ran bool
	run = func() {
		ran = true
	}
	main()
	if !ran {
		t.Error("Expected Run() to be called, but it wasn't")
	}
}
