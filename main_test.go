package main

import (
	"runtime"
	"testing"
)

func TestSetCPU(t *testing.T) {
	currentCPU := runtime.GOMAXPROCS(-1)
	maxCPU := runtime.NumCPU()
	halfCPU := int(0.5 * float32(maxCPU))
	if halfCPU < 1 {
		halfCPU = 1
	}
	for i, test := range []struct {
		input     string
		output    int
		shouldErr bool
	}{
		{"1", 1, false},
		{"-1", currentCPU, true},
		{"0", currentCPU, true},
		{"100%", maxCPU, false},
		{"50%", halfCPU, false},
		{"110%", currentCPU, true},
		{"-10%", currentCPU, true},
		{"invalid input", currentCPU, true},
		{"invalid input%", currentCPU, true},
		{"9999", maxCPU, false}, // over available CPU
	} {
		err := setCPU(test.input)
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

func TestSetVersion(t *testing.T) {
	setVersion()
	if !devBuild {
		t.Error("Expected default to assume development build, but it didn't")
	}
	if got, want := appVersion, "(untracked dev build)"; got != want {
		t.Errorf("Expected appVersion='%s', got: '%s'", want, got)
	}

	gitTag = "v1.1"
	setVersion()
	if devBuild {
		t.Error("Expected a stable build if gitTag is set with no changes")
	}
	if got, want := appVersion, "1.1"; got != want {
		t.Errorf("Expected appVersion='%s', got: '%s'", want, got)
	}

	gitTag = ""
	gitNearestTag = "v1.0"
	gitCommit = "deadbeef"
	buildDate = "Fri Feb 26 06:53:17 UTC 2016"
	setVersion()
	if !devBuild {
		t.Error("Expected inferring a dev build when gitTag is empty")
	}
	if got, want := appVersion, "1.0 (+deadbeef Fri Feb 26 06:53:17 UTC 2016)"; got != want {
		t.Errorf("Expected appVersion='%s', got: '%s'", want, got)
	}
}
