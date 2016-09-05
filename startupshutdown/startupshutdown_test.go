package startupshutdown

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mholt/caddy"
)

// The Startup function's tests are symmetrical to Shutdown tests,
// because the Startup and Shutdown functions share virtually the
// same functionality
func TestStartup(t *testing.T) {
	tempDirPath := os.TempDir()

	testDir := filepath.Join(tempDirPath, "temp_dir_for_testing_startupshutdown")
	defer func() {
		// clean up after non-blocking startup function quits
		time.Sleep(500 * time.Millisecond)
		os.RemoveAll(testDir)
	}()
	osSenitiveTestDir := filepath.FromSlash(testDir)
	os.RemoveAll(osSenitiveTestDir) // start with a clean slate

	var registeredFunction func() error
	fakeRegister := func(fn func() error) {
		registeredFunction = fn
	}

	tests := []struct {
		input              string
		shouldExecutionErr bool
		shouldRemoveErr    bool
	}{
		// test case #0 tests proper functionality blocking commands
		{"startup mkdir " + osSenitiveTestDir, false, false},

		// test case #1 tests proper functionality of non-blocking commands
		{"startup mkdir " + osSenitiveTestDir + " &", false, true},

		// test case #2 tests handling of non-existent commands
		{"startup " + strconv.Itoa(int(time.Now().UnixNano())), true, true},
	}

	for i, test := range tests {
		c := caddy.NewTestController("", test.input)
		err := registerCallback(c, fakeRegister)
		if err != nil {
			t.Errorf("Expected no errors, got: %v", err)
		}
		if registeredFunction == nil {
			t.Fatalf("Expected function to be registered, but it wasn't")
		}
		err = registeredFunction()
		if err != nil && !test.shouldExecutionErr {
			t.Errorf("Test %d received an error of:\n%v", i, err)
		}
		err = os.Remove(osSenitiveTestDir)
		if err != nil && !test.shouldRemoveErr {
			t.Errorf("Test %d received an error of:\n%v", i, err)
		}
	}
}
