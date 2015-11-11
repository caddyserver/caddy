package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The Startup function's tests are symmetrical to Shutdown tests,
// because the Startup and Shutdown functions share virtually the
// same functionality
func TestStartup(t *testing.T) {

	tempDirPath, err := getTempDirPath()
	if err != nil {
		t.Fatalf("BeforeTest: Failed to find an existing directory for testing! Error was: %v", err)
	}

	testDir := filepath.Join(tempDirPath, "temp_dir_for_testing_startupshutdown.go")
	osSenitiveTestDir := filepath.FromSlash(testDir)

	exec.Command("rm", "-r", osSenitiveTestDir).Run() // removes osSenitiveTestDir from the OS's temp directory, if the osSenitiveTestDir already exists

	tests := []struct {
		input              string
		shouldExecutionErr bool
		shouldRemoveErr    bool
	}{
		// test case #0 tests proper functionality blocking commands
		{"startup mkdir " + osSenitiveTestDir, false, false},

		// test case #1 tests proper functionality of non-blocking commands
		{"startup mkdir " + osSenitiveTestDir + " &", false, true},

		// test case #2 tests handling of non-existant commands
		{"startup " + strconv.Itoa(int(time.Now().UnixNano())), true, true},
	}

	for i, test := range tests {
		c := NewTestController(test.input)
		_, err = Startup(c)
		if err != nil {
			t.Errorf("Expected no errors, got: %v", err)
		}
		err = c.FirstStartup[0]()
		if err != nil && !test.shouldExecutionErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}
		err = os.Remove(osSenitiveTestDir)
		if err != nil && !test.shouldRemoveErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}

	}
}
