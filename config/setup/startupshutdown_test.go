package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/server"
)

// The Startup function's tests are symmetrical to Shutdown tests,
// because the Startup and Shutdown functions share virtually the
// same functionality
func TestStartup(t *testing.T) {

	var startupFuncs []func() error

	tempDirPath, err := getTempDirPath() // function defined in caddy/config/setup/root_test.go
	if err != nil {
		t.Fatalf("BeforeTest: Failed to find an existing directory for testing! Error was: %v", err)
	}

	testDir := filepath.Join(tempDirPath, "temp_dir_for_testing_startupshutdown.go")
	osSenitiveTestDir := filepath.FromSlash(testDir) // path separators correspond to OS-specific path separator

	exec.Command("rm", "-r", osSenitiveTestDir).Start() // removes osSenitiveTestDir from the OS's temp directory, if the osSenitiveTestDir already exists

	startupCommand := ` startup mkdir ` + osSenitiveTestDir + `
			    startup mkdir ` + osSenitiveTestDir + ` &
			    startup highly_unlikely_to_exist_command
			  `
	c := &Controller{
		Config:    &server.Config{Startup: startupFuncs},
		Dispenser: parse.NewDispenser("", strings.NewReader(startupCommand)),
	}
	_, err = Startup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	tests := []struct {
		shouldExecutionErr bool
		shouldRemoveErr    bool
	}{
		{false, false}, // expected struct booleans for blocking commands
		{false, true},  // expected struct booleans for non-blocking commands
		{true, true},   // expected struct booleans for non-existant commands
	}

	for i, test := range tests {
		err = c.Startup[i]()
		if err != nil && !test.shouldExecutionErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}
		err = os.Remove(osSenitiveTestDir)
		if err != nil && !test.shouldRemoveErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}

	}

}
