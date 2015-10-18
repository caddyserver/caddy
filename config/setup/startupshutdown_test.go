package setup

import (
	"fmt"
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

	tempDir := filepath.Join(tempDirPath, "nonexistant_dir_for_testing") // time.nanoseconds is concatenated to the directory in order to ensure uniqueness of the tempDir
	fmt.Println("The temp dir is " + tempDir)

	exec.Command("rm", "-r", tempDir).Start() // removes tempDir from the OS's temp directory, if the tempDir already exists

	startupCommand := ` startup mkdir ` + tempDir + `
			    startup mkdir ` + tempDir + ` &
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
		err = os.Remove(tempDir)
		if err != nil && !test.shouldRemoveErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}

	}

}
