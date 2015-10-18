package setup

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/server"
)

// The Startup function's tests are symmetrical to Shutdown tests,
// because the Startup and Shutdown functions share virtually the
// same functionality
func TestStartupWithBlockingCommand(t *testing.T) {
	var startupFuncs []func() error

	startupCommand := `-startup mkdir temp_dir_for_testing
			   -startup mkdir temp_dir_for_testing &
			   -startup highly_unlikely_to_exist_command 
			  `
	c := &Controller{
		Config:    &server.Config{Startup: startupFuncs},
		Dispenser: parse.NewDispenser("", strings.NewReader(startupCommand)),
	}

	_, err := Startup(c)
	if err != nil {
		t.Errorf("Expected no errors, got: %v", err)
	}

	tests := []struct {
		shouldExecutionErr bool
		shouldRemoveErr    bool
	}{
		{false, false},
		{false, true},
		{true, true},
	}

	for i, test := range tests {
		err = c.Startup[i]()
		if err != nil && !test.shouldExecutionErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}
		err = os.Remove("./temp_dir_for_testing")
		if err != nil && !test.shouldRemoveErr {
			t.Errorf("Test %d recieved an error of:\n%v", i, err)
		}

	}

	exec.Command("rm", "-r", "./temp_dir_for_testing").Start()

}
