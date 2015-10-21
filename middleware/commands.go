package middleware

import (
	"errors"
	"runtime"
	"strings"

	"github.com/flynn/go-shlex"
)

// SplitCommandAndArgs takes a command string and parses it
// shell-style into the command and its separate arguments.
func SplitCommandAndArgs(command string) (cmd string, args []string, err error) {

	// ensures that shlex does not strip Windows paths of their path separator
	if runtime.GOOS == "windows" {
		command = strings.Replace(command, "\\", "\\\\", -1)
	}

	parts, err := shlex.Split(command)
	if err != nil {
		err = errors.New("error parsing command: " + err.Error())
		return
	} else if len(parts) == 0 {
		err = errors.New("no command contained in '" + command + "'")
		return
	}

	cmd = parts[0]
	if len(parts) > 1 {
		args = parts[1:]
	}

	return
}
