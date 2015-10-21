package middleware

import (
	"errors"
	"runtime"
	"strings"
	"unicode"

	"github.com/flynn/go-shlex"
)

// SplitCommandAndArgs takes a command string and parses it
// shell-style into the command and its separate arguments.
func SplitCommandAndArgs(command string) (cmd string, args []string, err error) {
	var parts []string

	if runtime.GOOS == "windows" {
		parts = parseWindowsCommand(command) // parse it Windows-style
	} else {
		parts, err = shlex.Split(command) // parse it Unix-style
		if err != nil {
			err = errors.New("error parsing command: " + err.Error())
			return
		}
	}

	if len(parts) == 0 {
		err = errors.New("no command contained in '" + command + "'")
		return
	}

	cmd = parts[0]
	if len(parts) > 1 {
		args = parts[1:]
	}

	return
}

// parseWindowsCommand is a sad but good-enough attempt to
// split a command into the command and its arguments like
// the Windows command line would; only basic parsing is
// supported. This function has to be used on Windows instead
// of the shlex package because this function treats backslash
// characters properly.
//
// Loosely based off the rules here: http://stackoverflow.com/a/4094897/1048862
// True parsing is much, much trickier.
func parseWindowsCommand(cmd string) []string {
	var parts []string
	var part string
	var quoted bool
	var backslashes int

	for _, ch := range cmd {
		if ch == '\\' {
			backslashes++
			continue
		}
		var evenBacksl = (backslashes % 2) == 0
		if backslashes > 0 && ch != '\\' {
			numBacksl := (backslashes / 2) + 1
			if ch == '"' {
				numBacksl--
			}
			part += strings.Repeat(`\`, numBacksl)
			backslashes = 0
		}

		if quoted {
			if ch == '"' && evenBacksl {
				quoted = false
				continue
			}
			part += string(ch)
			continue
		}

		if unicode.IsSpace(ch) && len(part) > 0 {
			parts = append(parts, part)
			part = ""
			continue
		}

		if ch == '"' && evenBacksl {
			quoted = true
			continue
		}

		part += string(ch)
	}

	if len(part) > 0 {
		parts = append(parts, part)
		part = ""
	}

	return parts
}
