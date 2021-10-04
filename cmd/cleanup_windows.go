//go:build windows
// +build windows

package caddycmd

import "golang.org/x/sys/windows"

// Retain the original mode of the console to restore later.
// See: https://github.com/caddyserver/caddy/issues/4251
// The evaluation of this takes place before calling init()
// ref: https://golang.org/ref/spec#Order_of_evaluation
var inMode, outMode uint32
var _ = windows.GetConsoleMode(windows.Stdin, &inMode)
var _ = windows.GetConsoleMode(windows.Stdout, &outMode)

func resetTerminalState() error {
	if err := windows.SetConsoleMode(windows.Stdin, inMode); err != nil {
		return err
	}
	if err := windows.SetConsoleMode(windows.Stdout, outMode); err != nil {
		return err
	}
	return nil
}
