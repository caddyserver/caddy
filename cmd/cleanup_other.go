//go:build !windows
// +build !windows

package caddycmd

func resetTerminalState() error { return nil }
