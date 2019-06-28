// +build !windows

package caddycmd

import (
	"fmt"
	"syscall"
)

func gracefullyStopProcess(pid int) error {
	err := syscall.Kill(pid, syscall.SIGINT)
	if err != nil {
		return fmt.Errorf("kill: %v", err)
	}
	return nil
}
