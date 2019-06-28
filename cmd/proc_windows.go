package caddycmd

import (
	"fmt"
	"os/exec"
	"strconv"
)

func gracefullyStopProcess(pid int) error {
	cmd := exec.Command("taskkill", "/pid", strconv.Itoa(pid))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("taskkill: %v", err)
	}
	return nil
}
