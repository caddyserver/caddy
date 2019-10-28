// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !windows

package caddycmd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func gracefullyStopProcess(pid int) error {
	fmt.Printf("Graceful stop...\n")
	err := syscall.Kill(pid, syscall.SIGINT)
	if err != nil {
		return fmt.Errorf("kill: %v", err)
	}
	return nil
}

func getProcessName() string {
	return filepath.Base(os.Args[0])
}
