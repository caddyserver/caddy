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

package systemd

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
)

const systemdListenFDStart = 3 // stdin, stdout and stderr occupy descriptors 0 to 2

var cachedSystemdListenFDs = sync.OnceValues(func() (map[string]int, error) {
	return parseSystemdListenFDs(os.Getpid(), os.LookupEnv)
})

// ListenFD returns the first inherited descriptor with name.
func ListenFD(name string) (int, error) {
	descriptors, err := cachedSystemdListenFDs()
	if err != nil {
		return 0, err
	}
	return systemdListenFDByName(descriptors, name)
}

func parseSystemdListenFDs(pid int, lookupEnv func(string) (string, bool)) (map[string]int, error) {
	listenPID, ok := lookupEnv("LISTEN_PID")
	if !ok {
		return nil, errors.New("systemd socket activation: LISTEN_PID is unset")
	}
	parsedPID, err := strconv.Atoi(listenPID)
	if err != nil {
		return nil, fmt.Errorf("systemd socket activation: parsing LISTEN_PID: %w", err)
	}
	if parsedPID != pid {
		return nil, fmt.Errorf("systemd socket activation: LISTEN_PID does not match process: %d != %d", parsedPID, pid)
	}

	listenFDs, ok := lookupEnv("LISTEN_FDS")
	if !ok {
		return nil, errors.New("systemd socket activation: LISTEN_FDS is unset")
	}
	fdCount, err := strconv.Atoi(listenFDs)
	if err != nil {
		return nil, fmt.Errorf("systemd socket activation: parsing LISTEN_FDS: %w", err)
	}
	if fdCount <= 0 || fdCount > math.MaxInt-systemdListenFDStart {
		return nil, fmt.Errorf("systemd socket activation: invalid LISTEN_FDS count: %d", fdCount)
	}

	listenFDNames, ok := lookupEnv("LISTEN_FDNAMES")
	if !ok {
		return nil, errors.New("systemd socket activation: LISTEN_FDNAMES is unset")
	}
	names := strings.Split(listenFDNames, ":")
	if len(names) != fdCount {
		return nil, fmt.Errorf("systemd socket activation: LISTEN_FDS does not match LISTEN_FDNAMES count: %d != %d", fdCount, len(names))
	}

	descriptors := make(map[string]int, len(names))
	for index, name := range names {
		if _, exists := descriptors[name]; !exists {
			descriptors[name] = systemdListenFDStart + index
		}
	}
	return descriptors, nil
}

func systemdListenFDByName(descriptors map[string]int, name string) (int, error) {
	if name == "" {
		return 0, errors.New("systemd listen descriptor name is empty")
	}
	descriptor, ok := descriptors[name]
	if !ok {
		return 0, fmt.Errorf("systemd listen descriptor name not found: %q", name)
	}
	return descriptor, nil
}
