//go:build linux && !nosystemd

package caddy

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

func sdListenFds() (int, error) {
	lnPid, ok := os.LookupEnv("LISTEN_PID")
	if !ok {
		return 0, errors.New("LISTEN_PID is unset")
	}

	pid, err := strconv.Atoi(lnPid)
	if err != nil {
		return 0, err
	}

	if pid != os.Getpid() {
		return 0, fmt.Errorf("LISTEN_PID does not match pid: %d != %d", pid, os.Getpid())
	}

	lnFds, ok := os.LookupEnv("LISTEN_FDS")
	if !ok {
		return 0, errors.New("LISTEN_FDS is unset")
	}

	fds, err := strconv.Atoi(lnFds)
	if err != nil {
		return 0, err
	}

	return fds, nil
}

func sdListenFdsWithNames() (map[string][]uint, error) {
	const lnFdsStart = 3

	fds, err := sdListenFds()
	if err != nil {
		return nil, err
	}

	lnFdnames, ok := os.LookupEnv("LISTEN_FDNAMES")
	if !ok {
		return nil, errors.New("LISTEN_FDNAMES is unset")
	}

	fdNames := strings.Split(lnFdnames, ":")
	if fds != len(fdNames) {
		return nil, fmt.Errorf("LISTEN_FDS does not match LISTEN_FDNAMES length: %d != %d", fds, len(fdNames))
	}

	nameToFiles := make(map[string][]uint, len(fdNames))
	for index, name := range fdNames {
		nameToFiles[name] = append(nameToFiles[name], lnFdsStart+uint(index))
	}

	return nameToFiles, nil
}

func getSdListenFd(nameToFiles map[string][]uint, nameOffset string) (uint, error) {
	index := uint(0)

	name, offset, found := strings.Cut(nameOffset, ":")
	if found {
		off, err := strconv.ParseUint(offset, 0, strconv.IntSize)
		if err != nil {
			return 0, err
		}
		index += uint(off)
	}

	files, ok := nameToFiles[name]
	if !ok {
		return 0, fmt.Errorf("invalid listen fd name: %s", name)
	}

	if uint(len(files)) <= index {
		return 0, fmt.Errorf("invalid listen fd index: %d", index)
	}

	return files[index], nil
}

var initNameToFiles, initNameToFilesErr = sdListenFdsWithNames()

// systemdReplacementProvider handles {systemd.*} replacements
type systemdReplacementProvider struct{}

func (f systemdReplacementProvider) replace(key string) (any, bool) {
	// check environment variable
	const systemdListenPrefix = "systemd.listen."
	if strings.HasPrefix(key, systemdListenPrefix) {
		if initNameToFilesErr != nil {
			Log().Error("unable to read LISTEN_FDNAMES", zap.Error(initNameToFilesErr))
			return nil, false
		}
		fd, err := getSdListenFd(initNameToFiles, key[len(systemdListenPrefix):])
		if err != nil {
			Log().Error("unable to process {" + key + "}", zap.Error(err))
			return nil, false
		}
		return fd, true
	}

	// TODO const systemdCredsPrefix = "systemd.creds."

	return nil, false
}

var globalReplacementProviders = []replacementProvider{
	defaultReplacementProvider{},
	fileReplacementProvider{},
	systemdReplacementProvider{},
}
