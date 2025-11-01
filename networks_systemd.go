//go:build linux && !nosystemd

package caddy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

func IsSdNetwork(network string) bool {
	return network == "sd" || network == "sdgram"
}

func IsReservedNetwork(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6" ||
		network == "udp" || network == "udp4" || network == "udp6" ||
		IsUnixNetwork(network) ||
		IsIpNetwork(network) ||
		IsFdNetwork(network) ||
		IsSdNetwork(network)
}

func sdListenFdsWithNames() (map[string][]uint, error) {
	const lnFdsStart = 3

	lnPid, ok := os.LookupEnv("LISTEN_PID")
	if !ok {
		return nil, errors.New("LISTEN_PID is unset.")
	}

	pid, err := strconv.ParseUint(lnPid, 0, strconv.IntSize)
	if err != nil {
		return nil, err
	}

	if pid != uint64(os.Getpid()) {
		return nil, fmt.Errorf("LISTEN_PID does not match pid: %d != %d", pid, os.Getpid())
	}

	lnFds, ok := os.LookupEnv("LISTEN_FDS")
	if !ok {
		return nil, errors.New("LISTEN_FDS is unset.")
	}

	fds, err := strconv.ParseUint(lnFds, 0, strconv.IntSize)
	if err != nil {
		return nil, err
	}

	lnFdnames, ok := os.LookupEnv("LISTEN_FDNAMES")
	if !ok {
		return nil, errors.New("LISTEN_FDNAMES is unset.")
	}

	fdNames := strings.Split(lnFdnames, ":")
	if fds != uint64(len(fdNames)) {
		return nil, fmt.Errorf("LISTEN_FDS does not match LISTEN_FDNAMES length: %d != %d", fds, len(fdNames))
	}

	nameToFiles := make(map[string][]uint, len(fdNames))
	for index, name := range fdNames {
		nameToFiles[name] = append(nameToFiles[name], lnFdsStart+uint(index))
	}

	return nameToFiles, nil
}

func sdListenFd(nameToFiles map[string][]uint, host string, portOffset uint) (uint, error) {
	name, index, li := host, portOffset, strings.LastIndex(host, "/")
	if li >= 0 {
		name = host[:li]
		i, err := strconv.ParseUint(host[li+1:], 0, strconv.IntSize)
		if err != nil {
			return 0, err
		}
		index += uint(i)
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

var (
	initNameToFiles    map[string][]uint
	initNameToFilesErr error
	initNameToFilesMu  sync.Mutex
)

func getListenerFromNetwork(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	if IsSdNetwork(network) {
		initNameToFilesMu.Lock()
		defer initNameToFilesMu.Unlock()

		if initNameToFiles == nil && initNameToFilesErr == nil {
			initNameToFiles, initNameToFilesErr = sdListenFdsWithNames()
		}

		if initNameToFilesErr != nil {
			return nil, initNameToFilesErr
		}

		file, err := sdListenFd(initNameToFiles, host, portOffset)
		if err != nil {
			return nil, err
		}

		var fdNetwork string
		switch network {
		case "sd":
			fdNetwork = "fd"
		case "sdgram":
			fdNetwork = "fdgram"
		default:
			return nil, fmt.Errorf("invalid network: %s", network)
		}

		na, err := ParseNetworkAddress(JoinNetworkAddress(fdNetwork, strconv.FormatUint(uint64(file), 10), port))
		if err != nil {
			return nil, err
		}

		return na.Listen(ctx, portOffset, config)
	}
	return getListenerFromPlugin(ctx, network, host, port, portOffset, config)
}

func getHTTP3Network(originalNetwork string) (string, error) {
	switch originalNetwork {
	case "unixgram":
		return "unixgram", nil
	case "udp":
		return "udp", nil
	case "udp4":
		return "udp4", nil
	case "udp6":
		return "udp6", nil
	case "tcp":
		return "udp", nil
	case "tcp4":
		return "udp4", nil
	case "tcp6":
		return "udp6", nil
	case "fdgram":
		return "fdgram", nil
	case "sdgram":
		return "sdgram", nil
	}
	return getHTTP3Plugin(originalNetwork)
}
