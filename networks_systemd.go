//go:build linux && !nosystemd

package caddy

import (
	"context"
	"net"
	"sync"
	"os"
	"errors"
	"strconv"
	"fmt"
	"strings"
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

var (
	nameToFiles    map[string][]int
	nameToFilesErr error
	nameToFilesMu  sync.Mutex
)

func sdListenFds() (map[string][]int, error) {
	nameToFilesMu.Lock()
	defer nameToFilesMu.Unlock()

	if nameToFilesErr != nil {
		return nil, nameToFilesErr
	}

	if nameToFiles != nil {
		return nameToFiles, nil
	}

	const lnFdsStart = 3

	lnPid, ok := os.LookupEnv("LISTEN_PID")
	if !ok {
		nameToFilesErr = errors.New("LISTEN_PID is unset.")
		return nil, nameToFilesErr
	}

	pid, err := strconv.ParseUint(lnPid, 0, strconv.IntSize)
	if err != nil {
		nameToFilesErr = err
		return nil, nameToFilesErr
	}

	if pid != uint64(os.Getpid()) {
		nameToFilesErr = fmt.Errorf("LISTEN_PID does not match pid: %d != %d", pid, os.Getpid())
		return nil, nameToFilesErr
	}

	lnFds, ok := os.LookupEnv("LISTEN_FDS")
	if !ok {
		nameToFilesErr = errors.New("LISTEN_FDS is unset.")
		return nil, nameToFilesErr
	}

	fds, err := strconv.ParseUint(lnFds, 0, strconv.IntSize)
	if err != nil {
		nameToFilesErr = err
		return nil, nameToFilesErr
	}

	lnFdnames, ok := os.LookupEnv("LISTEN_FDNAMES")
	if !ok {
		nameToFilesErr = errors.New("LISTEN_FDNAMES is unset.")
		return nil, nameToFilesErr
	}

	fdNames := strings.Split(lnFdnames, ":")
	if fds != uint64(len(fdNames)) {
		nameToFilesErr = fmt.Errorf("LISTEN_FDS does not match LISTEN_FDNAMES length: %d != %d", fds, len(fdNames))
		return nil, nameToFilesErr
	}

	nameToFiles = make(map[string][]int, len(fdNames))
	for index, name := range fdNames {
		nameToFiles[name] = append(nameToFiles[name], lnFdsStart+index)
	}

	return nameToFiles, nil
}

func getListenerFromNetwork(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	if IsSdNetwork(network) {
		sdLnFds, err := sdListenFds()
		if err != nil {
			return nil, err
		}

		name, index, li := host, portOffset, strings.LastIndex(host, "/")
		if li >= 0 {
			name = host[:li]
			i, err := strconv.ParseUint(host[li+1:], 0, strconv.IntSize)
			if err != nil {
				return nil, err
			}
			index += uint(i)
		}

		files, ok := sdLnFds[name]
		if !ok {
			return nil, fmt.Errorf("invalid listen fd name: %s", name)
		}

		if uint(len(files)) <= index {
			return nil, fmt.Errorf("invalid listen fd index: %d", index)
		}
		file := files[index]

		var fdNetwork string
		switch network {
		case "sd":
			fdNetwork = "fd"
		case "sdgram":
			fdNetwork = "fdgram"
		default:
			return nil, fmt.Errorf("invalid network: %s", network)
		}

		na, err := ParseNetworkAddress(JoinNetworkAddress(fdNetwork, strconv.Itoa(file), port))
		if err != nil {
			return nil, err
		}

		return na.Listen(ctx, portOffset, config)
	}
	return getListenerFromPlugin(ctx, network, host, port, portOffset, config)
}

func getHTTP3Network(originalNetwork string) (string, error) {
	switch originalNetwork {
		case "unixgram": return "unixgram", nil
		case "udp":      return "udp", nil
		case "udp4":     return "udp4", nil
		case "udp6":     return "udp6", nil
		case "tcp":      return "udp", nil
		case "tcp4":     return "udp4", nil
		case "tcp6":     return "udp6", nil
		case "fdgram":   return "fdgram", nil
		case "sdgram":   return "sdgram", nil
	}
	return getHTTP3Plugin(originalNetwork)
}
