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

//go:build linux

package internal

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// WithBindCapability calls listen, which should bind to address on
// network, raising CAP_NET_BIND_SERVICE for the duration of the call
// if address is a privileged TCP or UDP port and the capability is in
// the permitted set but not the effective set.
//
// This allows the caddy binary to be granted the capability with
// `setcap cap_net_bind_service=+p` instead of `=+ep`. With the effective
// bit set, the kernel refuses to execute the binary at all when the
// capability can't be granted (for example, in containers run with
// `--cap-drop ALL`, or systemd units with an empty CapabilityBoundingSet),
// even if Caddy never binds a privileged port. See "Safety checking for
// capability-dumb binaries" in capabilities(7).
func WithBindCapability(network, address string, listen func() (any, error)) (any, error) {
	if !isPrivilegedPort(network, address) {
		return listen()
	}
	if raise, err := shouldRaiseBindCapability(); err != nil || !raise {
		return listen()
	}

	// capabilities are per-thread, so raise it on a locked OS thread
	// and bind from there; the goroutine exits without unlocking, so
	// the runtime terminates the thread instead of reusing it with
	// the raised capability (or wedges it, if it is the main thread,
	// which is why we also lower it again after binding)
	type result struct {
		ln  any
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if err := setBindCapability(true); err != nil {
			ch <- result{err: fmt.Errorf("raising CAP_NET_BIND_SERVICE: %v", err)}
			return
		}
		ln, err := listen()
		_ = setBindCapability(false)
		ch <- result{ln, err}
	}()
	r := <-ch
	return r.ln, r.err
}

// isPrivilegedPort reports whether address is a TCP or UDP
// address with a port below 1024 (other than 0).
func isPrivilegedPort(network, address string) bool {
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return false
	}
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	return err == nil && port > 0 && port < 1024
}

const bindCapabilityMask = 1 << unix.CAP_NET_BIND_SERVICE

// shouldRaiseBindCapability reports whether CAP_NET_BIND_SERVICE is
// permitted but not effective for the calling thread.
func shouldRaiseBindCapability() (bool, error) {
	_, data, err := getCapabilities()
	if err != nil {
		return false, err
	}
	return data[0].Permitted&bindCapabilityMask != 0 &&
		data[0].Effective&bindCapabilityMask == 0, nil
}

// setBindCapability adds or removes CAP_NET_BIND_SERVICE in the
// effective set of the calling thread. To add it, it must already
// be permitted.
func setBindCapability(effective bool) error {
	hdr, data, err := getCapabilities()
	if err != nil {
		return err
	}
	if effective {
		data[0].Effective |= bindCapabilityMask
	} else {
		data[0].Effective &^= bindCapabilityMask
	}
	return unix.Capset(&hdr, &data[0])
}

func getCapabilities() (unix.CapUserHeader, [2]unix.CapUserData, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	err := unix.Capget(&hdr, &data[0])
	return hdr, data, err
}
