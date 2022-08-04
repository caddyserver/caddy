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

// Package notify provides facilities for notifying process managers
// of state changes, mainly for when running as a system service.
package notify

import (
	"io"
	"net"
	"os"
	"strings"
)

// The documentation about this IPC protocol is available here:
// https://www.freedesktop.org/software/systemd/man/sd_notify.html

func sdNotify(path, payload string) error {
	socketAddr := &net.UnixAddr{
		Name: path,
		Net:  "unixgram",
	}

	conn, err := net.DialUnix(socketAddr.Net, nil, socketAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := io.Copy(conn, strings.NewReader(payload)); err != nil {
		return err
	}
	return nil
}

// notifyReadiness notifies systemd that caddy has finished its
// initialization routines.
func notifyReadiness() error {
	val, ok := os.LookupEnv("NOTIFY_SOCKET")
	if !ok || val == "" {
		return nil
	}
	if err := sdNotify(val, "READY=1"); err != nil {
		return err
	}
	return nil
}

// notifyReloading notifies systemd that caddy is reloading its config.
func notifyReloading() error {
	val, ok := os.LookupEnv("NOTIFY_SOCKET")
	if !ok || val == "" {
		return nil
	}
	if err := sdNotify(val, "RELOADING=1"); err != nil {
		return err
	}
	return nil
}

// notifyStopping notifies systemd that caddy is stopping.
func notifyStopping() error {
	val, ok := os.LookupEnv("NOTIFY_SOCKET")
	if !ok || val == "" {
		return nil
	}
	if err := sdNotify(val, "STOPPING=1"); err != nil {
		return err
	}
	return nil
}
