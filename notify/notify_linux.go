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
	"fmt"
	"net"
	"os"
	"strings"
)

// The documentation about this IPC protocol is available here:
// https://www.freedesktop.org/software/systemd/man/sd_notify.html

func sdNotify(payload string) error {
	if socketPath == "" {
		return nil
	}

	socketAddr := &net.UnixAddr{
		Name: socketPath,
		Net:  "unixgram",
	}

	conn, err := net.DialUnix(socketAddr.Net, nil, socketAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(payload))
	return err
}

// Ready notifies systemd that caddy has finished its
// initialization routines.
func Ready() error {
	return sdNotify("READY=1")
}

// Reloading notifies systemd that caddy is reloading its config.
func Reloading() error {
	return sdNotify("RELOADING=1")
}

// Stopping notifies systemd that caddy is stopping.
func Stopping() error {
	return sdNotify("STOPPING=1")
}

// Status sends systemd an updated status message.
func Status(msg string) error {
	return sdNotify("STATUS=" + msg)
}

// Error is like Status, but sends systemd an error message
// instead, with an optional errno-style error number.
func Error(err error, errno int) error {
	collapsedErr := strings.ReplaceAll(err.Error(), "\n", " ")
	msg := fmt.Sprintf("STATUS=%s", collapsedErr)
	if errno > 0 {
		msg += fmt.Sprintf("\nERRNO=%d", errno)
	}
	return sdNotify(msg)
}

var socketPath, _ = os.LookupEnv("NOTIFY_SOCKET")
