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

package logging

import (
	"fmt"
	"io"
	"net"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(UDPWriter{})
}

type UDPWriter struct {
	IPV4 string `json:"ipv4,omitempty"`
}

// CaddyModule returns the Caddy module information
func (UDPWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "caddy.logging.writers.udp",
		New:  func() caddy.Module { return new(UDPWriter) },
	}
}

// Provision sets up the module
func (udpw *UDPWriter) Provision(ctx caddy.Context) error {
	// Replace placeholder in filename
	repl := caddy.NewReplacer()
	ipv4, err := repl.ReplaceOrErr(udpw.IPV4, true, true)
	if err != nil {
		return fmt.Errorf("invalid ipv4 for udp host: %v", err)
	}
	udpw.IPV4 = ipv4
	_, err = net.ResolveUDPAddr("udp4", udpw.IPV4)
	if err != nil {
		return fmt.Errorf("invalid ipv4 for udp host: %v", err)
	}
	return nil
}

func (udpw UDPWriter) String() string {
	return "udp://" + udpw.IPV4
}

// WriterKey returns a unique key representing this udpw.
func (udpw UDPWriter) WriterKey() string {
	return "udp:" + udpw.IPV4
}

// OpenWriter opens a new udp connection.
func (udpw UDPWriter) OpenWriter() (io.WriteCloser, error) {
	s, err := net.ResolveUDPAddr("udp4", udpw.IPV4)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp4", nil, s)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*UDPWriter)(nil)
)
