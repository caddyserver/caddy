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
	caddy.RegisterModule(NetWriter{})
}

type NetWriter struct {
	IP string `json:"ip,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// CaddyModule returns the Caddy module information
func (NetWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "caddy.logging.writers.net",
		New:  func() caddy.Module { return new(NetWriter) },
	}
}

// Provision sets up the module
func (netw *NetWriter) Provision(ctx caddy.Context) error {
	// Replace placeholder in filename
	repl := caddy.NewReplacer()
	ip, err := repl.ReplaceOrErr(netw.IP, true, true)
	if err != nil {
		return fmt.Errorf("invalid ip for host: %v", err)
	}
	netw.IP = ip
	proto, err := repl.ReplaceOrErr(netw.Protocol, true, true)
	if err != nil {
		return fmt.Errorf("invalid protocol for host: %v", err)
	}
	netw.Protocol = proto
	return nil
}

func (netw NetWriter) String() string {
	return netw.Protocol + "://" + netw.IP
}

// WriterKey returns a unique key representing this netw.
func (netw NetWriter) WriterKey() string {
	return netw.Protocol + ":" + netw.IP
}

// OpenWriter opens a new udp connection.
func (netw NetWriter) OpenWriter() (io.WriteCloser, error) {
	c, err := net.Dial(netw.Protocol, netw.IP)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Interface guards
var (
	_ caddy.Provisioner = (*NetWriter)(nil)
)
