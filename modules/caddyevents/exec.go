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

package caddyevents

import (
	"context"
	"os"
	"os/exec"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ExecHandler{})
}

// ExecHandler implements an event handler that runs a command/program.
type ExecHandler struct {
	Command string         `json:"command,omitempty"`
	Args    []string       `json:"args,omitempty"`
	Dir     string         `json:"dir,omitempty"`
	Timeout caddy.Duration `json:"timeout,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ExecHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.exec",
		New: func() caddy.Module { return new(ExecHandler) },
	}
}

// Provision sets up the module.
func (eh *ExecHandler) Provision(ctx caddy.Context) error {
	eh.logger = ctx.Logger(eh)
	return nil
}

func (eh *ExecHandler) Handle(ctx context.Context, e Event) error {
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// expand placeholders in command args;
	// notably, WE DO NOT EXPAND PLACEHOLDERS
	// IN THE COMMAND ITSELF for safety reasons
	expandedArgs := make([]string, len(eh.Args))
	for i := range eh.Args {
		expandedArgs[i] = repl.ReplaceAll(eh.Args[i], "")
	}

	cmd := exec.Command(eh.Command, expandedArgs...)
	cmd.Dir = eh.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (eh *ExecHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		eh.Command = d.Val()
		eh.Args = d.RemainingArgs()
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*ExecHandler)(nil)
	_ caddy.Provisioner     = (*ExecHandler)(nil)
)
