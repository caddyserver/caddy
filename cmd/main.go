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

package caddycmd

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/caddyserver/caddy/v2"
)

// Main implements the main function of the caddy command.
// Call this if Caddy is to be the main() if your program.
func Main() {
	caddy.TrapSignals()

	if len(os.Args) <= 1 {
		fmt.Println(usageString())
		return
	}

	subcommand, ok := commands[os.Args[1]]
	if !ok {
		fmt.Printf("%q is not a valid command\n", os.Args[1])
		os.Exit(caddy.ExitCodeFailedStartup)
	}

	if exitCode, err := subcommand(); err != nil {
		log.Println(err)
		os.Exit(exitCode)
	}
}

// commandFunc is a function that executes
// a subcommand. It returns an exit code and
// any associated error.
type commandFunc func() (int, error)

var commands = map[string]commandFunc{
	"start":        cmdStart,
	"run":          cmdRun,
	"stop":         cmdStop,
	"reload":       cmdReload,
	"version":      cmdVersion,
	"list-modules": cmdListModules,
	"environ":      cmdEnviron,
}

func usageString() string {
	buf := new(bytes.Buffer)
	buf.WriteString("usage: caddy <command> [<args>]")
	flag.CommandLine.SetOutput(buf)
	flag.CommandLine.PrintDefaults()
	return buf.String()
}

// handlePingbackConn reads from conn and ensures it matches
// the bytes in expect, or returns an error if it doesn't.
func handlePingbackConn(conn net.Conn, expect []byte) error {
	defer conn.Close()
	confirmationBytes, err := ioutil.ReadAll(io.LimitReader(conn, 32))
	if err != nil {
		return err
	}
	if !bytes.Equal(confirmationBytes, expect) {
		return fmt.Errorf("wrong confirmation: %x", confirmationBytes)
	}
	return nil
}
