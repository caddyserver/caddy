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
	"github.com/caddyserver/caddy/v2/caddyconfig"
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
	"adapt-config": cmdAdaptConfig,
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

// loadConfig loads the config from configFile and adapts it
// using adapterName. If adapterName is specified, configFile
// must be also. It prints any warnings to stderr, and returns
// the resulting JSON config bytes.
func loadConfig(configFile, adapterName string) ([]byte, error) {
	// specifying an adapter without a config file is ambiguous
	if configFile == "" && adapterName != "" {
		return nil, fmt.Errorf("cannot adapt config without config file (use --config)")
	}

	// load initial config and adapter
	var config []byte
	var cfgAdapter caddyconfig.Adapter
	var err error
	if configFile != "" {
		config, err = ioutil.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %v", err)
		}
	} else if adapterName == "" {
		// as a special case when no config file or adapter
		// is specified, see if the Caddyfile adapter is
		// plugged in, and if so, try using a default Caddyfile
		cfgAdapter = caddyconfig.GetAdapter("caddyfile")
		if cfgAdapter != nil {
			config, err = ioutil.ReadFile("Caddyfile")
			if err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("reading default Caddyfile: %v", err)
			}
			configFile = "Caddyfile"
		}
	}

	// load config adapter
	if adapterName != "" {
		cfgAdapter = caddyconfig.GetAdapter(adapterName)
		if cfgAdapter == nil {
			return nil, fmt.Errorf("unrecognized config adapter: %s", adapterName)
		}
	}

	// adapt config
	if cfgAdapter != nil {
		adaptedConfig, warnings, err := cfgAdapter.Adapt(config, map[string]string{
			"filename": configFile,
			// TODO: all other options... (http-port, etc...)
		})
		if err != nil {
			return nil, fmt.Errorf("adapting config using %s: %v", adapterName, err)
		}
		for _, warn := range warnings {
			msg := warn.Message
			if warn.Directive != "" {
				msg = fmt.Sprintf("%s: %s", warn.Directive, warn.Message)
			}
			fmt.Printf("[WARNING][%s] %s:%d: %s", adapterName, warn.File, warn.Line, msg)
		}
		config = adaptedConfig
	}

	return config, nil
}
