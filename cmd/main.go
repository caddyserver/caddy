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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"text/template"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// Main implements the main function of the caddy command.
// Call this if Caddy is to be the main() if your program.
func Main() {
	caddy.TrapSignals()

	// run help command and exit when "caddy" or "caddy help".
	if len(os.Args) < 2 || os.Args[1] == "help" {
		exitCode := help()
		os.Exit(exitCode)
		return
	}

	subcommand, ok := commandMap[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q. ", os.Args[1])
		fmt.Fprintf(os.Stderr, "Run 'caddy help' for valid command.\n")
		os.Exit(caddy.ExitCodeFailedStartup)
	}

	if exitCode, err := subcommand.Run(); err != nil {
		log.Println(err)
		os.Exit(exitCode)
	}
}

type command struct {
	// Run is a function that executes a subcommand.
	// It returns an exit code and any associated error.
	Run func() (int, error)

	// Usage is the one-line message explaining args, flags.
	Usage string

	// Short is the short description for command.
	Short string

	// Long is the message for 'caddy help <command>'
	Long string

	// TODO: command can include flagset, and used to print
	// auto-generated flag help message.
	// Flag  flag.FlagSet
}

var commandMap = map[string]*command{
	"start":        cmdStart,
	"run":          cmdRun,
	"stop":         cmdStop,
	"reload":       cmdReload,
	"version":      cmdVersion,
	"list-modules": cmdListModules,
	"environ":      cmdEnviron,
	"adapt-config": cmdAdaptConfig,
}

var usageTemplate = `Caddy, The HTTP/2 Web Server with Automatic HTTPS.

Usage: 

    caddy <command> [<args>]

Available commands:
{{ range $name, $cmd := . }}{{ if ne $name "help" }}
    {{$name | printf "%-13s"}} {{$cmd.Short}}{{ end }}{{ end }}

Use "caddy help [command]" for more information about a command.
`

func usageString(commandMap map[string]*command) (string, error) {
	buf := new(bytes.Buffer)
	usage := template.Must(template.New("usage").Parse(usageTemplate))
	if err := usage.Execute(buf, commandMap); err != nil {
		return "", err
	}

	return buf.String(), nil
}

var helpTemplate = `usage: {{ .Usage }}
{{ .Long }}
Full documentation available on 
https://github.com/caddyserver/caddy/wiki/v2:-Documentation
`

// help is for subcommand "help".
// It describes commands formatted with template.
func help() int {
	if len(os.Args) == 1 || len(os.Args) == 2 {
		usage, err := usageString(commandMap)
		if err != nil {
			log.Println(err)
			return caddy.ExitCodeFailedStartup
		}
		fmt.Println(usage)
		return caddy.ExitCodeSuccess
	}

	if len(os.Args) > 3 {
		fmt.Fprintf(os.Stderr, "usage: caddy help [command]\n"+
			"Too many arguments given.\n")
		return caddy.ExitCodeFailedStartup
	}

	subcommand, ok := commandMap[os.Args[2]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q. ", os.Args[2])
		fmt.Fprintf(os.Stderr, "Run 'caddy help' for usage.\n")
		return caddy.ExitCodeFailedStartup
	}

	cmdhelp := template.Must(template.New("cmdhelp").Parse(helpTemplate))
	if err := cmdhelp.Execute(os.Stdout, *subcommand); err != nil {
		log.Println(err)
		return caddy.ExitCodeFailedStartup
	}
	return caddy.ExitCodeSuccess
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
			if os.IsNotExist(err) {
				// okay, no default Caddyfile; pretend like this never happened
				cfgAdapter = nil
				err = nil
			} else if err != nil {
				// default Caddyfile exists, but error reading it
				return nil, fmt.Errorf("reading default Caddyfile: %v", err)
			} else {
				// success reading default Caddyfile
				configFile = "Caddyfile"
			}
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
		adaptedConfig, warnings, err := cfgAdapter.Adapt(config, map[string]interface{}{
			"filename": configFile,
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
