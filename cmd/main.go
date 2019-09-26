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
	"text/template"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// Main implements the main function of the caddy command.
// Call this if Caddy is to be the main() if your program.
func Main() {
	commandMap["start"] = newCmdStart()
	commandMap["run"] = newCmdRun()
	commandMap["stop"] = newCmdStop()
	commandMap["reload"] = newCmdReload()
	commandMap["version"] = newCmdVersion()
	commandMap["list-modules"] = newCmdListModules()
	commandMap["environ"] = newCmdEnviron()
	commandMap["adapt-config"] = newCmdAdaptConfig()
	commandMap["help"] = newCmdHelp()

	caddy.TrapSignals()

	if len(os.Args) < 2 {
		msg, err := usageString()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(caddy.ExitCodeFailedStartup)
		}
		fmt.Print(msg)
		return
	}

	subcommand, ok := commandMap[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command '%s'. ", os.Args[1])
		fmt.Fprintf(os.Stderr, "Run 'caddy help' for valid command.\n")
		os.Exit(caddy.ExitCodeFailedStartup)
	}

	fs := subcommand.Flag
	fs.Parse(os.Args[2:])
	if exitCode, err := subcommand.Run(fs.Args()); err != nil {
		log.Println(err)
		os.Exit(exitCode)
	}
}

var commandMap = map[string]*command{}

type command struct {
	// Run is a function that executes a subcommand.
	// It returns an exit code and any associated error.
	// Takes non-flag commandline arguments as args.
	// Flag must be parsed before Run is executed.
	Run func(args []string) (int, error)

	// Usage is the one-line message explaining args, flags.
	Usage string

	// Short is the short description for command.
	Short string

	// Long is the message for 'caddy help <command>'
	Long string

	// Flag is flagset for command.
	Flag *flag.FlagSet
}

// FlagHelp is wrapper arround flag.PrintDefaults
// to generate string output
func (c *command) FlagHelp() string {
	// temporially redirect output
	out := c.Flag.Output()
	defer c.Flag.SetOutput(out)

	buf := new(bytes.Buffer)
	c.Flag.SetOutput(buf)
	c.Flag.PrintDefaults()
	return buf.String()
}

var usageTemplate = `Caddy, The HTTP/2 Web Server with Automatic HTTPS.

Usage: 

    caddy <command> [<args>]

Available commands:
{{ range $name, $cmd := . }}{{ if ne $name "help" }}
    {{$name | printf "%-13s"}} {{$cmd.Short}}{{ end }}{{ end }}

Use "caddy help <command>" for more information about a command.`

func usageString() (string, error) {
	buf := new(bytes.Buffer)
	usage := template.Must(template.New("usage").Parse(usageTemplate))
	if err := usage.Execute(buf, commandMap); err != nil {
		return "", err
	}

	return buf.String(), nil
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
