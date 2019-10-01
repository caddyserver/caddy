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
	"flag"
	"regexp"
)

// Command represents a subcommand. All fields
// are required to be set except for Flags if
// there are no flags and Usage if there are
// no flags or arguments.
type Command struct {
	Name string

	// Run is a function that executes a subcommand.
	// It returns an exit code and any associated error.
	// Takes non-flag commandline arguments as args.
	// Flag must be parsed before Run is executed.
	Func CommandFunc

	// Usage is the one-line message explaining args, flags.
	Usage string

	// Short is the short description for command.
	Short string

	// Long is the message for 'caddy help <command>'
	Long string

	// Flags is flagset for command.
	Flags *flag.FlagSet
}

// CommandFunc is a command's function. It runs the
// command and returns the proper exit code along with
// any error that occurred.
type CommandFunc func(Flags) (int, error)

var commands = map[string]Command{
	"start": {
		Name:  "start",
		Func:  cmdStart,
		Usage: "[--config <path>] [--adapter <name>]",
		Short: "Starts the Caddy process and returns after server has started.",
		Long: `
Starts the Caddy process, optionally bootstrapped with an initial
config file. Blocks until server is successfully running (or fails to run),
then returns. On Windows, the child process will remain attached to the
terminal, so closing the window will forcefully stop Caddy. See run for more
details.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("start", flag.ExitOnError)
			fs.String("config", "", "Configuration file")
			fs.String("adapter", "", "Name of config adapter to apply")
			return fs
		}(),
	},

	"run": {
		Name:  "run",
		Func:  cmdRun,
		Usage: "[--config <path>] [--adapter <name>] [--print-env]",
		Short: `Starts the Caddy process and blocks indefinitely.`,
		Long: `
Same as start, but blocks indefinitely; i.e. runs Caddy in "daemon" mode. On
Windows, this is recommended over caddy start when running Caddy manually since
it will be more obvious that Caddy is still running and bound to the terminal
window.

If a config file is specified, it will be applied immediately after the process
is running. If the config file is not in Caddy's native JSON format, you can
specify an adapter with --adapter to adapt the given config file to
Caddy's native format. The config adapter must be a registered module. Any
warnings will be printed to the log, but beware that any adaptation without
errors will immediately be used. If you want to review the results of the
adaptation first, use the 'adapt' subcommand.

As a special case, if the current working directory has a file called
"Caddyfile" and the caddyfile config adapter is plugged in (default), then that
file will be loaded and used to configure Caddy, even without any command line
flags.

If --environ is specified, the environment as seen by the Caddy process will
be printed before starting. This is the same as the environ command but does
not quit after printing.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("run", flag.ExitOnError)
			fs.String("config", "", "Configuration file")
			fs.String("adapter", "", "Name of config adapter to apply")
			fs.Bool("environ", false, "Print environment")
			fs.String("pingback", "", "Echo confirmation bytes to this address on success")
			return fs
		}(),
	},

	"stop": {
		Name:  "stop",
		Func:  cmdStop,
		Short: "Gracefully stops the running Caddy process",
		Long: `Gracefully stops the running Caddy process. (Note: this will stop any process
named the same as the executable.) On Windows, this stop is forceful and Caddy
will not have an opportunity to clean up any active locks; for a graceful
shutdown on Windows, use Ctrl+C or the /stop endpoint.`,
	},

	"reload": {
		Name:  "reload",
		Func:  cmdReload,
		Usage: "--config <path> [--adapter <name>] [--address <interface>]",
		Short: "Gives the running Caddy instance a new configuration",
		Long: `Gives the running Caddy instance a new configuration. This has the same effect
as POSTing a document to the /load endpoint, but is convenient for simple
workflows revolving around config files. Since the admin endpoint is
configurable, the endpoint configuration is loaded from the --address flag if
specified; otherwise it is loaded from the given config file; otherwise the
default is assumed.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("reload", flag.ExitOnError)
			fs.String("config", "", "Configuration file")
			fs.String("adapter", "", "Name of config adapter to apply")
			fs.String("address", "", "Address of the administration listener, if different from config")
			return fs
		}(),
	},

	"version": {
		Name:  "version",
		Func:  cmdVersion,
		Short: "Prints the version.",
		Long:  `Prints the version.`,
	},

	"list-modules": {
		Name:  "list-modules",
		Func:  cmdListModules,
		Short: "List installed Caddy modules.",
		Long:  `List installed Caddy modules.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("list-modules", flag.ExitOnError)
			fs.Bool("versions", false, "Print version information")
			return fs
		}(),
	},

	"environ": {
		Name:  "environ",
		Func:  cmdEnviron,
		Short: "Prints the environment as seen by Caddy.",
		Long:  `Prints the environment as seen by Caddy.`,
	},

	"adapt": {
		Name:  "adapt",
		Func:  cmdAdaptConfig,
		Usage: "--config <path> --adapter <name> [--pretty]",
		Short: "Adapts a configuration to Caddy's native JSON config structure",
		Long: `
Adapts a configuration to Caddy's native JSON config structure and writes the
output to stdout, along with any warnings to stderr. If --pretty is specified,
the output will be formatted with indentation for human readability.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("adapt", flag.ExitOnError)
			fs.String("config", "", "Configuration file to adapt")
			fs.String("adapter", "", "Name of config adapter")
			fs.Bool("pretty", false, "Format the output for human readability")
			return fs
		}(),
	},

	"validate": {
		Name:  "validate",
		Func:  cmdValidateConfig,
		Usage: "--config <path> [--adapter <name>]",
		Short: "Tests whether a configuration file is valid.",
		Long: `
Loads and provisions the provided config, but does not start
running it.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("load", flag.ExitOnError)
			fs.String("config", "", "Input configuration file")
			fs.String("adapter", "", "Name of config adapter")
			return fs
		}(),
	},
}

func init() {
	// the help command is special in that its func
	// refers to the commands map; thus, defining it
	// inline with the commands map's initialization
	// yields a compile-time error, so we have to
	// define this command separately
	commands["help"] = Command{
		Name:  "help",
		Func:  cmdHelp,
		Usage: "<command>",
		Short: "Shows help for a Caddy subcommand.",
	}
}

// RegisterCommand registers the command cmd.
// cmd.Name must be unique and conform to the
// following format:
//
//    - lowercase
//    - alphanumeric and hyphen characters only
//    - cannot start or end with a hyphen
//    - hyphen cannot be adjacent to another hyphen
//
// This function panics if the name is already registered,
// if the name does not meet the described format, or if
// any of the fields are missing from cmd.
func RegisterCommand(cmd Command) {
	if cmd.Name == "" {
		panic("command name is required")
	}
	if cmd.Func == nil {
		panic("command function missing")
	}
	if cmd.Short == "" {
		panic("command short string is required")
	}
	if _, exists := commands[cmd.Name]; exists {
		panic("command already registered: " + cmd.Name)
	}
	if !commandNameRegex.MatchString(cmd.Name) {
		panic("invalid command name")
	}
	commands[cmd.Name] = cmd
}

var commandNameRegex = regexp.MustCompile(`^[a-z0-9]$|^([a-z0-9]+-?[a-z0-9]*)+[a-z0-9]$`)
