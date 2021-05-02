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

// Command represents a subcommand. Name, Func,
// and Short are required.
type Command struct {
	// The name of the subcommand. Must conform to the
	// format described by the RegisterCommand() godoc.
	// Required.
	Name string

	// Func is a function that executes a subcommand using
	// the parsed flags. It returns an exit code and any
	// associated error.
	// Required.
	Func CommandFunc

	// Usage is a brief message describing the syntax of
	// the subcommand's flags and args. Use [] to indicate
	// optional parameters and <> to enclose literal values
	// intended to be replaced by the user. Do not prefix
	// the string with "caddy" or the name of the command
	// since these will be prepended for you; only include
	// the actual parameters for this command.
	Usage string

	// Short is a one-line message explaining what the
	// command does. Should not end with punctuation.
	// Required.
	Short string

	// Long is the full help text shown to the user.
	// Will be trimmed of whitespace on both ends before
	// being printed.
	Long string

	// Flags is the flagset for command.
	Flags *flag.FlagSet
}

// CommandFunc is a command's function. It runs the
// command and returns the proper exit code along with
// any error that occurred.
type CommandFunc func(Flags) (int, error)

var commands = make(map[string]Command)

func init() {
	RegisterCommand(Command{
		Name:  "help",
		Func:  cmdHelp,
		Usage: "<command>",
		Short: "Shows help for a Caddy subcommand",
	})

	RegisterCommand(Command{
		Name:  "start",
		Func:  cmdStart,
		Usage: "[--config <path> [--adapter <name>]] [--envfile <path>] [--watch] [--pidfile <file>]",
		Short: "Starts the Caddy process in the background and then returns",
		Long: `
Starts the Caddy process, optionally bootstrapped with an initial config file.
This command unblocks after the server starts running or fails to run.

If --envfile is specified, an environment file with environment variables in
the KEY=VALUE format will be loaded into the Caddy process.

On Windows, the spawned child process will remain attached to the terminal, so
closing the window will forcefully stop Caddy; to avoid forgetting this, try
using 'caddy run' instead to keep it in the foreground.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("start", flag.ExitOnError)
			fs.String("config", "", "Configuration file")
			fs.String("envfile", "", "Environment file to load")
			fs.String("adapter", "", "Name of config adapter to apply")
			fs.String("pidfile", "", "Path of file to which to write process ID")
			fs.Bool("watch", false, "Reload changed config file automatically")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "run",
		Func:  cmdRun,
		Usage: "[--config <path> [--adapter <name>]] [--envfile <path>] [--environ] [--resume] [--watch] [--pidfile <fil>]",
		Short: `Starts the Caddy process and blocks indefinitely`,
		Long: `
Starts the Caddy process, optionally bootstrapped with an initial config file,
and blocks indefinitely until the server is stopped; i.e. runs Caddy in
"daemon" mode (foreground).

If a config file is specified, it will be applied immediately after the process
is running. If the config file is not in Caddy's native JSON format, you can
specify an adapter with --adapter to adapt the given config file to
Caddy's native format. The config adapter must be a registered module. Any
warnings will be printed to the log, but beware that any adaptation without
errors will immediately be used. If you want to review the results of the
adaptation first, use the 'adapt' subcommand.

As a special case, if the current working directory has a file called
"Caddyfile" and the caddyfile config adapter is plugged in (default), then
that file will be loaded and used to configure Caddy, even without any command
line flags.

If --envfile is specified, an environment file with environment variables in
the KEY=VALUE format will be loaded into the Caddy process.

If --environ is specified, the environment as seen by the Caddy process will
be printed before starting. This is the same as the environ command but does
not quit after printing, and can be useful for troubleshooting.

The --resume flag will override the --config flag if there is a config auto-
save file. It is not an error if --resume is used and no autosave file exists.

If --watch is specified, the config file will be loaded automatically after
changes. ⚠️ This is dangerous in production! Only use this option in a local
development environment.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("run", flag.ExitOnError)
			fs.String("config", "", "Configuration file")
			fs.String("adapter", "", "Name of config adapter to apply")
			fs.String("envfile", "", "Environment file to load")
			fs.Bool("environ", false, "Print environment")
			fs.Bool("resume", false, "Use saved config, if any (and prefer over --config file)")
			fs.Bool("watch", false, "Watch config file for changes and reload it automatically")
			fs.String("pidfile", "", "Path of file to which to write process ID")
			fs.String("pingback", "", "Echo confirmation bytes to this address on success")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "stop",
		Func:  cmdStop,
		Short: "Gracefully stops a started Caddy process",
		Long: `
Stops the background Caddy process as gracefully as possible.

It requires that the admin API is enabled and accessible, since it will
use the API's /stop endpoint. The address of this request can be
customized using the --address flag if it is not the default.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("stop", flag.ExitOnError)
			fs.String("address", "", "The address to use to reach the admin API endpoint, if not the default")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "reload",
		Func:  cmdReload,
		Usage: "--config <path> [--adapter <name>] [--address <interface>]",
		Short: "Changes the config of the running Caddy instance",
		Long: `
Gives the running Caddy instance a new configuration. This has the same effect
as POSTing a document to the /load API endpoint, but is convenient for simple
workflows revolving around config files.

Since the admin endpoint is configurable, the endpoint configuration is loaded
from the --address flag if specified; otherwise it is loaded from the given
config file; otherwise the default is assumed.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("reload", flag.ExitOnError)
			fs.String("config", "", "Configuration file (required)")
			fs.String("adapter", "", "Name of config adapter to apply")
			fs.String("address", "", "Address of the administration listener, if different from config")
			fs.Bool("force", false, "Force config reload, even if it is the same")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "version",
		Func:  cmdVersion,
		Short: "Prints the version",
	})

	RegisterCommand(Command{
		Name:  "list-modules",
		Func:  cmdListModules,
		Usage: "[--packages] [--versions]",
		Short: "Lists the installed Caddy modules",
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("list-modules", flag.ExitOnError)
			fs.Bool("packages", false, "Print package paths")
			fs.Bool("versions", false, "Print version information")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "build-info",
		Func:  cmdBuildInfo,
		Short: "Prints information about this build",
	})

	RegisterCommand(Command{
		Name:  "environ",
		Func:  cmdEnviron,
		Short: "Prints the environment",
	})

	RegisterCommand(Command{
		Name:  "adapt",
		Func:  cmdAdaptConfig,
		Usage: "--config <path> [--adapter <name>] [--pretty] [--validate]",
		Short: "Adapts a configuration to Caddy's native JSON",
		Long: `
Adapts a configuration to Caddy's native JSON format and writes the
output to stdout, along with any warnings to stderr.

If --pretty is specified, the output will be formatted with indentation
for human readability.

If --validate is used, the adapted config will be checked for validity.
If the config is invalid, an error will be printed to stderr and a non-
zero exit status will be returned.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("adapt", flag.ExitOnError)
			fs.String("config", "", "Configuration file to adapt (required)")
			fs.String("adapter", "caddyfile", "Name of config adapter")
			fs.Bool("pretty", false, "Format the output for human readability")
			fs.Bool("validate", false, "Validate the output")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "validate",
		Func:  cmdValidateConfig,
		Usage: "--config <path> [--adapter <name>]",
		Short: "Tests whether a configuration file is valid",
		Long: `
Loads and provisions the provided config, but does not start running it.
This reveals any errors with the configuration through the loading and
provisioning stages.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("load", flag.ExitOnError)
			fs.String("config", "", "Input configuration file")
			fs.String("adapter", "", "Name of config adapter")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "fmt",
		Func:  cmdFmt,
		Usage: "[--overwrite] [<path>]",
		Short: "Formats a Caddyfile",
		Long: `
Formats the Caddyfile by adding proper indentation and spaces to improve
human readability. It prints the result to stdout.

If --overwrite is specified, the output will be written to the config file
directly instead of printing it.

If you wish you use stdin instead of a regular file, use - as the path.
When reading from stdin, the --overwrite flag has no effect: the result
is always printed to stdout.`,
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("format", flag.ExitOnError)
			fs.Bool("overwrite", false, "Overwrite the input file with the results")
			return fs
		}(),
	})

	RegisterCommand(Command{
		Name:  "upgrade",
		Func:  cmdUpgrade,
		Short: "Upgrade Caddy (EXPERIMENTAL)",
		Long: `
Downloads an updated Caddy binary with the same modules/plugins at the
latest versions. EXPERIMENTAL: May be changed or removed.`,
	})

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
//
// This function should be used in init().
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
