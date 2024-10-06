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
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/caddyserver/caddy/v2"
)

// Command represents a subcommand. Name, Func,
// and Short are required.
type Command struct {
	// The name of the subcommand. Must conform to the
	// format described by the RegisterCommand() godoc.
	// Required.
	Name string

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
	// This is ignored if CobraFunc is set.
	Flags *flag.FlagSet

	// Func is a function that executes a subcommand using
	// the parsed flags. It returns an exit code and any
	// associated error.
	// Required if CobraFunc is not set.
	Func CommandFunc

	// CobraFunc allows further configuration of the command
	// via cobra's APIs. If this is set, then Func and Flags
	// are ignored, with the assumption that they are set in
	// this function. A caddycmd.WrapCommandFuncForCobra helper
	// exists to simplify porting CommandFunc to Cobra's RunE.
	CobraFunc func(*cobra.Command)
}

// CommandFunc is a command's function. It runs the
// command and returns the proper exit code along with
// any error that occurred.
type CommandFunc func(Flags) (int, error)

// Commands returns a list of commands initialised by
// RegisterCommand
func Commands() map[string]Command {
	return commands
}

var commands = make(map[string]Command)

func init() {
	RegisterCommand(Command{
		Name:  "start",
		Usage: "[--config <path> [--adapter <name>]] [--envfile <path>] [--watch] [--pidfile <file>]",
		Short: "Starts the Caddy process in the background and then returns",
		Long: `
Starts the Caddy process, optionally bootstrapped with an initial config file.
This command unblocks after the server starts running or fails to run.

If --envfile is specified, an environment file with environment variables
in the KEY=VALUE format will be loaded into the Caddy process.

On Windows, the spawned child process will remain attached to the terminal, so
closing the window will forcefully stop Caddy; to avoid forgetting this, try
using 'caddy run' instead to keep it in the foreground.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Configuration file")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply")
			cmd.Flags().StringSliceP("envfile", "", []string{}, "Environment file(s) to load")
			cmd.Flags().BoolP("watch", "w", false, "Reload changed config file automatically")
			cmd.Flags().StringP("pidfile", "", "", "Path of file to which to write process ID")
			cmd.RunE = WrapCommandFuncForCobra(cmdStart)
		},
	})

	RegisterCommand(Command{
		Name:  "run",
		Usage: "[--config <path> [--adapter <name>]] [--envfile <path>] [--environ] [--resume] [--watch] [--pidfile <file>]",
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

If --envfile is specified, an environment file with environment variables
in the KEY=VALUE format will be loaded into the Caddy process.

If --environ is specified, the environment as seen by the Caddy process will
be printed before starting. This is the same as the environ command but does
not quit after printing, and can be useful for troubleshooting.

The --resume flag will override the --config flag if there is a config auto-
save file. It is not an error if --resume is used and no autosave file exists.

If --watch is specified, the config file will be loaded automatically after
changes. ⚠️ This can make unintentional config changes easier; only use this
option in a local development environment.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Configuration file")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply")
			cmd.Flags().StringSliceP("envfile", "", []string{}, "Environment file(s) to load")
			cmd.Flags().BoolP("environ", "e", false, "Print environment")
			cmd.Flags().BoolP("resume", "r", false, "Use saved config, if any (and prefer over --config file)")
			cmd.Flags().BoolP("watch", "w", false, "Watch config file for changes and reload it automatically")
			cmd.Flags().StringP("pidfile", "", "", "Path of file to which to write process ID")
			cmd.Flags().StringP("pingback", "", "", "Echo confirmation bytes to this address on success")
			cmd.RunE = WrapCommandFuncForCobra(cmdRun)
		},
	})

	RegisterCommand(Command{
		Name:  "stop",
		Usage: "[--config <path> [--adapter <name>]] [--address <interface>]",
		Short: "Gracefully stops a started Caddy process",
		Long: `
Stops the background Caddy process as gracefully as possible.

It requires that the admin API is enabled and accessible, since it will
use the API's /stop endpoint. The address of this request can be customized
using the --address flag, or from the given --config, if not the default.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Configuration file to use to parse the admin address, if --address is not used")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply (when --config is used)")
			cmd.Flags().StringP("address", "", "", "The address to use to reach the admin API endpoint, if not the default")
			cmd.RunE = WrapCommandFuncForCobra(cmdStop)
		},
	})

	RegisterCommand(Command{
		Name:  "reload",
		Usage: "--config <path> [--adapter <name>] [--address <interface>]",
		Short: "Changes the config of the running Caddy instance",
		Long: `
Gives the running Caddy instance a new configuration. This has the same effect
as POSTing a document to the /load API endpoint, but is convenient for simple
workflows revolving around config files.

Since the admin endpoint is configurable, the endpoint configuration is loaded
from the --address flag if specified; otherwise it is loaded from the given
config file; otherwise the default is assumed.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Configuration file (required)")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter to apply")
			cmd.Flags().StringP("address", "", "", "Address of the administration listener, if different from config")
			cmd.Flags().BoolP("force", "f", false, "Force config reload, even if it is the same")
			cmd.RunE = WrapCommandFuncForCobra(cmdReload)
		},
	})

	RegisterCommand(Command{
		Name:  "version",
		Short: "Prints the version",
		Long: `
Prints the version of this Caddy binary.

Version information must be embedded into the binary at compile-time in
order for Caddy to display anything useful with this command. If Caddy
is built from within a version control repository, the Go command will
embed the revision hash if available. However, if Caddy is built in the
way specified by our online documentation (or by using xcaddy), more
detailed version information is printed as given by Go modules.

For more details about the full version string, see the Go module
documentation: https://go.dev/doc/modules/version-numbers
`,
		Func: cmdVersion,
	})

	RegisterCommand(Command{
		Name:  "list-modules",
		Usage: "[--packages] [--versions] [--skip-standard]",
		Short: "Lists the installed Caddy modules",
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().BoolP("packages", "", false, "Print package paths")
			cmd.Flags().BoolP("versions", "", false, "Print version information")
			cmd.Flags().BoolP("skip-standard", "s", false, "Skip printing standard modules")
			cmd.RunE = WrapCommandFuncForCobra(cmdListModules)
		},
	})

	RegisterCommand(Command{
		Name:  "build-info",
		Short: "Prints information about this build",
		Func:  cmdBuildInfo,
	})

	RegisterCommand(Command{
		Name:  "environ",
		Usage: "[--envfile <path>]",
		Short: "Prints the environment",
		Long: `
Prints the environment as seen by this Caddy process.

The environment includes variables set in the system. If your Caddy
configuration uses environment variables (e.g. "{env.VARIABLE}") then
this command can be useful for verifying that the variables will have
the values you expect in your config.

If --envfile is specified, an environment file with environment variables
in the KEY=VALUE format will be loaded into the Caddy process.

Note that environments may be different depending on how you run Caddy.
Environments for Caddy instances started by service managers such as
systemd are often different than the environment inherited from your
shell or terminal.

You can also print the environment the same time you use "caddy run"
by adding the "--environ" flag.

Environments may contain sensitive data.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringSliceP("envfile", "", []string{}, "Environment file(s) to load")
			cmd.RunE = WrapCommandFuncForCobra(cmdEnviron)
		},
	})

	RegisterCommand(Command{
		Name:  "adapt",
		Usage: "--config <path> [--adapter <name>] [--pretty] [--validate] [--envfile <path>]",
		Short: "Adapts a configuration to Caddy's native JSON",
		Long: `
Adapts a configuration to Caddy's native JSON format and writes the
output to stdout, along with any warnings to stderr.

If --pretty is specified, the output will be formatted with indentation
for human readability.

If --validate is used, the adapted config will be checked for validity.
If the config is invalid, an error will be printed to stderr and a non-
zero exit status will be returned.

If --envfile is specified, an environment file with environment variables
in the KEY=VALUE format will be loaded into the Caddy process.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Configuration file to adapt (required)")
			cmd.Flags().StringP("adapter", "a", "caddyfile", "Name of config adapter")
			cmd.Flags().BoolP("pretty", "p", false, "Format the output for human readability")
			cmd.Flags().BoolP("validate", "", false, "Validate the output")
			cmd.Flags().StringSliceP("envfile", "", []string{}, "Environment file(s) to load")
			cmd.RunE = WrapCommandFuncForCobra(cmdAdaptConfig)
		},
	})

	RegisterCommand(Command{
		Name:  "validate",
		Usage: "--config <path> [--adapter <name>] [--envfile <path>]",
		Short: "Tests whether a configuration file is valid",
		Long: `
Loads and provisions the provided config, but does not start running it.
This reveals any errors with the configuration through the loading and
provisioning stages.

If --envfile is specified, an environment file with environment variables
in the KEY=VALUE format will be loaded into the Caddy process.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Input configuration file")
			cmd.Flags().StringP("adapter", "a", "", "Name of config adapter")
			cmd.Flags().StringSliceP("envfile", "", []string{}, "Environment file(s) to load")
			cmd.RunE = WrapCommandFuncForCobra(cmdValidateConfig)
		},
	})

	RegisterCommand(Command{
		Name:  "storage",
		Short: "Commands for working with Caddy's storage (EXPERIMENTAL)",
		Long: `
Allows exporting and importing Caddy's storage contents. The two commands can be
combined in a pipeline to transfer directly from one storage to another:

$ caddy storage export --config Caddyfile.old --output - |
> caddy storage import --config Caddyfile.new --input -

The - argument refers to stdout and stdin, respectively.

NOTE: When importing to or exporting from file_system storage (the default), the command
should be run as the user that owns the associated root path.

EXPERIMENTAL: May be changed or removed.
`,
		CobraFunc: func(cmd *cobra.Command) {
			exportCmd := &cobra.Command{
				Use:   "export --config <path> --output <path>",
				Short: "Exports storage assets as a tarball",
				Long: `
The contents of the configured storage module (TLS certificates, etc)
are exported via a tarball.

--output is required, - can be given for stdout.
`,
				RunE: WrapCommandFuncForCobra(cmdExportStorage),
			}
			exportCmd.Flags().StringP("config", "c", "", "Input configuration file (required)")
			exportCmd.Flags().StringP("output", "o", "", "Output path")
			cmd.AddCommand(exportCmd)

			importCmd := &cobra.Command{
				Use:   "import --config <path> --input <path>",
				Short: "Imports storage assets from a tarball.",
				Long: `
Imports storage assets to the configured storage module. The import file must be
a tar archive.

--input is required, - can be given for stdin.
`,
				RunE: WrapCommandFuncForCobra(cmdImportStorage),
			}
			importCmd.Flags().StringP("config", "c", "", "Configuration file to load (required)")
			importCmd.Flags().StringP("input", "i", "", "Tar of assets to load (required)")
			cmd.AddCommand(importCmd)
		},
	})

	RegisterCommand(Command{
		Name:  "fmt",
		Usage: "[--overwrite] [--diff] [<path>]",
		Short: "Formats a Caddyfile",
		Long: `
Formats the Caddyfile by adding proper indentation and spaces to improve
human readability. It prints the result to stdout.

If --overwrite is specified, the output will be written to the config file
directly instead of printing it.

If --diff is specified, the output will be compared against the input, and
lines will be prefixed with '-' and '+' where they differ. Note that
unchanged lines are prefixed with two spaces for alignment, and that this
is not a valid patch format.

If you wish you use stdin instead of a regular file, use - as the path.
When reading from stdin, the --overwrite flag has no effect: the result
is always printed to stdout.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().StringP("config", "c", "", "Configuration file")
			cmd.Flags().BoolP("overwrite", "w", false, "Overwrite the input file with the results")
			cmd.Flags().BoolP("diff", "d", false, "Print the differences between the input file and the formatted output")
			cmd.RunE = WrapCommandFuncForCobra(cmdFmt)
		},
	})

	RegisterCommand(Command{
		Name:  "upgrade",
		Short: "Upgrade Caddy (EXPERIMENTAL)",
		Long: `
Downloads an updated Caddy binary with the same modules/plugins at the
latest versions. EXPERIMENTAL: May be changed or removed.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().BoolP("keep-backup", "k", false, "Keep the backed up binary, instead of deleting it")
			cmd.RunE = WrapCommandFuncForCobra(cmdUpgrade)
		},
	})

	RegisterCommand(Command{
		Name:  "add-package",
		Usage: "<package[@version]...>",
		Short: "Adds Caddy packages (EXPERIMENTAL)",
		Long: `
Downloads an updated Caddy binary with the specified packages (module/plugin)
added, with an optional version specified (e.g., "package@version"). Retains
existing packages. Returns an error if any of the specified packages are already
included. EXPERIMENTAL: May be changed or removed.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().BoolP("keep-backup", "k", false, "Keep the backed up binary, instead of deleting it")
			cmd.RunE = WrapCommandFuncForCobra(cmdAddPackage)
		},
	})

	RegisterCommand(Command{
		Name:  "remove-package",
		Func:  cmdRemovePackage,
		Usage: "<packages...>",
		Short: "Removes Caddy packages (EXPERIMENTAL)",
		Long: `
Downloads an updated Caddy binaries without the specified packages (module/plugin).
Returns an error if any of the packages are not included.
EXPERIMENTAL: May be changed or removed.
`,
		CobraFunc: func(cmd *cobra.Command) {
			cmd.Flags().BoolP("keep-backup", "k", false, "Keep the backed up binary, instead of deleting it")
			cmd.RunE = WrapCommandFuncForCobra(cmdRemovePackage)
		},
	})

	defaultFactory.Use(func(rootCmd *cobra.Command) {
		rootCmd.AddCommand(caddyCmdToCobra(Command{
			Name:  "manpage",
			Usage: "--directory <path>",
			Short: "Generates the manual pages for Caddy commands",
			Long: `
Generates the manual pages for Caddy commands into the designated directory
tagged into section 8 (System Administration).

The manual page files are generated into the directory specified by the
argument of --directory. If the directory does not exist, it will be created.
`,
			CobraFunc: func(cmd *cobra.Command) {
				cmd.Flags().StringP("directory", "o", "", "The output directory where the manpages are generated")
				cmd.RunE = WrapCommandFuncForCobra(func(fl Flags) (int, error) {
					dir := strings.TrimSpace(fl.String("directory"))
					if dir == "" {
						return caddy.ExitCodeFailedQuit, fmt.Errorf("designated output directory and specified section are required")
					}
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return caddy.ExitCodeFailedQuit, err
					}
					if err := doc.GenManTree(rootCmd, &doc.GenManHeader{
						Title:   "Caddy",
						Section: "8", // https://en.wikipedia.org/wiki/Man_page#Manual_sections
					}, dir); err != nil {
						return caddy.ExitCodeFailedQuit, err
					}
					return caddy.ExitCodeSuccess, nil
				})
			},
		}))

		// source: https://github.com/spf13/cobra/blob/main/shell_completions.md
		rootCmd.AddCommand(&cobra.Command{
			Use:   "completion [bash|zsh|fish|powershell]",
			Short: "Generate completion script",
			Long: fmt.Sprintf(`To load completions:

	Bash:

	  $ source <(%[1]s completion bash)

	  # To load completions for each session, execute once:
	  # Linux:
	  $ %[1]s completion bash > /etc/bash_completion.d/%[1]s
	  # macOS:
	  $ %[1]s completion bash > $(brew --prefix)/etc/bash_completion.d/%[1]s

	Zsh:

	  # If shell completion is not already enabled in your environment,
	  # you will need to enable it.  You can execute the following once:

	  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

	  # To load completions for each session, execute once:
	  $ %[1]s completion zsh > "${fpath[1]}/_%[1]s"

	  # You will need to start a new shell for this setup to take effect.

	fish:

	  $ %[1]s completion fish | source

	  # To load completions for each session, execute once:
	  $ %[1]s completion fish > ~/.config/fish/completions/%[1]s.fish

	PowerShell:

	  PS> %[1]s completion powershell | Out-String | Invoke-Expression

	  # To load completions for every new session, run:
	  PS> %[1]s completion powershell > %[1]s.ps1
	  # and source this file from your PowerShell profile.
	`, rootCmd.Root().Name()),
			DisableFlagsInUseLine: true,
			ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
			Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
			RunE: func(cmd *cobra.Command, args []string) error {
				switch args[0] {
				case "bash":
					return cmd.Root().GenBashCompletion(os.Stdout)
				case "zsh":
					return cmd.Root().GenZshCompletion(os.Stdout)
				case "fish":
					return cmd.Root().GenFishCompletion(os.Stdout, true)
				case "powershell":
					return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
				default:
					return fmt.Errorf("unrecognized shell: %s", args[0])
				}
			},
		})
	})
}

// RegisterCommand registers the command cmd.
// cmd.Name must be unique and conform to the
// following format:
//
//   - lowercase
//   - alphanumeric and hyphen characters only
//   - cannot start or end with a hyphen
//   - hyphen cannot be adjacent to another hyphen
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
	if cmd.Func == nil && cmd.CobraFunc == nil {
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
	defaultFactory.Use(func(rootCmd *cobra.Command) {
		rootCmd.AddCommand(caddyCmdToCobra(cmd))
	})
}

var commandNameRegex = regexp.MustCompile(`^[a-z0-9]$|^([a-z0-9]+-?[a-z0-9]*)+[a-z0-9]$`)
