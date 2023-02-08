package caddycmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "caddy",
	Long: `Caddy is an extensible server platform written in Go.

At its core, Caddy merely manages configuration. Modules are plugged
in statically at compile-time to provide useful functionality. Caddy's
standard distribution includes common modules to serve HTTP, TLS,
and PKI applications, including the automation of certificates.

To run Caddy, use:

	- 'caddy run' to run Caddy in the foreground (recommended).
	- 'caddy start' to start Caddy in the background; only do this
	  if you will be keeping the terminal window open until you run
	  'caddy stop' to close the server.

When Caddy is started, it opens a locally-bound administrative socket
to which configuration can be POSTed via a restful HTTP API (see
https://caddyserver.com/docs/api).

Caddy's native configuration format is JSON. However, config adapters
can be used to convert other config formats to JSON when Caddy receives
its configuration. The Caddyfile is a built-in config adapter that is
popular for hand-written configurations due to its straightforward
syntax (see https://caddyserver.com/docs/caddyfile). Many third-party
adapters are available (see https://caddyserver.com/docs/config-adapters).
Use 'caddy adapt' to see how a config translates to JSON.

For convenience, the CLI can act as an HTTP client to give Caddy its
initial configuration for you. If a file named Caddyfile is in the
current working directory, it will do this automatically. Otherwise,
you can use the --config flag to specify the path to a config file.

Some special-purpose subcommands build and load a configuration file
for you directly from command line input; for example:

	- caddy file-server
	- caddy reverse-proxy
	- caddy respond

These commands disable the administration endpoint because their
configuration is specified solely on the command line.

In general, the most common way to run Caddy is simply:

	$ caddy run

Or, with a configuration file:

	$ caddy run --config caddy.json

If running interactively in a terminal, running Caddy in the
background may be more convenient:

	$ caddy start
	...
	$ caddy stop

This allows you to run other commands while Caddy stays running.
Be sure to stop Caddy before you close the terminal!

Depending on the system, Caddy may need permission to bind to low
ports. One way to do this on Linux is to use setcap:

	$ sudo setcap cap_net_bind_service=+ep $(which caddy)

Remember to run that command again after replacing the binary.

See the Caddy website for tutorials, configuration structure,
syntax, and module documentation: https://caddyserver.com/docs/

Custom Caddy builds are available on the Caddy download page at:
https://caddyserver.com/download

The xcaddy command can be used to build Caddy from source with or
without additional plugins: https://github.com/caddyserver/xcaddy

Where possible, Caddy should be installed using officially-supported
package installers: https://caddyserver.com/docs/install

Instructions for running Caddy in production are also available:
https://caddyserver.com/docs/running
`,
	Example: `  $ caddy run
  $ caddy run --config caddy.json
  $ caddy reload --config caddy.json
  $ caddy stop`,

	// kind of annoying to have all the help text printed out if
	// caddy has an error provisioning its modules, for instance...
	SilenceUsage: true,
}

const fullDocsFooter = `Full documentation is available at:
https://caddyserver.com/docs/command-line`

func init() {
	rootCmd.SetHelpTemplate(rootCmd.HelpTemplate() + "\n" + fullDocsFooter + "\n")
}

func caddyCmdToCobra(caddyCmd Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   caddyCmd.Name,
		Short: caddyCmd.Short,
		Long:  caddyCmd.Long,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fls := cmd.Flags()
			_, err := caddyCmd.Func(Flags{fls})
			return err
		},
	}
	cmd.Flags().AddGoFlagSet(caddyCmd.Flags)
	return cmd
}
