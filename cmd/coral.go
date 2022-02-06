package caddycmd

import (
	"os"

	"github.com/muesli/coral"
	"github.com/muesli/coral/doc"
)

var rootCmd = &coral.Command{
	Use: "caddy",
}

// TODO: figure out the correct directory
var manpageCmd = &coral.Command{
	Use:   "manpage",
	Short: "Generate the man pages",
	RunE: func(_ *coral.Command, _ []string) error {
		return doc.GenManTree(rootCmd, &doc.GenManHeader{
			Title:   "Caddy",
			Section: "1",
		}, "./")
	},
}

const docsHeader = `Caddy is an extensible server platform.`
const fullDocsFooter = `Full documentation is available at:
https://caddyserver.com/docs/command-line
`

func init() {
	rootCmd.SetHelpTemplate(docsHeader + "\n\n" + rootCmd.HelpTemplate() + "\n" + fullDocsFooter)

	rootCmd.AddCommand(manpageCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func caddyCmdToCoral(caddyCmd Command) *coral.Command {
	cmd := &coral.Command{
		Use:   caddyCmd.Name,
		Short: caddyCmd.Short,
		Long:  caddyCmd.Long,
		RunE: func(cmd *coral.Command, _ []string) error {
			fls := cmd.Flags()
			_, err := caddyCmd.Func(Flags{fls})
			return err
		},
	}
	cmd.Flags().AddGoFlagSet(caddyCmd.Flags)
	return cmd
}
