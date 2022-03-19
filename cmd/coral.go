package caddycmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var rootCmd = &cobra.Command{
	Use: "caddy",
}

// TODO: figure out the correct directory
var manpageCmd = &cobra.Command{
	Use:   "manpage",
	Short: "Generate the man pages",
	RunE: func(_ *cobra.Command, _ []string) error {
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

func caddyCmdToCoral(caddyCmd Command) *cobra.Command {
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
