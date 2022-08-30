package caddycmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "caddy",
}

const docsHeader = "{{if not .HasParent}} Caddy is an extensible server platform.\n\n{{end}}"
const fullDocsFooter = `Full documentation is available at:
https://caddyserver.com/docs/command-line
`

func init() {
	rootCmd.SetHelpTemplate(docsHeader + rootCmd.HelpTemplate() + "\n" + fullDocsFooter)
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
