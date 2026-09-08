package cli

import "github.com/spf13/cobra"

func init() {
	cmd := newListCommand()
	cmd.Use = "orgs"
	cmd.Short = "List organizations (alias for list orgs)."
	cmd.Args = cobra.NoArgs
	list := cmd.RunE
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return list(cmd, []string{"orgs"})
	}
	rootCmd.AddCommand(cmd)
}
