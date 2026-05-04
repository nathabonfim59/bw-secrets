package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bw-secrets",
	Short: "Bitwarden secret references for the terminal (like op://).",
	Long: `bw-secrets resolves secrets from your Bitwarden vault using URIs
like bw://VaultName/ItemName/FieldName.

First run 'bw-secrets login' to authenticate, then use subcommands.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
