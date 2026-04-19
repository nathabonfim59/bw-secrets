package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var serverFlag string

var rootCmd = &cobra.Command{
	Use:   "bw-secrets",
	Short: "Bitwarden secret references for the terminal (like op://).",
	Long: `bw-secrets resolves secrets from your Bitwarden vault using URIs
like bw://VaultName/ItemName/FieldName.

First run 'bw-secrets login' to authenticate, then use subcommands.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&serverFlag, "server", "s", "", "Bitwarden server URL (also settable via BW_SECRETS_SERVER)")
}

func serverURL() string {
	if serverFlag != "" {
		return serverFlag
	}
	if s := os.Getenv("BW_SECRETS_SERVER"); s != "" {
		return s
	}
	return ""
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
