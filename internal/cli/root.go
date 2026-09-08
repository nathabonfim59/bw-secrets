package cli

import (
	"cmp"
	"fmt"
	"os"

	"github.com/nathabonfim59/bw-secrets/internal/profile"
	"github.com/spf13/cobra"
)

// version is injected at build time via:
//
//	-ldflags="-X github.com/nathabonfim59/bw-secrets/internal/cli.version=vX.Y.Z"
var version = "dev"

var serverFlag string
var profileFlag string
var activeProfile profile.Selection

var rootCmd = &cobra.Command{
	Use:     "bw-secrets",
	Short:   "Bitwarden secret references for the terminal (like op://).",
	Version: version,
	Long: `bw-secrets resolves secrets from your Bitwarden vault using URIs
like bw://VaultName/ItemName/FieldName.

First run 'bw-secrets login' to authenticate, then use subcommands.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		activeProfile, err = profile.Resolve(profileFlag, os.Getenv(profile.Env), ".")
		return err
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&serverFlag, "server", "s", "", "Bitwarden server URL (also settable via BW_SECRETS_SERVER)")
	rootCmd.PersistentFlags().StringVar(&profileFlag, "profile", "", "Login profile (overrides directory bindings and BW_SECRETS_PROFILE)")
}

func serverURL() string {
	return cmp.Or(serverFlag, os.Getenv("BW_SECRETS_SERVER"))
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
