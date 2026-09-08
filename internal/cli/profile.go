package cli

import (
	"fmt"
	"os"

	"github.com/nathabonfim59/bw-secrets/internal/profile"
	"github.com/spf13/cobra"
)

func init() {
	profiles := &cobra.Command{
		Use:   "profile",
		Short: "Select login profiles and bind them to directories.",
		// Named exports must not depend on the current directory's selection.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
	profiles.AddCommand(&cobra.Command{
		Use:   "current",
		Short: "Print the effective profile for this directory.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, err := profile.Resolve(profileFlag, os.Getenv(profile.Env), ".")
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), selected.Name)
			return err
		},
	})
	profiles.AddCommand(&cobra.Command{
		Use:   "use [name]",
		Short: "Print a shell export for a named profile or the current profile.",
		Long: `Prints a POSIX shell export without changing the parent shell.
Apply it in bash/zsh/sh with: eval "$(bw-secrets profile use work)"
Omit the name to export the currently effective profile.
Directory bindings override this inherited default. No credentials are printed.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var name string
			if len(args) == 1 {
				name = args[0]
			} else {
				selected, err := profile.Resolve(profileFlag, os.Getenv(profile.Env), ".")
				if err != nil {
					return err
				}
				name = selected.Name
			}
			if err := profile.Validate(name); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "export %s=%s\n", profile.Env, name)
			return err
		},
	})
	profiles.AddCommand(&cobra.Command{
		Use:   "bind <name> [directory]",
		Short: "Bind a profile to a directory and all its subdirectories.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := profile.Validate(args[0]); err != nil {
				return err
			}
			dir := "."
			if len(args) == 2 {
				dir = args[1]
			}
			dir, err := profile.Directory(dir)
			if err != nil {
				return err
			}
			cfg, err := profile.Load()
			if err != nil {
				return err
			}
			cfg.Bindings[dir] = args[0]
			if err := cfg.Save(); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Bound %s to profile %s\n", dir, args[0])
			return err
		},
	})
	profiles.AddCommand(&cobra.Command{
		Use:   "unbind [directory]",
		Short: "Remove a directory's explicit profile binding.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			dir, err := profile.Directory(dir)
			if err != nil {
				return err
			}
			cfg, err := profile.Load()
			if err != nil {
				return err
			}
			delete(cfg.Bindings, dir)
			return cfg.Save()
		},
	})
	rootCmd.AddCommand(profiles)
}
