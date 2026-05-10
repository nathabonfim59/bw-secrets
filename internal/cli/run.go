package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(runCmd)
}

var (
	runEnvFiles []string
	runNoMask   bool
)

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command with secrets injected as environment variables.",
	Long: `Scans environment variables and .env files for bw:// URIs,
resolves them to secret values, and runs the given command with those
secrets injected. Secret values are masked in the subprocess output.

Examples:
  DB_PASS=bw://Production/MySQL/password bw-secrets run -- mysqldump ...
  bw-secrets run --env-file prod.env -- mysqldump ...`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, creds, err := getClient()
		if err != nil {
			return err
		}

		symKey, err := getSymmetricKey(creds)
		if err != nil {
			return err
		}

		syncResp, err := client.Sync(context.Background())
		if err != nil {
			return fmt.Errorf("syncing vault: %w", err)
		}
		v := vault.New(syncResp, symKey, creds.Scope)

		combinedEnv := make(map[string]string)
		for _, kv := range os.Environ() {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				combinedEnv[parts[0]] = parts[1]
			}
		}
		for _, f := range runEnvFiles {
			fileVars, err := parseEnvFile(f)
			if err != nil {
				return fmt.Errorf("parsing env file %q: %w", f, err)
			}
			for k, v := range fileVars {
				combinedEnv[k] = v
			}
		}

		var secrets []string

		for key, value := range combinedEnv {
			if !strings.HasPrefix(value, "bw://") {
				continue
			}
			parsed, err := vault.ParseURI(value)
			if err != nil {
				return fmt.Errorf("parsing %s=%s: %w", key, value, err)
			}
			resolved, _, _, err := v.ResolveValue(parsed, symKey)
			if err != nil {
				return fmt.Errorf("resolving %s=%s: %w", key, value, err)
			}
			combinedEnv[key] = resolved
			secrets = append(secrets, resolved)
		}

		cmdEnv := make([]string, 0, len(combinedEnv))
		for k, v := range combinedEnv {
			cmdEnv = append(cmdEnv, k+"="+v)
		}

		subCmd := exec.Command(args[0], args[1:]...)
		subCmd.Env = cmdEnv
		subCmd.Stdin = os.Stdin

		if runNoMask {
			subCmd.Stdout = os.Stdout
			subCmd.Stderr = os.Stderr
		} else {
			subCmd.Stdout = newMaskWriter(os.Stdout, secrets)
			subCmd.Stderr = newMaskWriter(os.Stderr, secrets)
		}

		if err := subCmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return err
		}
		return nil
	},
}

func init() {
	runCmd.Flags().StringSliceVarP(&runEnvFiles, "env-file", "e", nil, "Path to .env file (repeatable)")
	runCmd.Flags().BoolVar(&runNoMask, "no-masking", false, "Disable secret masking in subprocess output")
}

type maskWriter struct {
	w       io.Writer
	secrets []string
	buf     []byte
}

func newMaskWriter(w io.Writer, secrets []string) *maskWriter {
	return &maskWriter{w: w, secrets: secrets}
}

func (m *maskWriter) Write(p []byte) (int, error) {
	s := string(p)
	for _, secret := range m.secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "***")
	}
	n, err := m.w.Write([]byte(s))
	if err != nil {
		return n, err
	}
	return len(p), nil
}
