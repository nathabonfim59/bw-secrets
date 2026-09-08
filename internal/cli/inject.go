package cli

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(injectCmd)
}

var (
	injectInFile  string
	injectOutFile string
)

var injectCmd = &cobra.Command{
	Use:   "inject [file]",
	Short: "Replace bw:// references in a file or stdin with resolved secrets.",
	Long: `Reads input from stdin or a file, finds all bw:// URIs,
resolves them to their secret values, and writes the result.

Template variables ($VAR or ${VAR}) in the input are expanded from the
current environment, enabling multi-environment config templates:
  APP_ENV=prod bw-secrets inject -i config.yml.tpl`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v, _, err := loadVault(cmd.Context())
		if err != nil {
			return err
		}

		var input []byte
		source := injectInFile
		if source == "" && len(args) > 0 {
			source = args[0]
		}
		if source != "" {
			input, err = os.ReadFile(source)
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
		} else {
			input, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		}

		text := os.Expand(string(input), func(v string) string {
			return "$" + v
		})
		text = expandEnvTemplate(text)

		bwRe := regexp.MustCompile(`bw://[^\s"'` + "`" + `]+`)
		uris := dedupeURIs(bwRe.FindAllString(text, -1))

		replacements := make(map[string]string)
		for _, uri := range uris {
			parsed, err := vault.ParseURI(uri)
			if err != nil {
				return fmt.Errorf("parsing %q: %w", uri, err)
			}
			val, _, _, err := v.ResolveValue(parsed)
			if err != nil {
				return fmt.Errorf("resolving %q: %w", uri, err)
			}
			replacements[uri] = val
		}

		result := text
		for uri, val := range replacements {
			result = strings.ReplaceAll(result, uri, val)
		}

		var out io.Writer = os.Stdout
		if injectOutFile != "" {
			f, err := os.OpenFile(injectOutFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()
			out = f
		}
		_, err = out.Write([]byte(result))
		return err
	},
}

func init() {
	injectCmd.Flags().StringVarP(&injectInFile, "in-file", "i", "", "Input file (default: stdin)")
	injectCmd.Flags().StringVarP(&injectOutFile, "out-file", "o", "", "Output file (default: stdout)")
}

func expandEnvTemplate(text string) string {
	return expandEnvVars(text, nil)
}

func dedupeURIs(uris []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, u := range uris {
		if !seen[u] {
			seen[u] = true
			result = append(result, u)
		}
	}
	return result
}
