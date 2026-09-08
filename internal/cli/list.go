package cli

import (
	"encoding/json"
	"fmt"
	"slices"
	"text/tabwriter"
	"text/template"

	"github.com/nathabonfim59/bw-secrets/internal/vault"
	"github.com/spf13/cobra"
)

var listCmd = newListCommand()

var itemTypes = []string{"login", "note", "card", "identity"}

func init() { rootCmd.AddCommand(listCmd) }

func newListCommand() *cobra.Command {
	var options vault.ListOptions
	var format, tmpl, itemType string
	cmd := &cobra.Command{
		Use:   "list [items|login|note|card|identity|collections|orgs|folders]",
		Short: "List scoped vault metadata, using names or UUIDs as filters",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := options
			o.Kind = "items"
			if len(args) > 0 {
				o.Kind = args[0]
			}
			switch o.Kind {
			case "items", "login", "note", "card", "identity", "collections", "orgs", "folders":
			default:
				// Preserve the original positional folder selector.
				if o.Folder != "" {
					return fmt.Errorf("use either a positional folder or --folder")
				}
				o.Folder, o.Kind = o.Kind, "items"
			}
			if itemType != "" {
				if !slices.Contains(itemTypes, itemType) {
					return fmt.Errorf("unknown item type %q", itemType)
				}
				if o.Kind != "items" {
					return fmt.Errorf("--type is only valid for list items")
				}
				o.Kind = itemType
			}
			if o.Kind == "orgs" && (o.Collection != "" || o.Folder != "") || o.Kind == "collections" && o.Folder != "" || o.Kind == "folders" && (o.Organization != "" || o.Collection != "") {
				return fmt.Errorf("filter is not applicable to %s", o.Kind)
			}
			var t *template.Template
			switch format {
			case "table", "json", "text":
				if tmpl != "" {
					return fmt.Errorf("--template requires --format template")
				}
			case "template":
				if tmpl == "" {
					return fmt.Errorf("--format template requires --template")
				}
				var err error
				t, err = template.New("list").Option("missingkey=error").Parse(tmpl)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown format %q (use table, json, text, template)", format)
			}
			v, _, err := loadVault(cmd.Context())
			if err != nil {
				return err
			}
			rows, err := v.List(o)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch format {
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			case "template":
				return t.Execute(out, rows)
			case "text":
				for _, row := range rows {
					if _, err := fmt.Fprintln(out, row.ID); err != nil {
						return err
					}
				}
				return nil
			default:
				w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tNAME\tTYPE\tORGANIZATION ID")
				for _, row := range rows {
					fmt.Fprintf(w, "%s\t%q\t%s\t%s\n", row.ID, row.Name, row.Type, row.OrganizationID)
				}
				return w.Flush()
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&options.Recursive, "recursive", "r", false, "Include all items and descendants of selected folder/collection names")
	f.StringVar(&options.Organization, "organization", "", "Organization name or UUID")
	f.StringVar(&options.Collection, "collection", "", "Collection name or UUID")
	f.StringVar(&options.Folder, "folder", "", "Folder name or UUID")
	f.StringVar(&options.Search, "search", "", "Case-insensitive name substring")
	f.StringVar(&options.ID, "id", "", "Exact resource UUID")
	f.StringVar(&options.Name, "name", "", "Exact resource name (case-insensitive)")
	f.StringVar(&itemType, "type", "", "Item type: login, note, card, identity")
	f.StringVarP(&format, "format", "o", "table", "Output: table, json, text (UUIDs), template")
	f.StringVar(&tmpl, "template", "", "Go template over metadata entries")
	return cmd
}
