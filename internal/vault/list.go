package vault

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Entry contains listing metadata only, never secret values.
type Entry struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	OrganizationID string   `json:"organization_id,omitempty"`
	FolderID       string   `json:"folder_id,omitempty"`
	CollectionIDs  []string `json:"collection_ids,omitempty"`
}

type ListOptions struct {
	Kind, Organization, Collection, Folder, Search, ID, Name string
	Recursive                                                bool
}

// SelectID resolves an exact UUID before trying case-insensitive names.
func SelectID(names map[string]string, selector string) (string, error) {
	if selector == "" {
		return "", nil
	}
	if _, ok := names[selector]; ok {
		return selector, nil
	}
	result := ""
	for id, name := range names {
		if strings.EqualFold(name, selector) {
			if result != "" {
				return "", fmt.Errorf("ambiguous name %q; use a UUID", selector)
			}
			result = id
		}
	}
	if result == "" {
		return "", fmt.Errorf("%q not found", selector)
	}
	return result, nil
}

func (v *Vault) List(o ListOptions) ([]Entry, error) {
	org, err := SelectID(v.orgByID, o.Organization)
	if err != nil {
		return nil, err
	}
	collections := make(map[string]string)
	for id, name := range v.collectionsByID {
		if org == "" || v.collectionOrgs[id] == org {
			collections[id] = name
		}
	}
	col, err := SelectID(collections, o.Collection)
	if err != nil {
		return nil, err
	}
	folder, err := SelectID(v.folders, o.Folder)
	if err != nil {
		return nil, err
	}
	selected := func(id, root string, names map[string]string) bool {
		return root == "" || id == root || (o.Recursive && strings.HasPrefix(names[id], names[root]+"/"))
	}
	selectedCollection := func(id string) bool {
		return col == "" || v.collectionOrgs[id] == v.collectionOrgs[col] && selected(id, col, collections)
	}
	rows := []Entry{}
	add := func(e Entry) {
		if (o.ID == "" || e.ID == o.ID) && (o.Name == "" || strings.EqualFold(e.Name, o.Name)) && strings.Contains(strings.ToLower(e.Name), strings.ToLower(o.Search)) {
			rows = append(rows, e)
		}
	}
	// Metadata is restricted to the saved scope, including empty scoped containers.
	allowedCols, allowedOrgs, allowedFolders := map[string]bool{}, map[string]bool{}, map[string]bool{}
	if v.scope != nil {
		if v.scope.Type == "collection" {
			allowedCols[v.scope.ID] = true
			allowedOrgs[v.collectionOrgs[v.scope.ID]] = true
		}
		if v.scope.Type == "folder" {
			allowedFolders[v.scope.ID] = true
		}
		for _, dc := range v.items {
			if dc.Cipher.OrganizationID != nil {
				allowedOrgs[*dc.Cipher.OrganizationID] = true
			}
			if dc.Cipher.FolderID != nil {
				allowedFolders[*dc.Cipher.FolderID] = true
			}
			if v.scope.Type == "folder" {
				for _, id := range dc.Cipher.CollectionIDs {
					allowedCols[id] = true
				}
			}
		}
	}
	switch o.Kind {
	case "orgs":
		for id, name := range v.orgByID {
			if (v.scope == nil || allowedOrgs[id]) && (org == "" || org == id) {
				add(Entry{ID: id, Name: name, Type: "organization"})
			}
		}
	case "collections":
		for id, name := range collections {
			if (v.scope == nil || allowedCols[id]) && selectedCollection(id) {
				add(Entry{ID: id, Name: name, Type: "collection", OrganizationID: v.collectionOrgs[id]})
			}
		}
	case "folders":
		for id, name := range v.folders {
			if (v.scope == nil || allowedFolders[id]) && selected(id, folder, v.folders) {
				add(Entry{ID: id, Name: name, Type: "folder"})
			}
		}
	default:
		types := map[int]string{1: "login", 2: "note", 3: "card", 4: "identity"}
		for _, dc := range v.items {
			c := dc.Cipher
			if o.Kind != "items" && o.Kind != types[c.Type] {
				continue
			}
			e := Entry{ID: c.ID, Name: dc.Name, Type: types[c.Type], CollectionIDs: c.CollectionIDs}
			if c.OrganizationID != nil {
				e.OrganizationID = *c.OrganizationID
			}
			if c.FolderID != nil {
				e.FolderID = *c.FolderID
			}
			if org != "" && e.OrganizationID != org {
				continue
			}
			if !selected(e.FolderID, folder, v.folders) {
				continue
			}
			if col != "" && !slices.ContainsFunc(c.CollectionIDs, selectedCollection) {
				continue
			}
			if !o.Recursive && folder == "" && col == "" && v.scope == nil && (e.FolderID != "" || len(c.CollectionIDs) > 0) {
				continue
			}
			add(e)
		}
	}
	slices.SortFunc(rows, func(a, b Entry) int { return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.ID, b.ID)) })
	return rows, nil
}
