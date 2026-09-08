package vault

import (
	"slices"
	"testing"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
)

func TestListHierarchyAndScope(t *testing.T) {
	sync := &api.SyncResponse{
		Profile:     api.Profile{Organizations: []api.Organization{{ID: "o1", Name: "Acme Corp"}, {ID: "o2", Name: "Other"}}},
		Folders:     []api.Folder{{ID: "f1", Name: "Work"}, {ID: "f2", Name: "Work/Sub"}, {ID: "f3", Name: "Workshop"}},
		Collections: []api.Collection{{ID: "c1", Name: "Team", OrganizationID: "o1"}, {ID: "c2", Name: "Team/Sub", OrganizationID: "o1"}, {ID: "c3", Name: "Team", OrganizationID: "o2"}},
		Ciphers: []api.Cipher{
			{ID: "a", Name: "A", Type: 1},
			{ID: "b", Name: "B", Type: 1, FolderID: new("f1")},
			{ID: "c", Name: "C", Type: 1, FolderID: new("f2")},
			{ID: "d", Name: "D", Type: 1, FolderID: new("f3")},
			{ID: "e", Name: "E", Type: 1, OrganizationID: new("o1"), CollectionIDs: []string{"c1"}},
			{ID: "f", Name: "F", Type: 1, OrganizationID: new("o1"), CollectionIDs: []string{"c2"}},
			{ID: "g", Name: "G", Type: 1, OrganizationID: new("o2"), CollectionIDs: []string{"c3"}},
			{ID: "h", Name: "H", Type: 2},
			{ID: "deleted", Name: "Deleted", Type: 1, DeletedDate: new("today")},
		},
	}
	for _, tc := range []struct {
		name  string
		o     ListOptions
		scope *keyring.Scope
		want  []string
		fail  bool
	}{
		{name: "root", o: ListOptions{Kind: "login"}, want: []string{"a"}},
		{name: "all", o: ListOptions{Kind: "login", Recursive: true}, want: []string{"a", "b", "c", "d", "e", "f", "g"}},
		{name: "folder name", o: ListOptions{Kind: "login", Folder: "work"}, want: []string{"b"}},
		{name: "folder descendants", o: ListOptions{Kind: "login", Folder: "f1", Recursive: true}, want: []string{"b", "c"}},
		{name: "org collection", o: ListOptions{Kind: "login", Organization: "Acme Corp", Collection: "Team", Recursive: true}, want: []string{"e", "f"}},
		{name: "ambiguous", o: ListOptions{Kind: "login", Collection: "Team"}, fail: true},
		{name: "wrong org", o: ListOptions{Kind: "login", Organization: "o2", Collection: "c1"}, fail: true},
		{name: "collections", o: ListOptions{Kind: "collections"}, want: []string{"c1", "c3", "c2"}},
		{name: "scope root", o: ListOptions{Kind: "login"}, scope: &keyring.Scope{Type: "collection", ID: "c1"}, want: []string{"e"}},
		{name: "scope recursive", o: ListOptions{Kind: "login", Recursive: true}, scope: &keyring.Scope{Type: "collection", ID: "c1"}, want: []string{"e"}},
		{name: "scope metadata", o: ListOptions{Kind: "collections"}, scope: &keyring.Scope{Type: "collection", ID: "c1"}, want: []string{"c1"}},
		{name: "scope orgs", o: ListOptions{Kind: "orgs"}, scope: &keyring.Scope{Type: "collection", ID: "c1"}, want: []string{"o1"}},
		{name: "scope cannot widen", o: ListOptions{Kind: "login", Collection: "c3", Recursive: true}, scope: &keyring.Scope{Type: "collection", ID: "c1"}},
		{name: "search", o: ListOptions{Kind: "login", Recursive: true, Search: "b"}, want: []string{"b"}},
		{name: "id", o: ListOptions{Kind: "login", Recursive: true, ID: "c"}, want: []string{"c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(sync, nil, tc.scope)
			rows, err := v.List(tc.o)
			if tc.fail {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, row := range rows {
				ids = append(ids, row.ID)
			}
			if !slices.Equal(ids, tc.want) {
				t.Fatalf("got %v want %v", ids, tc.want)
			}
		})
	}
	v := New(sync, nil, nil)
	if dc, err := v.FindByOrgCollection("o2", "c3", "g"); err != nil || dc.Cipher.ID != "g" {
		t.Fatalf("UUID resolution: %v", err)
	}
	if _, err := v.FindByOrgCollection("o1", "c3", "g"); err == nil {
		t.Fatal("cross-org resolution succeeded")
	}
}
