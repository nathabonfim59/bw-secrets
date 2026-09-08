package vault

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
)

var (
	ErrVaultNotFound = errors.New("vault not found")
	ErrItemNotFound  = errors.New("item not found")
	ErrFieldNotFound = errors.New("field not found")
	ErrInvalidURI    = errors.New("invalid URI: expected bw://Vault/Item/Field or bw://Org//Collection/Item/Field")
	ErrMultipleItems = errors.New("multiple items match")
)

type Vault struct {
	folders           map[string]string
	collectionOrgs    map[string]string
	scope             *keyring.Scope
	items             []decryptedCipher
	collectionCiphers map[string][]decryptedCipher
	collectionsByID   map[string]string
	orgByID           map[string]string
}

type decryptedCipher struct {
	key       *crypto.SymmetricKey
	Cipher    api.Cipher
	Name      string
	VaultName string
}

func New(syncResp *api.SyncResponse, symKey *crypto.SymmetricKey, scope *keyring.Scope) (*Vault, error) {
	orgKeys, err := organizationKeys(syncResp, symKey)
	if err != nil {
		return nil, err
	}
	v := &Vault{
		scope:             scope,
		collectionOrgs:    make(map[string]string),
		collectionCiphers: make(map[string][]decryptedCipher),
		collectionsByID:   make(map[string]string),
		orgByID:           make(map[string]string),
	}

	for _, org := range syncResp.Profile.Organizations {
		v.orgByID[org.ID] = org.Name
	}

	foldersByID := make(map[string]string)
	v.folders = foldersByID
	for _, f := range syncResp.Folders {
		name, err := decryptName(f.Name, symKey)
		if err != nil {
			return nil, fmt.Errorf("folder %s: %w", f.ID, err)
		}
		foldersByID[f.ID] = name
	}

	for _, col := range syncResp.Collections {
		name, err := decryptName(col.Name, orgKeys[col.OrganizationID])
		if err != nil {
			return nil, fmt.Errorf("collection %s: %w", col.ID, err)
		}
		v.collectionsByID[col.ID] = name
		v.collectionOrgs[col.ID] = col.OrganizationID
	}

	for _, c := range syncResp.Ciphers {
		if c.DeletedDate != nil {
			continue
		}

		if scope != nil {
			switch scope.Type {
			case "folder":
				if c.FolderID == nil || *c.FolderID != scope.ID {
					continue
				}
			case "collection":
				if !slices.Contains(c.CollectionIDs, scope.ID) {
					continue
				}
			}
		}

		key := symKey
		if c.OrganizationID != nil {
			key = orgKeys[*c.OrganizationID]
		}
		if c.Key != "" {
			raw, err := decryptField(c.Key, key)
			if err != nil {
				return nil, fmt.Errorf("item %s key: %w", c.ID, err)
			}
			key, err = crypto.NewSymmetricKey([]byte(raw))
			if err != nil {
				return nil, fmt.Errorf("item %s key: %w", c.ID, err)
			}
		}
		name, err := decryptName(c.Name, key)
		if err != nil {
			return nil, fmt.Errorf("item %s name: %w", c.ID, err)
		}
		vaultName := "No Folder"
		if c.FolderID != nil {
			if fname, ok := foldersByID[*c.FolderID]; ok {
				vaultName = fname
			}
		}

		dc := decryptedCipher{
			key:       key,
			Cipher:    c,
			Name:      name,
			VaultName: vaultName,
		}
		v.items = append(v.items, dc)

		for _, collID := range c.CollectionIDs {
			v.collectionCiphers[collID] = append(v.collectionCiphers[collID], dc)
		}
	}

	return v, nil
}

func organizationKeys(s *api.SyncResponse, key *crypto.SymmetricKey) (map[string]*crypto.SymmetricKey, error) {
	keys := make(map[string]*crypto.SymmetricKey)
	var private *rsa.PrivateKey
	for _, org := range s.Profile.Organizations {
		if org.Key == "" {
			continue
		}
		var err error
		if private == nil {
			private, err = crypto.DecryptPrivateKey(s.Profile.PrivateKey, key)
			if err != nil {
				return nil, fmt.Errorf("account private key: %w", err)
			}
		}
		keys[org.ID], err = crypto.DecryptOrganizationKey(org.Key, private)
		if err != nil {
			return nil, fmt.Errorf("organization %s key: %w", org.ID, err)
		}
	}
	return keys, nil
}

func decryptName(value string, key *crypto.SymmetricKey) (string, error) {
	if len(value) < 2 || value[1] != '.' || value[0] < '0' || value[0] > '9' {
		return value, nil
	}
	return decryptField(value, key)
}

func (v *Vault) Items() []decryptedCipher {
	return v.items
}

func (v *Vault) FindByName(name, vaultName string) (*decryptedCipher, error) {
	folderID := ""
	if _, ok := v.folders[vaultName]; ok {
		folderID = vaultName
	}
	var matches []decryptedCipher
	for i := range v.items {
		dc := &v.items[i]
		if vaultName != "" && vaultName != "*" {
			if folderID != "" && (dc.Cipher.FolderID == nil || *dc.Cipher.FolderID != folderID) || folderID == "" && !strings.EqualFold(dc.VaultName, vaultName) {
				continue
			}
		}
		if dc.Cipher.ID == name || strings.EqualFold(dc.Name, name) {
			matches = append(matches, *dc)
		}
	}

	if len(matches) == 0 {
		if vaultName != "" {
			return nil, &ItemNotFoundError{Name: name, Vault: vaultName}
		}
		return nil, &ItemNotFoundError{Name: name}
	}
	if len(matches) > 1 {
		return nil, &MultipleItemsError{Name: name, Matches: matches}
	}
	return &matches[0], nil
}

func (v *Vault) FindByOrgCollection(orgName, collectionName, itemName string) (*decryptedCipher, error) {
	orgID, err := SelectID(v.orgByID, orgName)
	if err != nil {
		return nil, err
	}
	collections := make(map[string]string)
	for id, name := range v.collectionsByID {
		if v.collectionOrgs[id] == orgID {
			collections[id] = name
		}
	}
	collectionID, err := SelectID(collections, collectionName)
	if err != nil {
		return nil, err
	}

	ciphers := v.collectionCiphers[collectionID]
	var matches []decryptedCipher
	for _, dc := range ciphers {
		if dc.Cipher.ID == itemName || strings.EqualFold(dc.Name, itemName) {
			matches = append(matches, dc)
		}
	}

	if len(matches) == 0 {
		return nil, &ItemNotFoundError{Name: itemName, Vault: orgName + "//" + collectionName}
	}
	if len(matches) > 1 {
		return nil, &MultipleItemsError{Name: itemName, Matches: matches}
	}
	return &matches[0], nil
}

func decryptField(encString string, symKey *crypto.SymmetricKey) (string, error) {
	es, err := crypto.ParseEncString(encString)
	if err != nil {
		return encString, err
	}
	return es.Decrypt(symKey)
}

type ItemNotFoundError struct {
	Name  string
	Vault string
}

func (e *ItemNotFoundError) Error() string {
	if e.Vault != "" {
		return "item '" + e.Name + "' not found in vault '" + e.Vault + "'"
	}
	return "item '" + e.Name + "' not found"
}

type MultipleItemsError struct {
	Name    string
	Matches []decryptedCipher
}

func (e *MultipleItemsError) Error() string {
	var names []string
	for _, m := range e.Matches {
		names = append(names, m.VaultName+"/"+m.Name)
	}
	return "multiple items match '" + e.Name + "': " + strings.Join(names, ", ")
}
