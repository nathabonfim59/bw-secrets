package vault

import (
	"errors"
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
	items             []decryptedCipher
	collectionCiphers map[string][]decryptedCipher
	collectionsByID   map[string]string
	orgByID           map[string]string
}

type decryptedCipher struct {
	Cipher    api.Cipher
	Name      string
	VaultName string
}

func New(syncResp *api.SyncResponse, symKey *crypto.SymmetricKey, scope *keyring.Scope) *Vault {
	v := &Vault{
		collectionCiphers: make(map[string][]decryptedCipher),
		collectionsByID:   make(map[string]string),
		orgByID:           make(map[string]string),
	}

	for _, org := range syncResp.Profile.Organizations {
		v.orgByID[org.ID] = org.Name
	}

	foldersByID := make(map[string]string)
	for _, f := range syncResp.Folders {
		name := f.Name
		if decrypted, err := decryptField(f.Name, symKey); err == nil {
			name = decrypted
		}
		foldersByID[f.ID] = name
	}

	for _, col := range syncResp.Collections {
		name := col.Name
		if decrypted, err := decryptField(col.Name, symKey); err == nil {
			name = decrypted
		}
		v.collectionsByID[col.ID] = name
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

		name := c.Name
		if decrypted, err := decryptField(c.Name, symKey); err == nil {
			name = decrypted
		}
		vaultName := "No Folder"
		if c.FolderID != nil {
			if fname, ok := foldersByID[*c.FolderID]; ok {
				vaultName = fname
			}
		}

		dc := decryptedCipher{
			Cipher:    c,
			Name:      name,
			VaultName: vaultName,
		}
		v.items = append(v.items, dc)

		for _, collID := range c.CollectionIDs {
			v.collectionCiphers[collID] = append(v.collectionCiphers[collID], dc)
		}
	}

	return v
}

func (v *Vault) Items() []decryptedCipher {
	return v.items
}

func (v *Vault) FindByName(name, vaultName string) (*decryptedCipher, error) {
	var matches []decryptedCipher
	for i := range v.items {
		dc := &v.items[i]
		if vaultName != "" && vaultName != "*" {
			if !strings.EqualFold(dc.VaultName, vaultName) {
				continue
			}
		}
		if strings.EqualFold(dc.Name, name) {
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
	orgID := ""
	lowerOrg := strings.ToLower(orgName)
	for id, name := range v.orgByID {
		if strings.ToLower(name) == lowerOrg {
			orgID = id
			break
		}
	}
	if orgID == "" {
		return nil, &ItemNotFoundError{Name: itemName, Vault: orgName + "//" + collectionName}
	}

	collectionID := ""
	lowerColl := strings.ToLower(collectionName)
	for id, name := range v.collectionsByID {
		if strings.ToLower(name) == lowerColl {
			collectionID = id
			break
		}
	}
	if collectionID == "" {
		return nil, &ItemNotFoundError{Name: itemName, Vault: orgName + "//" + collectionName}
	}

	ciphers := v.collectionCiphers[collectionID]
	var matches []decryptedCipher
	for _, dc := range ciphers {
		if strings.EqualFold(dc.Name, itemName) {
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
