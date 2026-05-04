package vault

import (
	"errors"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
)

var (
	ErrVaultNotFound = errors.New("vault not found")
	ErrItemNotFound  = errors.New("item not found")
	ErrFieldNotFound = errors.New("field not found")
	ErrInvalidURI    = errors.New("invalid URI: expected bw://VaultName/ItemName/FieldName")
	ErrMultipleItems = errors.New("multiple items match")
)

type Vault struct {
	items []decryptedCipher
}

type decryptedCipher struct {
	Cipher    api.Cipher
	Name      string
	VaultName string
}

func New(syncResp *api.SyncResponse, symKey *crypto.SymmetricKey) *Vault {
	v := &Vault{}

	foldersByID := make(map[string]string)
	for _, f := range syncResp.Folders {
		name := f.Name
		if decrypted, err := decryptField(f.Name, symKey); err == nil {
			name = decrypted
		}
		foldersByID[f.ID] = name
	}

	for _, c := range syncResp.Ciphers {
		if c.DeletedDate != nil {
			continue
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
		v.items = append(v.items, decryptedCipher{
			Cipher:    c,
			Name:      name,
			VaultName: vaultName,
		})
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
