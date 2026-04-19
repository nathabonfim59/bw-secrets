package vault

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
)

type SecretURI struct {
	VaultName string
	ItemName  string
	FieldName string
}

func ParseURI(uri string) (*SecretURI, error) {
	if !strings.HasPrefix(uri, "bw://") {
		return nil, fmt.Errorf("%w: missing bw:// prefix", ErrInvalidURI)
	}
	rest := strings.TrimPrefix(uri, "bw://")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: got %q", ErrInvalidURI, uri)
	}

	vaultName, err := url.PathUnescape(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid vault name: %s", ErrInvalidURI, err)
	}
	itemName, err := url.PathUnescape(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid item name: %s", ErrInvalidURI, err)
	}
	fieldName, err := url.PathUnescape(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid field name: %s", ErrInvalidURI, err)
	}

	return &SecretURI{
		VaultName: vaultName,
		ItemName:  itemName,
		FieldName: fieldName,
	}, nil
}

func (v *Vault) ResolveValue(uri *SecretURI, symKey *crypto.SymmetricKey) (string, string, string, error) {
	dc, err := v.FindByName(uri.ItemName, uri.VaultName)
	if err != nil {
		return "", "", "", err
	}

	fieldName := strings.ToLower(uri.FieldName)
	c := dc.Cipher

	encValue := extractFieldEncValue(c, fieldName, symKey)

	if encValue == "" {
		return "", "", "", &FieldNotFoundError{
			Field: uri.FieldName,
			Item:  dc.Name,
			Type:  c.Type,
		}
	}

	value, err := decryptField(encValue, symKey)
	if err != nil {
		return "", "", "", fmt.Errorf("decrypting field: %w", err)
	}
	return value, dc.VaultName, dc.Name, nil
}

func extractFieldEncValue(c api.Cipher, fieldName string, symKey *crypto.SymmetricKey) string {
	switch c.Type {
	case 1:
		return resolveLoginField(c, fieldName, symKey)
	case 2:
		return resolveSecureNoteField(c, fieldName)
	case 3:
		return resolveCardField(c, fieldName)
	case 4:
		return resolveIdentityField(c, fieldName)
	default:
		if fieldName == "notes" && c.Notes != nil {
			return *c.Notes
		}
	}
	return ""
}

func resolveLoginField(c api.Cipher, fieldName string, symKey *crypto.SymmetricKey) string {
	switch fieldName {
	case "username":
		if c.Login != nil {
			return c.Login.Username
		}
	case "password":
		if c.Login != nil {
			return c.Login.Password
		}
	case "totp":
		if c.Login != nil && c.Login.TOTP != nil {
			return *c.Login.TOTP
		}
	case "notes":
		if c.Notes != nil {
			return *c.Notes
		}
	default:
		for _, f := range c.Fields {
			name, _ := decryptField(f.Name, symKey)
			if strings.EqualFold(name, fieldName) {
				return f.Value
			}
		}
	}
	return ""
}

func resolveSecureNoteField(c api.Cipher, fieldName string) string {
	if fieldName == "notes" && c.Notes != nil {
		return *c.Notes
	}
	return ""
}

func resolveCardField(c api.Cipher, fieldName string) string {
	if c.Card == nil {
		return ""
	}
	switch fieldName {
	case "cardholder", "cardholdername":
		return c.Card.CardholderName
	case "number":
		return c.Card.Number
	case "brand":
		return c.Card.Brand
	case "expmonth", "expirymonth":
		return c.Card.ExpMonth
	case "expyear", "expiryyear":
		return c.Card.ExpYear
	case "code", "cvv":
		return c.Card.Code
	}
	return ""
}

func resolveIdentityField(c api.Cipher, fieldName string) string {
	if c.Identity == nil {
		return ""
	}
	switch fieldName {
	case "title":
		return c.Identity.Title
	case "firstname":
		return c.Identity.FirstName
	case "lastname":
		return c.Identity.LastName
	case "username":
		return c.Identity.Username
	case "company":
		return c.Identity.Company
	case "email":
		return c.Identity.Email
	case "phone":
		return c.Identity.Phone
	}
	return ""
}

type FieldNotFoundError struct {
	Field string
	Item  string
	Type  int
}

func (e *FieldNotFoundError) Error() string {
	return fmt.Sprintf("field '%s' not found on item '%s' (type %d)", e.Field, e.Item, e.Type)
}
