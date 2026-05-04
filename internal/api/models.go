package api

import "fmt"

type PreloginResponse struct {
	Kdf            int `json:"Kdf"`
	KdfIterations  int `json:"KdfIterations"`
	KdfMemory      int `json:"KdfMemory"`
	KdfParallelism int `json:"KdfParallelism"`
}

type TokenResponse struct {
	AccessToken   string `json:"access_token"`
	ExpiresIn     int    `json:"expires_in"`
	TokenType     string `json:"token_type"`
	RefreshToken  string `json:"refresh_token"`
	Key           string `json:"Key"`
	PrivateKey    string `json:"PrivateKey"`
	Kdf           int    `json:"Kdf"`
	KdfIterations int    `json:"KdfIterations"`
}

type TwoFactorError struct {
	Providers  []string `json:"TwoFactorProviders"`
	Raw        string   `json:"-"`
}

func (e *TwoFactorError) Error() string {
	return fmt.Sprintf("two factor required (providers: %v)", e.Providers)
}

type SyncResponse struct {
	Profile Profile  `json:"Profile"`
	Folders []Folder `json:"Folders"`
	Ciphers []Cipher `json:"Ciphers"`
	Sends   []Send   `json:"Sends"`
}

type Profile struct {
	ID            string `json:"Id"`
	Name          string `json:"Name"`
	Email         string `json:"Email"`
	Key           string `json:"Key"`
	PrivateKey    string `json:"PrivateKey"`
	SecurityStamp string `json:"SecurityStamp"`
}

type Cipher struct {
	ID             string      `json:"Id"`
	OrganizationID *string     `json:"OrganizationId"`
	CollectionIDs  []string    `json:"CollectionIds"`
	FolderID       *string     `json:"FolderId"`
	Type           int         `json:"Type"`
	Name           string      `json:"Name"`
	Notes          *string     `json:"Notes"`
	Favorite       bool        `json:"Favorite"`
	Fields         []Field     `json:"Fields"`
	Login          *Login      `json:"Login"`
	SecureNote     *SecureNote `json:"SecureNote"`
	Card           *Card       `json:"Card"`
	Identity       *Identity   `json:"Identity"`
	Reprompt       int         `json:"Reprompt"`
	DeletedDate    *string     `json:"DeletedDate"`
}

type Field struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
	Type  int    `json:"Type"`
}

type Login struct {
	URIs     []LoginURI `json:"Uris"`
	Username string     `json:"Username"`
	Password string     `json:"Password"`
	TOTP     *string    `json:"Totp"`
}

type LoginURI struct {
	Match *int   `json:"Match"`
	URI   string `json:"Uri"`
}

type SecureNote struct {
	Type int `json:"Type"`
}

type Card struct {
	CardholderName string `json:"CardholderName"`
	Brand          string `json:"Brand"`
	Number         string `json:"Number"`
	ExpMonth       string `json:"ExpMonth"`
	ExpYear        string `json:"ExpYear"`
	Code           string `json:"Code"`
}

type Identity struct {
	Title     string `json:"Title"`
	FirstName string `json:"FirstName"`
	LastName  string `json:"LastName"`
	Username  string `json:"Username"`
	Company   string `json:"Company"`
	Email     string `json:"Email"`
	Phone     string `json:"Phone"`
}

type Folder struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Object string `json:"Object"`
}

type Send struct{}
