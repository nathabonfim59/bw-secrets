package api

import "fmt"

type PreloginResponse struct {
	Kdf            int `json:"Kdf"`
	KdfIterations  int `json:"KdfIterations"`
	KdfMemory      int `json:"KdfMemory"`
	KdfParallelism int `json:"KdfParallelism"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
}

type TwoFactorError struct {
	Providers []string `json:"TwoFactorProviders"`
}

func (e *TwoFactorError) Error() string {
	return fmt.Sprintf("two factor required (providers: %v)", e.Providers)
}

type SyncResponse struct {
	Profile     Profile      `json:"Profile"`
	Folders     []Folder     `json:"Folders"`
	Collections []Collection `json:"Collections"`
	Ciphers     []Cipher     `json:"Ciphers"`
}

type Profile struct {
	Organizations []Organization `json:"Organizations"`
}

type Organization struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
}

type Collection struct {
	ID             string `json:"Id"`
	OrganizationID string `json:"OrganizationId"`
	Name           string `json:"Name"`
}

type Cipher struct {
	ID             string    `json:"Id"`
	OrganizationID *string   `json:"OrganizationId"`
	CollectionIDs  []string  `json:"CollectionIds"`
	FolderID       *string   `json:"FolderId"`
	Type           int       `json:"Type"`
	Name           string    `json:"Name"`
	Notes          *string   `json:"Notes"`
	Fields         []Field   `json:"Fields"`
	Login          *Login    `json:"Login"`
	Card           *Card     `json:"Card"`
	Identity       *Identity `json:"Identity"`
	DeletedDate    *string   `json:"DeletedDate"`
}

type Field struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type Login struct {
	Username string  `json:"Username"`
	Password string  `json:"Password"`
	TOTP     *string `json:"Totp"`
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
	ID   string `json:"Id"`
	Name string `json:"Name"`
}
