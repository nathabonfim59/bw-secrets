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
