package api

type PreloginResponse struct {
	Kdf            int `json:"Kdf"`
	KdfIterations  int `json:"KdfIterations"`
	KdfMemory      int `json:"KdfMemory"`
	KdfParallelism int `json:"KdfParallelism"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
	PrivateKey   string `json:"PrivateKey"`
	Kdf          int    `json:"Kdf"`
	KdfIterations int   `json:"KdfIterations"`
}
