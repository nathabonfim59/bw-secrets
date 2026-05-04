package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nathabonfim59/bw-secrets/internal/api"
	"github.com/nathabonfim59/bw-secrets/internal/crypto"
	"github.com/nathabonfim59/bw-secrets/internal/keyring"
)

func getClient() (*api.Client, *keyring.Credentials, error) {
	creds, err := keyring.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Not logged in — run 'bw-secrets login'")
		os.Exit(2)
		return nil, nil, nil
	}

	url := serverURL()
	if url == "" {
		url = creds.ServerURL
	}

	expiry := tokenExpiry(creds.AccessToken)
	if expiry >= 0 && expiry < 5*time.Minute {
		client := api.NewClient(url)
		tokenResp, err := client.RefreshToken(context.Background(), creds.RefreshToken)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Session expired — run 'bw-secrets unlock'")
			os.Exit(2)
			return nil, nil, nil
		}
		creds.AccessToken = tokenResp.AccessToken
		creds.RefreshToken = tokenResp.RefreshToken
		if err := keyring.Save(creds); err != nil {
			return nil, nil, fmt.Errorf("saving refreshed tokens: %w", err)
		}
	}

	client := api.NewClient(url)
	client.SetAccessToken(creds.AccessToken)
	return client, creds, nil
}

func getSymmetricKey(creds *keyring.Credentials) (*crypto.SymmetricKey, error) {
	raw, err := base64.StdEncoding.DecodeString(creds.EncKey)
	if err != nil {
		return nil, fmt.Errorf("decoding enc key: %w", err)
	}
	return crypto.NewSymmetricKey(raw)
}

func tokenExpiry(accessToken string) time.Duration {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return -1
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return -1
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return -1
	}
	if claims.Exp == 0 {
		return -1
	}
	return time.Until(time.Unix(claims.Exp, 0))
}
