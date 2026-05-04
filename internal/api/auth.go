package api

import (
	"context"
	"net/url"
	"strings"
)

func (c *Client) Prelogin(ctx context.Context, email string) (*PreloginResponse, error) {
	var result PreloginResponse
	err := c.postJSON(ctx, "/api/accounts/prelogin", map[string]string{"email": email}, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Login(ctx context.Context, email, passwordHash string, deviceID string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"password"},
		"username":      {email},
		"password":      {passwordHash},
		"scope":         {"api offline_access"},
		"client_id":     {"browser"},
		"deviceType":    {"14"},
		"deviceName":    {"bw-secrets"},
	}
	if deviceID != "" {
		data.Set("deviceIdentifier", deviceID)
	}

	reqBody := strings.NewReader(data.Encode())
	var result TokenResponse
	err := c.do(ctx, "POST", "/identity/connect/token", reqBody, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"browser"},
	}
	reqBody := strings.NewReader(data.Encode())
	var result TokenResponse
	err := c.do(ctx, "POST", "/identity/connect/token", reqBody, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) LoginWithTwoFactor(ctx context.Context, email, passwordHash, provider, token, deviceID string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":         {"password"},
		"username":           {email},
		"password":           {passwordHash},
		"scope":              {"api offline_access"},
		"client_id":          {"browser"},
		"deviceType":         {"14"},
		"deviceName":         {"bw-secrets"},
		"TwoFactorProvider":  {provider},
		"TwoFactorToken":     {token},
		"TwoFactorRemember":  {"1"},
	}
	if deviceID != "" {
		data.Set("deviceIdentifier", deviceID)
	}

	reqBody := strings.NewReader(data.Encode())
	var result TokenResponse
	err := c.do(ctx, "POST", "/identity/connect/token", reqBody, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
