package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	serverURL   string
	accessToken string
	http        *http.Client
}

func NewClient(serverURL string) *Client {
	return &Client{
		serverURL: serverURL,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) SetAccessToken(token string) {
	c.accessToken = token
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body io.Reader, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.serverURL+path, body)
	if err != nil {
		return err
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	req.Header.Set("Device-Type", "14")

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if tfe := detectTwoFactor(bodyBytes); tfe != nil {
			return tfe
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if result != nil {
		return json.Unmarshal(bodyBytes, result)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, body any, result any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	return c.do(ctx, "POST", path, "application/json", &buf, result)
}

func detectTwoFactor(body []byte) *TwoFactorError {
	var tfe TwoFactorError
	if json.Unmarshal(body, &tfe) == nil && len(tfe.Providers) > 0 {
		return &tfe
	}
	return nil
}
