package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDetectTwoFactor(t *testing.T) {
	tfe := detectTwoFactor([]byte(`{"TwoFactorProviders":["0"],"error":"invalid_grant","error_description":"Two factor required."}`))
	if tfe == nil {
		t.Fatal("expected TwoFactorError")
	}
	if len(tfe.Providers) != 1 || tfe.Providers[0] != "0" {
		t.Errorf("providers = %v, want [0]", tfe.Providers)
	}
}

func TestDetectTwoFactorNil(t *testing.T) {
	if tfe := detectTwoFactor([]byte(`{"error":"invalid_grant","error_description":"Invalid credentials."}`)); tfe != nil {
		t.Errorf("expected nil, got %v", tfe)
	}
	if tfe := detectTwoFactor([]byte(`{"TwoFactorProviders":[]}`)); tfe != nil {
		t.Errorf("expected nil for empty providers, got %v", tfe)
	}
}

func TestLoginReturnsTwoFactorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts/prelogin" {
			json.NewEncoder(w).Encode(PreloginResponse{Kdf: 0, KdfIterations: 1000})
			return
		}
		w.WriteHeader(400)
		w.Write([]byte(`{"TwoFactorProviders":["0"],"error":"invalid_grant","error_description":"Two factor required."}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	_, err := client.Login(t.Context(), "test@example.com", "hash", "device-id")
	if err == nil {
		t.Fatal("expected error")
	}
	tfe, ok := errors.AsType[*TwoFactorError](err)
	if !ok {
		t.Fatalf("expected TwoFactorError, got %T: %v", err, err)
	}
	if tfe.Providers[0] != "0" {
		t.Errorf("provider = %s, want 0", tfe.Providers[0])
	}
}

func TestLoginWithTwoFactor(t *testing.T) {
	var receivedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedForm = r.Form
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			Key:          "encrypted-key",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	resp, err := client.LoginWithTwoFactor(t.Context(), "test@example.com", "hash", "0", "123456", "device-id")
	if err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken != "access-token" {
		t.Errorf("AccessToken = %s, want access-token", resp.AccessToken)
	}
	if receivedForm.Get("TwoFactorProvider") != "0" {
		t.Errorf("TwoFactorProvider = %s, want 0", receivedForm.Get("TwoFactorProvider"))
	}
	if receivedForm.Get("TwoFactorToken") != "123456" {
		t.Errorf("TwoFactorToken = %s, want 123456", receivedForm.Get("TwoFactorToken"))
	}
	if receivedForm.Get("TwoFactorRemember") != "1" {
		t.Errorf("TwoFactorRemember = %s, want 1", receivedForm.Get("TwoFactorRemember"))
	}
}

func TestHTTP400NotTwoFactor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_credentials"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	_, err := client.Prelogin(t.Context(), "test@example.com")
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := errors.AsType[*TwoFactorError](err); ok {
		t.Error("should not be a TwoFactorError for non-2FA 400")
	}
}

func TestRequestEncodings(t *testing.T) {
	for _, kind := range []string{"json", "form", "sync"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Device-Type") != "14" {
					t.Error("missing common request headers")
				}
				switch kind {
				case "json":
					if r.Method != "POST" || r.URL.Path != "/api/accounts/prelogin" || r.Header.Get("Content-Type") != "application/json" {
						t.Error("incorrect JSON request metadata")
					}
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["email"] != "test@example.com" {
						t.Errorf("incorrect JSON body: %v, %v", body, err)
					}
				case "form":
					if r.Method != "POST" || r.URL.Path != "/identity/connect/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
						t.Error("incorrect form request metadata")
					}
					if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "refresh" {
						t.Errorf("incorrect form body: %v", err)
					}
				case "sync":
					if r.Method != "GET" || r.URL.Path != "/api/sync" || r.Header.Get("Content-Type") != "" {
						t.Error("incorrect sync request metadata")
					}
				}
				json.NewEncoder(w).Encode(map[string]string{})
			}))
			defer server.Close()
			client := NewClient(server.URL)
			client.SetAccessToken("test-token")
			var err error
			switch kind {
			case "json":
				_, err = client.Prelogin(t.Context(), "test@example.com")
			case "form":
				_, err = client.RefreshToken(t.Context(), "refresh")
			case "sync":
				_, err = client.Sync(t.Context())
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
