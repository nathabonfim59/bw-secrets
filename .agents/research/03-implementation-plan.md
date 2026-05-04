# bw-secrets Implementation Plan

## 0. Project Identity

```
module: github.com/nathanael/bw-secrets  (adjust to actual remote path)
min Go:  1.22
license: MIT
```

---

## 1. Project Scaffold & Directory Layout

```
bw-secrets/
├── cmd/
│   └── bw-secrets/
│       └── main.go                  # Entry point, wires everything
├── internal/
│   ├── api/
│   │   ├── client.go                # HTTP client, request helpers, token refresh
│   │   ├── auth.go                  # prelogin + connect/token calls
│   │   ├── sync.go                  # GET /api/sync → full vault data
│   │   ├── items.go                 # GET /api/ciphers/{id}, list ciphers
│   │   └── models.go               # Request/response structs (PreloginResponse, TokenResponse, SyncData, Cipher, etc.)
│   ├── crypto/
│   │   ├── kdf.go                   # PBKDF2-SHA256 & Argon2id key derivation
│   │   ├── encstring.go            # EncString parser & decrypter (types 0, 2, 7)
│   │   └── encstring_test.go
│   ├── keyring/
│   │   ├── store.go                 # Set/Get/Delete for each credential field
│   │   └── store_test.go
│   ├── vault/
│   │   ├── vault.go                 # In-memory representation of synced vault (name→item lookup)
│   │   ├── resolver.go             # Parse bw:// URIs, look up items, decrypt & return field value
│   │   └── resolver_test.go
│   └── cli/
│       ├── root.go                  # Root command (cobra), --server/-s flag
│       ├── login.go                 # `bw-secrets login` command
│       ├── unlock.go                # `bw-secrets unlock` command
│       ├── lock.go                  # `bw-secrets lock` command
│       ├── logout.go                # `bw-secrets logout` command
│       ├── status.go                # `bw-secrets status` command
│       ├── get.go                   # `bw-secrets get <uri>` command (— `op read`)
│       ├── list.go                  # `bw-secrets list <vault>` command
│       ├── run.go                   # `bw-secrets run` command (— `op run`)
│       ├── inject.go                # `bw-secrets inject` command (— `op inject`)
│       ├── envfile.go               # .env file parser (KEY=VALUE, comments, quoting)
│       └── helpers.go               # Shared UI helpers (promptPassword, confirm)
├── go.mod
├── go.sum
├── README.md
└── .github/
    └── workflows/
        └── ci.yml                   # lint, test, build
```

**Rationale:**
- `cmd/` contains only the thin main. All logic in `internal/` so nothing leaks into the public API surface.
- `internal/api/` owns HTTP communication with the Bitwarden/Vaultwarden server.
- `internal/crypto/` owns all key derivation (KDF) and EncString parsing/decryption.
- `internal/keyring/` owns OS keyring persistence. Uses a single well-known key `"bw-secrets"` and stores JSON-blob of auth tokens.
- `internal/vault/` owns the logical vault: synced cipher cache plus URI resolution.
- `internal/cli/` owns cobra command definitions. Each file is one subcommand.

---

## 2. Dependencies

| Purpose | Library | Why |
|---|---|---|
| CLI framework | `github.com/spf13/cobra` v1.9+ | Most widely used Go CLI framework, subcommand tree, auto-completion |
| Keyring | `github.com/zalando/go-keyring` | Pure Go, zero cgo, works on Linux (D-Bus SecretService), macOS (Keychain via `/usr/bin/security`), Windows (Credential Manager) |
| PBKDF2 / HMAC / AES / Argon2 | `golang.org/x/crypto` | Standard extended Go crypto library. Has `pbkdf2`, `argon2`, `sha256`, `hmac`; AES-CBC via `crypto/aes` + `crypto/cipher` (stdlib) |
| HTTP | `net/http` (stdlib) | No external HTTP client needed. Straight JSON REST calls. |
| Testing | `github.com/stretchr/testify` | `assert` + `require` helpers. Already a transitive dep of go-keyring. |
| JSON | `encoding/json` (stdlib) | Standard; no schema complexity warrants a third-party library. |

**NOT used (and why):**
- `github.com/bitwarden/sdk-go` / `sdk-secrets` — still immature, unnecessary for reading-only use case.
- `github.com/zalando/go-keyring` vs `github.com/99designs/keyring` — zalando's is simpler (3 methods: Set/Get/Delete), no config, single-service model fits our use case perfectly.

---

## 3. Module Breakdown

### 3.1 `internal/api/models.go` — Request/Response Types

```go
package api

// POST /api/accounts/prelogin request
type PreloginRequest struct {
    Email string `json:"email"`
}

// POST /api/accounts/prelogin response
type PreloginResponse struct {
    Kdf            int `json:"Kdf"`            // 0=PBKDF2, 1=Argon2id
    KdfIterations  int `json:"KdfIterations"`  // PBKDF2 iterations
    KdfMemory      int `json:"KdfMemory"`      // Argon2 memory (KB)
    KdfParallelism int `json:"KdfParallelism"` // Argon2 parallelism
}

// Token request (form-urlencoded)
type TokenRequest struct {
    GrantType    string // "password" or "refresh_token"
    Username     string // email
    Password     string // master password hash (base64)
    RefreshToken string
    Scope        string // "api offline_access"
    ClientID     string // "browser"
    DeviceType   int    // 14 (CLI) or other device types
    DeviceName   string // "bw-secrets"
}

// Token response
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    ExpiresIn    int    `json:"expires_in"`
    TokenType    string `json:"token_type"`
    RefreshToken string `json:"refresh_token"`
    Key          string `json:"Key"`          // Encrypted symmetric key (EncString)
    PrivateKey   string `json:"PrivateKey"`   // Encrypted private key (EncString)
    Kdf          int    `json:"Kdf"`
    KdfIterations int   `json:"KdfIterations"`
}

// Sync response — full vault state
type SyncResponse struct {
    Profile   Profile    `json:"Profile"`
    Folders   []Folder   `json:"Folders"`
    Ciphers   []Cipher   `json:"Ciphers"`
    Sends     []Send     `json:"Sends"`
    // Collections, Policies, etc. for org
}

type Profile struct {
    ID           string `json:"Id"`
    Name         string `json:"Name"`
    Email        string `json:"Email"`
    Key          string `json:"Key"`          // encrypted symmetric key (redundant with token)
    PrivateKey   string `json:"PrivateKey"`
    SecurityStamp string `json:"SecurityStamp"`
}

type Cipher struct {
    ID               string        `json:"Id"`
    OrganizationID   *string       `json:"OrganizationId"`
    CollectionIDs    []string      `json:"CollectionIds"`
    FolderID         *string       `json:"FolderId"`
    Type             int           `json:"Type"`     // 1=Login, 2=SecureNote, 3=Card, 4=Identity
    Name             string        `json:"Name"`     // ENCRYPTED (EncString)
    Notes            *string       `json:"Notes"`    // ENCRYPTED (EncString)
    Favorite         bool          `json:"Favorite"`
    Fields           []Field       `json:"Fields"`   // Custom fields
    Login            *Login        `json:"Login"`
    SecureNote       *SecureNote   `json:"SecureNote"`
    Card             *Card         `json:"Card"`
    Identity         *Identity     `json:"Identity"`
    Reprompt         int           `json:"Reprompt"`
    DeletedDate      *string       `json:"DeletedDate"`
}

type Field struct {
    Name  string `json:"Name"`   // ENCRYPTED
    Value string `json:"Value"`  // ENCRYPTED
    Type  int    `json:"Type"`   // 0=text, 1=hidden, 2=boolean, 3=linked
}

type Login struct {
    URIs     []LoginURI `json:"Uris"`
    Username string     `json:"Username"` // ENCRYPTED
    Password string     `json:"Password"` // ENCRYPTED
    TOTP     *string    `json:"Totp"`     // ENCRYPTED
}

type LoginURI struct {
    Match *int   `json:"Match"`
    URI   string `json:"Uri"` // ENCRYPTED
}

type SecureNote struct { Type int `json:"Type"` }
type Card struct {
    CardholderName string `json:"CardholderName"` // ENCRYPTED
    Brand          string `json:"Brand"`          // ENCRYPTED
    Number         string `json:"Number"`         // ENCRYPTED
    ExpMonth       string `json:"ExpMonth"`       // ENCRYPTED
    ExpYear        string `json:"ExpYear"`        // ENCRYPTED
    Code           string `json:"Code"`           // ENCRYPTED
}
type Identity struct {
    Title          string `json:"Title"`          // ENCRYPTED
    FirstName      string `json:"FirstName"`      // ENCRYPTED
    LastName       string `json:"LastName"`       // ENCRYPTED
    // ... remaining ~20 fields, all encrypted
}

type Folder struct {
    ID     string `json:"Id"`
    Name   string `json:"Name"`  // ENCRYPTED
    Object string `json:"Object"`
}
type Send struct { /* ... not needed for MVP */ }
```

### 3.2 `internal/api/client.go` — HTTP Client

Key type:

```go
type Client struct {
    serverURL   string       // "https://vault.bitwarden.com" (no trailing slash)
    accessToken string
    http        *http.Client // with 30s timeout
}

func NewClient(serverURL string) *Client
func (c *Client) SetAccessToken(token string)
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, result interface{}) error
```

`do()` handles:
- Setting `Authorization: Bearer <token>` header
- Setting `Content-Type: application/json` or `application/x-www-form-urlencoded`
- Setting `Device-Type: 14` header (browser extension sets device type; 14 = CLI)
- Error response deserialization
- Returning typed errors for 401 (needs refresh), 404, 429, 5xx

### 3.3 `internal/api/auth.go` — Auth Calls

```go
func (c *Client) Prelogin(ctx context.Context, email string) (*PreloginResponse, error)
func (c *Client) Login(ctx context.Context, email, passwordHash string) (*TokenResponse, error)
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
```

`Login` makes a `POST /identity/connect/token` with `application/x-www-form-urlencoded` body:
```
grant_type=password&username={email}&password={hash}&scope=api+offline_access
&client_id=browser&deviceIdentifier={uuid}&deviceName=bw-secrets&deviceType=14
```

`RefreshToken` uses `grant_type=refresh_token&refresh_token={token}&client_id=browser`.

### 3.4 `internal/api/sync.go` — Sync

```go
func (c *Client) Sync(ctx context.Context) (*SyncResponse, error)
```

`GET /api/sync` — fetches all ciphers, folders, profile, etc. in one call.

### 3.5 `internal/api/items.go` — Item operations

```go
func (c *Client) GetCipher(ctx context.Context, id string) (*Cipher, error)
func (c *Client) ListCiphers(ctx context.Context) ([]Cipher, error)
```

`GET /api/ciphers/{id}` and `GET /api/ciphers`.

---

### 3.6 `internal/crypto/kdf.go` — Key Derivation

```go
package crypto

import "golang.org/x/crypto/argon2"
import "golang.org/x/crypto/pbkdf2"

// MakeMasterKey derives the 32-byte master key from email+password using the KDF parameters.
// salt = email.trim().toLowerCase()
// Kdf=0 → PBKDF2-SHA256(password, salt, iterations, 32)
// Kdf=1 → Argon2id(password, salt, memoryKB, parallelism, 32)
func MakeMasterKey(password string, email string, prelogin *api.PreloginResponse) ([]byte, error)

// MakePasswordHash derives the auth hash to send to /connect/token.
// hash = PBKDF2-SHA256(masterKey, password, 1, 32)
// Returns base64-encoded string.
func MakePasswordHash(masterKey []byte, password string) string

// StretchKey converts the 32-byte master key into a 64-byte symmetric crypto key
// by HKDF-Expand (Bitwarden clients use HKDF with label "enc" and "mac").
// This is used when we decrypt the "Key" field from the token response.
// Actually: the Key field decrypts directly to the 64-byte symmetric key.
// No stretching needed on the key used for AES decryption of the Key field.
// The master key IS the AES key for decrypting the Key field.
func StretchMasterKey(masterKey []byte) *SymmetricKey
```

**Note on Bitwarden's actual derivation:**

The master key (32 bytes from KDF) is used to:
1. Derive password hash: `PBKDF2-SHA256(masterKey, password, 1, 32)` — base64 encoded for auth
2. Decrypt the `Key` field from token response using AES-256-CBC with the master key directly

The decrypted `Key` field yields the 64-byte "Symmetric Key":
- `key[0:32]` = AES encryption key (for decrypting cipher fields)
- `key[32:64]` = HMAC authentication key (for verifying cipher field MACs)

**CRITICAL:** In the `Key` field itself, the encrypted value is the 64-byte symmetric key. The IV is in the EncString prefix. The AES decryption key is the 32-byte master key. So:
```
encString = tokenResponse.Key   // "2.iv|encryptedKey|mac"
parts = parseEncString(encString)
symmetricKey = AES-CBC-Decrypt(parts.ciphertext, masterKey[0:32], parts.iv)
// symmetricKey is now 64 bytes: [32 bytes enc key][32 bytes mac key]
```

### 3.7 `internal/crypto/encstring.go` — EncString Parser & Decrypter

```go
package crypto

// SymmetricKey is the decrypted 64-byte vault symmetric key.
type SymmetricKey struct {
    EncryptionKey     [32]byte
    MACKey            [32]byte
}

// NewSymmetricKey splits a 64-byte key into enc/mac halves.
func NewSymmetricKey(raw []byte) (*SymmetricKey, error)

// EncString represents a parsed encrypted string in Bitwarden format.
type EncString struct {
    Type       int    // 0, 2, 3, 4, 5, 6, 7
    IV         []byte // 16 bytes for AES-CBC
    CipherText []byte
    MAC        []byte // 32 bytes for type 2
    Data       []byte // for types 3, 4, 7 without separate IV/MAC
}

// ParseEncString parses a string like "2.iv|data|mac" into its components.
func ParseEncString(s string) (*EncString, error)

// Decrypt decrypts the EncString using the provided symmetric key.
// For type 2: verifies HMAC-SHA256(IV || ciphertext) == MAC first, then AES-CBC.
// For type 0: returns error (decryption of unauthenticated type 0 is disabled).
// For type 7: uses XChaCha20-Poly1305 (future/MVP-skip).
func (e *EncString) Decrypt(key *SymmetricKey) (string, error)

// DecryptBytes same as Decrypt but returns raw bytes (for binary data).
func (e *EncString) DecryptBytes(key *SymmetricKey) ([]byte, error)
```

**EncString format examples:**
- `"2.kMnFbPjQ..."`  → Type=2, then split by `|` → `[IV, ciphertext, MAC]`, each base64-decoded
- `"0.kMnFbPjQ..."`  → Type=0 (legacy, unauthenticated) — reject
- `"3.kMnFbPjQ..."`  → Type=3 (RSA asymmetric)
- `"7.kMnFbPjQ..."`  → Type=7 (XChaCha20-Poly1305, COSE encoded)

**Decryption algorithm for type 2:**
```
parts = encString[2:]  // strip "2."
fields = split(parts, "|") // ["iv_b64", "ct_b64", "mac_b64"]
iv = base64Decode(fields[0])    // 16 bytes
ct = base64Decode(fields[1])    // variable
mac = base64Decode(fields[2])   // 32 bytes

// 1. Verify MAC
expectedMAC = HMAC-SHA256(key.MACKey, iv || ct)
if !hmac.Equal(expectedMAC, mac) { return error("MAC verification failed") }

// 2. Decrypt
block, _ := aes.NewCipher(key.EncryptionKey[:])
mode := cipher.NewCBCDecrypter(block, iv)
plaintext := make([]byte, len(ct))
mode.CryptBlocks(plaintext, ct)

// 3. Remove PKCS#7 padding
plaintext = unpad(plaintext)

// 4. Return as string
return string(plaintext), nil
```

---

### 3.8 `internal/keyring/store.go` — OS Keyring Persistence

```go
package keyring

import "github.com/zalando/go-keyring"

const serviceName = "bw-secrets"

// Credentials holds everything we persist in the keyring.
type Credentials struct {
    ServerURL    string `json:"server_url"`
    Email        string `json:"email"`
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    EncKey       string `json:"enc_key,omitempty"`  // base64(raw 64-byte symmetric key)
}

// Save stores credentials in the OS keyring under service "bw-secrets" and user "default".
func Save(creds *Credentials) error

// Load retrieves credentials from the OS keyring.
func Load() (*Credentials, error)

// Delete removes credentials from the OS keyring.
func Delete() error
```

**Implementation detail:**
- `go-keyring` takes `(service, key, value)` triples.
- We store the entire `Credentials` struct as a single JSON blob under key `"default"`.
- `keyring.Set("bw-secrets", "default", jsonBlob)`
- `keyring.Get("bw-secrets", "default")` returns the JSON string.
- `keyring.Delete("bw-secrets", "default")` removes it.
- On error (keyring not found), return a sentinel `ErrNotLoggedIn`.

**What is NEVER stored:**
- Master password
- The raw 32-byte master key
- Decrypted vault items

**What IS stored:**
- Access token (JWT, ~1 hour TTL)
- Refresh token (long-lived, ~30 days)
- Server URL + email (for display and re-auth)
- Encrypted symmetric key — OR — the decrypted 64-byte symmetric encryption key (base64-encoded)

**Storing the decrypted symmetric key** is the pragmatic choice:
- Avoids re-deriving master key + re-decrypting Key field on every command
- Protected by OS-native encryption (the entire JSON blob is stored in the keyring)
- On `lock`, the credentials are deleted entirely
- On `unlock`, user re-enters master password, we re-derive, re-decrypt Key field, re-store

Storing the encrypted symmetric key (`Key` field as-is from server) is also possible but requires storing the master key or re-entering the password every time. The trade-off favors storing the already-decrypted key inside the OS-protected keyring.

---

### 3.9 `internal/vault/vault.go` — In-Memory Vault Cache

```go
package vault

// Vault holds all synced cipher data plus derived indices.
type Vault struct {
    ciphers       []api.Cipher
    folders       map[string]api.Folder // by folder ID
    byName        map[string][]api.Cipher // item name → ciphers (names aren't unique)
    byID          map[string]api.Cipher   // cipher ID → cipher
    symKey        *crypto.SymmetricKey    // decrypted symmetric key for field decryption
    serverURL     string
    email         string
}

// New creates a Vault from sync response data.
func New(syncResp *api.SyncResponse, symKey *crypto.SymmetricKey, serverURL, email string) *Vault
```

`New` builds the `byName` index:
- For each cipher, decrypt `Name` field using `symKey`.
- Lower-case and match against lookup keys. Store duplicates as slice (multiple entries can have same name).

Folders are also decrypted and indexed.

### 3.10 `internal/vault/resolver.go` — URI Resolution

```go
package vault

// ParseURI parses a bw:// URI into its components.
// Format: bw://VaultName/ItemName/FieldName
//   - VaultName: either a folder name, "No Folder", or "*" (wildcard)
//   - ItemName:  the name of the cipher item
//   - FieldName: the field to extract, e.g. "password", "username", "notes",
//                custom field name, or identity/card subfield
type SecretURI struct {
    VaultName string // folder name, "No Folder", or empty for all
    ItemName  string // cipher name
    FieldName string // field path (e.g. "password", "notes", "fields.myfield")
}

func ParseURI(uri string) (*SecretURI, error)

// Resolve looks up a SecretURI in the vault and returns the decrypted field value.
func (v *Vault) Resolve(uri *SecretURI) (string, error)

// FindItem finds ciphers whose decrypted name matches (case-insensitive).
// If multiple match, returns all matches; if VaultName specified, filters by folder.
func (v *Vault) FindItem(name string, vaultName string) ([]api.Cipher, error)
```

**Resolution algorithm for `bw://Personal/Google/password`:**

1. Parse URI → `{VaultName: "Personal", ItemName: "Google", FieldName: "password"}`
2. Find matching folder by decrypted name "Personal" → folder ID
3. Filter ciphers by `FolderID == folderID` (or `FolderID == nil` for "No Folder")
4. Among filtered ciphers, find one whose decrypted `Name` == "Google"
5. If cipher `Type == 1` (Login):
   - Field "username" → decrypt `cipher.Login.Username`
   - Field "password" → decrypt `cipher.Login.Password`
   - Field "totp" → decrypt `cipher.Login.TOTP`
   - Field "notes" → decrypt `cipher.Notes`
   - Field "name" → return decrypted name (identity)
   - Any other name → search `cipher.Fields[i].Name` (decrypt each, compare)
6. If cipher `Type == 2` (SecureNote):
   - Field "notes" → decrypt `cipher.Notes`
7. If cipher `Type == 3` (Card):
   - Field "number", "cardholder", "expMonth", etc.
8. If cipher `Type == 4` (Identity):
   - Field "firstName", "lastName", "email", etc.
9. Decrypt the target field using `v.symKey`
10. Return plaintext string

**Error cases:**
- `ErrItemNotFound` — no cipher matches the name
- `ErrMultipleItems` — multiple ciphers match (return list of matching names)
- `ErrFieldNotFound` — field doesn't exist on the matched item
- `ErrDecryptFailed` — MAC verification failed (wrong key? tampered data?)
- `ErrInvalidURI` — malformed URI

---

### 3.11 `internal/cli/` — CLI Commands

All commands use `cobra.Command`. Root command sets `--server` / `-s` persisted flag.

#### `bw-secrets login`
```
Flow:
1. Prompt for server URL:  "https://vault.bitwarden.com" (or user's Vaultwarden)
2. Prompt for email:       "user@example.com"
3. Prompt for master password: hidden (golang.org/x/term ReadPassword)
4. POST /api/accounts/prelogin → KDF params
5. crypto.MakeMasterKey(password, email, prelogin) → master key
6. crypto.MakePasswordHash(masterKey, password) → password hash
7. POST /identity/connect/token → access_token, refresh_token, Key
8. Decrypt Key field with master key → symmetric key (64 bytes)
9. keyring.Save(serverURL, email, access_token, refresh_token, base64(symmetricKey))
10. Print "Logged in as <email>"
```

#### `bw-secrets unlock`
```
If keyring has refresh_token but access_token is expired:
1. Load credentials from keyring
2. POST /identity/connect/token (refresh_token grant)
3. If refresh succeeds → store new access_token, refresh_token
4. If refresh fails → prompt for master password (same as login step 3-9)
5. Print "Vault unlocked"
```

#### `bw-secrets lock`
```
1. keyring.Delete("bw-secrets", "default")
2. Print "Vault locked"
```

#### `bw-secrets logout`
```
Same as lock — clears keyring. (Future: might add server-side token revocation)
```

#### `bw-secrets status`
```
1. Try keyring.Load()
2. If not found → "Not logged in"
3. If found → decode JWT access_token (no verification needed, just parse claims)
4. Check exp claim → if expired, "Expired — run 'bw-secrets unlock'"
5. If valid → "Logged in as <email> on <server_url>. Token expires in <duration>"
```

#### `bw-secrets get bw://Vault/Item/field`
```
1. Load creds from keyring
2. Check access token expiry; if expired, refresh
3. Create api.Client, set access token
4. Call client.Sync() → SyncResponse
5. Create vault.New(syncResp, symmetricKey, serverURL, email)
6. Call vault.Resolve(parsedURI)
7. If --reveal: print resolved value to stdout
8. If no --reveal: print "resolved: <vault>/<item>/<field> (use --reveal to output)" to stderr
9. Exit 0 on success, 1 on error
```

#### `bw-secrets list [vault]`
```
1. Load creds, refresh if needed
2. Sync vault
3. If vault name specified, filter by folder; if omitted, show all
4. For each cipher in scope: decrypt name, print "  <name>"
5. Option --type to filter by item type (login, note, card, identity)
6. Option --json to output structured data
```

#### `bw-secrets run` (like `op run`)

```
Usage:  bw-secrets run [flags] -- <command> [args...]
Flags:  --env-file, -e    Path to .env file with bw:// refs (repeatable)
        --no-masking      Disable secret masking in subprocess output

Flow:
1. Load creds from keyring, refresh token if expired
2. Collect env vars: copy current env, look for any var whose VALUE starts with "bw://"
3. For each --env-file: parse KEY=VALUE (with .env syntax: comments, quoting, $VAR expansion)
4. Sync vault once, decrypt ciphers locally
5. For each env var value that is a bw:// URI: resolve → actual secret value
6. Build env for subprocess: replace all uri-valued vars with resolved secrets
7. Fork subprocess with resolved env vars injected
8. Pipe subprocess stdout/stderr through masking filter (replace known secrets with "***")
9. Exit with subprocess exit code

Secret masking:
- Track all resolved secret values
- On each line of subprocess stdout/stderr, replace any occurrence with "***"
- Disable with --no-masking
```

#### `bw-secrets inject` (like `op inject`)

```
Usage:  bw-secrets inject [flags] [file]
Flags:  --in-file, -i     Input file (default: stdin)
        --out-file, -o    Output file (default: stdout)

If positional [file] is given, it's the same as --in-file.

Flow:
1. Load creds from keyring, refresh token if expired
2. Read full input (stdin or --in-file) into memory
3. Before resolution: expand env var template variables ($VAR or ${VAR}) in the text
   (This lets you write "bw://$APP_ENV/MySQL/password" and set APP_ENV=prod at runtime)
4. Scan for bw:// URIs (regex: bw://[^\s"'`]+)
5. Sync vault, decrypt ciphers locally
6. For each bw:// URI found: resolve → decrypted value, replace in the text
7. Write output (stdout or --out-file)

Template variable usage:
  config.yml.tpl:
    database:
      user: bw://$APP_ENV/MySQL/username
      password: bw://$APP_ENV/MySQL/password

  APP_ENV=prod bw-secrets inject -i config.yml.tpl
  → resolves to bw://prod/MySQL/username → actual value
```

---

## 4. Auth Flow (Detailed)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           LOGIN FLOW                                     │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Prelogin                                                             │
│     POST /api/accounts/prelogin  {"email": "user@example.com"}           │
│     → {Kdf:0, KdfIterations:100000}   // or Argon2id params              │
│                                                                          │
│  2. Derive Master Key (32 bytes)                                         │
│     salt = "user@example.com"                                            │
│     IF Kdf=0: masterKey = PBKDF2-SHA256(password, salt, iter, 32)       │
│     IF Kdf=1: masterKey = Argon2id(password, salt, mem, par, 32)        │
│                                                                          │
│  3. Derive Password Hash (for auth)                                      │
│     passwordHash = PBKDF2-SHA256(masterKey, password, 1, 32)            │
│     passwordHashB64 = base64(passwordHash)                               │
│                                                                          │
│  4. Get Tokens                                                            │
│     POST /identity/connect/token (form-urlencoded)                       │
│       grant_type=password                                                │
│       username=user@example.com                                          │
│       password=passwordHashB64                                           │
│       scope=api offline_access                                           │
│       client_id=browser                                                  │
│       deviceType=14                                                      │
│       deviceIdentifier=<random-uuid>                                     │
│       deviceName=bw-secrets                                              │
│     → {access_token, refresh_token, Key, PrivateKey, ...}                │
│                                                                          │
│  5. Decrypt Symmetric Key                                                │
│     encString = tokenResponse.Key   // "2.iv|enc_key|mac"               │
│     symKeyRaw = AES-CBC-Decrypt(encString.ciphertext, masterKey,         │
│                                  encString.iv)                           │
│     // symKeyRaw is 64 bytes: [32 enc key][32 mac key]                   │
│                                                                          │
│  6. Store in Keyring                                                     │
│     keyring.Save({                                                       │
│       server_url: "https://vault.example.com",                           │
│       email: "user@example.com",                                         │
│       access_token: "eyJ...",                                            │
│       refresh_token: "rT...",                                            │
│       enc_key: base64(symKeyRaw)                                         │
│     })                                                                   │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                         UNLOCK / REFRESH FLOW                            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Load from keyring                                                    │
│     creds = keyring.Load()                                               │
│                                                                          │
│  2. Try refresh                                                          │
│     POST /identity/connect/token                                         │
│       grant_type=refresh_token                                           │
│       refresh_token=creds.RefreshToken                                   │
│       client_id=browser                                                  │
│     → IF 200: save new tokens, done                                     │
│     → IF 401/400: refresh expired → need full re-auth                   │
│                                                                          │
│  3. Full re-auth (refresh failed)                                        │
│     Prompt for master password                                           │
│     Repeat login flow steps 1-6                                          │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Encryption Flow (decrypting cipher fields)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    FIELD DECRYPTION FLOW                                 │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Given:  encString = "2.YnVubmllcw==.S3BoQ1dZbHlOR2x6ZEc5dWNtRnVaQT09   │
│                        .UGo5bmRIVnVkV1YwTlZSdVpHTnllWEIwYVhScGIyNA=="    │
│  Key:    symKey = {encryptionKey[32], macKey[32]}                        │
│                                                                          │
│  1. Parse EncString                                                      │
│     type = parse first char before "." → 2                               │
│     rest = everything after "2."                                         │
│     parts = split(rest, "|") → 3 parts for type 2                       │
│     iv = base64Decode(parts[0])    // 16 bytes                           │
│     ct = base64Decode(parts[1])    // encrypted payload                  │
│     mac = base64Decode(parts[2])   // 32 bytes HMAC                      │
│                                                                          │
│  2. Verify HMAC                                                          │
│     expected = HMAC-SHA256(symKey.macKey, iv || ct)                      │
│     if !equal(expected, mac) → ERROR "MAC verification failed"           │
│                                                                          │
│  3. Decrypt                                                              │
│     block = AES.NewCipher(symKey.encryptionKey)                          │
│     mode = CBCDecrypter(block, iv)                                       │
│     plaintext = mode.CryptBlocks(ct)                                     │
│     plaintext = PKCS7Unpad(plaintext)                                    │
│                                                                          │
│  4. Return                                                               │
│     string(plaintext) → "my-secret-value"                                │
│                                                                          │
│  Note: Type 0 (AesCbc256_B64) has format "0.iv|data" (2 parts, no MAC).  │
│        Decryption of type 0 MUST be rejected (unauthenticated).          │
│        Type 7 (CoseEncrypt0) is XChaCha20-Poly1305 in COSE envelope.     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**PKCS#7 unpad:**
```go
func pkcs7Unpad(data []byte) ([]byte, error) {
    if len(data) == 0 { return nil, errors.New("empty data") }
    padLen := int(data[len(data)-1])
    if padLen > len(data) || padLen > aes.BlockSize || padLen == 0 {
        return nil, errors.New("invalid padding")
    }
    for i := len(data) - padLen; i < len(data); i++ {
        if data[i] != byte(padLen) { return nil, errors.New("invalid padding") }
    }
    return data[:len(data)-padLen], nil
}
```

**Why CBC + HMAC (Encrypt-then-MAC):**
Bitwarden uses Encrypt-then-MAC: compute HMAC over (IV || ciphertext), then compare before decrypting. This prevents padding oracle attacks and ciphertext tampering. Our decrypter MUST verify MAC before calling AES decrypt.

---

## 6. Keyring Integration

**Library:** `github.com/zalando/go-keyring`

**Single-service model:** All credentials stored under service name `"bw-secrets"` with key `"default"`.

```go
import "github.com/zalando/go-keyring"

func Save(creds *Credentials) error {
    data, _ := json.Marshal(creds)
    return keyring.Set("bw-secrets", "default", string(data))
}

func Load() (*Credentials, error) {
    data, err := keyring.Get("bw-secrets", "default")
    if errors.Is(err, keyring.ErrNotFound) {
        return nil, ErrNotLoggedIn
    }
    if err != nil {
        return nil, fmt.Errorf("keyring read error: %w", err)
    }
    var creds Credentials
    json.Unmarshal([]byte(data), &creds)
    return &creds, nil
}

func Delete() error {
    err := keyring.Delete("bw-secrets", "default")
    if errors.Is(err, keyring.ErrNotFound) {
        return nil // already clean
    }
    return err
}
```

**Platform support:**
| OS | Backend | Library calls |
|---|---|---|
| macOS | Keychain (`/usr/bin/security`) | `keyring_darwin.go` — shell out to `security add-generic-password`, `find-generic-password`, `delete-generic-password` |
| Linux | SecretService (D-Bus, GNOME Keyring / KWallet) | `keyring_unix.go` — D-Bus calls via `github.com/godbus/dbus` |
| Windows | Credential Manager | `keyring_windows.go` — Win32 API via `syscall` or `golang.org/x/sys/windows` |

**Linux dependencies:** On headless Linux, the user needs a D-Bus session and a Secret Service provider (gnome-keyring or kwallet). The tool should document this. Alternatively, could add a file-based fallback with appropriate permissions warning.

**Thread safety:** `go-keyring` operations are safe to call from multiple goroutines (each call is independent). Our CLI is single-threaded so no issue.

---

## 7. CLI Design

### Root command (`bw-secrets`)
```
Flags:
  --server, -s   URL of Bitwarden/Vaultwarden server. Default: none (will use
                 stored value after login, or prompt during login)
  --help, -h     Show help
```

### Subcommands

| Command | Short | Description |
|---|---|---|
| `login` | | Authenticate and store tokens |
| `unlock` | | Re-authenticate if tokens expired |
| `lock` | | Clear stored tokens |
| `logout` | | Clear stored tokens (same as lock) |
| `status` | | Show login status |
| `get` | | Resolve `bw://` URI (— `op read`) |
| `list` | `ls` | List items in vault |
| `run` | | Resolve bw:// refs from env vars / --env-file, inject as env vars, run subprocess (— `op run`) |
| `inject` | | Replace bw:// refs in stdin/file, output resolved result (— `op inject`) |
| `version` | | Print version info |
| `completion` | | Generate shell completions |

### Command-specific flags

`bw-secrets get`
```
Usage:  bw-secrets get [--reveal] <uri>
Args:   uri = bw://VaultName/ItemName/FieldName
Flags:
  --reveal          Output the actual secret value to stdout (required for sensitive fields)
  --out-file, -o    Write resolved value to file instead of stdout
  --json            Output JSON with metadata (field name, item name, vault)

Security: By default, secrets are NOT printed. The command resolves the reference
and prints metadata to stderr. Use --reveal to actually output the value.
```

`bw-secrets list`
```
Usage:  bw-secrets list [vault-name]
Flags:
  --type    Filter by type: login, note, card, identity
  --json    Output as JSON array
```

`bw-secrets run`
```
Usage:  bw-secrets run [flags] -- <command> [args...]
Flags:
  --env-file, -e    Path to .env file (repeatable, like op run --env-file)
  --no-masking      Disable secret masking in subprocess output
```

`bw-secrets inject`
```
Usage:  bw-secrets inject [flags] [file]
Flags:
  --in-file, -i     Input file (default: stdin; positional arg also works)
  --out-file, -o    Output file (default: stdout)
```

### Error output conventions
- All errors go to stderr
- Successful `get` without `--reveal` prints metadata to stderr (never the secret)
- Successful `get --reveal` output goes to stdout (plain text, no prefix)
- Exit codes: 0 = success, 1 = error, 2 = not logged in

---

## 8. Secret Resolution (end-to-end)

```
Input:  bw://Personal/Google/password

1. URI Parser (vault.ParseURI)
   "bw://Personal/Google/password"
   → SecretURI{VaultName:"Personal", ItemName:"Google", FieldName:"password"}

2. Vault name resolution
   - Decrypt all folder names in vault.folders
   - Find folder where decrypted Name == "Personal"
   - If no folder matches: error "vault 'Personal' not found"
   - If "Personal" == "No Folder": filter ciphers with FolderID == nil

3. Item name resolution
   - Filter ciphers by FolderID matching step 2
   - Decrypt each cipher.Name
   - Find cipher where decrypted Name == "Google" (case-insensitive)
   - If 0 matches: error "item 'Google' not found in vault 'Personal'"
   - If >1 matches: error "multiple items match 'Google': [full list with vaults]"

4. Field extraction
   - cipher.Type == 1 (Login):
     switch fieldName {
       case "username": encField = cipher.Login.Username
       case "password": encField = cipher.Login.Password
       case "totp":     encField = cipher.Login.TOTP
       case "notes":    encField = cipher.Notes
       case "name":     return cipher.Name (already decrypted)
       default:         search cipher.Fields for matching Name
     }
   - cipher.Type == 2 (SecureNote):
     "notes" → cipher.Notes
   - cipher.Type == 3 (Card):
     "number" → cipher.Card.Number, "cardholder" → ..., etc.
   - cipher.Type == 4 (Identity):
     "firstName" → cipher.Identity.FirstName, etc.

5. Decryption
   - encString := encField
   - parsed := crypto.ParseEncString(encString)
   - value := parsed.Decrypt(symKey)

6. Output
    If --reveal: fmt.Println(value)
    Else: print "resolved: <vault>/<item>/<field> (use --reveal to output)" to stderr
```

**Wildcard support (future):**
- `bw://*/Google/password` — search all vaults
- `bw://Work/*` — list all items in Work vault
- `bw://*/Google/*` — show all fields for Google item

---

## 9. Error Handling

### Error types

```go
// internal/errors/errors.go

var (
    ErrNotLoggedIn   = errors.New("not logged in — run 'bw-secrets login'")
    ErrTokenExpired  = errors.New("session expired — run 'bw-secrets unlock'")
    ErrLocked        = errors.New("vault is locked — run 'bw-secrets unlock'")
)

type InvalidURIError struct { URI string; Reason string }
type VaultNotFoundError struct { VaultName string }
type ItemNotFoundError struct { ItemName string; VaultName string }
type MultipleItemsError struct { ItemName string; Matches []string }
type FieldNotFoundError struct { FieldName string; ItemName string; ItemType int }
type DecryptError struct { Field string; Reason string }
type APIError struct { StatusCode int; Message string }
```

### Error surfacing
- All errors printed to stderr with `fmt.Fprintf(os.Stderr, "error: %v\n", err)`
- API connection errors include the URL attempted
- Decryption errors include which field failed (but NEVER the ciphertext)
- 401 from API → auto-trigger token refresh; if refresh fails → `ErrTokenExpired`
- `os.Exit(1)` on any error; `os.Exit(0)` on success
- For `get`, if the value is empty string but field exists, output empty string (not error)

---

## 10. Testing Strategy

### Unit Tests

**`internal/crypto/encstring_test.go`:**
- Parse known-valid EncStrings (type 0, 2) → verify IV, ciphertext, MAC extraction
- Reject type 0 decryption
- Decrypt known plaintext/ciphertext pairs (generate with Bitwarden SDK or known test vector)
- Test PKCS#7 unpadding edge cases
- Test MAC verification failure

**`internal/crypto/kdf_test.go`:**
- Test PBKDF2 with known inputs/outputs (use Bitwarden's known test vectors or generate once)
- Test Argon2id similarly
- Test MakePasswordHash produces correct base64 output

**`internal/vault/resolver_test.go`:**
- Parse valid URIs: `bw://Vault/Item/field`, `bw://*/Item/password`
- Parse invalid URIs: missing scheme, too many segments, empty parts
- Test field matching against various cipher types (mock decrypted data)

**`internal/keyring/store_test.go`:**
- Test round-trip: Save then Load returns same data
- Test Delete removes data (Load returns ErrNotLoggedIn)
- Requires: test skips if keyring unavailable (CI environment)

### Integration Tests

**`internal/api/client_test.go`:**
- Spin up `httptest.Server` that mimics Vaultwarden API endpoints:
  - `/api/accounts/prelogin` → returns KDF params
  - `/identity/connect/token` → returns mock tokens + encrypted Key
  - `/api/sync` → returns mock ciphers with properly encrypted fields
  - `/api/ciphers/{id}` → returns single cipher
- Use known keys to encrypt test data → verify full auth→sync→decrypt flow
- Test token refresh flow (expired access token → 401 → refresh → retry)
- Test error responses (401, 404, 429, 500)

**Test data generation:**
- For encrypting test ciphers, write a small helper that runs the encryption in reverse
- Or capture real API responses and use as golden files

### Mock server approach

Rather than mocking at the interface level, use `httptest.NewServer` with handler functions:

```go
func setupMockServer(t *testing.T) (*httptest.Server, *api.Client) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/accounts/prelogin":
            json.NewEncoder(w).Encode(api.PreloginResponse{
                Kdf: 0, KdfIterations: 1, // 1 iteration for fast tests
            })
        case "/identity/connect/token":
            // ... return mock token with test keys
        case "/api/sync":
            // ... return pre-encrypted test ciphers
        }
    }))
    return server, api.NewClient(server.URL)
}
```

### Running tests

```bash
go test ./...                    # all tests
go test -v ./internal/crypto/    # verbose for crypto
go test -race ./...              # race detector
```

### CI (`.github/workflows/ci.yml`)

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go vet ./...
      - run: go test -race ./...
      - run: go build ./cmd/bw-secrets
```

---

## 11. Build System

**`go.mod`** (initial):
```
module github.com/nathanael/bw-secrets

go 1.22

require (
    github.com/spf13/cobra v1.8.1
    github.com/zalando/go-keyring v0.2.6
    github.com/stretchr/testify v1.9.0
    golang.org/x/crypto v0.28.0
    golang.org/x/term v0.25.0
)
```

**Build:**
```bash
go build -o bin/bw-secrets ./cmd/bw-secrets
```

**Release (future):** goreleaser for multi-platform binaries (linux/amd64, darwin/amd64, darwin/arm64, windows/amd64).

---

## 12. Implementation Order (MVP)

| Phase | What | Effort |
|---|---|---|
| 1 | `go mod init`, scaffold `cmd/`, `internal/crypto/` with KDF + EncString | Small |
| 2 | `internal/api/` — Client, Prelogin, Login, Refresh, Sync, models | Medium |
| 3 | `internal/keyring/` — Save/Load/Delete with zalando/go-keyring | Small |
| 4 | `internal/vault/` — Vault cache, URI parser, field resolver | Medium |
| 5 | `internal/cli/` — login, unlock, lock, status, get, list, logout | Medium |
| 6 | `internal/cli/` — run, inject, envfile parser | Medium |
| 7 | Integration tests with mock server | Medium |
| 8 | CI, README, polish | Small |

---

## 13. Open Questions / Future Work

1. **2FA support:** The `/connect/token` endpoint may return a `TwoFactorProviders` array and error if 2FA is required. We'd need to handle providing TOTP / Duo / YubiKey / email codes. Out of scope for MVP but API surface is known.

2. **Vaultwarden vs Bitwarden Cloud:** Both expose the same API. The only difference is the server URL. The tool works with both.

3. **File attachments:** Future extension of `bw://` URI to support `bw://Vault/Item/attachment-name` for downloading file attachments.

4. **`bw://Vault/Item/Section/FieldName`:** Some items have "sections" (sub-groups of fields). The data model supports this but adds complexity.

5. **Concurrent safety:** In-memory vault cache is read-only after construction — no mutable shared state.

6. **Token revocation on logout:** Could call `POST /identity/connect/revoke` with the refresh token. Optional, nice-to-have.

7. **Environment variable override:** `BW_SECRETS_SERVER` for server URL, `BW_SECRETS_TOKEN` for direct token injection (bypass keyring).

8. **Config file:** `~/.config/bw-secrets/config.yaml` for default server URL, avoiding repeated prompts. But keyring already stores server URL.

---

## 14. References

- Bitwarden Clients repo (encryption source of truth): https://github.com/bitwarden/clients
  - EncString format: `libs/common/src/platform/models/domain/enc-string.ts`
  - Encryption types: `libs/common/src/platform/enums/encryption-type.enum.ts`
  - Symmetric key: `libs/common/src/platform/models/domain/symmetric-crypto-key.ts`
- Vaultwarden API endpoints: `.agents/research/02-vaultwarden-api-endpoints.md`
- Bitwarden Vault Management API OpenAPI spec: `docs/bitwarden/openapi/vault-managment-api.json`
- Bitwarden Public API OpenAPI spec: `docs/bitwarden/openapi/api.json`
- go-keyring: https://github.com/zalando/go-keyring
- Cobra: https://github.com/spf13/cobra
- golang.org/x/crypto: https://pkg.go.dev/golang.org/x/crypto
