CLI tool that resolves `bw://` URIs against a Bitwarden vault (like 1Password's `op://`).

## Commands

```bash
make build          # → bin/bw-secrets
make test           # go test ./...
make vet            # go vet ./...
make clean
```

CI runs `go vet`, `go test -race ./...`, then `go build ./cmd/bw-secrets`. Run vet before test.

Single test: `go test ./internal/crypto/...` or `go test -run TestName ./internal/...`

## Architecture

Go CLI (module: `github.com/nathabonfim59/bw-secrets`). Single binary, no submodules.

- `cmd/bw-secrets/main.go` — entrypoint, calls `cli.Execute()`
- `internal/cli/` — Cobra commands (root, login, unlock, get, list, inject, run, lock, logout, status)
- `internal/api/` — Bitwarden HTTP client, auth, sync, models
- `internal/crypto/` — KDF (PBKDF2/Argon2), encrypted string parsing
- `internal/keyring/` — OS keyring credential storage with file fallback
- `internal/vault/` — Vault decryption and `bw://` URI resolution

## Release

```bash
make release VERSION=v1.2.3
```

Tags and cross-compiles (linux/darwin/windows, amd64/arm64 + musl). Push tag to trigger CI release workflow.
