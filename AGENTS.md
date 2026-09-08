CLI tool that resolves `bw://` URIs against a Bitwarden vault (like 1Password's `op://`).

## Commands

```bash
make build          # → bin/bw-secrets
make test           # go test ./...
make vet            # go vet ./...
make clean
```

CI runs `go vet`, `go test -race ./...`, then `go build ./cmd/bw-secrets`, plus `goreleaser check` (`.goreleaser.yaml`). Run vet before test.

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
make release VERSION=v1.2.3   # checks tree + tags locally, then: git push origin v1.2.3
```

Pushing a `v*` tag triggers the GoReleaser release job in CI (single ubuntu runner,
pure Go): tar.gz archives, Windows zip, macOS universal binary, and deb/rpm/Arch
packages (amd64), plus checksums — see `.goreleaser.yaml`.

Validate release changes locally before tagging:

```bash
goreleaser check
goreleaser release --snapshot --clean
```
