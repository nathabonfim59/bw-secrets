# bw-secrets

A CLI tool for [Bitwarden](https://bitwarden.com) that resolves secrets like 1Password's `op://` — using `bw://VaultName/ItemName/FieldName` URIs.

Works with Bitwarden Cloud and self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).

## How it works

bw-secrets talks directly to the same HTTP API the Bitwarden browser extension uses. After login, auth tokens and the symmetric encryption key are stored in your OS keyring (or `~/.config/bw-secrets/credentials.json` as fallback). The vault stays "unlocked" — no need to enter your master password every time.

## Install

```bash
go install github.com/nathabonfim59/bw-secrets@latest
```

Or from source:

```bash
git clone https://github.com/nathabonfim59/bw-secrets
cd bw-secrets
make build          # → bin/bw-secrets
```

## Quick start

```bash
# Login (server URL, email, master password, TOTP if 2FA enabled)
bw-secrets login

# Scope to a specific personal folder
bw-secrets login --folder Work

# Scope to an organization collection
bw-secrets login --organization Acme --collection Engineering

# List available organizations
bw-secrets orgs

# Or skip the URL prompt
bw-secrets --server https://bitwarden.example.com login

# Check status
bw-secrets status

# List items
bw-secrets list
bw-secrets list "Personal"           # filter by folder
bw-secrets list --type login         # filter by type

# Resolve a secret (--reveal required to output the value)
bw-secrets get bw://Personal/Google/password
# → resolved: Personal/Google/password (use --reveal to output)
bw-secrets get --reveal bw://Personal/Google/password
# → actual password value

# Use in scripts
DB_PASS=$(bw-secrets get --reveal bw://Production/MySQL/password)
```

## Inject secrets into files

Use `bw-secrets inject` to replace `bw://` references in config files — safe to check into git:

```yaml
# config.yml.tpl
database:
  host: localhost
  user: bw://Production/MySQL/username
  password: bw://Production/MySQL/password
```

```bash
bw-secrets inject -i config.yml.tpl -o config.yml
```

Template variables let you switch environments:

```bash
APP_ENV=staging bw-secrets inject -i config.yml.tpl
```

Note: in `inject`, spaces in the URI must be URL-encoded (`%20`).

## Run commands with secrets as env vars

```bash
# From .env files
bw-secrets run --env-file prod.env -- mysqldump -u root

# From exported env vars (secrets masked in subprocess output)
DB_URL=bw://Production/MySQL/password bw-secrets run -- ./my-script.sh

# Disable masking
bw-secrets run --no-masking -- ./debug-script.sh
```

`.env` file format:

```env
# Comments
DB_HOST=localhost
DB_USER=admin
DB_PASS=bw://Production/MySQL/password
QUOTED="value with spaces"
EMPTY=               # becomes empty string
URL=http://${DB_HOST}:8080   # variable expansion
```

## URI format

```
bw://VaultName/ItemName/FieldName        (personal folders)
bw://OrgName//CollectionName/ItemName/FieldName  (organization collections)
```

The `//` separates organization name from collection name — no ambiguity with folders.

| Component | Meaning | Example |
|---|---|---|
| VaultName | Folder name in Bitwarden, or `No Folder` | `Personal`, `No Folder` |
| OrgName | Organization name | `Acme` |
| CollectionName | Collection within the organization | `Engineering` |
| ItemName | Name of the vault item (case-insensitive) | `Google`, `My Server` |
| FieldName | Field to retrieve | `password`, `username`, `notes`, `totp`, `number`, custom field name |

Examples:
```
bw://Work/Google/password              → personal folder "Work"
bw://Acme//Engineering/DB/password     → org "Acme", collection "Engineering"
```

Fields by item type:

| Type | Available fields |
|---|---|
| Login | `username`, `password`, `totp`, `notes`, custom field names |
| Secure Note | `notes` |
| Card | `cardholder`, `number`, `brand`, `expmonth`, `expyear`, `code` |
| Identity | `firstname`, `lastname`, `username`, `company`, `email`, `phone`, `title` |

## Commands

| Command | Description |
|---|---|
| `login` | Authenticate and store credentials; use `--folder` or `--organization`/`--collection` to scope |
| `unlock` | Re-authenticate when tokens expire |
| `lock` | Clear stored credentials |
| `logout` | Same as `lock` |
| `status` | Show login status, token expiry, and active scope |
| `orgs` | List available organizations |
| `get` | Resolve a `bw://` URI (`op read` equivalent) |
| `list` | List vault items |
| `run` | Inject secrets as env vars and run a command (`op run` equivalent) |
| `inject` | Replace `bw://` refs in files/stdin (`op inject` equivalent) |

## Environment variables

| Variable | Purpose |
|---|---|
| `BW_SECRETS_SERVER` | Default server URL (overridden by `--server`) |

## Security

- Master password is **never** stored
- Credentials are stored in the OS keyring (or `~/.config/bw-secrets/credentials.json` with `0600` permissions)
- `bw-secrets get` requires `--reveal` to output the actual value
- `bw-secrets run` masks secrets in subprocess output by default
- All server communication is over HTTPS

## License

MIT
