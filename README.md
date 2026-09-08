# bw-secrets

A CLI tool for [Bitwarden](https://bitwarden.com) that resolves secrets like 1Password's `op://` — using `bw://VaultName/ItemName/FieldName` URIs.

Works with Bitwarden Cloud and self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden).

## How it works

bw-secrets talks directly to the same HTTP API the Bitwarden browser extension uses. After login, auth tokens and the symmetric encryption key are stored in your OS keyring (or `~/.config/bw-secrets/credentials.json` as fallback). The vault stays "unlocked" — no need to enter your master password every time.

## Install

Direct downloads pull the latest release automatically:

<!-- The Windows logo is inlined as a data URI: simple-icons removed
     all Microsoft marks after a legal request, so logo=windows no
     longer renders anything. -->

| Linux | macOS | Windows |
| :---: | :---: | :---: |
| [![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://github.com/nathabonfim59/bw-secrets/releases/latest/download/bw-secrets_linux_amd64.deb)<br>[![Red Hat](https://img.shields.io/badge/Red_Hat-EE0000?style=for-the-badge&logo=redhat&logoColor=white)](https://github.com/nathabonfim59/bw-secrets/releases/latest/download/bw-secrets_linux_x86_64.rpm)<br>[![Arch Linux](https://img.shields.io/badge/Arch_Linux-1793D1?style=for-the-badge&logo=archlinux&logoColor=white)](https://github.com/nathabonfim59/bw-secrets/releases/latest/download/bw-secrets_linux_x86_64.pkg.tar.zst) | [![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/nathabonfim59/bw-secrets/releases/latest/download/bw-secrets_darwin_all.tar.gz) | [![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTAgMy40NDlMOS43NSAyLjF2OS40NTFIMG0xMC45NDktOS42MDJMMjQgMHYxMS40SDEwLjk0OU0wIDEyLjZoOS43NXY5LjQ1MUwwIDIwLjY5OU0xMC45NDkgMTIuNkgyNFYyNGwtMTIuOS0xLjgwMSIvPjwvc3ZnPg%3D%3D&logoColor=white)](https://github.com/nathabonfim59/bw-secrets/releases/latest/download/bw-secrets_windows_amd64.zip) |

The macOS download is a **universal** binary (Intel + Apple Silicon).
The Linux packages install to `/usr/bin/bw-secrets`:

| Platform | Install |
| --- | --- |
| Debian/Ubuntu | `sudo apt install ./bw-secrets_*_amd64.deb` |
| RHEL/Fedora | `sudo dnf install ./bw-secrets-*.x86_64.rpm` |
| Arch Linux | `sudo pacman -U ./bw-secrets-*-x86_64.pkg.tar.zst` |

Archives (`.tar.gz`/`.zip`) are available on the
[releases page](https://github.com/nathabonfim59/bw-secrets/releases/latest)
for portable use.

With Go:

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
bw-secrets list -r                  # all items in the selected profile's scope
bw-secrets list "Personal"           # filter by folder
bw-secrets list login -r             # all login items

# Resolve a secret (--reveal required to output the value)
bw-secrets get bw://Personal/Google/password
# → resolved: Personal/Google/password (use --reveal to output)
bw-secrets get --reveal bw://Personal/Google/password
# → actual password value

# Use in scripts
DB_PASS=$(bw-secrets get --reveal bw://Production/MySQL/password)
```

## Login profiles and directory scopes

Keep multiple logins without re-authenticating whenever you switch projects:

```bash
bw-secrets login --profile personal
bw-secrets login --profile work --organization Acme --collection Engineering
```

Each profile has independent credentials, server settings, and an optional
folder/collection scope. Existing logins are available as the `default` profile;
no migration is needed. Tokens refresh automatically while the session remains
refreshable. Use `unlock --profile work` when re-authentication is required.

### Export a shell default

In bash, zsh, or another POSIX-compatible shell:

```bash
eval "$(bw-secrets profile use work)"
# Equivalent to: export BW_SECRETS_PROFILE=work

bw-secrets profile current  # work
bash                       # subshell inherits work
```

`profile use` prints only an export statement; it does not log in or modify your
parent shell by itself. With no name, it exports the currently effective profile:

```bash
eval "$(bw-secrets profile use)"
```

For other shells, set the environment variable directly:

```fish
set -gx BW_SECRETS_PROFILE work
```

```powershell
$env:BW_SECRETS_PROFILE = 'work'
```

### Bind a directory recursively

```bash
bw-secrets profile bind work ~/projects/customer-a
bw-secrets profile bind personal ~/projects/my-app

cd ~/projects/customer-a/backend
bw-secrets profile current  # work, including all subdirectories
bw-secrets status           # profile, selection source, binding path, login and vault scope
```

Bindings are stored locally in `profiles.json` in the OS user configuration
directory (`~/.config/bw-secrets/` on Linux, or under `XDG_CONFIG_HOME`). No YAML
or credential files are added to your project. Directory paths are absolute and
symlinks are resolved. If you move a project, bind its new location.

The effective profile is selected in this order:

1. Explicit `--profile NAME`.
2. The nearest directory binding, searching from the working directory upward.
3. Inherited `BW_SECRETS_PROFILE`.
4. `default`.

A nested directory binding overrides a parent binding. Bindings apply to `login`,
`unlock`, `lock`, `logout`, `status`, and all vault commands. A selected profile
without credentials fails rather than falling back to another login. Malformed
bindings also produce an error instead of silently selecting a default.

**Directory selection does not change your shell's exported default.** If `work`
is exported, commands in a directory bound to `personal` use `personal`; outside
that directory they use `work` again. An ordinary subshell inherits the exported
value, while each invocation of bw-secrets still checks its own working directory.

`bw-secrets run` passes its **effective** profile to the child process as
`BW_SECRETS_PROFILE`, including when selected by a binding or `--profile`. This
value takes precedence over any assignment in an `--env-file`. Further bw-secrets
invocations in that child still follow the same selection order.

```bash
bw-secrets profile bind work       # bind the current directory
bw-secrets profile unbind          # remove only this directory's binding
bw-secrets profile unbind ~/projects/my-app
unset BW_SECRETS_PROFILE           # remove the shell default (POSIX shells)
bw-secrets logout --profile work   # remove only work's credentials
```

Removing a binding exposes the nearest parent binding, then the environment or
default profile. Logging out keeps directory bindings in place. Profile names
are 1–64 ASCII letters, digits, underscores, or hyphens and must start with a
letter or digit. `profile bind` and `profile use NAME` can select a profile before
you log in to it.

Directory bindings select a login and its saved folder/collection scope. They are
a CLI convenience, not an operating-system sandbox or server-side access policy.
For service-account-style access restrictions, use an identity with appropriately
limited server-side permissions.

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

Organization collections and items are decrypted using their organization's key,
unwrapped with the account private key from the sync response. Items with their
own encryption key use that key for both names and secret fields. This applies
to listings, login/rescope selectors, `get`, `inject`, and `run`. Key or encrypted
name decryption failures return an error instead of displaying ciphertext.

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
| `lock` | Clear tokens and keys; preserve remembered login details |
| `logout` | Delete the selected profile's credentials and remembered details |
| `rescope` | Re-authenticate and change or remove the saved scope |
| `status` | Show login status, token expiry, and active scope |
| `profile current` | Print the effective profile for the current directory |
| `profile use [name]` | Print a POSIX shell export for a named or effective profile |
| `profile bind <name> [directory]` | Bind a profile recursively; defaults to the current directory |
| `profile unbind [directory]` | Remove a directory's explicit binding |
| `orgs` | Alias for `list orgs`, including output and filtering flags |
| `get` | Resolve a `bw://` URI (`op read` equivalent) |
| `list` | List items, collections, organizations, or folders |
| `run` | Inject secrets as env vars and run a command (`op run` equivalent) |
| `inject` | Replace `bw://` refs in files/stdin (`op inject` equivalent) |

## Environment variables

| Variable | Purpose |
|---|---|
| `BW_SECRETS_SERVER` | Default server URL (overridden by `--server`) |
| `BW_SECRETS_PROFILE` | Inherited profile; overridden by a directory binding or `--profile` |

## Security

- Master password is **never** stored
- Credentials are stored independently per profile in the OS keyring. File fallback uses `0600` permissions: `~/.config/bw-secrets/credentials.json` for `default`, or `~/.config/bw-secrets/profiles/<name>/credentials.json` for named profiles on Linux.
- `bw-secrets get` requires `--reveal` to output the actual value
- `bw-secrets run` masks secrets in subprocess output by default
- All server communication is over HTTPS

## Release builds

`make release-build` requires GoReleaser and runs `goreleaser build --snapshot
--clean`. Local binaries use the same platform matrix as CI in `.goreleaser.yaml`
(Linux amd64, macOS amd64/arm64, Windows amd64), with snapshot versions derived
from Git. The old separate ARM64 Linux/Windows and musl-named builds are replaced
by this shared matrix; builds use `CGO_ENABLED=0`.

To validate the complete release packaging locally, run `goreleaser check` and
`goreleaser release --snapshot --clean`. `make release VERSION=v1.2.3` still creates
the local tag before building; pushing that tag triggers the published CI release.

## Listing, filters, and output

```bash
bw-secrets list collections
bw-secrets list orgs
bw-secrets list folders
bw-secrets list login                  # top-level logins
bw-secrets list login -r               # include items in folders/collections
bw-secrets list login --organization "Acme Corp" -r
bw-secrets list login --organization "Acme Corp" --collection "Engineering" -r
bw-secrets list login --folder '<folder-uuid>' --search database -r
bw-secrets list collections --organization '<org-uuid>' --format json
bw-secrets list login --id '<item-uuid>' -r --format json
bw-secrets list login --name 'Database' -r --format text
bw-secrets list orgs --format template --template '{{range .}}{{.Name}}: {{.ID}}{{"\n"}}{{end}}'
```

Resource kinds are `items` (default), `login`, `note`, `card`, `identity`,
`collections`, `orgs`, and `folders`. The legacy `list "Folder Name"` and
`list --type login` forms remain supported. Use `--folder` for folder names
that coincide with resource keywords.

`--organization`, `--collection`, and `--folder` accept exact UUIDs or
case-insensitive names. UUIDs take precedence; ambiguous container names require
a UUID or an organization filter. `--name` matches an exact name, `--search`
matches a name substring, and `--id` matches an exact UUID. Filters combine with
AND. Unknown containers and inapplicable filters return errors.

Without `-r`, unscoped item listings show items with neither a folder nor a
collection. Selecting a folder or collection lists its direct items; `-r`
also matches containers named `Parent/Child`, respecting slash boundaries and
organization ownership. Bitwarden containers are flat records; this hierarchy
is inferred from their names. Metadata listings include all visible containers,
including empty ones, without requiring `-r`.

A saved scope is the listing root. Its direct items remain visible without
`-r`; recursive filters never widen the saved scope. Collection-scoped metadata
shows that collection and its organization; folder-scoped metadata shows the
folder and organizations/collections associated with its visible items.

Output goes to **stdout**, sorted by name then UUID, and contains metadata only.
`--format` (`-o`) supports `table` (default), `json` (an array, including `[]` for
no results), `text` (one UUID per line), and `template` with `--template`.
Templates receive entries with `ID`, `Name`, `Type`, `OrganizationID`, `FolderID`,
and `CollectionIDs`. JSON uses snake_case field names. Passwords and other secret
values are never included. Use JSON with `jq` for more elaborate projections.

Scope flags on `login` and `rescope`, as well as folder, organization, collection,
and item components in `bw://` references, also accept names or UUIDs:

```bash
bw-secrets get --reveal 'bw://<org-uuid>//<collection-uuid>/<item-uuid>/password'
```

## Remembering login details and changing scope

After a successful login, answer the remember question to reuse the selected
profile's host and email next time. Subsequent `login --profile work` needs only
the master password (plus 2FA if required), retaining the saved scope.
`login --edit` lets you review prefilled host/email values. Use `--remember` or
`--remember=false` to set the preference without the final question.
The preference is stored per profile with its credentials; passwords are never
saved. Declining disables automatic reuse: host/email still exist in the stored
session for refresh/unlock and appear as defaults. `lock` clears tokens and keys,
preserving details only when remember is enabled. `logout` deletes these details.

```bash
bw-secrets rescope --profile work --folder 'Work Folder'
bw-secrets rescope --profile work --organization '<org-uuid>' --collection '<collection-uuid>'
bw-secrets rescope --profile work --all
```

`rescope` reuses the saved host/email and prompts for the master password and any
required 2FA. It saves the new scope only after authentication and scope lookup
succeed. `--all` removes the local scope restriction. Other profiles are unaffected.

## License

MIT
