# Vaultwarden API Endpoints (Complete Reference)

**Purpose:** Complete API surface of Vaultwarden — the self-hosted Bitwarden server implementation.
This covers both the **Vault Management API** (individual vault item CRUD) and the **Public API** (org management).

**Web framework:** Rocket v0.5.1 (Rust)
**Repo:** https://github.com/dani-garcia/vaultwarden (cloned at `/home/nathanael/Work/OSS/vaultwarden`)

## Authentication

### Auth Guards (request guards in Rocket)

| Guard | Purpose | Auth Mechanism |
|-------|---------|----------------|
| `Headers` | Standard authenticated user | Bearer JWT in `Authorization` header; validates claims, looks up Device+User from DB, verifies `security_stamp` |
| `OrgHeaders` | User with org membership | Extends `Headers` + org membership lookup |
| `OrgMemberHeaders` | Confirmed org member | Extends `OrgHeaders`; requires non-revoked + type >= User |
| `ManagerHeaders` | Confirmed manager+ | Extends `OrgHeaders`; requires confirmed + type >= Manager + collection manage permission |
| `AdminHeaders` | Confirmed admin+ | Extends `OrgHeaders`; requires confirmed + type >= Admin |
| `OwnerHeaders` | Confirmed owner | Extends `OrgHeaders`; requires confirmed + type == Owner |
| `AdminToken` | Admin panel | Cookie-based (`VW_ADMIN` cookie); Argon2id hash validation |
| `PublicToken` | Org API key auth | Bearer JWT; validates against org API key records |
| `ClientHeaders` | Minimal (device type + IP) | No auth, just reads `device-type` header + extracts IP |

### JWT Token Types (all RS256 signed)

| Issuer Suffix | Purpose |
|---------------|---------|
| `|login` | User access/refresh tokens |
| `|api.organization` | Organization API key |
| `|invite` | Org invite tokens |
| `|emergencyaccessinvite` | Emergency access invite |
| `|delete` | Account deletion recovery |
| `|verifyemail` | Email verification |
| `|admin` | Admin panel JWT |
| `|send` | Send file download |
| `|file_download` | Attachment download |
| `|register_verify` | Registration verification |
| `|2faremember` | 2FA "remember this device" |

---

## Route Mount Points

Defined in `src/main.rs`:

```
/              → api::web_routes()
/api           → api::core_routes()
/admin         → api::admin_routes()
/events        → api::core_events_routes()
/identity      → api::identity_routes()
/icons         → api::icons_routes()
/notifications → api::notifications_routes()
```

All prefixed by configurable `domain_path`.

---

## 1. Identity Routes (`/identity`)

**Source:** `src/api/identity.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/connect/token` | Rate-limited | OAuth2 token endpoint (login, refresh, SSO) |
| POST | `/accounts/prelogin` | `ClientHeaders` | Get KDF parameters for email |
| POST | `/accounts/register` | `ClientHeaders` | Register new user |
| POST | `/accounts/register/send-verification-email` | `ClientHeaders` | Send registration verification email |
| POST | `/accounts/register/finish` | `ClientHeaders` | Complete registration with token |
| GET | `/sso/prevalidate` | None | Prevalidate SSO domain |
| GET | `/connect/oidc-signin` | None | SSO OIDC callback |
| GET | `/connect/authorize` | None | SSO OAuth authorize endpoint |

---

## 2. Core API Routes (`/api`)

### 2.1 Meta / Utility

**Source:** `src/api/core/mod.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/alive` | None | Health check with DB validation |
| GET | `/now` | None | Current UTC timestamp |
| GET | `/version` | None | Vaultwarden version string |
| GET | `/config` | None | Server config, feature flags, environment URLs |
| GET | `/settings/domains` | `Headers` | Get equivalent domain settings |
| POST/PUT | `/settings/domains` | `Headers` | Update equivalent domains |
| GET | `/hibp/breach?username=` | `Headers` | HIBP breach check |

### 2.2 Account Routes

**Source:** `src/api/core/accounts.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/accounts/prelogin` | `ClientHeaders` | Pre-login KDF info |
| POST | `/accounts/set-password` | `Headers` | Set master password |
| GET | `/accounts/profile` | `Headers` | Get user profile |
| PUT/POST | `/accounts/profile` | `Headers` | Update profile |
| PUT | `/accounts/avatar` | `Headers` | Update avatar |
| GET | `/users/<id>/public-key` | `Headers` | Get user public key |
| POST | `/accounts/keys` | `Headers` | Update encryption keys |
| POST | `/accounts/password` | `Headers` | Change master password |
| POST | `/accounts/kdf` | `Headers` | Change KDF settings |
| POST | `/accounts/key-management/rotate-user-account-keys` | `Headers` | Rotate encryption key |
| POST | `/accounts/security-stamp` | `Headers` | Invalidate sessions |
| POST | `/accounts/email-token` | `Headers` | Request email change token |
| POST | `/accounts/email` | `Headers` | Change email |
| POST | `/accounts/verify-email` | `Headers` | Resend verification email |
| POST | `/accounts/verify-email-token` | `ClientHeaders` | Verify email with token |
| POST | `/accounts/delete-recover` | `ClientHeaders` | Initiate account deletion |
| POST | `/accounts/delete-recover-token` | `ClientHeaders` | Submit deletion token |
| POST/DELETE | `/accounts` | `Headers` | Delete account |
| GET | `/accounts/revision-date` | `Headers` | Get revision date |
| POST | `/accounts/password-hint` | `ClientHeaders` | Request password hint |
| POST | `/accounts/verify-password` | `Headers` | Verify master password |
| POST | `/accounts/api-key` | `Headers` | Get user API key |
| POST | `/accounts/rotate-api-key` | `Headers` | Rotate API key |
| POST | `/accounts/request-otp` | `Headers` | Request protected action OTP |
| POST | `/accounts/verify-otp` | `Headers` | Verify protected action OTP |

### 2.3 Device Routes

**Source:** `src/api/core/accounts.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/devices/knowndevice` | `Headers` | Check if device is known |
| GET | `/devices` | `Headers` | List all user devices |
| GET | `/devices/identifier/<id>` | `Headers` | Get device info |
| POST/PUT | `/devices/identifier/<id>/token` | `Headers` | Set device push token |
| POST/PUT | `/devices/identifier/<id>/clear-token` | `Headers` | Clear device push token |

### 2.4 Auth Request Routes (login with device)

**Source:** `src/api/core/accounts.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth-requests` | `Headers` | Create auth request |
| GET | `/auth-requests` | `Headers` | List all auth requests |
| GET | `/auth-requests/pending` | `Headers` | List pending auth requests |
| GET | `/auth-requests/<id>` | `Headers` | Get auth request |
| PUT | `/auth-requests/<id>` | `Headers` | Update auth request |
| GET | `/auth-requests/<id>/response` | `Headers` | Get auth request response |

### 2.5 Cipher Routes (Vault Management API)

**Source:** `src/api/core/ciphers.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/sync` | `Headers` | Full vault sync |
| GET | `/ciphers` | `Headers` | List all ciphers |
| GET | `/ciphers/<id>` | `Headers` | Get single cipher |
| GET | `/ciphers/<id>/admin` | `Headers` | Get cipher admin info |
| GET | `/ciphers/<id>/details` | `Headers` | Get cipher details |
| POST | `/ciphers` | `Headers` | Create cipher |
| POST | `/ciphers/create` | `Headers` | Create cipher (alt) |
| POST | `/ciphers/admin` | `Headers` | Create org cipher as admin |
| PUT/POST | `/ciphers/<id>` | `Headers` | Update cipher |
| PUT/POST | `/ciphers/<id>/admin` | `AdminHeaders` | Update cipher as admin |
| PUT/POST | `/ciphers/<id>/partial` | `Headers` | Partial update |
| POST | `/ciphers/import` | `Headers` | Bulk import |
| POST | `/ciphers/import-organization` | `AdminHeaders` | Import to org |
| PUT/POST | `/ciphers/<id>/collections` | `Headers` | Update cipher collections |
| PUT/POST | `/ciphers/<id>/collections_v2` | `Headers` | Update collections (v2) |
| PUT/POST | `/ciphers/<id>/collections-admin` | `AdminHeaders` | Update collections as admin |
| PUT/POST | `/ciphers/<id>/share` | `Headers` | Share cipher to org |
| PUT | `/ciphers/share` | `Headers` | Bulk share |
| POST | `/ciphers/bulk-collections` | `AdminHeaders` | Bulk assign to collections |
| GET | `/ciphers/<id>/attachment/<att_id>` | `Headers` | Get attachment info |
| POST | `/ciphers/<id>/attachment/v2` | `Headers` | Upload attachment (v2) |
| POST | `/ciphers/<id>/attachment/<att_id>` | `Headers` | Upload attachment data (v2) |
| POST | `/ciphers/<id>/attachment` | `Headers` | Upload attachment (legacy) |
| POST | `/ciphers/<id>/attachment-admin` | `Headers` | Upload attachment as admin |
| POST | `/ciphers/<id>/attachment/<att_id>/share` | `Headers` | Share attachment |
| DELETE/POST | `/ciphers/<id>/attachment/<att_id>` | `Headers` | Delete attachment |
| DELETE/POST | `/ciphers/<id>/attachment/<att_id>/admin` | `Headers` | Delete attachment as admin |
| DELETE/POST | `/ciphers/<id>` | `Headers` | Soft-delete cipher |
| DELETE/POST | `/ciphers/<id>/admin` | `AdminHeaders` | Soft-delete as admin |
| DELETE/POST/PUT | `/ciphers` | `Headers` | Bulk soft-delete |
| DELETE/POST/PUT | `/ciphers/admin` | `AdminHeaders` | Bulk soft-delete as admin |
| PUT | `/ciphers/<id>/restore` | `Headers` | Restore from trash |
| PUT | `/ciphers/<id>/restore-admin` | `AdminHeaders` | Restore as admin |
| PUT | `/ciphers/restore` | `Headers` | Bulk restore |
| PUT | `/ciphers/restore-admin` | `AdminHeaders` | Bulk restore as admin |
| POST/PUT | `/ciphers/move` | `Headers` | Move ciphers to folder/org |
| POST | `/ciphers/purge?organization=` | `Headers`+OrgIdGuard | Purge org vault |
| POST | `/ciphers/purge` | `Headers` | Purge personal vault |
| GET | `/ciphers/organization-details` | `OrgHeaders` | Get org ciphers |

### 2.6 Folder Routes

**Source:** `src/api/core/folders.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/folders` | `Headers` | List folders |
| GET | `/folders/<id>` | `Headers` | Get folder |
| POST | `/folders` | `Headers` | Create folder |
| PUT/POST | `/folders/<id>` | `Headers` | Update folder |
| DELETE/POST | `/folders/<id>` | `Headers` | Delete folder |

### 2.7 Send Routes

**Source:** `src/api/core/sends.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/sends` | `Headers` | List sends |
| GET | `/sends/<id>` | `Headers` | Get send |
| POST | `/sends` | `Headers` | Create text send |
| POST | `/sends/file` | `Headers` | Create file send (multipart) |
| POST | `/sends/file/v2` | `Headers` | Create file send (v2 JSON) |
| POST | `/sends/<id>/file/<file_id>` | `Headers` | Upload file data |
| POST | `/sends/access/<access_id>` | **Public** | Access text send |
| POST | `/sends/<id>/access/file/<file_id>` | **Public** | Access file send |
| GET | `/sends/<id>/<file_id>` | **Public** | Download send file |
| PUT | `/sends/<id>` | `Headers` | Update send |
| DELETE | `/sends/<id>` | `Headers` | Delete send |
| PUT | `/sends/<id>/remove-password` | `Headers` | Remove send password |

### 2.8 Organization Routes

**Source:** `src/api/core/organizations.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/organizations` | `Headers` | Create org |
| DELETE/POST | `/organizations/<id>` | `OwnerHeaders` | Delete org |
| POST | `/organizations/<id>/leave` | `OrgHeaders` | Leave org |
| GET | `/organizations/<id>` | `OrgHeaders` | Get org details |
| PUT/POST | `/organizations/<id>` | `OwnerHeaders` | Update org |
| GET | `/collections` | `Headers` | List user collections |
| GET | `/organizations/<id>/auto-enroll-status` | `Headers` | Check auto-enrollment |
| GET | `/organizations/<id>/collections` | `OrgHeaders` | List org collections |
| GET | `/organizations/<id>/collections/details` | `OrgHeaders` | List collections with details |
| GET | `/organizations/<id>/collections/<cid>/details` | `OrgHeaders` | Get collection detail |
| GET | `/organizations/<id>/collections/<cid>/users` | `ManagerHeaders` | List collection users |
| POST | `/organizations/<id>/collections` | `ManagerHeaders` | Create collection |
| PUT/POST | `/organizations/<id>/collections/<cid>` | `ManagerHeaders` | Update collection |
| DELETE/POST | `/organizations/<id>/collections/<cid>` | `ManagerHeaders` | Delete collection |
| DELETE | `/organizations/<id>/collections` | `ManagerHeadersLoose` | Bulk delete collections |
| POST | `/organizations/<id>/collections/bulk-access` | `ManagerHeadersLoose` | Bulk access collections |
| GET | `/organizations/<id>/users` | `OrgHeaders` | List org members |
| GET | `/organizations/<id>/users/<mid>` | `OrgHeaders` | Get member details |
| GET | `/organizations/<id>/users/mini-details` | `OrgHeaders` | Mini user details |
| POST | `/organizations/<id>/users/invite` | `AdminHeaders` | Invite users |
| POST | `/organizations/<id>/users/reinvite` | `AdminHeaders` | Bulk reinvite |
| POST | `/organizations/<id>/users/<mid>/reinvite` | `AdminHeaders` | Reinvite single member |
| POST | `/organizations/<id>/users/<mid>/accept` | `OrgHeaders` | Accept invite |
| POST | `/organizations/<id>/users/confirm` | `AdminHeaders` | Bulk confirm |
| POST | `/organizations/<id>/users/<mid>/confirm` | `AdminHeaders` | Confirm invite |
| PUT/POST | `/organizations/<id>/users/<mid>` | `AdminHeaders` | Update member |
| DELETE | `/organizations/<id>/users` | `AdminHeaders` | Bulk delete members |
| DELETE | `/organizations/<id>/users/<mid>` | `AdminHeaders` | Delete member |
| POST | `/organizations/<id>/users/public-keys` | `OrgHeaders` | Bulk get public keys |
| PUT | `/organizations/<id>/users/<mid>/revoke` | `AdminHeaders` | Revoke member |
| PUT | `/organizations/<id>/users/revoke` | `AdminHeaders` | Bulk revoke |
| PUT | `/organizations/<id>/users/<mid>/restore` | `AdminHeaders` | Restore member |
| PUT | `/organizations/<id>/users/restore` | `AdminHeaders` | Bulk restore |
| PUT | `/organizations/<id>/users/<mid>/reset-password` | `AdminHeaders` | Reset user password |
| GET | `/organizations/<id>/users/<mid>/reset-password-details` | `OrgHeaders` | Get reset password details |
| PUT | `/organizations/<id>/users/<uid>/reset-password-enrollment` | `OrgHeaders` | Enroll in password reset |
| POST | `/organizations/<id>/keys` | `OwnerHeaders` | Set org keys |
| GET | `/organizations/<id>/public-key` | `OrgHeaders` | Get org public key |
| GET | `/organizations/<id>/keys` | `OrgHeaders` | Get org keys |
| GET | `/organizations/<id>/policies` | `OrgHeaders` | List policies |
| GET | `/organizations/<id>/policies/token?token=` | **Public** | List policies via token |
| GET | `/organizations/<id>/policies/<type>` | `OrgHeaders` | Get specific policy |
| PUT | `/organizations/<id>/policies/<type>` | `AdminHeaders` | Save policy |
| GET | `/organizations/<id>/groups` | `OrgHeaders` | List groups |
| GET | `/organizations/<id>/groups/details` | `OrgHeaders` | List groups with details |
| POST | `/organizations/<id>/groups` | `AdminHeaders` | Create group |
| GET | `/organizations/<id>/groups/<gid>` | `OrgHeaders` | Get group |
| GET | `/organizations/<id>/groups/<gid>/details` | `OrgHeaders` | Get group details |
| PUT | `/organizations/<id>/groups/<gid>` | `AdminHeaders` | Update group |
| DELETE/POST | `/organizations/<id>/groups/<gid>` | `AdminHeaders` | Delete group |
| DELETE | `/organizations/<id>/groups` | `AdminHeaders` | Bulk delete groups |
| GET | `/organizations/<id>/groups/<gid>/users` | `OrgHeaders` | List group members |
| PUT | `/organizations/<id>/groups/<gid>/users` | `AdminHeaders` | Set group members |
| POST | `/organizations/<id>/groups/<gid>/delete-user/<mid>` | `AdminHeaders` | Remove user from group |
| GET | `/organizations/<id>/export` | `OrgHeaders` | Export org vault |
| POST | `/organizations/<id>/api-key` | `OwnerHeaders` | Get org API key |
| POST | `/organizations/<id>/rotate-api-key` | `OwnerHeaders` | Rotate org API key |
| GET | `/plans` | **Public** | Get available plans |
| POST | `/organizations/domain/sso/verified` | **Public** | Verify domain SSO |

### 2.9 Emergency Access Routes

**Source:** `src/api/core/emergency_access.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/emergency-access/trusted` | `Headers` | List trusted contacts |
| GET | `/emergency-access/granted` | `Headers` | List grantees |
| GET/PUT/POST/DELETE | `/emergency-access/<id>` | `Headers` | CRUD emergency access |
| POST | `/emergency-access/<id>/delete` | `Headers` | Delete (POST variant) |
| POST | `/emergency-access/invite` | `Headers` | Invite emergency contact |
| POST | `/emergency-access/<id>/reinvite` | `Headers` | Resend invite |
| POST | `/emergency-access/<id>/accept` | `Headers` | Accept invite |
| POST | `/emergency-access/<id>/confirm` | `Headers` | Confirm |
| POST | `/emergency-access/<id>/initiate` | `Headers` | Initiate access |
| POST | `/emergency-access/<id>/approve` | `Headers` | Approve |
| POST | `/emergency-access/<id>/reject` | `Headers` | Reject |
| POST | `/emergency-access/<id>/view` | `Headers` | View vault |
| POST | `/emergency-access/<id>/takeover` | `Headers` | Take over account |
| POST | `/emergency-access/<id>/password` | `Headers` | Set new password |
| GET | `/emergency-access/<id>/policies` | `Headers` | Get policies |

### 2.10 Two-Factor Routes

**Source:** `src/api/core/two_factor/`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/two-factor` | `Headers` | List 2FA methods |
| POST | `/two-factor/get-recover` | `Headers` | Get recovery code |
| POST/PUT | `/two-factor/disable` | `Headers` | Disable 2FA |
| GET | `/two-factor/get-device-verification-settings` | `Headers` | Device verification settings |
| POST | `/two-factor/get-authenticator` | `Headers` | Generate TOTP secret |
| POST/PUT | `/two-factor/authenticator` | `Headers` | Activate TOTP |
| DELETE | `/two-factor/authenticator` | `Headers` | Disable TOTP |
| POST | `/two-factor/get-duo` | `Headers` | Get Duo config |
| POST/PUT | `/two-factor/duo` | `Headers` | Activate Duo |
| POST | `/two-factor/get-email` | `Headers` | Get email 2FA |
| POST | `/two-factor/send-email` | `Headers` | Send email 2FA |
| POST/PUT | `/two-factor/email` | `Headers` | Activate email 2FA |
| POST | `/two-factor/send-email-login` | `ClientHeaders` | Send 2FA email at login |
| POST | `/two-factor/get-yubikey` | `Headers` | Get YubiKey config |
| POST/PUT | `/two-factor/yubikey` | `Headers` | Activate YubiKey |
| POST | `/two-factor/get-webauthn` | `Headers` | Get WebAuthn credentials |
| POST | `/two-factor/get-webauthn-challenge` | `Headers` | Generate WebAuthn challenge |
| POST/PUT | `/two-factor/webauthn` | `Headers` | Activate WebAuthn |
| DELETE | `/two-factor/webauthn` | `Headers` | Delete WebAuthn credential |

### 2.11 Public API Routes

**Source:** `src/api/core/public.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/public/organization/import` | `PublicToken` | LDAP/SCIM directory import |

### 2.12 Event Routes (mounted at `/api` and `/events`)

**Source:** `src/api/core/events.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/organizations/<id>/events` | `AdminHeaders` | Get org events |
| GET | `/ciphers/<id>/events` | `Headers` | Get cipher events |
| GET | `/organizations/<id>/users/<mid>/events` | `AdminHeaders` | Get member events |
| POST | `/events/collect` | `Headers` | Collect client-side events |

---

## 3. Admin Panel Routes (`/admin`)

**Source:** `src/api/admin.rs`
**Auth:** `AdminToken` (cookie-based `VW_ADMIN`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/` | Admin panel HTML |
| POST | `/admin/` | Admin login (rate-limited) |
| GET | `/admin/logout` | Logout |
| GET | `/admin/users` | List users (JSON) |
| GET | `/admin/users/overview` | Users overview (HTML) |
| GET | `/admin/users/by-mail/<mail>` | Get user by email |
| GET | `/admin/users/<id>` | Get user details |
| POST | `/admin/users/<id>/delete` | Delete user |
| DELETE | `/admin/users/<id>/sso` | Delete SSO user |
| POST | `/admin/users/<id>/deauth` | Deauthorize user |
| POST | `/admin/users/<id>/disable` | Disable user |
| POST | `/admin/users/<id>/enable` | Enable user |
| POST | `/admin/users/<id>/remove-2fa` | Remove 2FA |
| POST | `/admin/users/<id>/invite/resend` | Resend invite |
| POST | `/admin/users/org_type` | Update membership type |
| POST | `/admin/users/update_revision` | Update all revisions |
| GET | `/admin/organizations/overview` | Orgs overview (HTML) |
| POST | `/admin/organizations/<id>/delete` | Delete organization |
| GET | `/admin/diagnostics` | Diagnostics (HTML) |
| GET | `/admin/diagnostics/config` | Config (JSON) |
| GET | `/admin/diagnostics/http?code=` | Test HTTP status |
| POST | `/admin/invite` | Invite user |
| POST | `/admin/test/smtp` | Test SMTP |
| POST | `/admin/config` | Update runtime config |
| POST | `/admin/config/delete` | Delete config value |
| POST | `/admin/config/backup_db` | Backup database |

---

## 4. Icon Routes (`/icons`)

**Source:** `src/api/icons.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/<domain>/icon.png` | **Public** | Fetch website favicon |

---

## 5. Notification Routes (`/notifications`)

**Source:** `src/api/notifications.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/hub` | `WsAccessTokenHeader` | WebSocket sync hub |
| GET | `/anonymous-hub` | Token in query | Anonymous WebSocket hub |

---

## 6. Web Routes (`/`)

**Source:** `src/api/web.rs`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET/HEAD | `/` | None | Web vault index |
| GET | `/app-id.json` | None | App manifest |
| GET | `/attachments/<cipher_id>/<file_id>?token=` | None | Download attachment |
| GET/HEAD | `/alive` | None | Health check |

---

## Rate Limiting

- **Login:** `LOGIN_RATELIMIT_SECONDS` / `LOGIN_RATELIMIT_MAX_BURST`
- **Admin login:** `ADMIN_RATELIMIT_SECONDS` / `ADMIN_RATELIMIT_MAX_BURST`

## References

- Vaultwarden repo: https://github.com/dani-garcia/vaultwarden
- Local clone: `/home/nathanael/Work/OSS/vaultwarden`
- Route definitions: `src/api/` directory
- Auth guards: `src/auth.rs`
- Route mounting: `src/main.rs` (lines 577-584)
