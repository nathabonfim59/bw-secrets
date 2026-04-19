# Bitwarden Public API

**Purpose:** Organization management API for members, collections, groups, event logs, and policies.
**Does NOT manage individual vault items** — use the Vault Management API for that.

## Capabilities

- Manage organization members (invite, confirm, revoke, remove)
- Manage collections and collection assignments
- Manage groups and group memberships
- Retrieve event logs (audit trail)
- Manage organization policies
- LDAP/SCIM directory import

## Authentication

- **Method:** OAuth2 Client Credentials flow
- **Credentials:** Organization API key (`client_id` + `client_secret`)
  - `client_id` format: `"organization.ClientId"` (NOT the personal API key)
  - Obtained by org owners: Admin Console → Settings → Organization info → API key section
- **Scope:** `api.organization`
- **Grant type:** `client_credentials`

### Token Request

```
POST https://identity.bitwarden.com/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=api.organization&client_id=<ID>&client_secret=<SECRET>
```

**Self-hosted:** `https://your.domain.com/identity/connect/token`
**EU cloud:** `https://identity.bitwarden.eu/connect/token`

### Token Response

```json
{
  "access_token": "<TOKEN>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

Token valid for 60 minutes. Expired tokens return `401 Unauthorized`.

## Base URL

- Cloud: `https://api.bitwarden.com` or `https://api.bitwarden.eu`
- Self-hosted: `https://your.domain.com/api`

## Content Types

- API requests/responses: `application/json`
- Auth endpoint request: `application/x-www-form-urlencoded`
- Auth endpoint response: `application/json`

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (missing/malformed params) |
| 401 | Missing, invalid, or expired token |
| 404 | Resource not found |
| 429 | Rate limited |
| 500/502/503/504 | Server error |

## Pagination

Endpoints returning 50+ results use `continuationToken`. Pass it as a query param:

```
GET /public/events?continuationToken=<token_value>
```

Applies to: `collections`, `events`, `groups`, `members`, `policies` list endpoints.

## Swagger / OpenAPI

OAS3 spec available at:
- Cloud: `https://bitwarden.com/help/api/` (Swagger UI)
- Self-hosted: `https://your.domain.com/api/docs/`

## Availability

Enterprise and Teams organizations only.

## References

- https://bitwarden.com/help/public-api/
- https://bitwarden.com/help/api/ (Swagger UI)
