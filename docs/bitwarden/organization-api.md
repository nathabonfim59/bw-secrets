# Bitwarden Organization (Public) API Reference

Base URLs:
- US: `https://api.bitwarden.com`
- EU: `https://api.bitwarden.eu`

Auth: OAuth2 client credentials, scope `api.organization`.

All paths prefixed with `/public`.

## Collections

| Method | Path | Description |
|--------|------|-------------|
| GET | `/collections` | List all org collections (excludes group associations in response) |
| GET | `/collections/{id}` | Get a collection by UUID |
| PUT | `/collections/{id}` | Update a collection |
| DELETE | `/collections/{id}` | Delete a collection (permanent) |

**Collection response fields:** `id`, `object`, `externalId`, `groups[]`

**Update body:** `externalId`, `groups[]` (each with `id`, `readOnly`, `hidePasswords`, `manage`)

## Events

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events` | List org event logs (paginated, defaults to last 30 days) |

**Query params:** `start`, `end` (date-time), `actingUserId` (uuid), `itemId` (uuid), `secretId` (uuid), `projectId` (uuid), `continuationToken`

**Event fields:** `type` (int), `date`, `itemId`, `collectionId`, `groupId`, `policyId`, `memberId`, `actingUserId`, `installationId`, `device`, `ipAddress`, `secretId`, `projectId`, `serviceAccountId`

## Groups

| Method | Path | Description |
|--------|------|-------------|
| GET | `/groups` | List all groups (includes collection associations) |
| POST | `/groups` | Create a group |
| GET | `/groups/{id}` | Get a group by UUID |
| PUT | `/groups/{id}` | Update a group |
| DELETE | `/groups/{id}` | Delete a group (permanent) |
| GET | `/groups/{id}/member-ids` | List UUIDs of members in this group |
| PUT | `/groups/{id}/member-ids` | Replace group's member associations |

**Group create/update body:** `name` (required), `externalId`, `collections[]` (each with `id`, `readOnly`, `hidePasswords`, `manage`)

**Member IDs update body:** `memberIds` (uuid array)

## Members

| Method | Path | Description |
|--------|------|-------------|
| GET | `/members` | List all org members (includes collection associations) |
| POST | `/members` | Invite a new member |
| GET | `/members/{id}` | Get a member by UUID |
| PUT | `/members/{id}` | Update a member |
| DELETE | `/members/{id}` | Remove member from org (account persists) |
| GET | `/members/{id}/group-ids` | List UUIDs of groups this member belongs to |
| PUT | `/members/{id}/group-ids` | Replace member's group associations |
| POST | `/members/{id}/reinvite` | Resend invitation email |
| POST | `/members/{id}/revoke` | Revoke org access |
| POST | `/members/{id}/restore` | Restore previously revoked member |

**Member create body:** `email` (required), `type` (required), `externalId`, `permissions`, `collections[]`, `groups[]`

**Member update body:** `type` (required), `externalId`, `permissions`, `collections[]`, `groups[]`

**Member response fields:** `id`, `userId`, `name`, `email`, `type`, `status`, `twoFactorEnabled`, `externalId`, `permissions`, `collections[]`, `resetPasswordEnrolled`, `ssoExternalId`

**Member types:** Owner (0), Admin (1), User (2), Custom (4)

**Member statuses:** Invited (0), Accepted (1), Confirmed (2), Revoked (-1)

## Organization

| Method | Path | Description |
|--------|------|-------------|
| GET | `/organization/subscription` | Get subscription details (Password Manager + Secrets Manager) |
| PUT | `/organization/subscription` | Update subscription (seats, storage, autoscale) |
| POST | `/organization/import` | Bulk import members and groups |

**Import body:** `groups[]` (name, externalId, memberExternalIds[]), `members[]` (email, externalId, deleted), `overwriteExisting` (bool), `largeImport` (bool)

## Policies

| Method | Path | Description |
|--------|------|-------------|
| GET | `/policies` | List all org policies |
| GET | `/policies/{type}` | Get a policy by type integer |
| PUT | `/policies/{type}` | Update a policy |

**Policy response fields:** `id`, `type`, `enabled`, `data`, `object`

**Policy update body:** `enabled` (required), `data`, `metadata`

**Policy types:** TwoFactorAuthentication (0), MasterPassword (1), PasswordGenerator (2), SingleOrg (3), RequireSso (4), OrganizationDataOwnership (5), DisableSend (6), SendOptions (7), ResetPassword (8), MaximumVaultTimeout (9), DisablePersonalVaultExport (10), ActivateAutofill (11), AutomaticAppLogIn (12), FreeFamiliesSponsorshipPolicy (13), RemoveUnlockWithPin (14), RestrictedItemTypesPolicy (15), UriMatchDefaults (16), AutotypeDefaultSetting (17), AutomaticUserConfirmation (18), BlockClaimedDomainAccountCreation (19), OrganizationUserNotification (20), SendControls (21)

## Error responses

All endpoints may return:
- `400` with `{ object: "error", message: string, errors?: object }`
- `404` Not Found

## References

- Official docs: https://bitwarden.com/help/api/
- OAuth token endpoints: `https://identity.bitwarden.com/connect/token` (US), `https://identity.bitwarden.eu/connect/token` (EU)
