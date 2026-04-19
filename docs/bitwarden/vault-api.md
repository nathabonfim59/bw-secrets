# Bitwarden Vault Management API Reference

Local API served by the Bitwarden CLI (`bw serve`). Requires an unlocked vault session.

## Lock & Unlock

| Method | Path | Description |
|--------|------|-------------|
| POST | `/lock` | Lock the vault (destroys session key) |
| POST | `/unlock` | Unlock the vault with master password |

**Unlock body:** `{ "password": "..." }` — returns a session key in `data.raw`.

## Vault Items

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list/object/items` | List vault items (supports filters) |
| POST | `/object/item` | Create a new item |
| GET | `/object/item/{id}` | Get an item by UUID |
| PUT | `/object/item/{id}` | Replace an item (full object required) |
| DELETE | `/object/item/{id}` | Send item to trash |
| POST | `/restore/item/{id}` | Restore item from trash |

**List query params:** `organizationId`, `collectionId`, `folderid`, `url`, `trash`, `search`

Multiple filters apply OR logic. Filters + search applies AND logic.

**Item types:** Login (1), Secure Note (2), Card (3), Identity (4)

**Item body structure:**

| Field | Type | Notes |
|-------|------|-------|
| `organizationId` | uuid? | Org this item belongs to |
| `collectionIds` | uuid[] | Collections to add to |
| `folderId` | uuid? | Folder assignment |
| `type` | int | 1=login, 2=note, 3=card, 4=identity |
| `name` | string | Item name |
| `notes` | string? | Free-text notes |
| `favorite` | bool | Marked as favorite |
| `fields` | array | Custom fields |
| `login` | object | Login data (type 1 only) |
| `secureNote` | object | `{ type: 0 }` (type 2 only) |
| `card` | object | Card data (type 3 only) |
| `identity` | object | Identity data (type 4 only) |
| `reprompt` | int | 0=off, 1=on (master password reprompt) |

**Login fields:** `uris[]` (match, uri), `username`, `password`, `totp`

**Card fields:** `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code`

**Identity fields:** `title`, `firstName`, `middleName`, `lastName`, `address1`-`address3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`, `licenseNumber`

**Custom field types:** Text (0), Hidden (1), Boolean (2), Linked (3)

## Attachments & Item Fields

| Method | Path | Description |
|--------|------|-------------|
| POST | `/attachment?itemid={id}` | Upload file attachment (multipart/form-data) |
| GET | `/object/attachment/{id}?itemid={id}` | Download an attachment |
| DELETE | `/object/attachment/{id}?itemid={id}` | Delete an attachment |
| GET | `/object/username/{id}` | Get username from a login item |
| GET | `/object/password/{id}` | Get password from a login item |
| GET | `/object/uri/{id}` | Get first URI from a login item |
| GET | `/object/totp/{id}` | Get current TOTP code for a login item |
| GET | `/object/notes/{id}` | Get notes from any item |
| GET | `/object/exposed/{id}` | Check how many times the password appeared in breaches |

## Folders

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list/object/folders` | List all folders (optional `search` param) |
| POST | `/object/folder` | Create folder |
| GET | `/object/folder/{id}` | Get folder by UUID |
| PUT | `/object/folder/{id}` | Rename folder |
| DELETE | `/object/folder/{id}` | Delete folder (items are NOT deleted) |

**Folder body:** `{ "name": "..." }`

## Send

Only text sends supported.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list/object/send` | List sends (optional `search` param) |
| POST | `/object/send` | Create a send |
| GET | `/object/send/{id}` | Get send by UUID |
| PUT | `/object/send/{id}` | Replace send (full object required) |
| DELETE | `/object/send/{id}` | Delete send |
| POST | `/send/{id}/remove-password` | Remove password protection from send |

**Send body:** `name`, `notes`, `type` (0=text), `text: { text, hidden }`, `maxAccessCount`, `deletionDate`, `expirationDate`, `password`, `emails[]`, `disabled`, `hideEmail`

## Collections & Organizations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/list/object/organizations` | List orgs you belong to (optional `search`) |
| GET | `/list/object/collections` | List collections across all orgs (optional `search`) |
| GET | `/list/object/org-collections?organizationId={id}` | List collections for one org (optional `search`) |
| GET | `/list/object/org-members?organizationId={id}` | List members of an org |
| POST | `/object/org-collection?organizationId={id}` | Create org collection |
| GET | `/object/org-collection/{id}?organizationId={id}` | Get org collection |
| PUT | `/object/org-collection/{id}?organizationId={id}` | Update org collection |
| DELETE | `/object/org-collection/{id}?organizationId={id}` | Delete org collection (items NOT deleted) |
| POST | `/move/{itemid}/{organizationId}` | Move item to org collections |
| POST | `/confirm/org-member/{id}?organizationId={id}` | Confirm a pending org member |

**Org collection body:** `organizationId`, `name`, `externalId`, `groups[]` (id, readOnly, hidePasswords)

**Move body:** array of collection UUIDs

## Trusted Device Approval

| Method | Path | Description |
|--------|------|-------------|
| GET | `/device-approval/{orgId}` | List pending device requests |
| POST | `/device-approval/{orgId}/approve/{requestId}` | Approve one request |
| POST | `/device-approval/{orgId}/approve-all` | Approve all pending |
| POST | `/device-approval/{orgId}/deny/{requestId}` | Deny one request |
| POST | `/device-approval/{orgId}/deny-all` | Deny all pending |

**Device approval fields:** `id`, `userId`, `organizationUserId`, `email`, `requestDeviceIdentifier`, `requestDeviceType`, `requestIpAddress`, `creationDate`

## Miscellaneous

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sync` | Sync vault with server |
| GET | `/status` | CLI status (serverUrl, lastSync, userEmail, userId, status) |
| GET | `/generate` | Generate password or passphrase |
| GET | `/object/template/{type}` | Get JSON template for an object type |
| GET | `/object/fingerprint/me` | Get your account fingerprint phrase |

**Status values:** `unauthenticated`, `locked`, `unlocked`

**Generate params (password):** `length`, `uppercase`, `lowercase`, `number`, `special`

**Generate params (passphrase):** `passphrase=true`, `words`, `separator`, `capitalize`, `includeNumber`

Default: 14-char password with uppercase, lowercase, and numbers.

**Template types:** `item`, `item.field`, `item.login`, `item.login.uri`, `item.card`, `item.identity`, `item.securenote`, `folder`, `collection`, `item-collections`, `org-collection`

## Common response envelope

```json
{
  "success": true,
  "data": { ... },
  "revisionDate": "...",
  "deleteDate": null
}
```

## Error codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request |
| 404 | Not Found |
| 500 | Internal Server Error |

## References

- Official docs: https://bitwarden.com/help/vault-management-api/
- CLI docs: https://bitwarden.com/help/cli/
