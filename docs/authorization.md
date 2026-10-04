# Authorization in auth-lib

auth-lib puts authorization data **into the access token**, so backends and
UIs can authorize without asking the database. The store is read only at
**login and refresh**. Admin changes and the startup catalog load also touch
it, but verification and regular requests never do.

## Modes

Set with `AUTH_AUTHZ_MODE`, or `RawConfig::authz_mode`. The default is `rbac`.

| Mode | Token carries | Enabled services |
|---|---|---|
| `none` | identity only | none |
| `rbac` | `rol` (role codes) | `RoleService` |
| `permissions` | `prm`, `pv` | `PermissionService` (user grants) |
| `combined` | `rol`, `prm`, `pv` | both; roles can hold permission grants |

A service outside the active mode returns `AuthError::AuthzModeDisabled`
(HTTP 409 `authz_mode_disabled`).

## Roles (`rbac`, `combined`)

A role has an `id`, an immutable **`code`** (`^[a-z][a-z0-9_.:-]*$`, at most
64 characters), a display `name` and a `description`. Tokens carry the codes
of the user's **active** roles, sorted:

```json
{ "rol": ["billing_admin", "user"] }
```

Check them with `auth.authorizer().has_role(&claims, "billing_admin")`. The
code is the stable identifier for application code and UIs; renaming a role
never changes it.

## Permissions (`permissions`, `combined`)

The application defines a catalog. The library stores it in the
`permissions` and `permission_options` tables. There are four kinds:

| Kind | Value | Example |
|---|---|---|
| `bool` | granted or not | `reports.view` |
| `single` | exactly one option | `region` = `eu` |
| `multi` | any subset of options | `reports.export` = `csv`, `pdf` |
| `text` | string ≤ `max_length` (default 64) | `upload.max_mb` = `250` |

```rust
auth.permissions().define(&NewPermission {
    code: "reports.export".into(),
    kind: PermissionKind::Multi,
    description: None,
    options: vec!["csv".into(), "pdf".into()],
}).await?;
auth.permissions()
    .grant_to_user(user_id, "reports.export", &PermissionValue::Choices(vec!["csv".into()]))
    .await?;

// Request time: no I/O.
let perms = auth.authorizer().permissions(&claims);
perms.allowed("reports.view");
perms.choices("reports.export"); // ["csv"]
perms.choice("region");          // Some("eu")
perms.text("upload.max_mb");     // Some("250")
```

### Combined mode: merge rules

Effective permissions merge the user's direct grants with the grants of the
user's **active** roles:

- **`bool`** is granted if any source grants it.
- **`multi`** is the union of the chosen options.
- **`single` / `text`:** the direct grant wins. Otherwise the role with the
  lexicographically lowest **code** wins.

## Token format (v1)

```json
{
  "rol": ["user"],
  "prm": { "b": "Bg", "t": { "6": "250" } },
  "pv": 6
}
```

Decoded against the catalog example below: `reports.view` is granted (bit 1),
`reports.export` = `csv` (bit 2), and `upload.max_mb` = `250`.
`Bg` = byte `0b0000_0110`.

| Claim | Meaning |
|---|---|
| `pv` | Catalog version the token was encoded against. Present whenever permissions are in use, even if nothing is granted. |
| `prm.b` | Bitset of granted positions. Omitted when empty. |
| `prm.t` | Map from text-permission position (a decimal string key) to value. Omitted when empty. |

**Positions.** Every `bool` permission, every `text` permission, and every
option of a `single` / `multi` permission has a **permanent position**: a
positive integer from one sequence. A position is **never reused**, not even
after a delete.

**Bitset `b`:**
1. For each granted `bool` permission and each chosen option, set bit `p`
   (the position): byte `floor(p / 8)`, bit `p % 8`, least significant bit
   first.
2. Drop trailing zero bytes.
3. Encode as **base64url without padding**. No grants gives an empty string,
   so `b` is omitted.

**Text `t`** maps the text permission's position to its value.

**Decoding**, which UIs implement with the catalog:

```text
bytes = base64url_decode(prm.b or "")
bit(p) = p/8 < len(bytes) and (bytes[p/8] >> (p%8)) & 1

for permission in catalog.permissions:
  bool   → granted if bit(permission.position)
  single → the first option o with bit(o.position)
  multi  → every option o with bit(o.position)
  text   → prm.t[str(permission.position)]
```

Positions the catalog doesn't know are ignored, so decoding fails closed:
not granted.

### The catalog is a separate, cached download

The catalog is **never** inside a token. UIs fetch it once:

```
GET /permissions/catalog   →  PermissionCatalogResponse
```

```json
{
  "version": 6,
  "permissions": [
    { "code": "reports.view",   "kind": "bool",   "position": 1, "max_length": null, "options": [] },
    { "code": "reports.export", "kind": "multi",  "position": null, "max_length": null,
      "options": [ { "code": "csv", "position": 2 }, { "code": "pdf", "position": 3 } ] },
    { "code": "upload.max_mb",  "kind": "text",   "position": 6, "max_length": 8, "options": [] }
  ]
}
```

Keep it cached, for example in `localStorage` keyed by `version`. **Refetch
only when a token's `pv` exceeds the cached `version`.** The version is the
highest position in use. It grows when something is added; deletions never
require a refetch.

The backend serves this response from memory, through
`api::handlers::permission_catalog`.

## When changes take effect

Authorization data is a **snapshot taken at login and refresh**. A role
assignment, revocation or permission grant reaches the user's token at the
next refresh, which happens within the access-token TTL (5 min by default).

Backends decode with an in-memory `CatalogCache`:
- It's loaded by `auth.start()`.
- It's updated by catalog changes made through this instance.
- It's reloaded when another instance pushes `catalog_changed` (see
  [`cluster.md`](cluster.md)), and by any login or refresh that sees a newer
  catalog version.

Role and permission grants still take effect at the user's next refresh.
They change what the next token carries, and the old token stays valid
until it expires. To cut a user off immediately, revoke their sessions
(`TokenRevocationService`); the revocation is pushed to every instance at
once.
