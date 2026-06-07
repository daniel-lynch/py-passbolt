# Passbolt v5 API notes (encrypted metadata)

Discovery notes for adding v5 support to py-passbolt. Everything below was
**validated end-to-end against Passbolt CE 5.12.0** using the scripts in
`.devstack/v5/` (`probe.py`, `v5_e2e.py`). These are working notes for the v5
implementation effort, not user docs.

## TL;DR

- The legacy GPGAuth login this SDK already uses **still works** on v5.
- A **fresh v5.12 instance defaults to v4 cleartext** resources. v5 encrypted
  metadata is **opt-in** by an admin. This is why the current v3-targeted SDK
  keeps working against stock v5 instances.
- The big change: for v5 resources, `name`/`username`/`uri`/`description` move
  out of cleartext columns into an **encrypted `metadata` blob**. Cleartext
  columns come back `null`. Lookups by name therefore require decrypting
  metadata first.
- An instance can hold **both v4 and v5 resources at once**, so the client must
  detect the format per resource.

## Instance configuration

`GET /metadata/types/settings.json` (defaults on a fresh 5.12 CE):

```json
{
  "default_resource_types": "v4",
  "allow_creation_of_v5_resources": false,
  "allow_creation_of_v4_resources": true,
  "allow_v4_v5_upgrade": false,
  "allow_v5_v4_downgrade": false
  // ... folder/tag/comment variants
}
```

To enable v5 (admin only): `POST /metadata/types/settings.json` with the same
object, setting `default_resource_types: "v5"` and
`allow_creation_of_v5_resources: true`.

**Ordering gotcha:** enabling v5 settings fails with *"An active metadata key
could not be found, create a key first"* — you must create the shared metadata
key (below) **before** flipping the settings.

## Resource types

`GET /resource-types.json` returns both v4 and v5 types. IDs are stable across
instances. Confirmed on 5.12.0:

| slug | id |
|---|---|
| `password-string` (v4 simple) | `669f8c64-242a-59fb-92fc-81f660975fd3` |
| `password-and-description` (v4) | `a28a04cd-6f53-518a-967c-9963bf9cec51` |
| `password-description-totp` (v4) | `8cca88d9-a3f6-56df-b860-3ef08de5c5c4` |
| `totp` (v4) | `05ba5c75-504d-5ad6-819a-83af68867d86` |
| `v5-default` | `dd1f723d-0d1e-513f-8218-4055dc0530d0` |
| `v5-password-string` | `761e5863-e17e-5ded-b3c2-76ffd5d0a2dc` |
| `v5-default-with-totp` | `7438294d-f71c-5164-ba95-d9e60e295564` |
| `v5-totp-standalone` | `bb2280b5-c4d9-569c-9337-62b307f1139c` |
| `v5-note` | `0a72c76b-b8e6-53f0-8bef-0a8ca6b5c764` |
| `v5-pin-code` | `4357bbc7-ed4d-52ff-b59d-9f7f17881bb3` |
| `v5-custom-fields` | `0551544e-2ccd-5ce8-95cf-86f0aab0f827` |

Each type carries a JSON-schema `definition` for both `resource` (the metadata
shape) and `secret`. For `v5-default` the metadata fields are `name` (required),
`username`, `uris` (array, max 32), `description`, `icon`.

## Shared metadata key

`POST /metadata/keys.json` (admin):

```json
{
  "fingerprint": "<40-hex fingerprint of the metadata key>",
  "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK----- ...",
  "metadata_private_keys": [
    {
      "user_id": "<user uuid>",
      "data": "-----BEGIN PGP MESSAGE----- ..."   // see below, encrypted to that user
    }
  ]
}
```

Each `metadata_private_keys[].data` is a PGP message **encrypted to that user's
personal key**. Its plaintext is JSON (`object_type` `PASSBOLT_METADATA_PRIVATE_KEY`):

```json
{
  "object_type": "PASSBOLT_METADATA_PRIVATE_KEY",
  "domain": "https://passbolt.example.com",
  "fingerprint": "<metadata key fingerprint>",
  "armored_key": "-----BEGIN PGP PRIVATE KEY BLOCK----- ...",
  "passphrase": ""
}
```

So every user who needs to read shared metadata gets their own encrypted copy of
the shared **private** key. Response returns the created key incl. its `id`
(= `metadata_key_id`).

Fetch later: `GET /metadata/keys.json?contain[metadata_private_keys]=1`. The
client decrypts its `data` with its personal key, imports the metadata private
key, and uses it for metadata encrypt/decrypt.

> Note: in this PoC the metadata key was generated *with* a passphrase (carried
> in the `passphrase` field). Passbolt's own clients may generate it without a
> passphrase (`passphrase: ""`). Either works since the whole blob is itself
> encrypted to the user; the SDK should read/write the `passphrase` field rather
> than assume.

## Creating a v5 resource

`POST /resources.json`:

```json
{
  "resource_type_id": "dd1f723d-0d1e-513f-8218-4055dc0530d0",
  "metadata": "-----BEGIN PGP MESSAGE----- ...",
  "metadata_key_id": "<metadata key uuid>",
  "metadata_key_type": "shared_key",
  "secrets": [{ "data": "-----BEGIN PGP MESSAGE----- ..." }]
}
```

- `metadata_key_type` ∈ `shared_key` | `user_key`.
  - `shared_key`: `metadata` encrypted to the shared metadata key; `metadata_key_id`
    is the shared key's id. Use for shared (or shareable) resources.
  - `user_key`: `metadata` encrypted to the **owner's own** key (personal
    resources). `metadata_key_id` is null / the user's key id.
- `metadata` plaintext is JSON (`object_type` `PASSBOLT_RESOURCE_METADATA`):

```json
{
  "object_type": "PASSBOLT_RESOURCE_METADATA",
  "resource_type_id": "dd1f723d-0d1e-513f-8218-4055dc0530d0",
  "name": "...",
  "username": "...",
  "uris": ["https://..."],
  "description": "..."
}
```

- `secrets[].data` plaintext for `v5-default` is JSON
  (`object_type` `PASSBOLT_SECRET_DATA`): `{ "object_type": "PASSBOLT_SECRET_DATA",
  "password": "...", "description": "..." }`, encrypted to each recipient (as today).

## Reading v5 resources

`GET /resources.json` returns v5 resources with cleartext `name`, `username`,
`uri` = **`null`** and the encrypted `metadata` + `metadata_key_id` +
`metadata_key_type` populated. To get the human-readable fields the client must
decrypt `metadata` (with the user key for `user_key`, or the imported shared
metadata key for `shared_key`).

**Implication for the SDK:** `getpassword`, `__getresource`, `__getresourceid`
currently match on `resource["name"]`. For v5 they must decrypt each resource's
metadata first and match on the decrypted name. This is the most invasive change
and motivates a metadata/session-key cache.

## Endpoint map (Metadata plugin)

```
GET/POST  /metadata/types/settings.json      v4/v5 type policy
GET/POST  /metadata/keys/settings.json       key policy (zero-knowledge vs server)
GET       /metadata/keys.json                 list shared metadata keys (+contain[metadata_private_keys])
POST      /metadata/keys.json                 create shared metadata key
PUT/DEL   /metadata/keys/{id}.json
POST      /metadata/keys/{id}/private.json    add a user's encrypted private key copy
POST      /metadata/keys/privates.json        share missing private keys to users
GET/POST  /metadata/session-keys.json         per-user session-key cache (perf)
POST      /metadata/upgrade/...               migrate v4 -> v5 content
POST      /metadata/rotate-key/...            rotate the shared metadata key
```

## Open decisions for implementation

1. **`user_key` vs `shared_key` default**: personal resources can use `user_key`
   (no shared key needed). Shared resources need `shared_key`. The SDK likely
   wants `shared_key` by default so resources are shareable, but should support
   both. (PoC validated `shared_key`.)
2. **Format detection**: branch on instance settings + per-resource
   `metadata`/`metadata_key_type` presence to stay compatible with v4.
3. **Session-key cache**: decrypting metadata for every resource on every lookup
   is expensive; use `/metadata/session-keys.json` and/or an in-memory cache.
4. **Metadata key bootstrap in CI**: the integration stack must create the shared
   metadata key + enable v5 before tests (see `.devstack/v5/v5_e2e.py` for the
   working sequence).

## Reproduce

```
cd .devstack/v5
docker compose up -d                       # passbolt 5.12 on :8090
# bootstrap two users (PASSBOLT_BASE_URL etc. point here)
python probe.py                            # dump settings / types / keys
python v5_e2e.py                           # full encrypted-metadata round trip
```
