# Plan: full Passbolt v5 (encrypted metadata) support

Implementation brief for adding v5 support to py-passbolt. The confirmed API
shapes this plan relies on are in [`v5-api-notes.md`](./v5-api-notes.md)
(validated end-to-end against Passbolt CE 5.12.0).

## Framing

v5 support is **additive, not a rewrite**. A stock v5 instance defaults to v4
cleartext; encrypted metadata is admin opt-in, so the current SDK keeps working.
The work is to *also* handle the encrypted-metadata format when an instance uses
it, while detecting v4 vs v5 per resource.

The single most invasive change: for v5 resources `name`/`username`/`uri` are
`null` on the server (they live in the encrypted `metadata` blob), so
**lookup-by-name requires decrypting metadata first**. This touches nearly every
method.

## Phases

### Phase 0 — Discovery & test bed ✅ DONE
- Ephemeral v5.12 stack + bootstrap (`.devstack/v5/`).
- Confirmed all payloads/endpoints; full encrypted-metadata round trip proven
  (`.devstack/v5/v5_e2e.py`). See `v5-api-notes.md`.

### Phase 1 — Metadata key plumbing + read path  *(Opus)*
- Probe instance config (`/metadata/types/settings.json`): is v5 enabled, what's
  the default type.
- Fetch + decrypt + cache the shared metadata key
  (`GET /metadata/keys.json?contain[metadata_private_keys]=1`); import the
  metadata private key; read the `passphrase` field rather than assuming.
- Helpers: `__encrypt_metadata` / `__decrypt_metadata`; per-resource format
  detection (v4 vs v5 via `metadata_key_type`/`metadata` presence).
- Rework `getpassword`, `__getresource`, `__getresourceid` to decrypt metadata
  and match on decrypted name. **Riskiest piece** — correctness + perf (N
  decryptions per lookup → needs the metadata/session-key cache).

### Phase 2 — Write path  *(Opus)*
- `createpassword` / `updatepassword`: build the `PASSBOLT_RESOURCE_METADATA`
  blob, encrypt it, set `metadata`, `metadata_key_id`, `metadata_key_type`.
  Choose `user_key` (personal) vs `shared_key` (shareable) — default
  `shared_key`.
- `sharepassword`: when sharing a `user_key` resource, the metadata must be
  re-encrypted to the shared key (or recipients given access to it). Mirror the
  existing secret re-encryption.
- Secrets for v5 types use the `PASSBOLT_SECRET_DATA` JSON shape.

### Phase 3 — Backward-compat & public surface  *(Sonnet)*
- Auto-detect v4 vs v5 so existing callers are unaffected.
- Keep `name=`/`username=`/`uri=` kwargs, mapping them into metadata
  transparently for v5. Document the `uris` array (v5 supports multiple URIs).
- Bump to **2.0** (behavioural change) with a clear changelog.

### Phase 4 — Tests & CI  *(Sonnet)*
- Mock unit tests for v5 paths (metadata encrypt/decrypt, key selection, format
  detection) following the existing `tests/test_unit.py` patterns.
- Matrix the integration workflow: one job on a **v4-cleartext** instance, one on
  a **v5-encrypted-metadata** instance (bootstrap must create the metadata key +
  enable v5 first — see `.devstack/v5/v5_e2e.py` for the working sequence).

### Phase 5 — Docs & release  *(Sonnet)*
- README v5 section, migration notes, version bump, changelog.

## Model split

- **Opus: Phase 1–2.** Cryptographic correctness (encrypt metadata/secrets to the
  right keys) and the invasive metadata-decryption rework — high blast radius.
- **Sonnet: Phase 3–5**, once helpers exist and tests define "correct."
  Backward-compat wiring, additional tests on an established pattern, docs, CI
  matrix — low ambiguity.

Handoff rule: once a passing test defines correct behaviour, Sonnet can extend
safely; until then the crypto/discovery work stays on Opus.

## Sequencing note

Hold Phase 1+ until there is a v5 test instance in CI (Phase 4's bootstrap), or
develop against the local `.devstack/v5/` stack. Don't ship v5 write paths
without the e2e matrix green on both formats.
