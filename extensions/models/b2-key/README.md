# @sntxrr/b2-key

A [swamp](https://swamp-club.com) model for a **Backblaze B2 application key** —
one model instance per key, keyed by its real `applicationKeyId`. Wraps the
[B2 Native API v4](https://www.backblaze.com/apidocs/b2-create-key) using only
Deno's built-in `fetch` — no SDK.

Model type: `@sntxrr/b2/key`.

> **v4, not v2/v3.** `b2_authorize_account` nests everything under
> `apiInfo.storageApi`, the cluster-specific `apiUrl` there is where every other
> call goes, `allowed.buckets` is an **array**, and the bucket restriction field
> is **`bucketIds` (plural)** — v4 removed the singular `bucketId`. Most online
> examples are v2 and are wrong on all four counts.

## The one-shot secret

B2 returns the `applicationKey` **secret exactly once**, in the `b2_create_key`
response. It is never retrievable again — not by `b2_list_keys`, not by anything
else. This model handles that explicitly:

- **The resource snapshot holds metadata only**: `applicationKeyId`, `keyName`,
  `capabilities`, `bucketIds`, `namePrefix`, `expirationTimestamp`, `options`,
  `accountId`. The snapshot schema has **no field capable of holding the
  secret**, and the mapper never reads `applicationKey` out of a response. This
  matters because swamp resources sync to a remote S3 datastore.
- **The secret goes to 1Password Connect**, written directly by `create` to a
  named item field. `secretDestination` on the snapshot records *where* it
  landed (`op://<vaultId>/<itemId>/<field>`), never the value.
- **`create` fails closed.** With no Connect destination configured it refuses to
  mint at all, before a single B2 call. A key minted with nowhere to put its
  secret is a key nobody can ever use and which must immediately be revoked —
  so this model does not mint-then-discard, and never prints the secret to a
  log as a fallback.

`authorizationToken` (a 24h bearer credential) and `connectToken` are likewise
never written to a snapshot or a log line. All of this is asserted by tests.

## Methods

| Method   | What it does                                                                                                   |
| -------- | ---------------------------------------------------------------------------------------------------------------- |
| `sync`   | Locate the managed key with `b2_list_keys` and snapshot its metadata. Records `status: absent` if it is gone     |
| `create` | Mint a key with `b2_create_key` and deliver the one-shot secret to 1Password Connect. Refuses to run without one |
| `delete` | Revoke the managed key with `b2_delete_key`. Idempotent — an already-absent key is success                      |

`create` and `delete` auto-run the pre-flight checks below.

## Required B2 capabilities

| Method   | Capabilities on the **calling** key |
| -------- | ------------------------------------- |
| `sync`   | `listKeys`                            |
| `create` | `writeKeys` (and `listKeys`)          |
| `delete` | `deleteKeys` **and** `listKeys`       |

`delete` needs `listKeys` as well as `deleteKeys`: it verifies the key exists
before revoking it, which is what makes it genuinely idempotent. B2 documents no
`404` and no dedicated "key not found" code for `b2_delete_key`, so absence
cannot be inferred from the failure alone — and treating every generic `400
bad_request` as "already gone" would swallow real request bugs.

> **A key can never be granted a capability its creator lacks.** Minting a
> bucket-scoped key from an already-scoped key is the usual cause of a confusing
> `401 unauthorized`. That `401` is a permanent authorization failure, **not**
> transient, and is never retried — only `401 expired_auth_token` triggers a
> re-authorization.

## Pre-flight checks

| Check                           | Label    | Applies to | What it enforces                                                    |
| ------------------------------- | -------- | ---------- | ------------------------------------------------------------------- |
| `secret-destination-configured` | `policy` | `create`   | The 1Password Connect global arguments form a complete destination  |
| `connect-reachable`             | `live`   | `create`   | Connect answers and exposes the destination vault, before minting   |

Both are scoped to `create`, so `delete` never requires Connect configuration.
Checks can be bypassed with `--skip-checks`, so `create` re-validates the
destination itself — the check is a fast gate, the in-method guard is
authoritative.

## Setup

```bash
# B2 credentials
swamp vault create local_encryption b2
swamp vault put b2 B2_APPLICATION_KEY_ID
swamp vault put b2 B2_APPLICATION_KEY

# 1Password Connect token (the only outlet for the one-shot secret)
swamp vault put b2 OP_CONNECT_TOKEN

swamp model create @sntxrr/b2/key restic-example \
  --global-arg 'applicationKeyId=${{ vault.get(b2, B2_APPLICATION_KEY_ID) }}' \
  --global-arg 'applicationKey=${{ vault.get(b2, B2_APPLICATION_KEY) }}' \
  --global-arg 'connectHost=http://connect.example.com:8080' \
  --global-arg 'connectToken=${{ vault.get(b2, OP_CONNECT_TOKEN) }}' \
  --global-arg 'connectVaultTitle=homelab' \
  --global-arg 'connectItemTitle=b2-restic-example'
```

Connect cannot read the built-in Private/Personal/Employee or the default Shared
vault — the item must live in a vault the Connect token was granted.

## Usage

```bash
# Read-only: locate the managed key and snapshot its metadata
swamp model @sntxrr/b2/key method run sync restic-example

# Mint a bucket-scoped key; the secret lands in 1Password, never in swamp
swamp model @sntxrr/b2/key method run create restic-example \
  --input 'keyName=restic-example' \
  --input 'capabilities=["listBuckets","listFiles","readFiles","writeFiles","deleteFiles"]' \
  --input 'bucketIds=["4a48fe8875c6214145260818"]'

# Revoke it (idempotent)
swamp model @sntxrr/b2/key method run delete restic-example
```

After `create`, pin the new key on the model so `sync` and `delete` can find it:

```bash
swamp model get restic-example --json | jq -r '.resources.key | keys[]'
# then set --global-arg 'managedKeyId=<applicationKeyId>'
```

## Global arguments

| Arg                      | Required    | Default            | Description                                                              |
| ------------------------ | ----------- | ------------------ | ------------------------------------------------------------------------ |
| `applicationKeyId`       | yes         | —                  | B2 key ID used to authenticate this model                                |
| `applicationKey`         | yes         | —                  | B2 application key (sensitive; wire from a vault)                        |
| `authHost`               | no          | B2 well-known host | Override the authorize host (testing only)                               |
| `accountId`              | no          | from authorize     | B2 account ID; the authorize response is correct for normal setups       |
| `managedKeyId`           | conditional | —                  | `applicationKeyId` of the managed key. Required by `sync` and `delete`   |
| `maxKeyCount`            | no          | B2 default (100)   | `b2_list_keys` page size, max 10000. Every list call is class C          |
| `connectHost`            | for `create`| —                  | 1Password Connect base URL                                               |
| `connectToken`           | for `create`| —                  | Connect API token (sensitive; wire from a vault)                         |
| `connectVaultId`         | for `create`| —                  | Destination vault UUID (or use `connectVaultTitle`)                      |
| `connectVaultTitle`      | for `create`| —                  | Destination vault title, resolved to a UUID when `connectVaultId` is unset |
| `connectItemTitle`       | for `create`| —                  | Destination item title; created if absent. Overridable per run           |
| `connectItemCategory`    | no          | `API_CREDENTIAL`   | Category used when the item has to be created                            |
| `connectKeyIdFieldLabel` | no          | `applicationKeyId` | Item field receiving the non-secret key ID                               |
| `connectKeyFieldLabel`   | no          | `applicationKey`   | Item field receiving the secret, written `CONCEALED`                     |
| `connectTimeoutMs`       | no          | `10000`            | Per-call Connect timeout                                                 |

## Create inputs

| Input                    | Required | Description                                                                |
| ------------------------ | -------- | -------------------------------------------------------------------------- |
| `keyName`                | yes      | Letters, numbers and `-` only, max 100 chars. A label, not an identifier   |
| `capabilities`           | yes      | Capability strings granted to the new key                                  |
| `bucketIds`              | no       | **Plural** v4 multi-bucket restriction                                     |
| `namePrefix`             | no       | File-name prefix restriction; applies across all buckets unless `bucketIds` is also set |
| `validDurationInSeconds` | no       | Expire after N seconds (B2 max `86400000`, ~1000 days)                     |
| `itemTitle`              | no       | Per-run override of `connectItemTitle`                                     |
| `allowDuplicateName`     | no       | Mint even when a key of that name exists (default `false` — see below)     |

**B2 key names are not unique and are not identifiers.** Re-running `create`
would therefore mint a *second* key, overwrite the secret in 1Password, and
leave the first key live, billable and unreachable. `create` refuses by default:
it checks for a name clash before minting and names the offending key IDs. Pass
`allowDuplicateName=true` only when two same-named keys are genuinely intended.

If the secret cannot be delivered after the key is minted, `create` records the
key with `secretDelivered: false` **and then fails** — so an orphaned credential
is visible in swamp rather than only in a scrollback error — and tells you to
revoke it.

An unknown capability is warned about, not rejected — B2 stays the authority, so
a capability Backblaze adds later works without a model release.

## Cost note

`b2_list_keys` is a **class C** transaction, billed per 1000. `sync` costs one
per page, and `delete` costs one drain for its existence check. Raise
`maxKeyCount` rather than paging.

## Connect's destructive replace

1Password Connect's item update (`PUT /v1/vaults/{vaultId}/items/{itemId}`)
**replaces the entire field set**: any field omitted from the payload is silently
deleted. This model always GETs the item first and re-sends every pre-existing
field — preserving each field's `id`, `type`, `purpose` and `section` — updating
only the two target labels. A dedicated test asserts unrelated fields survive.

## Development

```bash
DENO=~/.swamp/deno/deno
$DENO check b2_key.ts
$DENO test --allow-net b2_key_test.ts
swamp extension fmt     manifest.yaml --check
swamp extension quality manifest.yaml --json
```

## License

MIT — see [LICENSE.md](./LICENSE.md).
