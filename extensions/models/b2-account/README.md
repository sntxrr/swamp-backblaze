# @sntxrr/b2-account

A [swamp](https://swamp-club.com) model that turns a whole **Backblaze B2
account** into queryable, typed state. It is the **read-only root** of the
`@sntxrr/b2/*` suite: one factory method, `scan`, inventories every bucket and
every application key the credentials can see.

Wraps the [B2 Native API v4](https://www.backblaze.com/apidocs/b2-native-api)
(`/b2api/v4`) using only Deno's built-in `fetch` — no SDK, no `b2` CLI shell-out.

Model type: `@sntxrr/b2/account`

> **This model never mutates.** Bucket and key lifecycle live in
> `@sntxrr/b2/bucket` and `@sntxrr/b2/key`. Provisioning a host's backup target
> spans both domains, so it is a workflow, not a method here.

## Methods

| Method | What it does                                                                                                                                                                |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan` | Factory discovery — authorize once, then snapshot every bucket (`b2_list_buckets`), every application key (`b2_list_keys`), and an account-level summary. Read-only.        |

`scan` writes three kinds of resource:

| Spec      | Instance name              | Contains                                                                                                                                                    |
| --------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bucket`  | `bucket-<bucketName>`      | `bucketId`, `bucketType`, `bucketInfo`, `corsRules`, `lifecycleRules`, `fileLockConfiguration`, `defaultServerSideEncryption`, `replicationConfiguration`, `options`, `revision` |
| `key`     | `key-<applicationKeyId>`   | `keyName`, `capabilities`, `bucketIds`, `namePrefix`, `expirationTimestamp`, `options`                                                                      |
| `account` | `account-<accountId>`      | `bucketCount`, `keyCount`, `truncated`, `keysTruncated`, cluster URLs, and the scanning key's own grant                                                      |

> **Instance names are spec-prefixed on purpose.** All three specs are written
> by one `scan` into a single flat storage namespace, and B2 bucket names are
> user-chosen (6–63 lowercase alphanumerics and hyphens) — so a bucket may
> legally be named exactly a 12-character account ID or a 25-character
> application key ID. Without the prefix that bucket's snapshot would silently
> clobber the `key` or `account` snapshot on disk. Address a snapshot by its
> full instance name:
>
> ```
> ${{ data.latest("homelab", "bucket-restic-host-a").attributes.bucketId }}
> ${{ data.latest("homelab", "account-4a48fe8875c6214145260818").attributes.keyCount }}
> ```
>
> A bucket named literally `latest` (a reserved swamp data name) falls back to
> its bucket ID, giving `bucket-<bucketId>`.

The `credentials-present` pre-flight check (label `policy`) validates that both
halves of the application key are set. This model has no mutating verb, so the
check never auto-fires — run it explicitly when diagnosing an empty inventory.

## Required B2 capabilities

| To get                    | The key needs |
| ------------------------- | ------------- |
| `bucket` resources        | `listBuckets` |
| `key` resources           | `listKeys`    |
| `account` summary         | (none beyond authorize) |

A key that lacks a capability fails with `401 unauthorized`. That is **not**
transient and is deliberately not retried — fix the key's grant instead.

A **bucket-scoped** key (which is what every per-host restic key is) can see
only its own bucket and usually lacks `listKeys` entirely. Use a key with
account-wide `listBuckets` + `listKeys` for a real audit; the `account`
summary's `allowedBuckets` and `allowedCapabilities` tell you which kind of key
produced any given scan.

## Setup

```bash
# Store the B2 application key in a vault — never inline it
swamp vault create local_encryption b2
swamp vault put b2 B2_APPLICATION_KEY   # paste the application key

# Register the account
swamp model create @sntxrr/b2/account homelab \
  --global-arg 'applicationKeyId=0021a2b3c4d5e6f0000000001' \
  --global-arg 'applicationKey=${{ vault.get(b2, B2_APPLICATION_KEY) }}'
```

## Usage

```bash
# Full inventory
swamp model @sntxrr/b2/account method run scan homelab

# Private buckets only, with a larger key page (fewer billed calls)
swamp model @sntxrr/b2/account method run scan homelab \
  --input 'bucketTypes=["allPrivate"]' \
  --input 'maxKeyCount=5000'

# Read the results back
swamp model get homelab --json
```

## Global arguments

| Arg                | Required | Default                       | Description                                                                          |
| ------------------ | -------- | ----------------------------- | -------------------------------------------------------------------------------------- |
| `applicationKeyId` | yes      | —                             | B2 application key ID (master or scoped)                                             |
| `applicationKey`   | yes      | —                             | B2 application key (**sensitive** — wire from a vault)                               |
| `authHost`         | no       | `https://api.backblazeb2.com` | Override the authorize host (testing only)                                           |

Only `b2_authorize_account` uses `authHost`. Every other call goes to the
cluster-specific `apiUrl` returned by that response — it is never guessed or
hardcoded.

## Method arguments (`scan`)

| Arg           | Default | Description                                                                                     |
| ------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `bucketTypes` | (all)   | Filter `b2_list_buckets`, e.g. `["allPrivate"]`. Omitted entirely from the request when unset.  |
| `maxKeyCount` | `1000`  | Application keys per `b2_list_keys` page (B2 max `10000`, B2 default `100`).                    |
| `maxKeyPages` | `50`    | Hard cap on key pages. Hitting it sets `truncated` rather than silently returning a partial set. |

## Cost — every listing is billed

`b2_list_buckets`, `b2_list_keys`, and `b2_authorize_account` are all **class C
transactions**, billed per 1000. A `scan` costs `2 + ceil(keys / maxKeyCount)`
of them, so a nightly scan is a small but recurring bill. Raising `maxKeyCount`
lowers the page count; it does not change what is returned.

> **Truncation is loud on purpose.** If the key listing hits `maxKeyPages`, the
> `account` summary sets `truncated: true` and `scan` logs a warning. While that
> flag is set, a missing key in the inventory is **not** evidence the key was
> deleted — it may simply be past the cap. Raise `maxKeyPages` and re-scan
> before acting on an absence.

## v4 response-shape notes

Most B2 examples online are v2/v3 and are **wrong** for v4:

- `b2_authorize_account` nests the cluster URLs and the key's grant under
  `apiInfo.storageApi`, not at the top level.
- `allowed.buckets` (authorize) and `bucketIds` (list keys) are **arrays**. v2's
  scalar `bucketId`/`bucketName` were removed, so code reading
  `allowed.bucketId` silently gets `undefined`. A bucket-scoped key appears as a
  one-element array.
- `b2_list_buckets` returns the entire account in **one** response with no
  cursor. `b2_list_keys` is cursor-paginated
  (`nextApplicationKeyId` → `startApplicationKeyId`).
- `fileLockConfiguration` and `defaultServerSideEncryption` are wrapped by B2 as
  `{ isClientAuthorizedToRead, value }` and are filtered by the calling key's
  capabilities. They are carried through verbatim.

## Security

- `applicationKey` is marked sensitive and is only ever sent as the `Basic`
  authorize header.
- The 24h `authorizationToken` is a bearer credential. It is never written to a
  resource or a log line — asserted by a unit test that scans every snapshot and
  every log line for both secrets.
- `b2_list_keys` does not return key material; only `b2_create_key` does, and
  that lives in `@sntxrr/b2/key`.
- `bucketInfo` is arbitrary user-supplied bucket metadata and is stored verbatim
  in the snapshot. Do not put credentials in it.

## Development

```bash
DENO=~/.swamp/deno/deno
$DENO check b2_account.ts
$DENO test  b2_account_test.ts
swamp extension fmt     manifest.yaml --check
swamp extension quality manifest.yaml --json
```

## License

MIT — see [LICENSE.md](./LICENSE.md).
