# @sntxrr/b2-bucket

A [swamp](https://swamp-club.com) model for a **single Backblaze B2 bucket**,
keyed by its real bucket name. Wraps the
[B2 Native API v4](https://www.backblaze.com/apidocs/) using only Deno's built-in
`fetch` — no SDK, no npm dependencies beyond zod.

Model type: **`@sntxrr/b2/bucket`**

## Why lifecycle rules are the point of this model

`restic forget --prune` deletes pack files from a B2 bucket. B2 does not
actually remove them — it keeps each one as a **hidden version, forever**, unless
the bucket carries a lifecycle rule with `daysFromHidingToDeleting`. Without that
rule you pay to store every byte restic has already pruned, indefinitely, and
nothing in the restic output tells you.

The restic-safe rule is:

```json
[
  {
    "fileNamePrefix": "",
    "daysFromUploadingToHiding": null,
    "daysFromHidingToDeleting": 1
  }
]
```

- `fileNamePrefix: ""` — applies to every object in the bucket.
- `daysFromUploadingToHiding: null` — B2 never hides a live file on its own.
  restic decides what to prune; B2 must not second-guess it.
- `daysFromHidingToDeleting: 1` — once restic has hidden a pack file, B2 deletes
  it for real a day later. Keep it at `1` unless you want a rollback window.

Every snapshot this model writes carries the verdict directly:

| Field                         | Meaning                                                            |
| ----------------------------- | ------------------------------------------------------------------ |
| `prunesHiddenVersions`        | `false` means hidden versions are retained — and billed — forever  |
| `minDaysFromHidingToDeleting` | Smallest retention window across the bucket's rules, or `null`     |
| `unprunedPrefixes`            | Prefixes whose rule has no `daysFromHidingToDeleting`              |

## Methods

| Method                   | B2 operation                          | HTTP | Required capability                        |
| ------------------------ | ------------------------------------- | ---- | ------------------------------------------ |
| `sync`                   | `b2_list_buckets` (filtered by name)   | POST | `listBuckets`                              |
| `create`                 | `b2_create_bucket`                     | POST | `writeBuckets` (+ `writeBucketRetentions` for `fileLockEnabled`) |
| `update`                 | `b2_update_bucket`                     | POST | `writeBuckets` (+ `listBuckets` unless `bucketId` is set)        |
| `delete`                 | `b2_delete_bucket`                     | POST | `deleteBuckets` (+ `listBuckets` unless `bucketId` is set)       |
| `get_notification_rules` | `b2_get_bucket_notification_rules`     | **GET** | `readBucketNotifications`               |
| `set_notification_rules` | `b2_set_bucket_notification_rules`     | POST | `writeBucketNotifications`                 |

Notes that will otherwise cost you an afternoon:

- **`b2_get_bucket_notification_rules` is a GET with query parameters.** Nearly
  every other B2 operation is a POST with a JSON body.
- **A missing capability returns `401 unauthorized`, and that is _not_
  transient.** The client deliberately does not retry it — only `429`, `503` and
  `500` are retried, and `401 expired_auth_token` triggers exactly one
  re-authorization. If `get_notification_rules` fails with `401`, mint a key with
  `readBucketNotifications` rather than retrying.
- **`set_notification_rules` replaces every rule on the bucket.** Pass the
  complete desired set; pass `[]` to remove them all.
- **`delete` is idempotent.** A `404`, or a `400` with B2 code `bad_bucket_id`,
  is treated as success and still writes an `exists: false` snapshot.
- **`create` is _not_ idempotent.** An existing name fails with
  `duplicate_bucket_name` rather than silently adopting a bucket whose settings
  may differ from what you declared. Run `sync` first if you need to branch.
- **Each method writes a snapshot keyed by the real bucket name**, never the
  reserved data name `latest`.

### Pre-flight check: `lifecycle-hidden-version-retention`

Label: `policy`. Scope: `appliesTo: ["create", "update"]`.

It fails the run when the bucket would be left with no lifecycle rule setting
`daysFromHidingToDeleting`. It judges, in order:

1. `globalArgs.allowUnprunedHiddenVersions: true` → waived (with a warning).
2. `globalArgs.lifecycleRules` declared → judged directly. Rules that prune pass;
   individual prefixes without `daysFromHidingToDeleting` are warned about.
3. Nothing declared → falls back to the last `bucket` snapshot's
   `prunesHiddenVersions`, because `update` leaves undeclared fields untouched.
   With no snapshot to consult, it fails and tells you to run `sync` first.

Escape hatches: set `allowUnprunedHiddenVersions=true` on the model, or
`--skip-check lifecycle-hidden-version-retention` / `--skip-check-label policy`
for one run.

> **`set_notification_rules` does not fire a pre-flight check.** swamp only
> auto-runs `checks` before methods *named* `create`, `update`, `delete` or
> `action`. The method keeps its descriptive name rather than being renamed to
> game that mechanism — so treat it as unguarded.

## Setup

```bash
# Store the B2 application key pair in a vault
swamp vault create local_encryption b2
swamp vault put b2 B2_APPLICATION_KEY_ID   # paste the key ID
swamp vault put b2 B2_APPLICATION_KEY      # paste the key secret

# Register a restic backup bucket with the restic-safe lifecycle rule
swamp model create @sntxrr/b2/bucket example-backup-bucket \
  --global-arg 'applicationKeyId=${{ vault.get(b2, B2_APPLICATION_KEY_ID) }}' \
  --global-arg 'applicationKey=${{ vault.get(b2, B2_APPLICATION_KEY) }}' \
  --global-arg 'bucketName=example-backup-bucket' \
  --global-arg 'bucketType=allPrivate' \
  --global-arg 'lifecycleRules=[{"fileNamePrefix":"","daysFromUploadingToHiding":null,"daysFromHidingToDeleting":1}]'
```

Credentials come from `@sntxrr/1password-connect` in production; until that
lands, `${{ env.B2_APPLICATION_KEY }}` works for a smoke test. Never inline a key.

## Usage

```bash
swamp model @sntxrr/b2/bucket method run sync   example-backup-bucket
swamp model @sntxrr/b2/bucket method run create example-backup-bucket
swamp model @sntxrr/b2/bucket method run update example-backup-bucket
swamp model @sntxrr/b2/bucket method run update example-backup-bucket --input ifRevisionIs=4
swamp model @sntxrr/b2/bucket method run get_notification_rules example-backup-bucket
swamp model @sntxrr/b2/bucket method run delete example-backup-bucket

# Is anything in the estate quietly hoarding pruned pack files?
swamp data query example-backup-bucket 'attributes.prunesHiddenVersions == false'
```

`sync` and `get_notification_rules` are read-only. `sync` and every `bucketId`
lookup cost one **class-C** B2 transaction (billed per 1000) — set the `bucketId`
global argument to skip the lookup on `update`/`delete`/notification methods.

## Global arguments

| Arg                           | Required | Default        | Description                                                          |
| ----------------------------- | -------- | -------------- | -------------------------------------------------------------------- |
| `applicationKeyId`            | yes      | —              | B2 application key ID (master or scoped)                             |
| `applicationKey`              | yes      | —              | B2 application key (sensitive; wire from a vault)                    |
| `authHost`                    | no       | `https://api.backblazeb2.com` | Override the authorize host (testing only)            |
| `bucketName`                  | yes      | —              | The bucket this model manages (6–63 chars); also the resource key    |
| `bucketId`                    | no       | resolved       | Skip the `b2_list_buckets` lookup on `update`/`delete`/notifications |
| `bucketType`                  | no       | see below      | `allPrivate` or `allPublic`                                          |
| `lifecycleRules`              | no       | —              | Desired lifecycle rules — see the restic-safe rule above             |
| `corsRules`                   | no       | —              | Desired CORS rules                                                   |
| `bucketInfo`                  | no       | —              | User-defined bucket metadata (also Cache-Control policies)           |
| `fileLockEnabled`             | no       | —              | Enable Object Lock (cannot be undone)                                |
| `defaultServerSideEncryption` | no       | —              | `{ mode: "SSE-B2" \| "none", algorithm: "AES256" \| null }`          |
| `defaultRetention`            | no       | —              | `{ mode, period: { duration, unit } }` (update only)                 |
| `replicationConfiguration`    | no       | —              | Cloud Replication config, passed through unmodified                  |
| `allowUnprunedHiddenVersions` | no       | `false`        | Acknowledge that this bucket keeps hidden versions forever           |

> **`bucketInfo` is stored verbatim.** Whatever B2 returns in `bucketInfo` is
> written into the resource snapshot as-is, and snapshots sync to whatever
> datastore this repo is configured with — potentially a remote bucket. It is
> arbitrary user-controlled metadata, so never put a credential, token, or any
> other secret in it.

> **`bucketType` has no schema-level default.** `create` uses `allPrivate` when
> you do not set it — a restic repository must never be public. It is
> deliberately *not* a schema default, because a default would make `update`
> send `bucketType` on every run, silently flipping an `allPublic` bucket
> private for an operator who only meant to change lifecycle rules.

> **`replicationConfigured` is nullable.** `null` means the calling key is not
> authorized to read the replication configuration — it does **not** mean
> "not configured". `fileLockEnabled` and `defaultServerSideEncryptionMode`
> carry the same distinction, because B2 returns those three fields wrapped as
> `{ isClientAuthorizedToRead, value }` and nulls `value` when the key lacks
> the capability.

Every configuration field also exists as a per-run `--input` override on `create`
and `update`. It lives in `globalArgs` as well because pre-flight checks receive
`globalArgs` but never the method's arguments — that is what lets the retention
check see your declared lifecycle rules.

## Resources

| Spec                | Instance name                       | Contents                                                            |
| ------------------- | ----------------------------------- | ------------------------------------------------------------------- |
| `bucket`            | `<bucketName>`                      | Full bucket configuration plus the hidden-version retention verdict |
| `notificationRules` | `notification-rules-<bucketName>`   | Event notification rules, **redacted**                              |

Both are keyed by the real bucket name. The notification-rules spec carries a
prefix because instance names map directly onto storage paths and must be unique
across *all* specs of a model: two specs sharing the bare bucket name would
silently overwrite each other on disk.

One exception: a bucket named exactly `latest` is keyed `bucket-latest`. `latest`
is a reserved swamp data name that swamp rejects at write time only, and B2
bucket names are 6-63 characters from a global namespace, so `latest` is a legal
name somebody owns. Without the alias every method would fail against that bucket
with an opaque run-time error. The snapshot still records `bucketName: "latest"`;
only the instance key is aliased.

## Secret handling

- `applicationKey` is `sensitive` and must be wired from a vault.
- The 24h `authorizationToken` from `b2_authorize_account` is a bearer credential.
  It is never logged and never written into a resource.
- `hmacSha256SigningSecret` on a notification rule is **sent to B2 but never
  stored** — a snapshot records only `hasSigningSecret: true`.
- Custom webhook header **values** are also dropped (a custom header is a common
  place to put a bearer token); only `customHeaderNames` is kept, which is enough
  to detect drift.

A unit test asserts that no resource written by any method, and no log line,
contains an application key, an authorization token, a signing secret, or a
custom header value.

## Development

```bash
DENO=~/.swamp/deno/deno
$DENO check extensions/models/b2-bucket/b2_bucket.ts
$DENO test  --allow-net extensions/models/b2-bucket/b2_bucket_test.ts
swamp extension fmt     extensions/models/b2-bucket/manifest.yaml --check
swamp extension quality extensions/models/b2-bucket/manifest.yaml --json
```

Tests mock `fetch` — they never call Backblaze. `--allow-net` is only needed
because Deno checks the permission before the mock intercepts.

## License

MIT — see [LICENSE.md](./LICENSE.md).
