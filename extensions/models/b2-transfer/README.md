# @sntxrr/b2-transfer

The Backblaze B2 **data plane** — the thirteen upload, download and large-file
operations — completing this suite's coverage of all 33 Native API v4
operations.

## This model is a deliberate misfit, and it is guarded

Streaming a multi-gigabyte object through a Deno subprocess produces no
meaningful typed state, and restic already moves those bytes over the
S3-compatible API, faster and without swamp in the path. So `upload` and
`download` exist for **completeness and validation**, not to be anybody's data
pipeline. Both refuse to move more than `maxTransferBytes` — **100 MB by
default** — without an explicit per-run override.

A model that cannot say no to a 40 GB restic pack file has no business holding
these methods. This one says no.

## What it is actually for

1. **Prove a bucket is readable and writable, independently of restic.**
   `upload` a canary, `download` it back, compare the SHA-1. That is a real
   end-to-end assertion about a backup destination — and it is the half of
   restore-validation that does not need restic installed.
2. **Make abandoned uploads actionable.** A large upload that never reached
   `b2_finish_large_file` leaves its parts in the bucket **indefinitely**. They
   do not appear in `b2_list_file_names`, they are invisible in the console's
   file browser, and they are billed as storage. `scan` finds them,
   `list_parts` sizes one, `delete` cancels it.
3. **Reach the large-file API at all**, so you are not forced back to the `b2`
   CLI for `copy_part` or a resumable upload.

## Methods

| Method               | B2 operations                                                                   | Mutates |
| -------------------- | ------------------------------------------------------------------------------- | ------- |
| `scan`               | `b2_list_unfinished_large_files` (+ `b2_list_parts` with `countParts`)          | no      |
| `upload`             | `b2_get_upload_url`, `b2_upload_file` — or `b2_start_large_file`, `b2_get_upload_part_url`, `b2_upload_part`, `b2_finish_large_file` | **yes** |
| `download`           | `b2_download_file_by_id` **or** `b2_download_file_by_name`                       | no      |
| `authorize_download` | `b2_get_download_authorization`                                                  | no      |
| `list_parts`         | `b2_list_parts`                                                                  | no      |
| `copy_part`          | `b2_start_large_file`, `b2_copy_part` per source, `b2_finish_large_file`         | **yes** |
| `delete`             | `b2_cancel_large_file`                                                           | **yes** |

`delete` is idempotent, but not for the reason B2's error table suggests.
Cancelling an already-cancelled large file returns neither `404` nor
`file_not_present` — it returns the catch-all `bad_request` with the message
`No active upload for large file (...)`. This model matches the code **and**
that specific message; any other `bad_request` still throws, so a malformed
request is never mistaken for a no-op.

## `copy_part` assembles a file server-side

Give it a destination name and an ordered list of sources; each becomes one
part, and B2 copies the bytes internally:

```yaml
# copy-args.yaml
fileName: assembled.bin
sources:
  - sourceFileId: "4_z...first"
    range: "bytes=0-4999999"
  - sourceFileId: "4_z...second"
```

```bash
swamp model method run b2-canary copy_part --input-file copy-args.yaml
```

**Every part except the last must be at least 5,000,000 bytes** — B2's minimum.
A small range is only valid as the final source.

It owns the whole lifecycle (start, copy each source, finish) rather than
exposing `b2_copy_part` alone, and that is a correction rather than a
convenience. The first version took a `largeFileId` and a `partNumber`, mirroring
the B2 call one-for-one — and was **unreachable**. `b2_copy_part` requires an
*in-progress* large file, but `upload` starts and finishes atomically, so its
result is a completed file that B2 rejects with `No active upload for`, and
`scan` only finds unfinished uploads that already exist. On a healthy account
there was no way to obtain a valid `largeFileId` at all. A failure cancels the
half-built file, so this cannot create the invisible billed waste `scan` exists
to find.

## Required B2 capabilities

| Method               | Capabilities                                                     |
| -------------------- | ---------------------------------------------------------------- |
| `scan`               | `listFiles`, plus `listBuckets` unless `bucketName`+`bucketId` are both set |
| `upload`             | `writeFiles`, plus `listBuckets` unless `bucketId` is set        |
| `download`           | `readFiles`; by name also needs `listBuckets` unless `bucketId` is set |
| `authorize_download` | `shareFiles`, plus `listBuckets` unless `bucketId` is set        |
| `list_parts`         | `writeFiles` — B2 scopes `b2_list_parts` to the write capability |
| `copy_part`          | `writeFiles` and `readFiles`                                     |
| `delete`             | `writeFiles`                                                     |

A scoped key missing a capability fails with `401 unauthorized`, which is **not
transient** — do not retry it. The fix is the key's grant.

Every method addressed purely by `fileId` — `download` by ID, `list_parts`,
`delete` — deliberately performs **no** bucket lookup, so a
bucket-restricted key with no `listBuckets` capability can still use them.

## Quick start

```bash
swamp vault create @sntxrr/1password-connect b2
swamp model create @sntxrr/b2/transfer b2-canary
```

```yaml
# models/@sntxrr/b2/transfer/<uuid>.yaml
globalArguments:
  applicationKeyId: ${{ vault.get(b2, B2_APPLICATION_KEY_ID) }}
  applicationKey: ${{ vault.get(b2, B2_APPLICATION_KEY) }}
  bucketName: example-host-ubuntu
  bucketId: 4a48fe8875c6214145260818
  maxTransferBytes: 1048576
```

```bash
# Find abandoned uploads across the whole account (leave bucketName unset)
swamp model method run b2-canary scan --input countParts=true

# Prove the bucket round-trips
swamp model method run b2-canary upload \
  --input fileName=canary.txt --input content="hello"
swamp model method run b2-canary download --input fileName=canary.txt

# Size an abandoned upload, then cancel it
swamp model method run b2-canary list_parts --input fileId=4_z...
swamp model method run b2-canary delete \
  --input fileId=4_z... --input allowTransferDestruction=true
```

## Honest nulls

Consistent with the rest of the suite: a value that was never measured is
`null`, never `0` or `false`.

- **`sha1Verified: null` means NOT CHECKED.** `false` means computed and
  mismatched. Only one of those is an emergency, and a `!sha1Verified` filter
  would treat them identically — branch on `=== false`.
- **B2 does not always return a comparable SHA-1.** Large files assembled from
  parts come back as `none`, and uploads without a supplied checksum are
  prefixed `unverified:`. Neither is a hash, so comparing against them would
  manufacture a mismatch from a value that was never a SHA-1. `sha1Verified`
  stays `null`.
- **`partCount: null` means `list_parts` was never run**, not that the upload
  has no parts. `scan` leaves it null on purpose — counting is one class-C call
  per unfinished file. After `delete`, `partCount: 0` is a *measured* zero.
- **`partsTruncated: true` makes `partCount` and `partBytes` a FLOOR.**

## The download authorization is never persisted

`b2_get_download_authorization` returns a bearer token granting read access to
everything under a prefix, for up to seven days. **It is never written to a
snapshot or a log line.**

This diverges from `@sntxrr/b2/key`, which delivers an application key's secret
to 1Password and records `secretDestination`. The difference is
**regenerability**: B2 returns an application key's secret exactly once and it
is lost forever if not captured, whereas a download authorization can be minted
again any time. A secret that is cheap to regenerate should never be persisted
— and swamp resources sync to a remote S3 datastore.

The snapshot records the authorization's *shape*: prefix, duration, computed
`expiresAt`, and `tokenPersisted: false`, which is present so the guarantee is
visible in the data rather than only in this README.

`verify: true` (the default) exercises the minted token against B2, because a
token that mints but grants nothing is exactly the failure this method exists
to catch.

## Cost

| Class | Operations here                                             | Note              |
| ----- | ------------------------------------------------------------ | ----------------- |
| A     | uploads, `b2_cancel_large_file`                              | free              |
| B     | `b2_download_*`                                              | cheap             |
| C     | `b2_list_*`, `b2_get_upload_url`, `b2_authorize_account`     | billed per 1000   |

`scan` costs one class-C call per page per bucket. `countParts=true` adds one
**per unfinished file**, which is why it is opt-in.

`copy_part` is server-side: no bytes pass through this process, so
`maxTransferBytes` does not apply to it. Assembling a 40 GB file from ranges
costs nothing locally.

## Safety

- **`delete` refuses without `allowTransferDestruction`** (method input or
  global argument). Cancelling an in-flight large upload discards every part
  already sent; against a backup mid-run that destroys work the backup tool is
  never told about.
- **There is deliberately no pre-flight check for that acknowledgement.** One
  existed and was removed after it blocked the first real deletion. swamp does
  not pass method inputs to checks, so it could only see `globalArgs` — making
  `--input allowTransferDestruction=true` invisible to it, and leaving
  permanently setting the flag on the model as the only way through. A check
  meant to prevent destruction was forcing it to be armed for good. The gate
  lives in `execute`, which sees both paths.
- **A failed large upload cancels itself.** Otherwise its parts would be stored
  and billed forever, invisibly. If the cancel *also* fails, the warning names
  the exact command to clean it up manually.
- The pre-flight check for destruction catches the **global-argument path
  only** — swamp does not pass method inputs to checks, so the real enforcement
  lives inside `execute`, where both are visible.
- `fileInfo` is arbitrary user metadata that B2 stores and returns on every
  read. It lands in a snapshot verbatim — **never put a credential in it.**

## Development

```bash
DENO=~/.swamp/deno/deno
$DENO check extensions/models/b2-transfer/b2_transfer.ts
$DENO test  extensions/models/b2-transfer/b2_transfer_test.ts
swamp extension fmt     extensions/models/b2-transfer/manifest.yaml --check
swamp extension quality extensions/models/b2-transfer/manifest.yaml --json
```

## License

MIT — see [LICENSE.md](LICENSE.md).
