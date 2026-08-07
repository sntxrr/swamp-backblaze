# @sntxrr/b2-files

A [swamp](https://swamp-club.com) model that inventories and manages the
**files inside Backblaze B2 buckets**. Its reason for existing is one number:
how many bytes a bucket is billed for but no longer serves.

Wraps the [B2 Native API v4](https://www.backblaze.com/apidocs/b2-native-api)
(`/b2api/v4`) using only Deno's built-in `fetch` — no SDK, no `b2` CLI
shell-out.

Model type: `@sntxrr/b2/files`

## Why

`@sntxrr/b2/bucket` can tell you a bucket has no lifecycle rule setting
`daysFromHidingToDeleting`. It cannot tell you what that costs.

When `restic forget --prune` deletes a pack file, B2 does not remove it. It
writes a **hide marker** and keeps the data — stored, and billed — until a
lifecycle rule reaps it. With no such rule, every pack file restic has ever
pruned is still on the invoice. The only way to size that is to enumerate the
versions, which is what `scan` does: it separates `currentBytes` (what the
bucket holds) from `nonCurrentBytes` (what it is merely still paying for).

## Methods

| Method   | What it does                                                                                                                                                          |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan`   | **Factory.** Inventory file versions and write one `aggregate` per bucket, optionally per prefix group. Read-only. Defaults to every bucket the key can see.           |
| `sync`   | Snapshot one file's current state. By `fileId` it is a cheap class-B call; by `fileName` it reports the newest version, so a deleted file comes back as its hide marker. |
| `delete` | **Destructive, gated.** Permanently remove one file version and write a tombstone. Idempotent.                                                                        |
| `hide`   | **Destructive in effect, gated.** Write a hide marker so downloads by name stop resolving. The bytes underneath stay stored and billed.                                |
| `copy`   | Server-side copy of a file version (up to B2's 5 GB limit). Non-destructive — B2 writes a new version and never removes the source.                                    |
| `update` | Set or clear a file version's legal hold and Object Lock retention, then re-read the file. Compliance mode is gated.                                                   |

### Resources

| Spec        | Instance name                              | Contains                                                                                          |
| ----------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `aggregate` | `aggregate-<bucket>-<group>-<hash>`        | current / non-current counts and bytes, hide markers, unfinished uploads, lock counts, truncation, cost |
| `file`      | `file-<fileId>`                            | one file version: size, type, timestamps, `fileInfo`, legal hold and retention with their authorization flags |

Instance names are **spec-prefixed** because instance names share one flat
storage namespace across all specs, and one `scan` writes both kinds. Aggregate
names additionally carry a hash of the raw `(bucket, group)` pair: a prefix
group is user-controlled text containing slashes, and two prefixes that sanitize
to the same readable fragment must still get distinct instances. `file` keys on
`fileId` rather than `fileName`, because a name has arbitrarily many versions
and keying by name would make them overwrite each other.

## Reading an aggregate honestly

Three things in this resource are easy to misread, and all three are deliberate.

**`null` means "not measured", never "zero".** With `includeVersions: false`
the scan uses `b2_list_file_names`, which cannot see a hidden or superseded
version at all — so `nonCurrentBytes`, `nonCurrentFileCount`, `hideMarkerCount`,
`unfinishedCount` and `totalBytes` are all `null`. Reporting `0` there would be
indistinguishable from a bucket with no debt, which is the opposite of the truth
on a restic bucket. Filter on `!= null` before you trust a count.

**`truncated: true` makes every count a floor.** Listing stops at `maxPages`, or
at `maxFiles` in detailed mode. A truncated aggregate is a lower bound, not a
total. A bucket that was requested but could not be seen also gets
`truncated: true` with zeroes — because nothing was listed, so "zero files" is
not a fact that run established.

**An unreadable lock is not an absent one.** B2 wraps `fileRetention` and
`legalHold` as `{ isClientAuthorizedToRead, value }` and nulls `value` when the
key lacks `readFileRetentions` / `readFileLegalHolds`. The aggregate counts
those separately as `legalHoldUnreadableCount` and `retentionUnreadableCount`,
and the `file` resource carries `legalHoldAuthorized` / `retentionAuthorized`
beside each value. Check the flag before concluding a file is unprotected.

```bash
# Which buckets are paying for data they no longer serve?
swamp data query b2-files 'attributes.nonCurrentBytes != null && attributes.nonCurrentBytes > 0'

# ...and is that number complete?
swamp data query b2-files 'attributes.truncated == true'
```

## Cost

Every `b2_list_*` call is a **class C transaction**, billed per 1000 files
returned. That is the tier that costs money, so the aggregate reports what it
spent in `classCTransactions`.

The arithmetic is smaller than it looks. B2 bills per 1000 files regardless of
page size, so the default `maxFileCount: 10000` costs exactly what ten
1000-file pages cost while making a tenth as many round trips. A 100,000-file
restic repository is 100 billed transactions; a 24-bucket fleet sweep of that
size is ~2,400, well under a cent. The real budget is wall-clock, not money,
which is what `maxPages` (default 50, so up to 500,000 files per bucket) bounds.

`b2_get_file_info` is class B (cheap) and `b2_delete_file_version` is class A
(free).

## Aggregate versus detailed

`scan` defaults to **aggregate** mode: one summary resource per bucket, no
per-file resources. A restic repository holds tens of thousands of pack files,
and emitting one snapshot each would bury the repo in state nobody reads.

`mode: "detailed"` emits one `file` resource per version and therefore
**requires** both an explicit `prefix` and a `maxFiles` cap. Listing also stops
once `maxFiles` is in hand, so you do not pay to enumerate a million versions in
order to discard all but the first thousand.

```bash
# Fleet-wide debt, split by restic's top-level layout
swamp model method run b2-files scan --input groupBy=topLevel

# Look at the snapshots specifically — small, bounded, and worth the detail
swamp model method run b2-files scan \
  --input mode=detailed --input prefix=snapshots/ --input maxFiles=200
```

## Required B2 capabilities

| To run                              | The key needs                                                                  |
| ----------------------------------- | -------------------------------------------------------------------------------- |
| `scan`                              | `listFiles`, plus `listBuckets` unless one bucket is pinned by `bucketName` + `bucketId` |
| `scan` lock columns readable        | `readFileRetentions`, `readFileLegalHolds` (without them the values come back unreadable, not off) |
| `sync` by `fileId`                  | `readFiles`                                                                    |
| `sync` by `fileName`                | `listFiles`                                                                    |
| `delete`                            | `deleteFiles`, plus `listFiles` when identifying by name, plus `bypassGovernance` to delete through governance retention |
| `hide`                              | `writeFiles`                                                                   |
| `copy`                              | `readFiles` on the source, `writeFiles` on the destination                      |
| `update`                            | `writeFileLegalHolds` / `writeFileRetentions`, `readFiles` for the re-read, `bypassGovernance` to shorten an existing governance lock |

A key that lacks a capability fails with `401 unauthorized`. That is **not**
transient and is deliberately not retried — fix the key's grant instead.

## Safety gates

`delete` and `hide` both refuse to run without `allowFileDestruction`, as a
global argument or a method input. Deleting or hiding a restic pack file leaves
the repository unreadable with **no error until the next restore**, which is the
worst possible time to discover it.

`update` refuses to set `retentionMode: "compliance"` without
`allowComplianceRetention`. Compliance retention can be extended but never
shortened or removed — not by the account owner, not by support — so the object
is stored and billed until it expires even if setting it was a mistake. Use
`governance` when you want a lock you can undo.

> **The enforcement lives in the methods, and deliberately not in a pre-flight
> check.** swamp gives a check the model's global arguments but never the
> method's inputs, so a check cannot see `--input allowFileDestruction=true`
> and cannot be the thing that stops — or permits — the run. Pre-flight checks
> also fire only for methods named `create` / `update` / `delete` / `action`,
> so no check could ever guard `hide` regardless.

### Changed in 2026.08.06.1 — the `file-destruction-acknowledged` check is gone

Version `2026.08.05.1` shipped a `file-destruction-acknowledged` pre-flight
check, and it made `delete` unusable as documented. Because a check sees only
global arguments, it rejected `--input allowFileDestruction=true` **before**
`execute` ever received the flag — while its own error message instructed you
to pass exactly that.

The consequence was worse than a self-contradicting message. With the per-run
path blocked, the only way to delete anything was to set
`allowFileDestruction: true` **permanently** on the model — so a check written
to prevent accidental destruction was forcing you to arm destruction for good,
on a model whose `delete` can corrupt a restic repository. It failed on the
safe configuration and passed on the dangerous one.

The check is removed. `assertDestructionAllowed` inside `delete` and `hide` is
unchanged and still refuses without the acknowledgement — it simply now sees
both the method input and the global argument, as it always should have. **No
behaviour you relied on is lost:** if you had set `allowFileDestruction` on the
model to work around this, it still works, and you can now drop it and
acknowledge per run instead.

## Quick start

```bash
# 1. Store the application key (never inline it)
swamp vault put onepassword Backblaze/backblaze-primary-application-key

# 2. Create a fleet-wide inventory model — bucketName deliberately unset
swamp model create @sntxrr/b2/files b2-files \
  --global-arg 'applicationKeyId=${{ vault.get(onepassword, "Backblaze/backblaze-primary-key") }}' \
  --global-arg 'applicationKey=${{ vault.get(onepassword, "Backblaze/backblaze-primary-application-key") }}'

# 3. Size the debt
swamp model method run b2-files scan --input groupBy=topLevel
swamp model get b2-files --json
```

Pin `bucketName` (and ideally `bucketId`) on a **separate** model for the
single-file methods — they act on one file in one bucket and refuse to guess
which.

> **`fileInfo` lands in a snapshot verbatim.** It is arbitrary user metadata
> that B2 stores with each file and returns on every read, so it must never be
> used to hold a credential. The same caution applies to `bucketInfo` in
> `@sntxrr/b2/bucket`.

## Development

```bash
DENO=~/.swamp/deno/deno
$DENO check extensions/models/b2-files/b2_files.ts
$DENO test  --allow-net extensions/models/b2-files/b2_files_test.ts
swamp extension fmt     extensions/models/b2-files/manifest.yaml --check
swamp extension quality extensions/models/b2-files/manifest.yaml --json
```

Tests mock `fetch` and never call B2. The `writeResource` stub validates every
write against the real spec schema, because a recording-only stub is blind to
the derived-field bugs this suite keeps producing — see `CONVENTIONS.md` §10.1.

## License

MIT — see [LICENSE.md](./LICENSE.md).
