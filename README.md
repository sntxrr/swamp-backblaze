# swamp-backblaze

Backblaze B2 as typed, queryable [swamp](https://swamp-club.com) resources —
complete coverage of the **B2 Native API v4**.

## Why

A homelab fleet backs up to per-host B2 buckets with restic. Nothing gave
fleet-wide visibility into that estate: which buckets exist, which application
keys are still live, which keys are orphaned against deleted buckets, which
buckets are quietly accumulating hidden file versions that restic already
pruned, and which have leaked unfinished large uploads. Each of those is
recurring cost or a standing security surface.

These extensions make the B2 account inventoryable and replace CLI shell-outs
with typed API calls.

## Design

Decomposed by **object domain, not by endpoint**. Each model owns one class of
thing that exists in B2, exposes a `scan` factory method emitting one resource
per discovered object, and a small set of intent methods that mutate that class.
Full API coverage falls out of the decomposition rather than producing a flat
33-method wrapper.

Cross-domain operations are workflows, not model methods.

## Extensions

| Extension              | Status  | What it manages                                        |
| ---------------------- | ------- | ------------------------------------------------------ |
| `@sntxrr/b2/account`   | wave 1  | Account inventory — fans out buckets and keys          |
| `@sntxrr/b2/bucket`    | wave 1  | Bucket lifecycle, lifecycle rules, event notifications |
| `@sntxrr/b2/key`       | wave 1  | Application keys, bucket-scoped minting                |
| `@sntxrr/b2/files`     | wave 2  | File and version inventory, retention, legal hold      |
| `@sntxrr/b2/transfer`  | wave 3  | Uploads, downloads, large-file part management         |

## Scope

**In:** the B2 Native API v4 — 33 operations.

**Out:** the S3-Compatible API (restic uses it directly for the data plane, and
it cannot manage buckets or keys anyway) and the Partner API (provisions B2
accounts; requires a partner agreement).

## Credentials

Every model takes an `applicationKeyId` / `applicationKey` pair, wired from a
vault — never inline. [`@sntxrr/1password-connect`](https://github.com/sntxrr/swamp-1password-connect)
reads 1Password Connect over plain HTTP and so works headless, in cron, in
containers, and under `swamp serve`.

Capability requirements differ per method and are documented in each
extension's README. A scoped key missing a capability fails `401`, which is not
transient.

## A note on cost

Every `b2_list_*` operation is a **class C transaction** — the billed tier. A
nightly full scan across a fleet of buckets is a recurring charge. These models
prefer aggregate results over per-object enumeration, cap page counts, and
surface a `truncated` flag rather than silently returning a partial inventory.

## Development

See [`CONVENTIONS.md`](./CONVENTIONS.md) for the shared technical contract and
[`PRD.md`](./PRD.md) for scope. Both are lead-owned.

## License

MIT
