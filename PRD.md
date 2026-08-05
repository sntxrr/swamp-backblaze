# PRD — Backblaze B2 Extension Suite

**Lead-owned.** Scope authority. For implementation detail, `CONVENTIONS.md`
wins.

---

## 1. Why

The homelab backs up 14 hosts with restic into per-host Backblaze B2 buckets
(`s3:s3.us-west-002.backblazeb2.com/<host>-<distro>`), provisioned by the
`restic` role in `~/git/ansible-server-setup`. That role shells out to the `b2`
CLI to create buckets and mint bucket-scoped application keys, parsing the key
out of the CLI's last stdout line with a regex.

Nothing gives fleet-wide visibility into that estate: which buckets exist, which
application keys are still live, which keys are orphaned against deleted
buckets, which buckets are accumulating hidden file versions that restic already
pruned, and which have leaked unfinished large uploads. All of those are
recurring cost and a standing security surface.

This suite makes the B2 account a queryable, typed swamp resource, and replaces
the CLI shell-out with typed API calls.

Companion suite: `@sntxrr/restic` (separate repo) consumes this inventory for
backup restore-validation. The B2 side must land first — it is the cheaper,
lower-risk half and has no fleet dependencies.

## 2. Scope

**In:** complete coverage of the **B2 Native API v4** — 33 operations across 5
models (the 31 documented operations plus the 2 event-notification endpoints).

**Out:**

- **S3-Compatible API.** restic already uses it directly for the data plane, and
  it cannot manage buckets or keys anyway — which is precisely why the Ansible
  role reaches for the `b2` CLI.
- **Partner API.** Provisions B2 accounts; requires a partner agreement.

## 3. Design stance

Decompose by **object domain, not by endpoint.** Each model owns one class of
thing that exists in B2, exposes a `scan` factory method emitting one resource
per discovered object, and a small set of intent methods that mutate that class.
Full API coverage falls out of the decomposition rather than producing a flat
33-method wrapper.

Explicitly rejected: the one-model-per-endpoint shape (cf.
`@webframp/cloudflare/r2`, ~40 methods). It is not a factory and does not
compose.

Cross-domain operations are **workflows**, not model methods. Provisioning a
host's backup target spans buckets and keys, so it is a workflow composing
`bucket.create` → `key.create` → vault write — not a method that reaches across
two domains and breaks the decomposition.

## 4. Models

| Model                  | Dir              | `scan` emits                       | Intent methods                                                                            | Operations covered                                                                                                                                                       |
| ---------------------- | ---------------- | ---------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@sntxrr/b2/account`   | `b2-account/`    | `bucket/<name>`, `key/<keyId>`     | — (read-only root)                                                                        | `b2_authorize_account`, `b2_list_buckets`, `b2_list_keys`                                                                                                               |
| `@sntxrr/b2/bucket`    | `b2-bucket/`     | —                                  | `create`, `delete`, `update`, `sync`, `get_notification_rules`, `set_notification_rules`  | `b2_create_bucket`, `b2_delete_bucket`, `b2_update_bucket`, `b2_get_bucket_notification_rules`, `b2_set_bucket_notification_rules`                                       |
| `@sntxrr/b2/key`       | `b2-key/`        | —                                  | `create`, `delete`, `sync`                                                                | `b2_create_key`, `b2_delete_key`                                                                                                                                        |
| `@sntxrr/b2/files`     | `b2-files/`      | `file/<fileId>` **or** aggregate   | `sync`, `delete`, `hide`, `copy`, `update` (legal hold / retention)                       | `b2_list_file_names`, `b2_list_file_versions`, `b2_get_file_info`, `b2_delete_file_version`, `b2_hide_file`, `b2_copy_file`, `b2_update_file_legal_hold`, `b2_update_file_retention` |
| `@sntxrr/b2/transfer`  | `b2-transfer/`   | `unfinished-upload/<fileId>`       | `upload`, `download`, `authorize_download`, `list_parts`, `delete` (cancel), `copy_part`  | the 13 upload / download / large-file operations                                                                                                                        |

## 5. Waves

**Wave 1 — control plane (current).** `b2-account`, `b2-bucket`, `b2-key`.
Ten operations. Covers 100% of what the restic estate needs, and is a
publishable release on its own.

**Wave 2 — inventory.** `b2-files` (aggregate mode first), plus the
`b2-hygiene` report.

**Wave 3 — data plane.** `b2-transfer`, completing all 33.

Wave 1 is the gate: waves 2 and 3 copy its landed client and schema conventions.

## 6. Wave 2+ design constraints (recorded now, built later)

- **`files.scan` defaults to aggregate mode.** Per-prefix object count and total
  bytes, no per-file resources. Per-file emission requires explicit
  `mode: detailed` plus a required `prefix` and a `maxFiles` cap. A restic repo
  holds tens of thousands of pack files, `b2_list_file_names` returns 1000 per
  class-C call, and the default must be the safe one.
- **`transfer` is a deliberate misfit, guarded.** Streaming multi-GB objects
  through a Deno subprocess produces no meaningful typed state, and restic moves
  the bytes better via S3. Implement for completeness with a size guard
  (default ~100 MB, explicit override). Its real value is validation:
  `download` + `authorize_download` verify a bucket is readable independently of
  restic, and `list_parts` + cancel make the hygiene report's unfinished-upload
  findings actionable.

## 7. Definition of done (per extension)

1. `deno check` and `deno test` pass.
2. Registers: `swamp model type search b2 --json` lists the type.
3. Read-only smoke test against live B2 succeeds.
4. `swamp extension fmt --check` clean; `quality` ≥ 14/15.
5. Adversarial Review Gate report written and every dimension adjudicated.
6. README documents required B2 capabilities per method.
7. No secret — `applicationKey` or `authorizationToken` — appears in any
   resource snapshot or log line, asserted by a test.
