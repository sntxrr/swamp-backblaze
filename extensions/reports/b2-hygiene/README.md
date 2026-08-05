# @sntxrr/b2-hygiene

A **read-only** fleet audit for Backblaze B2. It runs after
`@sntxrr/b2/account`'s `scan` and turns the raw inventory into findings, ordered
most severe first.

It never calls B2. It reads only the resource snapshots the scan already wrote,
so it costs no transactions, cannot mutate anything, and is safe to run on a
schedule.

## Why

Two things this was built to surface, both invisible in the B2 console without
clicking through every object in turn:

- **Hidden-version retention.** `restic forget --prune` does not delete from B2 —
  it *hides* file versions. Without a lifecycle rule setting
  `daysFromHidingToDeleting`, B2 keeps and bills those versions forever. On the
  estate this was written for, **0 of 24 buckets had any lifecycle rule**.
- **Key blast radius.** A per-host backup key should reach exactly one bucket.
  Three per-host keys on that same estate had empty `bucketIds`, meaning
  account-wide: any one compromised host could delete every other host's
  backups.

## Findings

| Code                                  | Severity      | Means                                                          |
| ------------------------------------- | ------------- | -------------------------------------------------------------- |
| `bucket-public`                       | critical      | `bucketType` is `allPublic`                                     |
| `key-dangerous-capability`            | critical/high | Holds `writeKeys`, `bypassGovernance`, `deleteKeys`, `deleteBuckets`, or `writeBucketRetentions` |
| `lifecycle-no-hidden-version-pruning` | high          | No rule deletes hidden versions — pruned data is still billed  |
| `key-account-wide`                    | high          | Empty `bucketIds`, so the key applies to every bucket           |
| `key-orphaned`                        | medium        | Restricted to bucket IDs that no longer exist                   |
| `key-never-expires`                   | low           | No `expirationTimestamp`                                        |
| `lifecycle-unreadable`                | low           | Lifecycle rules could not be parsed — **status unknown**        |

`writeKeys` and `bypassGovernance` escalate to critical because they are the two
that break containment: the first turns one leaked key into every future key,
the second defeats the Object Lock retention that is supposed to survive a
compromise.

## Two honesty rules

**A truncated inventory is never presented as a clean account.** `b2_list_keys`
is paginated and `scan` caps pages, so an inventory can be incomplete. When it
is, the report says so *before* any count, marks `inventoryComplete: false` in
the JSON, and will not print the "everything is clean" line. A clean audit over
a partial inventory is the most dangerous output this could produce.

**"Cannot tell" is never reported as "is fine" or as "is broken".** `b2-account`
stores `lifecycleRules` unmodelled, so a value this report cannot parse yields
`lifecycle-unreadable` — explicitly *not* evidence of safety, and explicitly not
an accusation that the bucket lacks a rule.

It also declines to audit at all when the run was not a `scan`, or when the scan
failed — a partial inventory from a failed run would produce findings that look
authoritative while describing only whatever happened to be written first.

## Usage

```bash
# Runs automatically after a scan when selected on the model definition.
swamp model method run <b2-account-model> scan

# Or inspect the most recent result directly.
swamp report get @sntxrr/b2/hygiene --model <b2-account-model> --json
```

The JSON payload carries `findings[]` (each with `code`, `severity`, `subject`,
`detail`, `impact`), the object counts, `truncated`, and `inventoryComplete`:

```json
{
  "bucketCount": 24,
  "keyCount": 23,
  "truncated": false,
  "inventoryComplete": true,
  "findingCount": 27,
  "findings": [
    {
      "severity": "high",
      "code": "lifecycle-no-hidden-version-pruning",
      "subject": "example-host-ubuntu",
      "detail": "Bucket has no lifecycle rule at all.",
      "impact": "B2 keeps every deleted file version forever without such a rule..."
    }
  ]
}
```

Always branch on `inventoryComplete` before acting on `findingCount` — a zero
count from a truncated scan means "nothing found in the part we looked at", not
"nothing wrong".

## What it does not do

It does not size the cost. Knowing a bucket keeps hidden versions forever is not
the same as knowing how many bytes that is — that needs per-prefix object counts
from `@sntxrr/b2/files` (wave 2). Until then this tells you *which* buckets are
bleeding, not *how much*.

It also does not remediate. Fixing a lifecycle gap is a `b2-bucket update`, and
revoking an over-scoped key must not happen until a restore has been proven from
the backups that key protects.
