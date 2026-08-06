# @sntxrr/b2-hygiene

A **read-only** fleet audit for Backblaze B2, in two reports:

| Report                     | Scope      | Answers                                     |
| -------------------------- | ---------- | ------------------------------------------- |
| `@sntxrr/b2/hygiene`       | `method`   | Which buckets and keys are misconfigured?   |
| `@sntxrr/b2/fleet-hygiene` | `workflow` | …and what is each of those gaps costing?    |

Neither ever calls B2. Both read only resource snapshots that were already
written, so they cost no transactions, cannot mutate anything, and are safe to
run on a schedule.

**Which one you want.** `b2/hygiene` runs after a single `@sntxrr/b2/account`
`scan` and is enough on its own. `b2/fleet-hygiene` runs after a *workflow* that
also ran an `@sntxrr/b2/files` scan, and joins the two: same findings, ranked by
how much data fixing each one actually recovers. The split is not stylistic — a
method-scope report only ever sees the resources its own execution produced, and
the byte totals live in a different model's. Workflow scope is the only place
the two can meet.

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

**You must attach it to the model definition first.** Reports are attached to
model *types*, and this is a standalone report extension rather than one
declared inline on `@sntxrr/b2/account`, so installing it is not enough — it
registers as a type but never executes, and `swamp report get` then reports
"Report not found" with no indication why. Add it to the definition:

```yaml
# models/@sntxrr/b2/account/<uuid>.yaml
reports:
  require:
    - '@sntxrr/b2/hygiene'
```

```bash
# Then it runs automatically after every scan.
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

## `@sntxrr/b2/fleet-hygiene` — the same findings, priced

Attach it to the **workflow**, not to a model — it is workflow-scope:

```yaml
# workflows/b2-fleet-audit.yaml
reports:
  require:
    - '@sntxrr/b2/fleet-hygiene'
```

The workflow needs two steps: an `@sntxrr/b2/account` `scan` and an
`@sntxrr/b2/files` `scan`. The report finds them by the **specs they wrote**
(`bucket`/`account` and `aggregate`), never by step or model name, so renaming a
step does not break it.

```bash
swamp workflow run b2-fleet-audit
swamp report get @sntxrr/b2/fleet-hygiene --workflow b2-fleet-audit --markdown
```

It adds a worklist ordered by recoverable bytes rather than by severity, because
24 identical `lifecycle-no-hidden-version-pruning` findings tell you nothing
about where to start:

```
| bucket                | finding                               | non-current | waste |
| example-example-alpha-debian | `lifecycle-no-hidden-version-pruning` | 20.57 GiB   | 92%   |
| example-example-beta-ubuntu   | `lifecycle-no-hidden-version-pruning` | 12.30 GiB   | 73%   |
| example-host-ubuntu   | `lifecycle-no-hidden-version-pruning` | 155 B       | 20%   |
```

Those proportions are real, from a 24-bucket fleet: two buckets held 33 of the
39.64 GiB. The last row is there on purpose — units scale down to bytes, because
a fixed `GiB` format rendered five real buckets as `0.00 GiB`, and a report that
refuses to show an unknown as zero must not show a known quantity as zero
either.

### A byte total has four states, and three of them are not zero

This is the report's central contract. Every bucket is exactly one of:

| State          | Means                                                       |
| -------------- | ----------------------------------------------------------- |
| `measured`     | A complete versions listing. The number is real.            |
| `truncated`    | Listing hit `maxPages`. The number is a **FLOOR**.          |
| `unmeasurable` | The scan listed *names*, which cannot see a non-current version. |
| `unmeasured`   | No aggregate covered this bucket at all.                    |

The last three are unknowns and are never rendered, summed, or exported as `0`.
`unmeasurable` and `unmeasured` buckets are excluded from the fleet total
**entirely — including their known current bytes**, because contributing one
half of a bucket's numbers would shrink the apparent waste ratio. Understating
the debt is the one direction this must never fail in.

Branch on `sizingComplete` — deliberately separate from `inventoryComplete`,
since the inventory can be whole while the sizing over it is a floor:

```json
{
  "inventoryComplete": true,
  "sizingComplete": true,
  "totals": {
    "measuredBuckets": 24, "truncatedBuckets": 0,
    "unmeasurableBuckets": 0, "unmeasuredBuckets": 0,
    "nonCurrentBytes": 42561501224, "isFloor": false,
    "estimatedMonthlyUsd": 0.2554
  },
  "rate": { "usdPerGbMonth": 0.006, "observed": "2026-08" }
}
```

**Set `maxPages` high enough on the b2-files step.** The default of 50 truncates
past ~500k versions, which silently capped the six largest buckets on the first
live run. The bundled workflow passes `maxPages: 600`. A truncated bucket taints
the whole fleet total (`isFloor: true`), and the report says so above every
number rather than below it.

### The dollar figure is an estimate, and says so

`estimatedMonthlyUsd` applies a **published list price** — $0.006/GB-month,
observed 2026-08, exported as `rate` — to the non-current bytes. It is not a
reading of your invoice, it bills in decimal GB as B2 does (not GiB), and it
covers storage only. Verify it against current B2 pricing before acting on it.

## What neither does

Neither remediates. Fixing a lifecycle gap is a `b2-bucket update`, and revoking
an over-scoped key must not happen until a restore has been proven from the
backups that key protects.
