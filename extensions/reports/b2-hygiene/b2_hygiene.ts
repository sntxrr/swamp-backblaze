/**
 * Backblaze B2 fleet hygiene audit.
 *
 * A method-scope report that runs after `@sntxrr/b2/account` `scan` and turns a
 * raw inventory into findings. Read-only: it reads the resources the scan
 * already wrote and never calls B2, so it costs nothing and cannot mutate.
 *
 * **Why this exists.** The estate it audits had, at first scan, zero of 24
 * buckets carrying any lifecycle rule — meaning every pack file restic has ever
 * pruned is still stored and still billed as a hidden version — and three
 * per-host keys that were account-wide rather than bucket-scoped, so any one
 * host could delete every other host's backups. Neither fact is visible in the
 * B2 console without clicking through every bucket and key in turn.
 *
 * **Honesty rule.** `b2_list_keys` is paginated and the scan caps pages, so an
 * inventory can be incomplete. When it is, absence is not evidence: this report
 * refuses to present a finding count as complete and says so first, loudly. A
 * clean audit over a partial inventory is the most dangerous output this could
 * produce.
 *
 * @module
 */

/**
 * What a report returns — swamp's documented `ReportResult` shape.
 *
 * Declared and applied to `execute` deliberately. Without it TypeScript infers
 * a union of the early-return skip object and the full result, and every
 * `out.json.<field>` access in a test fails to compile — which is exactly what
 * happened here: `deno test` aborted at type-check, so this file's tests
 * silently never ran despite passing under `--no-check`. Annotating the return
 * collapses the union to the interface swamp actually contracts for.
 */
export type ReportResult = {
  markdown: string;
  json: Record<string, unknown>;
};

/** Severity ordering used for sorting and for the summary counts. */
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
export type Severity = typeof SEVERITY_ORDER[number];

/** One audit finding about one B2 object. */
export type Finding = {
  severity: Severity;
  /** Stable kebab-case identifier, safe to alert or filter on. */
  code: string;
  /** The object this is about — bucket name or application key ID. */
  subject: string;
  /** What is true. */
  detail: string;
  /** What it costs or risks, in concrete terms. */
  impact: string;
};

/** Capabilities that let a key escalate, or defeat retention, if it leaks. */
const DANGEROUS_CAPABILITIES: Record<string, string> = {
  writeKeys:
    "can mint new application keys, so a leak of this key is a leak of every future key",
  deleteKeys: "can revoke other keys, including the ones backups depend on",
  bypassGovernance:
    "can delete objects that Object Lock governance mode is supposed to protect",
  writeBucketRetentions:
    "can weaken or remove Object Lock retention on a bucket",
  deleteBuckets: "can delete an entire bucket",
};

/** A B2 lifecycle rule, as far as this report needs to understand one. */
type LifecycleRule = {
  fileNamePrefix?: unknown;
  daysFromHidingToDeleting?: unknown;
};

/**
 * Decide whether a bucket's lifecycle rules ever delete hidden versions.
 *
 * `b2-account` stores `lifecycleRules` unmodelled (CONVENTIONS §4.9), so this
 * takes the value as `unknown` and refuses to guess: anything that is not
 * recognisably an array of rules returns `null` for "cannot tell" rather than
 * `false` for "does not prune". Reporting "no lifecycle rule" about a bucket
 * whose rules simply could not be parsed would be a false accusation, and this
 * report's whole value is that its findings can be trusted.
 */
export function prunesHiddenVersions(
  lifecycleRules: unknown,
): { verdict: boolean | null; unprunedPrefixes: string[] } {
  if (lifecycleRules === null || lifecycleRules === undefined) {
    // B2 returns [] for "no rules", so an explicit null/absent value means the
    // scan did not capture it — unknown, not empty.
    return { verdict: null, unprunedPrefixes: [] };
  }
  if (!Array.isArray(lifecycleRules)) {
    return { verdict: null, unprunedPrefixes: [] };
  }
  if (lifecycleRules.length === 0) {
    return { verdict: false, unprunedPrefixes: [""] };
  }

  let anyPrunes = false;
  const unpruned: string[] = [];
  for (const raw of lifecycleRules as LifecycleRule[]) {
    if (typeof raw !== "object" || raw === null) continue;
    const days = raw.daysFromHidingToDeleting;
    const prefix = typeof raw.fileNamePrefix === "string"
      ? raw.fileNamePrefix
      : "";
    if (typeof days === "number" && days > 0) anyPrunes = true;
    else unpruned.push(prefix);
  }
  return { verdict: anyPrunes, unprunedPrefixes: unpruned };
}

/** Parse a resource snapshot's bytes into an object, or null if unreadable. */
async function readSnapshot(
  // deno-lint-ignore no-explicit-any
  context: any,
  handle: { name: string; version?: number },
): Promise<Record<string, unknown> | null> {
  try {
    const raw = await context.dataRepository.getContent(
      context.modelType,
      context.modelId,
      handle.name,
      handle.version,
    );
    if (!raw) return null;
    return JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Build every finding from an already-loaded inventory. Pure — easy to test. */
export function analyze(
  buckets: Record<string, unknown>[],
  keys: Record<string, unknown>[],
): Finding[] {
  const findings: Finding[] = [];
  const knownBucketIds = new Set(
    buckets.map((b) => String(b.bucketId ?? "")).filter((id) => id !== ""),
  );

  for (const b of buckets) {
    const name = String(b.bucketName ?? "<unnamed>");

    if (b.bucketType === "allPublic") {
      findings.push({
        severity: "critical",
        code: "bucket-public",
        subject: name,
        detail:
          "Bucket type is allPublic — its contents are readable by anyone.",
        impact:
          "A backup repository must never be public. Anyone who learns the bucket name can download every backup in it.",
      });
    }

    const { verdict, unprunedPrefixes } = prunesHiddenVersions(
      b.lifecycleRules,
    );
    if (verdict === false) {
      const where = unprunedPrefixes.length === 1 && unprunedPrefixes[0] === ""
        ? "no lifecycle rule at all"
        : `no daysFromHidingToDeleting for prefix(es): ${
          unprunedPrefixes.map((p) => p === "" ? "(all files)" : p).join(", ")
        }`;
      findings.push({
        severity: "high",
        code: "lifecycle-no-hidden-version-pruning",
        subject: name,
        detail: `Bucket has ${where}.`,
        impact:
          "B2 keeps every deleted file version forever without such a rule. Each restic forget --prune marks pack files hidden rather than removing them, so this bucket is still storing — and still billing for — data that was pruned.",
      });
    } else if (verdict === null) {
      findings.push({
        severity: "low",
        code: "lifecycle-unreadable",
        subject: name,
        detail:
          "Lifecycle rules could not be parsed from the snapshot, so pruning status is unknown.",
        impact:
          "Not evidence of a problem, and not evidence of safety — this bucket was not actually audited for hidden-version retention.",
      });
    }
  }

  for (const k of keys) {
    const keyId = String(k.applicationKeyId ?? "<unknown>");
    const keyName = typeof k.keyName === "string" && k.keyName
      ? k.keyName
      : keyId;
    const subject = keyName === keyId ? keyId : `${keyName} (${keyId})`;
    const bucketIds = Array.isArray(k.bucketIds) ? k.bucketIds.map(String) : [];
    const capabilities = Array.isArray(k.capabilities)
      ? k.capabilities.map(String)
      : [];

    if (bucketIds.length === 0) {
      findings.push({
        severity: "high",
        code: "key-account-wide",
        subject,
        detail:
          "Key is not restricted to any bucket, so it applies to every bucket in the account.",
        impact:
          "A per-host backup key should reach only that host's bucket. Account-wide, any single compromised host can read or destroy every other host's backups.",
      });
    } else {
      const dangling = bucketIds.filter((id) => !knownBucketIds.has(id));
      if (dangling.length > 0) {
        findings.push({
          severity: "medium",
          code: "key-orphaned",
          subject,
          detail:
            `Key is restricted to ${dangling.length} bucket ID(s) that do not exist in this account.`,
          impact:
            "The bucket was deleted but its key was not revoked. It grants nothing today, but it is a live credential that will silently regain access if a bucket is ever recreated with the same ID.",
        });
      }
    }

    const dangerous = capabilities.filter((c) => c in DANGEROUS_CAPABILITIES);
    if (dangerous.length > 0) {
      findings.push({
        severity: dangerous.includes("writeKeys") ||
            dangerous.includes("bypassGovernance")
          ? "critical"
          : "high",
        code: "key-dangerous-capability",
        subject,
        detail: `Key holds ${dangerous.length} high-privilege capability(s): ${
          dangerous.join(", ")
        }.`,
        impact: dangerous.map((c) => `${c} — ${DANGEROUS_CAPABILITIES[c]}`)
          .join("; "),
      });
    }

    if (k.expirationTimestamp === null || k.expirationTimestamp === undefined) {
      findings.push({
        severity: "low",
        code: "key-never-expires",
        subject,
        detail: "Key has no expiration timestamp.",
        impact:
          "It stays valid until explicitly revoked, so a leak has an unbounded window. Acceptable for a long-lived backup key, but it must then be rotated deliberately.",
      });
    }
  }

  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.code.localeCompare(b.code) ||
      a.subject.localeCompare(b.subject),
  );
}

/** Render the findings as markdown. */
export function renderMarkdown(
  findings: Finding[],
  meta: {
    bucketCount: number;
    keyCount: number;
    truncated: boolean;
    keysTruncated: boolean;
    scannedAt: string | null;
  },
): string {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const lines: string[] = ["# B2 fleet hygiene audit", ""];

  if (meta.truncated) {
    // This goes first, before any number, so it cannot be skimmed past.
    lines.push(
      "> **This inventory is INCOMPLETE.** A listing hit its page cap" +
        (meta.keysTruncated ? " (application keys)" : "") +
        ", so objects exist that were never examined. Treat every count below as a" +
        " lower bound, and do not read the absence of a finding as evidence that a" +
        " problem is not there.",
      "",
    );
  }

  lines.push(
    `Scanned ${meta.bucketCount} bucket(s) and ${meta.keyCount} application key(s)` +
      (meta.scannedAt ? ` at ${meta.scannedAt}` : "") + ".",
    "",
  );

  if (findings.length === 0) {
    lines.push(
      meta.truncated
        ? "No findings **in the portion of the account that was scanned**."
        : "No findings. Every bucket prunes hidden versions and every key is scoped.",
      "",
    );
    return lines.join("\n");
  }

  const summary = SEVERITY_ORDER.filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");
  lines.push(`**${findings.length} finding(s):** ${summary}.`, "");

  lines.push(...renderFindingSections(findings));

  return lines.join("\n");
}

/**
 * Render findings grouped into severity sections.
 *
 * Extracted so the workflow-scope companion report renders findings the same
 * way rather than drifting its own copy — `extra` is its hook for appending a
 * per-finding line (the byte cost) without duplicating the section structure.
 * When `extra` is omitted the output is byte-identical to what this produced
 * inline, which is what keeps the published method-scope report unchanged.
 */
export function renderFindingSections(
  findings: Finding[],
  extra?: (f: Finding) => string | null,
): string[] {
  const lines: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    lines.push(`## ${sev.toUpperCase()} (${group.length})`, "");
    for (const f of group) {
      lines.push(
        `### \`${f.code}\` — ${f.subject}`,
        "",
        f.detail,
        "",
        `**Why it matters:** ${f.impact}`,
        "",
      );
      const more = extra?.(f);
      if (more) lines.push(more, "");
    }
  }
  return lines;
}

/**
 * The hygiene report.
 *
 * Method-scope, so it runs after a single `scan` and sees exactly the resources
 * that scan produced. It declines to run against any other method or against a
 * failed scan rather than auditing a partial inventory.
 */
export const report = {
  name: "@sntxrr/b2/hygiene",
  description:
    "Audit a scanned Backblaze B2 account for hidden-version retention gaps, over-scoped or orphaned application keys, and public buckets. Read-only — analyses the scan's resources and never calls B2.",
  scope: "method" as const,
  labels: ["audit", "security", "cost", "backblaze", "b2"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<ReportResult> => {
    // Only b2-account's scan produces the inventory this audits. Anything else
    // gets an explicit no-op rather than a misleading empty clean bill.
    if (context.methodName !== "scan") {
      return {
        markdown:
          `# B2 fleet hygiene audit\n\nSkipped: this report audits the inventory produced by \`scan\`, and this run was \`${context.methodName}\`.\n`,
        json: { skipped: true, reason: "not-a-scan", findings: [] },
      };
    }
    if (context.executionStatus !== "succeeded") {
      return {
        markdown:
          "# B2 fleet hygiene audit\n\nSkipped: the scan did not succeed, so any inventory it wrote is partial and auditing it would be misleading.\n",
        json: { skipped: true, reason: "scan-failed", findings: [] },
      };
    }

    const handles = (context.dataHandles ?? []) as Array<
      { name: string; specName?: string; version?: number }
    >;
    const bySpec = (spec: string) => handles.filter((h) => h.specName === spec);

    const buckets: Record<string, unknown>[] = [];
    for (const h of bySpec("bucket")) {
      const snap = await readSnapshot(context, h);
      if (snap) buckets.push(snap);
    }
    const keys: Record<string, unknown>[] = [];
    for (const h of bySpec("key")) {
      const snap = await readSnapshot(context, h);
      if (snap) keys.push(snap);
    }
    const accountHandle = bySpec("account")[0];
    const account = accountHandle
      ? await readSnapshot(context, accountHandle)
      : null;

    const truncated = account?.truncated === true;
    const meta = {
      bucketCount: buckets.length,
      keyCount: keys.length,
      truncated,
      keysTruncated: account?.keysTruncated === true,
      scannedAt: typeof account?.observedAt === "string"
        ? account.observedAt
        : null,
    };

    const findings = analyze(buckets, keys);
    context.logger?.info?.(
      "B2 hygiene audit produced {n} finding(s) over {b} bucket(s) and {k} key(s)",
      { n: findings.length, b: buckets.length, k: keys.length },
    );

    return {
      markdown: renderMarkdown(findings, meta),
      json: {
        ...meta,
        // Never let a consumer read a count as complete without the caveat.
        inventoryComplete: !truncated,
        findingCount: findings.length,
        findings,
      },
    };
  },
};
