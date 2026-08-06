/**
 * Backblaze B2 fleet hygiene audit — findings joined to what they cost.
 *
 * A workflow-scope companion to `@sntxrr/b2/hygiene`. The method-scope report
 * audits one `b2-account` scan and answers "which buckets have no
 * hidden-version retention rule?". It cannot answer "and what is that costing?"
 * — the bytes live in a `@sntxrr/b2/files` aggregate written by a *different*
 * model, and a method-scope report only ever sees the resources its own
 * execution produced.
 *
 * Workflow scope is the seam that closes that gap: `context.stepExecutions`
 * carries every step's `modelType`, `modelId` and `dataHandles`, so this report
 * can read the inventory from one step and the sizing from another and join
 * them on bucket name. The finding and its price stop being two documents.
 *
 * **Why the join matters.** "0 of 24 buckets prunes hidden versions" is a
 * policy finding that reads the same whether it costs pennies or hundreds of
 * dollars. Joined to the aggregate it becomes a ranked worklist: on the estate
 * this was built for, two buckets carried 33 of the 39.49 GiB of non-current
 * data, and nine were over 80% waste. Same 24 findings, radically different
 * order of attack.
 *
 * **Honesty rules, inherited and extended.** The method-scope report refuses to
 * present a finding count as complete over a truncated inventory. This one adds
 * the same rule for bytes, and it needs a stricter version: a byte total is far
 * more inviting to quote than a finding count, and there are three distinct
 * ways for it to be wrong. A bucket can be unmeasured (no aggregate — the
 * sizing step never covered it), unmeasurable (`nonCurrentBytes` is null
 * because the scan listed names rather than versions, so non-current data was
 * invisible by construction), or under-measured (`truncated` — listing stopped
 * at the page cap, so the number is a floor). None of the three is zero, and
 * this report never renders them as one.
 *
 * @module
 */

import {
  analyze,
  type Finding,
  renderFindingSections,
  type ReportResult,
  SEVERITY_ORDER,
} from "./b2_hygiene.ts";

/**
 * B2 Cloud Storage list price per GB-month, in USD.
 *
 * Stated as a constant, printed in the output, and labelled an estimate on
 * purpose: this is a published list price observed 2026-08, not something the
 * report can verify against the account's actual invoice. A reader who quotes a
 * dollar figure must be able to see the rate it came from and check it. Storage
 * only — non-current data costs nothing in transactions once it is sitting
 * there, so this deliberately does not model class-B/C fees.
 */
const USD_PER_GB_MONTH = 0.006;
const RATE_OBSERVED = "2026-08";
const BYTES_PER_GIB = 1024 ** 3;
/** B2 bills per GB (decimal), not per GiB — keep the two conversions distinct. */
const BYTES_PER_GB = 1000 ** 3;

/** How a bucket's non-current bytes are known, or why they are not. */
type SizingState =
  /** An aggregate was found and reports a real byte count. */
  | "measured"
  /** An aggregate was found but stopped at the page cap — the count is a floor. */
  | "truncated"
  /** An aggregate was found but listed names, so versions were never visible. */
  | "unmeasurable"
  /** No aggregate covers this bucket at all. */
  | "unmeasured";

/** One bucket's sizing, joined onto its findings. */
type Sizing = {
  bucketName: string;
  state: SizingState;
  /** Null whenever `state` is anything but "measured" or "truncated". */
  nonCurrentBytes: number | null;
  currentBytes: number | null;
  nonCurrentFileCount: number | null;
  hideMarkerCount: number | null;
  /** Non-current as a share of total, or null when it cannot be computed. */
  wasteRatio: number | null;
};

/** A finding with whatever the sizing step could say about its subject. */
export type SizedFinding = Finding & { sizing: Sizing | null };

/** Read a number that may legitimately be null, rejecting anything else. */
function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/**
 * Reduce one bucket's aggregate snapshots to a single sizing.
 *
 * A fleet scan writes one aggregate per (bucket, group) pair plus a bucket-wide
 * total, and the total is the one carrying `group === null`. Prefer it; fall
 * back to summing the groups only when the total is absent, because summing
 * groups is not equivalent — a group split covers the same bytes but a missing
 * group would silently under-count, and under-counting is the failure mode this
 * whole report exists to prevent. When falling back, truncation on ANY group
 * taints the sum.
 */
export function sizeBucket(
  bucketName: string,
  aggregates: Record<string, unknown>[],
): Sizing {
  const mine = aggregates.filter((a) =>
    String(a.bucketName ?? "") === bucketName
  );
  if (mine.length === 0) {
    return {
      bucketName,
      state: "unmeasured",
      nonCurrentBytes: null,
      currentBytes: null,
      nonCurrentFileCount: null,
      hideMarkerCount: null,
      wasteRatio: null,
    };
  }

  const total = mine.find((a) => a.group === null);
  const chosen = total ? [total] : mine;

  // "names" listing cannot observe a non-current version at all, so its zero is
  // a claim the data does not support. Treat it as unmeasurable, not as clean.
  if (chosen.every((a) => a.listing === "names")) {
    return {
      bucketName,
      state: "unmeasurable",
      nonCurrentBytes: null,
      currentBytes: sum(chosen, "currentBytes"),
      nonCurrentFileCount: null,
      hideMarkerCount: null,
      wasteRatio: null,
    };
  }

  const nonCurrentBytes = sum(chosen, "nonCurrentBytes");
  if (nonCurrentBytes === null) {
    return {
      bucketName,
      state: "unmeasurable",
      nonCurrentBytes: null,
      currentBytes: sum(chosen, "currentBytes"),
      nonCurrentFileCount: null,
      hideMarkerCount: null,
      wasteRatio: null,
    };
  }

  const currentBytes = sum(chosen, "currentBytes");
  const denominator = (currentBytes ?? 0) + nonCurrentBytes;
  return {
    bucketName,
    state: chosen.some((a) => a.truncated === true) ? "truncated" : "measured",
    nonCurrentBytes,
    currentBytes,
    nonCurrentFileCount: sum(chosen, "nonCurrentFileCount"),
    hideMarkerCount: sum(chosen, "hideMarkerCount"),
    wasteRatio: denominator > 0 ? nonCurrentBytes / denominator : null,
  };
}

/**
 * Sum one field across aggregates, propagating null rather than coercing it.
 *
 * A single null makes the whole sum unknown. Treating it as zero is exactly the
 * wave-1 `unprunedPrefixes` bug — a value that reads as "measured and fine"
 * when the truth is "never measured".
 */
function sum(rows: Record<string, unknown>[], field: string): number | null {
  let acc = 0;
  for (const r of rows) {
    const v = num(r[field]);
    if (v === null) return null;
    acc += v;
  }
  return acc;
}

/** Attach sizing to every finding whose subject is a bucket we measured. */
export function joinSizing(
  findings: Finding[],
  aggregates: Record<string, unknown>[],
): SizedFinding[] {
  const cache = new Map<string, Sizing>();
  return findings.map((f) => {
    // Key findings are subject-ed on an application key, not a bucket, so there
    // is nothing to join and null says so rather than inventing an empty sizing.
    if (!f.code.startsWith("lifecycle-") && f.code !== "bucket-public") {
      return { ...f, sizing: null };
    }
    if (!cache.has(f.subject)) {
      cache.set(f.subject, sizeBucket(f.subject, aggregates));
    }
    return { ...f, sizing: cache.get(f.subject) as Sizing };
  });
}

/** Fleet-wide totals, carrying how much of the fleet they actually cover. */
export type FleetTotals = {
  measuredBuckets: number;
  truncatedBuckets: number;
  unmeasurableBuckets: number;
  unmeasuredBuckets: number;
  nonCurrentBytes: number;
  currentBytes: number;
  /** True when any contributing bucket was truncated — the total is a floor. */
  isFloor: boolean;
  estimatedMonthlyUsd: number;
};

/** Total the sizings, tracking coverage so the total can never pose as complete. */
export function totalFleet(sizings: Sizing[]): FleetTotals {
  const t: FleetTotals = {
    measuredBuckets: 0,
    truncatedBuckets: 0,
    unmeasurableBuckets: 0,
    unmeasuredBuckets: 0,
    nonCurrentBytes: 0,
    currentBytes: 0,
    isFloor: false,
    estimatedMonthlyUsd: 0,
  };
  for (const s of sizings) {
    if (s.state === "measured") t.measuredBuckets++;
    else if (s.state === "truncated") {
      t.truncatedBuckets++;
      t.isFloor = true;
    } else if (s.state === "unmeasurable") {
      // Skipped ENTIRELY, including its currentBytes, which are often known.
      // A bucket contributes both numbers or neither: letting its current bytes
      // into the total while its non-current bytes stay missing would swell the
      // "against N GiB of current data" comparison and make fleet waste look
      // smaller than it is. Understating the debt is the one direction this
      // report must never fail in.
      t.unmeasurableBuckets++;
      continue;
    } else {
      t.unmeasuredBuckets++;
      continue;
    }
    t.nonCurrentBytes += s.nonCurrentBytes ?? 0;
    t.currentBytes += s.currentBytes ?? 0;
  }
  t.estimatedMonthlyUsd = (t.nonCurrentBytes / BYTES_PER_GB) * USD_PER_GB_MONTH;
  return t;
}

/**
 * Format bytes in the largest unit that keeps them visible.
 *
 * Fixed GiB was the first implementation and the live run killed it: five
 * buckets rendered as "0.00 GiB" in a table every row of which had already
 * passed a `> 0` filter, so each of those zeroes was a rounding artefact
 * standing where real data should be — one bucket's 155 bytes and another's
 * 4.4 MiB read as identically nothing. A report whose
 * entire purpose is refusing to render an unknown as zero must not render a
 * known quantity as zero either. Scaling the unit is the fix; the alternative,
 * more decimal places, just moves the threshold.
 */
function gib(bytes: number): string {
  const units: Array<[number, string]> = [
    [BYTES_PER_GIB * 1024, "TiB"],
    [BYTES_PER_GIB, "GiB"],
    [1024 ** 2, "MiB"],
    [1024, "KiB"],
  ];
  for (const [size, name] of units) {
    if (bytes >= size) return `${(bytes / size).toFixed(2)} ${name}`;
  }
  // Below a KiB, show the exact count — at this scale a decimal is noise and
  // the honest answer is simply the number.
  return `${bytes} B`;
}

/** Render one bucket's sizing as a short human phrase. */
function describeSizing(s: Sizing): string {
  switch (s.state) {
    case "unmeasured":
      return "**not measured** — no b2-files aggregate covered this bucket";
    case "unmeasurable":
      return "**not measurable** — the scan listed file names, which cannot see a non-current version";
    case "truncated":
      return `**at least ${
        gib(s.nonCurrentBytes as number)
      }** non-current (listing hit its page cap — this is a FLOOR)`;
    case "measured":
      return `${gib(s.nonCurrentBytes as number)} non-current` +
        (s.wasteRatio !== null
          ? ` (${
            (s.wasteRatio * 100).toFixed(0)
          }% of this bucket's stored bytes)`
          : "");
  }
}

// ---------------------------------------------------------------------------
// Abandoned uploads — the third kind of waste, and the only one that can bite
// ---------------------------------------------------------------------------

/**
 * How old an unfinished upload must be before it is called abandoned.
 *
 * This threshold is a SAFETY device, not a tuning knob. An interrupted large
 * upload and an upload that is happening right now are the same object in the
 * B2 API — `b2_list_unfinished_large_files` returns both, identically. So a
 * report that flags every unfinished upload as waste is telling an operator to
 * cancel a transfer that may be mid-flight, and `delete` would then discard
 * every part already sent, silently, while the tool that was uploading carries
 * on believing it succeeded.
 *
 * One day is far longer than any transfer this estate performs and far shorter
 * than the five years the real abandoned uploads had been sitting. Anything
 * younger is reported as excluded rather than as a finding.
 */
const ABANDONED_AFTER_DAYS = 1;

/** One interrupted upload, as the b2-transfer scan snapshots it. */
type UnfinishedUpload = {
  fileId: string;
  fileName: string;
  bucketName: string;
  ageDays: number | null;
  partCount: number | null;
  partBytes: number | null;
  partsTruncated: boolean | null;
  status: string;
};

/** What the abandoned-upload sweep found, and what it deliberately excluded. */
export type UploadTotals = {
  abandonedCount: number;
  /** Bytes across abandoned uploads whose parts were actually measured. */
  abandonedBytes: number;
  /** Abandoned uploads whose parts were never counted — NOT zero bytes. */
  unsizedCount: number;
  /** Young enough to be in flight, so deliberately not called waste. */
  recentCount: number;
  /** No timestamp, so age could not be established either way. */
  unknownAgeCount: number;
  /** True when any contributing part listing was truncated. */
  isFloor: boolean;
};

/** Coerce a snapshot into the fields this report reads, defensively. */
export function toUpload(raw: Record<string, unknown>): UnfinishedUpload {
  const n = (v: unknown): number | null =>
    typeof v === "number" && Number.isFinite(v) ? v : null;
  return {
    fileId: String(raw.fileId ?? ""),
    fileName: String(raw.fileName ?? ""),
    bucketName: String(raw.bucketName ?? ""),
    ageDays: n(raw.ageDays),
    partCount: n(raw.partCount),
    partBytes: n(raw.partBytes),
    partsTruncated: typeof raw.partsTruncated === "boolean"
      ? raw.partsTruncated
      : null,
    status: String(raw.status ?? "present"),
  };
}

/**
 * Turn interrupted uploads into findings, refusing to call a live one waste.
 *
 * Three outcomes, and the split is the whole point:
 *
 * - Old enough to be certainly dead → `upload-abandoned`, a real finding.
 * - Young enough to be in flight → NO finding. Counted and reported as
 *   excluded, so its absence from the list is visible rather than silent.
 * - No timestamp at all → `upload-age-unknown` at low severity, which says
 *   explicitly that it is not an accusation and not a clean bill.
 *
 * An upload already cancelled (`status: "absent"`) is not a finding either — it
 * is a tombstone from a previous `delete`, and re-reporting it would make a
 * fixed problem look permanent.
 */
export function analyzeUploads(uploads: UnfinishedUpload[]): Finding[] {
  const findings: Finding[] = [];
  for (const u of uploads) {
    if (u.status !== "present") continue;
    const where = `${u.bucketName}/${u.fileName}`;
    if (u.ageDays === null) {
      findings.push({
        severity: "low",
        code: "upload-age-unknown",
        subject: where,
        detail:
          "An interrupted large upload B2 reported no start timestamp for, so " +
          "its age could not be established.",
        impact:
          "Not evidence of waste, and not evidence of safety — it cannot be " +
          "told apart from an upload that is in flight right now, and " +
          "cancelling one of those discards every part already sent while the " +
          "uploading tool carries on believing it succeeded. Establish its age " +
          "before acting on it.",
      });
      continue;
    }
    if (u.ageDays < ABANDONED_AFTER_DAYS) continue;

    const size = u.partBytes === null
      ? "an unmeasured number of parts (run scan with countParts=true to size it)"
      : `${u.partCount ?? "?"} part(s) totalling ${
        u.partsTruncated ? "at least " : ""
      }${gib(u.partBytes)}`;
    findings.push({
      severity: "medium",
      code: "upload-abandoned",
      subject: where,
      detail:
        `A large upload interrupted ${u.ageDays} day(s) ago still holds ${size}.`,
      impact:
        "B2 stores and bills an unfinished large file's parts indefinitely. " +
        "They do not appear in b2_list_file_names and the console's file " +
        "browser cannot show them, so unlike every other kind of waste here " +
        "there is no way to notice this by looking. Cancel it with " +
        "@sntxrr/b2/transfer delete --input allowTransferDestruction=true.",
    });
  }
  return findings;
}

/**
 * Total the abandoned uploads, keeping unmeasured ones out of the byte sum.
 *
 * Same rule as the lifecycle totals: an upload whose parts were never counted
 * contributes to `unsizedCount`, never a zero to `abandonedBytes`. A byte total
 * that quietly includes unmeasured objects as zero understates the waste, and
 * understating is the one direction this report must not fail in.
 */
export function totalUploads(uploads: UnfinishedUpload[]): UploadTotals {
  const t: UploadTotals = {
    abandonedCount: 0,
    abandonedBytes: 0,
    unsizedCount: 0,
    recentCount: 0,
    unknownAgeCount: 0,
    isFloor: false,
  };
  for (const u of uploads) {
    if (u.status !== "present") continue;
    if (u.ageDays === null) {
      t.unknownAgeCount++;
      continue;
    }
    if (u.ageDays < ABANDONED_AFTER_DAYS) {
      t.recentCount++;
      continue;
    }
    t.abandonedCount++;
    if (u.partBytes === null) {
      t.unsizedCount++;
      continue;
    }
    t.abandonedBytes += u.partBytes;
    if (u.partsTruncated === true) t.isFloor = true;
  }
  return t;
}

/** Metadata the renderer needs that is not derivable from the findings. */
export type FleetMeta = {
  bucketCount: number;
  keyCount: number;
  inventoryTruncated: boolean;
  keysTruncated: boolean;
  scannedAt: string | null;
  /** Null when the workflow carried no b2-files step at all. */
  sizingStepStatus: "succeeded" | "failed" | "skipped" | null;
  aggregateCount: number;
  /** Null when the workflow carried no b2-transfer step at all. */
  uploadStepStatus: "succeeded" | "failed" | "skipped" | null;
  uploadTotals: UploadTotals;
};

/** Render the combined audit as markdown. */
export function renderMarkdown(
  sized: SizedFinding[],
  totals: FleetTotals,
  meta: FleetMeta,
): string {
  const lines: string[] = ["# B2 fleet hygiene audit — findings and cost", ""];

  // Both incompleteness warnings go above every number, for the same reason the
  // method-scope report puts its own there: a caveat below a total does not get
  // read, and a total that gets quoted without its caveat is worse than absent.
  if (meta.inventoryTruncated) {
    lines.push(
      "> **This inventory is INCOMPLETE.** A listing hit its page cap" +
        (meta.keysTruncated ? " (application keys)" : "") +
        ", so objects exist that were never examined. Treat every count below as a" +
        " lower bound, and do not read the absence of a finding as evidence that a" +
        " problem is not there.",
      "",
    );
  }
  if (meta.sizingStepStatus === null) {
    lines.push(
      "> **No sizing available.** This workflow run carried no `@sntxrr/b2/files`" +
        " step, so the findings below have no byte cost attached. They are not" +
        " free — they are unpriced.",
      "",
    );
  } else if (meta.sizingStepStatus !== "succeeded") {
    lines.push(
      `> **Sizing did not run to completion** (the b2-files step ${meta.sizingStepStatus}).` +
        " Any bucket below that shows no byte count was not measured, which is" +
        " not the same as measuring zero.",
      "",
    );
  }
  if (totals.isFloor) {
    lines.push(
      `> **The byte totals below are a FLOOR.** ${totals.truncatedBuckets} bucket(s)` +
        " stopped listing at the page cap, so their real non-current data is larger" +
        " than reported — re-run the b2-files scan with a higher `maxPages` before" +
        " quoting any of these numbers.",
      "",
    );
  }
  if (meta.uploadStepStatus !== null && meta.uploadStepStatus !== "succeeded") {
    lines.push(
      `> **The abandoned-upload sweep did not complete** (the b2-transfer step` +
        ` ${meta.uploadStepStatus}). Interrupted large uploads are invisible in` +
        " the B2 console, so nothing below should be read as evidence there are" +
        " none.",
      "",
    );
  }

  lines.push(
    `Scanned ${meta.bucketCount} bucket(s) and ${meta.keyCount} application key(s)` +
      (meta.scannedAt ? ` at ${meta.scannedAt}` : "") + ".",
    "",
  );

  if (meta.sizingStepStatus !== null) {
    const covered = totals.measuredBuckets + totals.truncatedBuckets;
    lines.push(
      "## The lifecycle debt",
      "",
      `**${totals.isFloor ? "At least " : ""}${
        gib(totals.nonCurrentBytes)
      }** of` +
        " non-current data across " + `${covered} measured bucket(s)` +
        `, against ${gib(totals.currentBytes)} of current data.`,
      "",
      `Estimated at **$${totals.estimatedMonthlyUsd.toFixed(2)}/month**` +
        `${totals.isFloor ? " or more" : ""}, at the B2 list price of` +
        ` $${USD_PER_GB_MONTH}/GB-month observed ${RATE_OBSERVED}. That is an` +
        " estimate from a published rate, not a reading of your invoice — verify" +
        " it against current B2 pricing before acting on it.",
      "",
    );
    if (totals.unmeasuredBuckets > 0 || totals.unmeasurableBuckets > 0) {
      lines.push(
        `Not included above: ${totals.unmeasuredBuckets} bucket(s) no aggregate` +
          ` covered and ${totals.unmeasurableBuckets} bucket(s) whose scan could` +
          " not observe non-current versions. Those are unknowns, not zeroes.",
        "",
      );
    }
  }

  // Kept as its own section rather than folded into the lifecycle total on
  // purpose: these are two different wastes with two different fixes. The
  // lifecycle debt is a policy gap fixed by a bucket rule; an abandoned upload
  // is a stuck transfer fixed by cancelling it. Adding them would produce one
  // number that points at neither remedy.
  const u = meta.uploadTotals;
  if (meta.uploadStepStatus !== null) {
    lines.push("## Abandoned uploads", "");
    if (u.abandonedCount === 0) {
      lines.push(
        "No interrupted large uploads older than " +
          `${ABANDONED_AFTER_DAYS} day(s).`,
        "",
      );
    } else {
      lines.push(
        `**${u.isFloor ? "At least " : ""}${gib(u.abandonedBytes)}** across` +
          ` ${u.abandonedCount} interrupted large upload(s), billed as storage` +
          " and invisible to `b2_list_file_names` and to the console's file" +
          " browser alike.",
        "",
        `Estimated at **$${
          (u.abandonedBytes / BYTES_PER_GB * USD_PER_GB_MONTH).toFixed(4)
        }/month** at the same list price. A small sum here is still worth` +
          " cancelling: nothing reclaims it on its own, and nothing else in" +
          " this suite can see it.",
        "",
      );
      if (u.unsizedCount > 0) {
        lines.push(
          `${u.unsizedCount} of those were never sized — run the b2-transfer` +
            " scan with `countParts=true`. They are unmeasured, not empty.",
          "",
        );
      }
    }
    // The exclusions are printed even when they are zero-free, because a reader
    // must be able to tell "we found none" from "we deliberately left some out".
    if (u.recentCount > 0 || u.unknownAgeCount > 0) {
      lines.push(
        `Deliberately excluded: ${u.recentCount} upload(s) younger than` +
          ` ${ABANDONED_AFTER_DAYS} day(s), which may be IN FLIGHT right now,` +
          ` and ${u.unknownAgeCount} whose age B2 did not report. Cancelling a` +
          " live upload discards every part already sent while the uploading" +
          " tool carries on believing it succeeded.",
        "",
      );
    }
  }

  if (sized.length === 0) {
    lines.push(
      meta.inventoryTruncated
        ? "No findings **in the portion of the account that was scanned**."
        : "No findings. Every bucket prunes hidden versions and every key is scoped.",
      "",
    );
    return lines.join("\n");
  }

  const counts: Record<string, number> = {};
  for (const f of sized) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const summary = SEVERITY_ORDER.filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");
  lines.push(`**${sized.length} finding(s):** ${summary}.`, "");

  // The worklist is the whole point of joining: same findings, ordered by what
  // fixing them actually recovers rather than by severity alone.
  const priced = sized
    .filter((f) => f.sizing && (f.sizing.nonCurrentBytes ?? 0) > 0)
    .sort((a, b) =>
      (b.sizing?.nonCurrentBytes ?? 0) - (a.sizing?.nonCurrentBytes ?? 0)
    );
  if (priced.length > 0) {
    lines.push("## Worklist — by what fixing it recovers", "");
    lines.push(
      "| bucket | finding | non-current | waste |",
      "| --- | --- | --- | --- |",
    );
    for (const f of priced) {
      const s = f.sizing as Sizing;
      const bytes = (s.state === "truncated" ? "≥ " : "") +
        gib(s.nonCurrentBytes as number);
      const waste = s.wasteRatio !== null
        ? `${(s.wasteRatio * 100).toFixed(0)}%`
        : "—";
      lines.push(`| ${f.subject} | \`${f.code}\` | ${bytes} | ${waste} |`);
    }
    lines.push("");
  }

  lines.push(...renderFindingSections(sized, (f) => {
    const s = (f as SizedFinding).sizing;
    return s ? `**Costing:** ${describeSizing(s)}` : null;
  }));

  return lines.join("\n");
}

/** Parse a resource snapshot's bytes into an object, or null if unreadable. */
async function readSnapshot(
  // deno-lint-ignore no-explicit-any
  context: any,
  step: { modelType: string; modelId: string },
  handle: { name: string; version?: number },
): Promise<Record<string, unknown> | null> {
  try {
    const raw = await context.dataRepository.getContent(
      step.modelType,
      step.modelId,
      handle.name,
      handle.version,
    );
    if (!raw) return null;
    return JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Collect every snapshot a step wrote under one spec name. */
async function readSpec(
  // deno-lint-ignore no-explicit-any
  context: any,
  // deno-lint-ignore no-explicit-any
  step: any,
  specName: string,
): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  const handles = (step.dataHandles ?? []) as Array<
    { name: string; specName?: string; version?: number }
  >;
  for (const h of handles.filter((h) => h.specName === specName)) {
    const snap = await readSnapshot(context, step, h);
    if (snap) out.push(snap);
  }
  return out;
}

/**
 * The combined fleet audit.
 *
 * Workflow-scope, so it sees every step. It identifies the inventory and sizing
 * steps by the SPECS they wrote rather than by step name or model name, because
 * a step name is a label the workflow author picks and this report should keep
 * working when someone renames one.
 */
export const report = {
  name: "@sntxrr/b2/fleet-hygiene",
  description:
    "Audit a Backblaze B2 fleet and price the result: joins @sntxrr/b2/hygiene's findings to the non-current byte totals from @sntxrr/b2/files, so a lifecycle gap is ranked by what fixing it recovers. Read-only — reads what the workflow's steps already wrote and never calls B2.",
  scope: "workflow" as const,
  labels: ["audit", "security", "cost", "backblaze", "b2"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<ReportResult> => {
    const steps = (context.stepExecutions ?? []) as Array<
      // deno-lint-ignore no-explicit-any
      any
    >;
    const hasSpec = (s: unknown, spec: string) =>
      // deno-lint-ignore no-explicit-any
      ((s as any)?.dataHandles ?? []).some((h: any) => h.specName === spec);

    const inventoryStep = steps.find((s) =>
      s.status === "succeeded" &&
      (hasSpec(s, "bucket") || hasSpec(s, "account"))
    );
    const sizingStep = steps.find((s) => hasSpec(s, "aggregate"));
    const uploadStep = steps.find((s) => hasSpec(s, "unfinished-upload"));

    if (!inventoryStep) {
      return {
        markdown:
          "# B2 fleet hygiene audit — findings and cost\n\nSkipped: no succeeded step in this workflow wrote a B2 inventory, so there is nothing to audit. A partial or failed scan is deliberately not audited — a clean bill over an inventory that was never taken is the most dangerous output this report could produce.\n",
        json: { skipped: true, reason: "no-inventory-step", findings: [] },
      };
    }

    const buckets = await readSpec(context, inventoryStep, "bucket");
    const keys = await readSpec(context, inventoryStep, "key");
    const account = (await readSpec(context, inventoryStep, "account"))[0] ??
      null;

    // Only a succeeded sizing step may contribute bytes. A failed one that
    // wrote some aggregates before dying would otherwise total a partial fleet
    // and present it as the fleet.
    const aggregates = sizingStep && sizingStep.status === "succeeded"
      ? await readSpec(context, sizingStep, "aggregate")
      : [];

    // Same rule as the sizing step: only a succeeded sweep may contribute. A
    // failed one that listed some buckets before dying would otherwise let
    // "we found three" stand in for "there are three".
    const uploads =
      (uploadStep && uploadStep.status === "succeeded"
        ? await readSpec(context, uploadStep, "unfinished-upload")
        : []).map(toUpload);

    const findings = [...analyze(buckets, keys), ...analyzeUploads(uploads)]
      .sort((a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) -
          SEVERITY_ORDER.indexOf(b.severity) ||
        a.code.localeCompare(b.code) ||
        a.subject.localeCompare(b.subject)
      );
    const sized = joinSizing(findings, aggregates);

    // Total over every bucket in the inventory, not merely over the ones that
    // produced a finding — otherwise a bucket that prunes correctly but still
    // holds non-current data would vanish from the fleet total.
    const totals = totalFleet(
      buckets.map((b) => sizeBucket(String(b.bucketName ?? ""), aggregates)),
    );

    const meta: FleetMeta = {
      bucketCount: buckets.length,
      keyCount: keys.length,
      inventoryTruncated: account?.truncated === true,
      keysTruncated: account?.keysTruncated === true,
      scannedAt: typeof account?.observedAt === "string"
        ? account.observedAt
        : null,
      sizingStepStatus: sizingStep ? sizingStep.status : null,
      aggregateCount: aggregates.length,
      uploadStepStatus: uploadStep ? uploadStep.status : null,
      uploadTotals: totalUploads(uploads),
    };

    context.logger?.info?.(
      "B2 fleet audit: {n} finding(s) over {b} bucket(s), {m} bucket(s) sized, {g} of non-current data{floor}; {a} abandoned upload(s) holding {ab}",
      {
        n: findings.length,
        b: buckets.length,
        m: totals.measuredBuckets + totals.truncatedBuckets,
        g: gib(totals.nonCurrentBytes),
        floor: totals.isFloor ? " (a FLOOR — some listings truncated)" : "",
        a: meta.uploadTotals.abandonedCount,
        ab: gib(meta.uploadTotals.abandonedBytes),
      },
    );

    return {
      markdown: renderMarkdown(sized, totals, meta),
      json: {
        ...meta,
        inventoryComplete: !meta.inventoryTruncated,
        // Distinct from inventoryComplete on purpose: the inventory can be whole
        // while the sizing over it is a floor, and a consumer gating on cost
        // needs to know which of the two it is looking at.
        sizingComplete: !totals.isFloor && totals.unmeasuredBuckets === 0 &&
          totals.unmeasurableBuckets === 0,
        // A third completeness flag, separate again: the abandoned-upload sweep
        // can be whole while the lifecycle sizing is a floor, or vice versa,
        // and a consumer acting on one must not be misled by the other's state.
        uploadSweepComplete: meta.uploadStepStatus === "succeeded" &&
          !meta.uploadTotals.isFloor && meta.uploadTotals.unsizedCount === 0,
        findingCount: findings.length,
        totals,
        rate: { usdPerGbMonth: USD_PER_GB_MONTH, observed: RATE_OBSERVED },
        findings: sized,
      },
    };
  },
};
