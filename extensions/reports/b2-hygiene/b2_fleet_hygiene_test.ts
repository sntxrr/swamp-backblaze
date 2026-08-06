/**
 * Unit tests for b2_fleet_hygiene.ts.
 *
 * The join is the easy part. What these tests are actually defending is the
 * distinction between the four sizing states — measured, truncated,
 * unmeasurable, unmeasured — because three of them are NOT zero and every one
 * of them is one careless `?? 0` away from rendering as zero. That is the
 * wave-1 `unprunedPrefixes` bug class, and a byte total is far more likely to
 * be quoted out of context than a finding count.
 *
 * @module
 */
import {
  assert,
  assertEquals,
  assertFalse,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { analyze, renderFindingSections } from "./b2_hygiene.ts";
import {
  type FleetMeta,
  joinSizing,
  renderMarkdown,
  report,
  sizeBucket,
  type SizedFinding,
  totalFleet,
} from "./b2_fleet_hygiene.ts";

const GIB = 1024 ** 3;

function agg(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bucketName: "example-host-ubuntu",
    bucketId: "b00000000000000000000001",
    group: null,
    listing: "versions",
    scanMode: "aggregate",
    currentBytes: 10 * GIB,
    nonCurrentBytes: 30 * GIB,
    nonCurrentFileCount: 1000,
    hideMarkerCount: 1000,
    truncated: false,
    ...over,
  };
}
function bucket(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bucketId: "b00000000000000000000001",
    bucketName: "example-host-ubuntu",
    bucketType: "allPrivate",
    lifecycleRules: [],
    ...over,
  };
}
function meta(over: Partial<FleetMeta> = {}): FleetMeta {
  return {
    bucketCount: 1,
    keyCount: 0,
    inventoryTruncated: false,
    keysTruncated: false,
    scannedAt: "2026-08-06T00:00:00Z",
    sizingStepStatus: "succeeded",
    aggregateCount: 1,
    ...over,
  };
}

// --- the four sizing states -------------------------------------------------

Deno.test("a complete versions listing is measured, with a waste ratio", () => {
  const s = sizeBucket("example-host-ubuntu", [agg()]);
  assertEquals(s.state, "measured");
  assertEquals(s.nonCurrentBytes, 30 * GIB);
  assertEquals(s.currentBytes, 10 * GIB);
  assertEquals(s.wasteRatio, 0.75);
});

Deno.test("a truncated listing is a FLOOR, never a total", () => {
  const s = sizeBucket("example-host-ubuntu", [agg({ truncated: true })]);
  assertEquals(s.state, "truncated");
  // The bytes are still reported — they are real, they are just not all of them.
  assertEquals(s.nonCurrentBytes, 30 * GIB);
});

Deno.test("a names listing is unmeasurable, not zero", () => {
  // b2_list_file_names cannot see a non-current version, so its silence is not
  // evidence of absence. Reporting 0 here would be the wave-1 bug verbatim.
  const s = sizeBucket(
    "example-host-ubuntu",
    [agg({ listing: "names", nonCurrentBytes: null })],
  );
  assertEquals(s.state, "unmeasurable");
  assertEquals(s.nonCurrentBytes, null);
  assertEquals(s.wasteRatio, null);
});

Deno.test("a bucket with no aggregate is unmeasured, not zero", () => {
  const s = sizeBucket("never-scanned", [agg()]);
  assertEquals(s.state, "unmeasured");
  assertEquals(s.nonCurrentBytes, null);
  assertEquals(s.currentBytes, null);
});

Deno.test("a null byte field makes the sum unknown rather than smaller", () => {
  // One unmeasured group must not quietly contribute 0 to a total that then
  // reads as measured — this is the exact shape of the bug this suite exists for.
  const s = sizeBucket("example-host-ubuntu", [
    agg({ group: "data/", nonCurrentBytes: 5 * GIB }),
    agg({ group: "index/", nonCurrentBytes: null }),
  ]);
  assertEquals(s.state, "unmeasurable");
  assertEquals(s.nonCurrentBytes, null);
});

// --- choosing which aggregate speaks for the bucket -------------------------

Deno.test("the bucket-wide total wins over the per-group rows", () => {
  // group:null is the whole bucket; the groups are a split OF it, so summing
  // both would double-count. Prefer the total.
  const s = sizeBucket("example-host-ubuntu", [
    agg({ group: null, nonCurrentBytes: 30 * GIB }),
    agg({ group: "data/", nonCurrentBytes: 20 * GIB }),
    agg({ group: "index/", nonCurrentBytes: 10 * GIB }),
  ]);
  assertEquals(s.nonCurrentBytes, 30 * GIB);
});

Deno.test("without a bucket-wide total the groups are summed", () => {
  const s = sizeBucket("example-host-ubuntu", [
    agg({ group: "data/", nonCurrentBytes: 20 * GIB, currentBytes: 1 * GIB }),
    agg({ group: "index/", nonCurrentBytes: 10 * GIB, currentBytes: 1 * GIB }),
  ]);
  assertEquals(s.state, "measured");
  assertEquals(s.nonCurrentBytes, 30 * GIB);
});

Deno.test("truncation on any summed group taints the whole bucket", () => {
  const s = sizeBucket("example-host-ubuntu", [
    agg({ group: "data/", truncated: true }),
    agg({ group: "index/", truncated: false }),
  ]);
  assertEquals(s.state, "truncated");
});

// --- joining ----------------------------------------------------------------

Deno.test("a key finding gets no sizing, because a key has no bytes", () => {
  const findings = analyze([], [{
    applicationKeyId: "0021a2b3c4d5e6f0000000001",
    keyName: "example-host",
    capabilities: ["listBuckets"],
    bucketIds: [],
    expirationTimestamp: null,
  }]);
  const sized = joinSizing(findings, [agg()]);
  assert(sized.length > 0);
  for (const f of sized) assertEquals(f.sizing, null);
});

Deno.test("a lifecycle finding is joined to its bucket's bytes", () => {
  const sized = joinSizing(analyze([bucket()], []), [agg()]);
  const lifecycle = sized.find((f) =>
    f.code === "lifecycle-no-hidden-version-pruning"
  ) as SizedFinding;
  assertEquals(lifecycle.sizing?.nonCurrentBytes, 30 * GIB);
});

// --- fleet totals -----------------------------------------------------------

Deno.test("unmeasured and unmeasurable buckets are excluded from the total, and counted", () => {
  const t = totalFleet([
    sizeBucket("example-host-ubuntu", [agg()]),
    sizeBucket("no-aggregate", []),
    sizeBucket("names-only", [
      agg({ bucketName: "names-only", listing: "names", nonCurrentBytes: null }),
    ]),
  ]);
  assertEquals(t.nonCurrentBytes, 30 * GIB);
  // Asserted because the names-only bucket has a KNOWN currentBytes of 10 GiB.
  // Letting it in while its non-current stays missing would understate fleet
  // waste — and a mutation that dropped the exclusion passed every other test
  // in this file, so this assertion is the only thing holding that line.
  assertEquals(t.currentBytes, 10 * GIB);
  assertEquals(t.measuredBuckets, 1);
  assertEquals(t.unmeasuredBuckets, 1);
  assertEquals(t.unmeasurableBuckets, 1);
  assertFalse(t.isFloor);
});

Deno.test("one truncated bucket makes the whole fleet total a floor", () => {
  const t = totalFleet([
    sizeBucket("example-host-ubuntu", [agg()]),
    sizeBucket("big", [agg({ bucketName: "big", truncated: true })]),
  ]);
  assert(t.isFloor);
  assertEquals(t.truncatedBuckets, 1);
});

Deno.test("the cost estimate uses decimal GB, as B2 bills", () => {
  // 30 GiB is ~32.21 GB; at $0.006/GB-month that is ~$0.193. Billing in GiB
  // would understate it by 7%, which compounds across a fleet.
  const t = totalFleet([sizeBucket("example-host-ubuntu", [agg()])]);
  assert(
    Math.abs(t.estimatedMonthlyUsd - 0.1932735) < 0.001,
    `expected ~0.1933, got ${t.estimatedMonthlyUsd}`,
  );
});

// --- rendering honesty ------------------------------------------------------

Deno.test("an unmeasured bucket never renders as 0.00 GiB", () => {
  const sized = joinSizing(analyze([bucket()], []), []);
  const md = renderMarkdown(sized, totalFleet([sizeBucket("example-host-ubuntu", [])]), meta());
  assertStringIncludes(md, "not measured");
  assertFalse(
    md.includes("0.00 GiB non-current"),
    "an unmeasured bucket must never be rendered as a zero byte count",
  );
});

Deno.test("a small but real byte count never rounds away to zero", () => {
  // Found live, not by mocking: five buckets rendered "0.00 GiB" in a table
  // whose rows are all > 0 by construction, so every one of those zeroes was
  // a rounding artefact sitting where real data should be. 155 bytes and
  // 4.4 MiB read as identically nothing.
  for (
    const [bytes, expect] of [
      [155, "155 B"],
      [2156, "2.11 KiB"],
      [4_574_013, "4.36 MiB"],
    ] as Array<[number, string]>
  ) {
    const aggs = [agg({ bucketName: "tiny", nonCurrentBytes: bytes })];
    const md = renderMarkdown(
      joinSizing(analyze([bucket({ bucketName: "tiny" })], []), aggs),
      totalFleet([sizeBucket("tiny", aggs)]),
      meta(),
    );
    assertStringIncludes(md, expect);
  }
});

Deno.test("the floor warning appears before any byte total", () => {
  const sizings = [sizeBucket("example-host-ubuntu", [agg({ truncated: true })])];
  const sized = joinSizing(analyze([bucket()], []), [agg({ truncated: true })]);
  const md = renderMarkdown(sized, totalFleet(sizings), meta());
  const warn = md.indexOf("FLOOR");
  const total = md.indexOf("The lifecycle debt");
  assert(warn >= 0 && total >= 0, "both the warning and the total must render");
  assert(warn < total, "a caveat below the number does not get read");
});

Deno.test("a missing sizing step says findings are unpriced, not free", () => {
  const sized = joinSizing(analyze([bucket()], []), []);
  const md = renderMarkdown(sized, totalFleet([]), meta({ sizingStepStatus: null }));
  assertStringIncludes(md, "unpriced");
  assertFalse(
    md.includes("## The lifecycle debt"),
    "no sizing step means no debt section — an empty one would read as zero debt",
  );
});

Deno.test("a failed sizing step is called out rather than silently omitted", () => {
  const md = renderMarkdown(
    joinSizing(analyze([bucket()], []), []),
    totalFleet([]),
    meta({ sizingStepStatus: "failed" }),
  );
  assertStringIncludes(md, "did not run to completion");
});

Deno.test("the dollar figure always carries the rate it came from", () => {
  const md = renderMarkdown(
    joinSizing(analyze([bucket()], []), [agg()]),
    totalFleet([sizeBucket("example-host-ubuntu", [agg()])]),
    meta(),
  );
  assertStringIncludes(md, "$0.006/GB-month");
  assertStringIncludes(md, "estimate");
});

Deno.test("the worklist ranks buckets by bytes, not by severity", () => {
  const aggs = [
    agg({ bucketName: "small", nonCurrentBytes: 1 * GIB }),
    agg({ bucketName: "huge", nonCurrentBytes: 100 * GIB }),
  ];
  const buckets = [bucket({ bucketName: "small" }), bucket({ bucketName: "huge" })];
  const md = renderMarkdown(
    joinSizing(analyze(buckets, []), aggs),
    totalFleet(buckets.map((b) => sizeBucket(String(b.bucketName), aggs))),
    meta({ bucketCount: 2 }),
  );
  const table = md.slice(md.indexOf("## Worklist"));
  assert(
    table.indexOf("| huge |") < table.indexOf("| small |"),
    "the biggest recovery must come first",
  );
});

// --- the published method-scope report must not have changed ----------------

Deno.test("renderFindingSections without an extra hook adds nothing per finding", () => {
  // b2_hygiene.renderMarkdown was refactored to call this. If the no-hook path
  // ever emits an extra line, the PUBLISHED report's output silently changes.
  const findings = analyze([bucket()], []);
  const plain = renderFindingSections(findings);
  const hooked = renderFindingSections(findings, () => "**Costing:** x");
  assertEquals(hooked.length, plain.length + 2 * findings.length);
  assertFalse(plain.some((l) => l.startsWith("**Costing:**")));
});

// --- execute ----------------------------------------------------------------

/** Build a mock workflow context whose dataRepository serves the given snapshots. */
function ctx(
  steps: Array<Record<string, unknown>>,
  snapshots: Record<string, Record<string, unknown>>,
) {
  const logs: string[] = [];
  return {
    logs,
    context: {
      scope: "workflow",
      stepExecutions: steps,
      logger: { info: (m: string) => logs.push(m) },
      dataRepository: {
        getContent: (
          _t: string,
          _m: string,
          name: string,
        ): Promise<Uint8Array | null> => {
          const snap = snapshots[name];
          return Promise.resolve(
            snap
              ? new TextEncoder().encode(JSON.stringify(snap))
              : null,
          );
        },
      },
    },
  };
}

const INVENTORY_STEP = {
  stepName: "scan-account",
  modelType: "@sntxrr/b2/account",
  modelId: "m1",
  status: "succeeded",
  dataHandles: [
    { name: "bucket-example-host-ubuntu", specName: "bucket" },
    { name: "account-summary", specName: "account" },
  ],
};
const SIZING_STEP = {
  stepName: "size-hidden-version-debt",
  modelType: "@sntxrr/b2/files",
  modelId: "m2",
  status: "succeeded",
  dataHandles: [{ name: "aggregate-example-all", specName: "aggregate" }],
};
const SNAPSHOTS = {
  "bucket-example-host-ubuntu": bucket(),
  "account-summary": { truncated: false, observedAt: "2026-08-06T00:00:00Z" },
  "aggregate-example-all": agg(),
};

Deno.test("execute joins the inventory step to the sizing step", async () => {
  const { context } = ctx([INVENTORY_STEP, SIZING_STEP], SNAPSHOTS);
  const out = await report.execute(context);
  assertEquals(out.json.findingCount, 1);
  assertStringIncludes(out.markdown, "The lifecycle debt");
  assertStringIncludes(out.markdown, "30.00 GiB");
});

Deno.test("execute finds the steps by spec, not by step name", async () => {
  // A workflow author may rename a step at any time; the specs are the contract.
  const { context } = ctx(
    [
      { ...INVENTORY_STEP, stepName: "renamed-entirely" },
      { ...SIZING_STEP, stepName: "also-renamed" },
    ],
    SNAPSHOTS,
  );
  const out = await report.execute(context);
  assertEquals(out.json.findingCount, 1);
  assertStringIncludes(out.markdown, "30.00 GiB");
});

Deno.test("execute refuses to audit when no step produced an inventory", async () => {
  const { context } = ctx([SIZING_STEP], SNAPSHOTS);
  const out = await report.execute(context);
  assertEquals(out.json.skipped, true);
  assertEquals(out.json.reason, "no-inventory-step");
});

Deno.test("execute refuses to audit a failed inventory step", async () => {
  const { context } = ctx(
    [{ ...INVENTORY_STEP, status: "failed" }, SIZING_STEP],
    SNAPSHOTS,
  );
  const out = await report.execute(context);
  assertEquals(out.json.skipped, true);
});

Deno.test("a failed sizing step contributes no bytes at all", async () => {
  // It may well have written some aggregates before dying. Totalling a partial
  // fleet and presenting it as the fleet is the failure being prevented.
  const { context } = ctx(
    [INVENTORY_STEP, { ...SIZING_STEP, status: "failed" }],
    SNAPSHOTS,
  );
  const out = await report.execute(context);
  assertEquals(out.json.aggregateCount, 0);
  assertStringIncludes(out.markdown, "did not run to completion");
  assertFalse(out.markdown.includes("30.00 GiB"));
});

Deno.test("a workflow with no sizing step still audits, and says it is unpriced", async () => {
  const { context } = ctx([INVENTORY_STEP], SNAPSHOTS);
  const out = await report.execute(context);
  assertEquals(out.json.findingCount, 1);
  assertEquals(out.json.sizingStepStatus, null);
  assertStringIncludes(out.markdown, "unpriced");
});

Deno.test("sizingComplete is reported separately from inventoryComplete", async () => {
  // The inventory can be whole while the sizing over it is a floor. A consumer
  // gating on cost must be able to tell which of the two it is looking at.
  const { context } = ctx(
    [INVENTORY_STEP, SIZING_STEP],
    { ...SNAPSHOTS, "aggregate-example-all": agg({ truncated: true }) },
  );
  const out = await report.execute(context);
  assertEquals(out.json.inventoryComplete, true);
  assertEquals(out.json.sizingComplete, false);
});

Deno.test("an unreadable snapshot is skipped, not counted as a clean object", async () => {
  const { context } = ctx([INVENTORY_STEP, SIZING_STEP], {
    "account-summary": SNAPSHOTS["account-summary"],
    "aggregate-example-all": SNAPSHOTS["aggregate-example-all"],
  });
  const out = await report.execute(context);
  assertEquals(out.json.bucketCount, 0);
  assertEquals(out.json.findingCount, 0);
});

Deno.test("the report declares workflow scope and audit labels", () => {
  assertEquals(report.scope, "workflow");
  assertEquals(report.name, "@sntxrr/b2/fleet-hygiene");
  assert(report.labels.includes("cost"));
  assert(report.labels.includes("audit"));
});
