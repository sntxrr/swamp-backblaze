/**
 * Unit tests for b2_hygiene.ts — finding detection, the "cannot tell" path that
 * must not be reported as "does not prune", and the truncation honesty rule.
 * @module
 */
import { assert, assertEquals, assertFalse, assertStringIncludes } from "jsr:@std/assert@1";
import { analyze, prunesHiddenVersions, renderMarkdown, report } from "./b2_hygiene.ts";

const RESTIC_RULE = [{
  fileNamePrefix: "",
  daysFromUploadingToHiding: null,
  daysFromHidingToDeleting: 1,
}];

function bucket(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bucketId: "b00000000000000000000001",
    bucketName: "example-host-ubuntu",
    bucketType: "allPrivate",
    lifecycleRules: RESTIC_RULE,
    ...over,
  };
}
function key(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    applicationKeyId: "0021a2b3c4d5e6f0000000001",
    keyName: "example-host",
    capabilities: ["listBuckets", "readFiles", "writeFiles"],
    bucketIds: ["b00000000000000000000001"],
    expirationTimestamp: 1798761600000,
    ...over,
  };
}
const codes = (f: ReturnType<typeof analyze>) => f.map((x) => x.code);

// --- lifecycle parsing ------------------------------------------------------

Deno.test("a bucket with no lifecycle rules is reported as not pruning", () => {
  assertEquals(prunesHiddenVersions([]).verdict, false);
  const f = analyze([bucket({ lifecycleRules: [] })], []);
  assertEquals(codes(f), ["lifecycle-no-hidden-version-pruning"]);
  assertEquals(f[0].severity, "high");
});

Deno.test("a restic-safe rule produces no lifecycle finding", () => {
  assertEquals(prunesHiddenVersions(RESTIC_RULE).verdict, true);
  assertEquals(analyze([bucket()], []).length, 0);
});

Deno.test("unparseable lifecycle rules are 'cannot tell', never 'does not prune'", () => {
  // The distinction is the point: accusing a bucket of having no retention rule
  // when the field simply could not be read would be a false finding, and a
  // report whose findings cannot be trusted is worse than no report.
  for (const weird of [null, undefined, "surprise", 42, { rules: [] }]) {
    assertEquals(
      prunesHiddenVersions(weird).verdict,
      null,
      `${JSON.stringify(weird)} must be unknown, not false`,
    );
  }
  const f = analyze([bucket({ lifecycleRules: null })], []);
  assertEquals(codes(f), ["lifecycle-unreadable"]);
  assertEquals(f[0].severity, "low");
  assertStringIncludes(f[0].impact, "not evidence of safety");
});

Deno.test("a rule that only hides, never deletes, still counts as not pruning", () => {
  const hideOnly = [{ fileNamePrefix: "", daysFromUploadingToHiding: 30 }];
  assertEquals(prunesHiddenVersions(hideOnly).verdict, false);
  const f = analyze([bucket({ lifecycleRules: hideOnly })], []);
  assertEquals(codes(f), ["lifecycle-no-hidden-version-pruning"]);
});

Deno.test("a partially covered bucket names the unpruned prefixes", () => {
  const mixed = [
    { fileNamePrefix: "data/", daysFromHidingToDeleting: 7 },
    { fileNamePrefix: "logs/", daysFromHidingToDeleting: null },
  ];
  const { verdict, unprunedPrefixes } = prunesHiddenVersions(mixed);
  assertEquals(verdict, true, "at least one rule prunes");
  assertEquals(unprunedPrefixes, ["logs/"]);
});

// --- key findings -----------------------------------------------------------

Deno.test("an account-wide key is a high-severity finding", () => {
  const f = analyze([bucket()], [key({ bucketIds: [] })]);
  assertEquals(codes(f), ["key-account-wide"]);
  assertStringIncludes(f[0].impact, "every other host");
});

Deno.test("a key scoped to a bucket that no longer exists is orphaned", () => {
  const f = analyze([bucket()], [key({ bucketIds: ["bdeadbeefdeadbeefdead0000"] })]);
  assertEquals(codes(f), ["key-orphaned"]);
  assertEquals(f[0].severity, "medium");
});

Deno.test("an account-wide key is not also reported as orphaned", () => {
  // Empty bucketIds means unrestricted, not "restricted to nothing" — emitting
  // both findings would double-count and misdescribe the key.
  const f = analyze([bucket()], [key({ bucketIds: [] })]);
  assertFalse(codes(f).includes("key-orphaned"));
});

Deno.test("writeKeys and bypassGovernance escalate to critical", () => {
  const f = analyze([bucket()], [
    key({ capabilities: ["listBuckets", "writeKeys", "bypassGovernance"] }),
  ]);
  const dangerous = f.find((x) => x.code === "key-dangerous-capability");
  assert(dangerous, "expected a dangerous-capability finding");
  assertEquals(dangerous.severity, "critical");
  assertStringIncludes(dangerous.impact, "every future key");
});

Deno.test("deleteBuckets alone is high, not critical", () => {
  const f = analyze([bucket()], [key({ capabilities: ["deleteBuckets"] })]);
  const d = f.find((x) => x.code === "key-dangerous-capability");
  assert(d);
  assertEquals(d.severity, "high");
});

Deno.test("an ordinary scoped key with a normal capability set is clean", () => {
  assertEquals(analyze([bucket()], [key()]).length, 0);
});

Deno.test("a key with no expiry is a low finding, not a blocker", () => {
  const f = analyze([bucket()], [key({ expirationTimestamp: null })]);
  assertEquals(codes(f), ["key-never-expires"]);
  assertEquals(f[0].severity, "low");
});

Deno.test("a public bucket is critical", () => {
  const f = analyze([bucket({ bucketType: "allPublic" })], []);
  assertEquals(codes(f), ["bucket-public"]);
  assertEquals(f[0].severity, "critical");
});

Deno.test("findings are ordered most severe first", () => {
  const f = analyze(
    [bucket({ bucketType: "allPublic" }), bucket({ bucketId: "b2", bucketName: "x", lifecycleRules: [] })],
    [key({ expirationTimestamp: null })],
  );
  assertEquals(f.map((x) => x.severity), ["critical", "high", "low"]);
});

// --- truncation honesty -----------------------------------------------------

Deno.test("a truncated inventory says so BEFORE any count, even with zero findings", () => {
  // The dangerous output is a clean audit over a partial inventory. The warning
  // must precede the numbers so it cannot be skimmed past.
  const md = renderMarkdown([], {
    bucketCount: 24,
    keyCount: 100,
    truncated: true,
    keysTruncated: true,
    scannedAt: "2026-08-05T20:10:21Z",
  });
  assertStringIncludes(md, "INCOMPLETE");
  assertStringIncludes(md, "application keys");
  assert(
    md.indexOf("INCOMPLETE") < md.indexOf("Scanned 24 bucket"),
    "the incompleteness warning must come before the counts",
  );
  assertStringIncludes(md, "portion of the account that was scanned");
  assert(
    !md.includes("Every bucket prunes hidden versions"),
    "a truncated scan must never claim the whole account is clean",
  );
});

Deno.test("a complete scan with no findings may state the account is clean", () => {
  const md = renderMarkdown([], {
    bucketCount: 24,
    keyCount: 23,
    truncated: false,
    keysTruncated: false,
    scannedAt: null,
  });
  assertFalse(md.includes("INCOMPLETE"));
  assertStringIncludes(md, "Every bucket prunes hidden versions");
});

Deno.test("the json payload marks inventory completeness explicitly", async () => {
  const ctx = makeContext({ truncated: true, keysTruncated: true });
  const out = await report.execute(ctx);
  assertEquals(out.json.inventoryComplete, false);
  assertEquals(out.json.truncated, true);
});

// --- execute() wiring -------------------------------------------------------

// deno-lint-ignore no-explicit-any
function makeContext(accountOver: Record<string, unknown> = {}): any {
  const snapshots: Record<string, Record<string, unknown>> = {
    "bucket-a": bucket({ lifecycleRules: [] }),
    "key-a": key({ bucketIds: [] }),
    "account-a": {
      truncated: false,
      keysTruncated: false,
      observedAt: "2026-08-05T20:10:21Z",
      ...accountOver,
    },
  };
  return {
    methodName: "scan",
    executionStatus: "succeeded",
    modelType: "@sntxrr/b2/account",
    modelId: "model-1",
    logger: { info: () => {} },
    dataHandles: [
      { name: "bucket-a", specName: "bucket", version: 1 },
      { name: "key-a", specName: "key", version: 1 },
      { name: "account-a", specName: "account", version: 1 },
    ],
    dataRepository: {
      getContent: (_t: string, _m: string, name: string) =>
        Promise.resolve(
          snapshots[name]
            ? new TextEncoder().encode(JSON.stringify(snapshots[name]))
            : null,
        ),
    },
  };
}

Deno.test("execute reads the scan's resources and reports both findings", async () => {
  const out = await report.execute(makeContext());
  assertEquals(out.json.bucketCount, 1);
  assertEquals(out.json.keyCount, 1);
  assertEquals(out.json.findingCount, 2);
  assertStringIncludes(out.markdown, "lifecycle-no-hidden-version-pruning");
  assertStringIncludes(out.markdown, "key-account-wide");
  assertEquals(out.json.inventoryComplete, true);
});

Deno.test("execute refuses to audit a method that is not scan", async () => {
  const ctx = makeContext();
  ctx.methodName = "sync";
  const out = await report.execute(ctx);
  assertEquals(out.json.skipped, true);
  assertEquals(out.json.reason, "not-a-scan");
  assertEquals(out.json.findings, []);
});

Deno.test("execute refuses to audit a failed scan", async () => {
  // A partial inventory from a failed run would produce findings that look
  // authoritative but describe only whatever happened to be written first.
  const ctx = makeContext();
  ctx.executionStatus = "failed";
  const out = await report.execute(ctx);
  assertEquals(out.json.skipped, true);
  assertEquals(out.json.reason, "scan-failed");
  assertStringIncludes(out.markdown, "auditing it would be misleading");
});

Deno.test("an unreadable snapshot is skipped, not counted as a clean object", async () => {
  const ctx = makeContext();
  ctx.dataRepository.getContent = (
    _t: string,
    _m: string,
    name: string,
  ) => Promise.resolve(name === "bucket-a" ? null : new TextEncoder().encode(JSON.stringify({
    truncated: false,
    keysTruncated: false,
    observedAt: "x",
  })));
  const out = await report.execute(ctx);
  assertEquals(out.json.bucketCount, 0, "an unreadable bucket must not be counted");
});

Deno.test("the report declares method scope and audit labels", () => {
  assertEquals(report.scope, "method");
  assertEquals(report.name, "@sntxrr/b2/hygiene");
  assert(report.labels.includes("audit"));
  assert(report.labels.includes("security"));
});
