/**
 * Mechanical verification for b2-files, per the adversarial-review contract:
 * schema-write conformance, truncation honesty, instance-name consistency and
 * schema field coverage — executed, not read.
 *
 * Judgment-based review has missed this class of defect in this suite every
 * time, so run it rather than reason about it:
 *
 *   deno run --allow-net --allow-env --allow-read --no-check \
 *     reviews/mechanical-verification-b2-files.ts
 *
 * Unlike b2-bucket, truncation honesty IS asserted here: `scan` paginates, and
 * a silently truncated inventory reporting a byte total is the single most
 * dangerous output this model can produce.
 */
import { model } from "../extensions/models/b2-files/b2_files.ts";

const BUCKET_NAME = "example-backup-bucket";
const BUCKET_ID = "4a48fe8875c6214145260818";
const ACCOUNT_ID = "a1b2c3d4e5f6";
const API = "https://api002.backblazeb2.com";

function authBody() {
  return {
    accountId: ACCOUNT_ID,
    authorizationToken: "4_004token",
    apiInfo: {
      storageApi: {
        apiUrl: API,
        downloadUrl: "https://f002.backblazeb2.com",
        s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
        allowed: {
          buckets: [{ id: BUCKET_ID, name: BUCKET_NAME }],
          capabilities: [],
          namePrefix: null,
        },
      },
    },
  };
}

function fileBody(over: Record<string, unknown> = {}) {
  return {
    accountId: ACCOUNT_ID,
    action: "upload",
    bucketId: BUCKET_ID,
    contentLength: 1024,
    contentMd5: "0cc175b9c0f1b6a831c399e269772661",
    contentSha1: "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
    contentType: "application/octet-stream",
    fileId: "4_zexamplefileid0000000001",
    fileInfo: {},
    fileName: "data/00/pack-0001",
    fileRetention: {
      isClientAuthorizedToRead: true,
      value: { mode: null, retainUntilTimestamp: null },
    },
    legalHold: { isClientAuthorizedToRead: true, value: "off" },
    replicationStatus: null,
    serverSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
    uploadTimestamp: 1754000000000,
    ...over,
  };
}

type W = { spec: string; name: string; data: Record<string, unknown> };

const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), {
    status: s,
    headers: { "content-type": "application/json" },
  });

async function run(
  method: string,
  handler: (i: number) => Response,
  rawArgs: Record<string, unknown> = {},
  extraGlobals: Record<string, unknown> = {},
): Promise<W[]> {
  const writes: W[] = [];
  const orig = globalThis.fetch;
  let i = 0;
  globalThis.fetch = (() =>
    Promise.resolve(handler(i++))) as typeof globalThis.fetch;
  const ctx = {
    globalArgs: (model.globalArguments as { parse: (o: unknown) => unknown })
      .parse({
        applicationKeyId: "004keyid",
        applicationKey: "K004secret",
        bucketName: BUCKET_NAME,
        bucketId: BUCKET_ID,
        ...extraGlobals,
      }),
    logger: { info: () => {}, warn: () => {} },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  try {
    // deno-lint-ignore no-explicit-any
    const def = (model.methods as any)[method];
    // Parse args through the method's declared schema, as swamp does before
    // calling execute — a required argument must not be silently undefined.
    const args = def.arguments ? def.arguments.parse(rawArgs) : rawArgs;
    await def.execute(args, ctx);
  } finally {
    globalThis.fetch = orig;
  }
  return writes;
}

console.log("--- 0. Every method executed against a mocked B2 ---");

const runs: Array<
  [string, (i: number) => Response, Record<string, unknown>, Record<string, unknown>]
> = [
  [
    "scan",
    (i) => i === 0 ? json(authBody()) : json({ files: [fileBody()] }),
    { groupBy: "topLevel" },
    {},
  ],
  [
    "scan",
    (i) => i === 0 ? json(authBody()) : json({ files: [fileBody()] }),
    { mode: "detailed", prefix: "data/", maxFiles: 5 },
    {},
  ],
  [
    "sync",
    (i) => i === 0 ? json(authBody()) : json(fileBody()),
    { fileId: "4_zexamplefileid0000000001" },
    {},
  ],
  [
    "sync",
    (i) => i === 0 ? json(authBody()) : json({ files: [] }),
    { fileName: "data/missing" },
    {},
  ],
  [
    "delete",
    (i) => i === 0 ? json(authBody()) : i === 1 ? json(fileBody()) : json({}),
    { fileId: "4_zexamplefileid0000000001" },
    { allowFileDestruction: true },
  ],
  [
    "hide",
    (i) =>
      i === 0
        ? json(authBody())
        : json(fileBody({ action: "hide", contentLength: 0, fileId: "4_zmark" })),
    { fileName: "data/00/pack-0001" },
    { allowFileDestruction: true },
  ],
  [
    "copy",
    (i) => i === 0 ? json(authBody()) : json(fileBody({ fileId: "4_zcopy" })),
    { sourceFileId: "4_zsrc", fileName: "data/00/pack-copy" },
    {},
  ],
  [
    "update",
    (i) => i === 0 ? json(authBody()) : i === 1 ? json({}) : json(fileBody()),
    {
      fileId: "4_zexamplefileid0000000001",
      fileName: "data/00/pack-0001",
      legalHold: "on",
    },
    {},
  ],
];

const all: W[] = [];
const perRun: W[][] = [];
for (const [m, plan, args, globals] of runs) {
  const w = await run(m, plan, args, globals);
  all.push(...w);
  perRun.push(w);
  const label = `${m}${args.mode ? ` (${args.mode})` : ""}`;
  console.log(
    `  ${label.padEnd(24)} -> ${
      w.map((x) => `${x.spec}:"${x.name}"`).join(", ") || "(no write)"
    }`,
  );
}

let fail = 0;

console.log("\n--- 1 & 4. Schema-write conformance + field coverage ---");
for (
  const [spec, def] of Object.entries(
    model.resources as Record<
      string,
      {
        schema: {
          shape: Record<string, unknown>;
          safeParse: (d: unknown) => { success: boolean; error?: unknown };
        };
      }
    >,
  )
) {
  const schemaKeys = new Set(Object.keys(def.schema.shape));
  const writes = all.filter((w) => w.spec === spec);
  const writtenUnion = new Set<string>();
  for (const w of writes) for (const k of Object.keys(w.data)) writtenUnion.add(k);

  const neverWritten = [...schemaKeys].filter((k) => !writtenUnion.has(k));
  const notInSchema = [...writtenUnion].filter((k) => !schemaKeys.has(k));
  console.log(
    `  spec "${spec}": ${schemaKeys.size} schema fields, ${writes.length} writes observed`,
  );
  if (neverWritten.length) {
    console.log(`    FAIL never written: ${neverWritten.join(", ")}`);
    fail++;
  }
  if (notInSchema.length) {
    console.log(`    FAIL written but not in schema: ${notInSchema.join(", ")}`);
    fail++;
  }

  // Per-write completeness AND run-time validity: swamp parses every write
  // against the spec schema, so a write that would fail there must fail here.
  for (const w of writes) {
    const missing = [...schemaKeys].filter((k) => !(k in w.data));
    if (missing.length) {
      console.log(`    FAIL write "${w.name}" missing: ${missing.join(", ")}`);
      fail++;
    }
    const parsed = def.schema.safeParse(w.data);
    if (!parsed.success) {
      console.log(
        `    FAIL write "${w.name}" rejected by its own spec schema: ${
          JSON.stringify(parsed.error)
        }`,
      );
      fail++;
    }
  }
  if (!neverWritten.length && !notInSchema.length) {
    console.log("    OK 1:1 coverage, every write schema-valid");
  }
}

console.log("\n--- 2. Truncation honesty ---");
// A listing that stops with a live cursor must say so. Reporting a byte total
// from a partial drain as if it were complete is the failure mode that makes an
// audit lie.
const truncWrites = await run(
  "scan",
  (i) =>
    i === 0
      ? json(authBody())
      : json({
        files: [fileBody()],
        nextFileName: "more",
        nextFileId: "more-id",
      }),
  { maxPages: 2 },
);
const truncAgg = truncWrites.find((w) => w.spec === "aggregate");
if (truncAgg?.data.truncated === true) {
  console.log("    OK a page-capped scan reports truncated=true");
} else {
  console.log(
    `    FAIL page-capped scan reported truncated=${truncAgg?.data.truncated}`,
  );
  fail++;
}
// The complete case must NOT claim truncation, or the flag means nothing.
const wholeAgg = perRun[0].find((w) => w.spec === "aggregate");
if (wholeAgg?.data.truncated === false) {
  console.log("    OK a complete scan reports truncated=false");
} else {
  console.log(
    `    FAIL complete scan reported truncated=${wholeAgg?.data.truncated}`,
  );
  fail++;
}
// Unmeasured is null, never zero — the wave-1 `unprunedPrefixes: []` bug class.
const namesWrites = await run(
  "scan",
  (i) => i === 0 ? json(authBody()) : json({ files: [fileBody()] }),
  { includeVersions: false },
);
const namesAgg = namesWrites.find((w) => w.spec === "aggregate");
if (namesAgg?.data.nonCurrentBytes === null && namesAgg?.data.totalBytes === null) {
  console.log("    OK a name-only listing reports unmeasured metrics as null");
} else {
  console.log(
    `    FAIL name-only listing reported nonCurrentBytes=${namesAgg?.data.nonCurrentBytes}, totalBytes=${namesAgg?.data.totalBytes} (must be null, not 0)`,
  );
  fail++;
}

console.log("\n--- 3. Instance-name consistency ---");
const byName = new Map<string, Set<string>>();
for (const w of all) {
  if (!byName.has(w.name)) byName.set(w.name, new Set());
  byName.get(w.name)!.add(w.spec);
}
for (const [name, specs] of byName) {
  if (specs.size > 1) {
    console.log(
      `    FAIL "${name}" written by multiple specs: ${[...specs].join(", ")}`,
    );
    fail++;
  }
}
if (![...byName.values()].some((s) => s.size > 1)) {
  console.log("    OK no instance name is shared across specs");
}
// Within ONE execution, two writes to the same instance clobber each other on
// disk — which is exactly how b2-bucket's notification snapshot ate its bucket
// snapshot. A scan writing a total plus N groups must produce N+1 distinct names.
for (let i = 0; i < perRun.length; i++) {
  const names = perRun[i].map((w) => w.name);
  const dupes = names.filter((n, j) => names.indexOf(n) !== j);
  if (dupes.length) {
    console.log(
      `    FAIL run #${i} (${runs[i][0]}) wrote the same instance twice: ${
        [...new Set(dupes)].join(", ")
      }`,
    );
    fail++;
  }
}
if (!perRun.some((w) => new Set(w.map((x) => x.name)).size !== w.length)) {
  console.log("    OK no execution clobbers one of its own instances");
}
// The reserved data name fails at run time only, so catch it here.
if (all.some((w) => w.name === "latest")) {
  console.log('    FAIL an instance was named the reserved literal "latest"');
  fail++;
} else {
  console.log('    OK no instance is named "latest"');
}

console.log("\n--- 5. Secret hygiene ---");
const blob = JSON.stringify(all);
if (blob.includes("K004secret") || blob.includes("4_004token")) {
  console.log("    FAIL a snapshot carries an application key or auth token");
  fail++;
} else {
  console.log("    OK no snapshot carries a credential");
}

console.log(
  fail === 0 ? "\nMECHANICAL: ALL PASS" : `\nMECHANICAL: ${fail} FAILURE(S)`,
);
