/**
 * Mechanical verification for b2-bucket, per the adversarial-review contract:
 * schema-write conformance, truncation honesty, instance-name consistency and
 * schema field coverage — executed, not read.
 *
 * Judgment-based review has missed this class of defect in this suite every
 * time, so run it rather than reason about it:
 *
 *   deno run --allow-net --allow-env --allow-read --no-check \
 *     reviews/mechanical-verification.ts
 *
 * Truncation honesty is not asserted here because no b2-bucket method
 * paginates: b2_list_buckets is unpaginated and is called once via b2Fetch.
 */
import { model } from "../extensions/models/b2-bucket/b2_bucket.ts";

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
        allowed: { buckets: [{ id: BUCKET_ID, name: BUCKET_NAME }], capabilities: [], namePrefix: null },
      },
    },
  };
}
function bucketBody() {
  return {
    accountId: ACCOUNT_ID,
    bucketId: BUCKET_ID,
    bucketName: BUCKET_NAME,
    bucketType: "allPrivate",
    bucketInfo: { owner: "restic" },
    corsRules: [],
    lifecycleRules: [{ fileNamePrefix: "", daysFromUploadingToHiding: null, daysFromHidingToDeleting: 1 }],
    fileLockConfiguration: {
      isClientAuthorizedToRead: true,
      value: { isFileLockEnabled: true, defaultRetention: { mode: "governance", period: { duration: 7, unit: "days" } } },
    },
    defaultServerSideEncryption: { isClientAuthorizedToRead: true, value: { mode: "none" } },
    replicationConfiguration: { isClientAuthorizedToRead: true, value: null },
    revision: 4,
    options: ["s3"],
  };
}

type W = { spec: string; name: string; data: Record<string, unknown> };

async function run(
  method: string,
  handler: (i: number) => Response,
  rawArgs: Record<string, unknown> = {},
): Promise<W[]> {
  const writes: W[] = [];
  const orig = globalThis.fetch;
  let i = 0;
  globalThis.fetch = (() => Promise.resolve(handler(i++))) as typeof globalThis.fetch;
  const ctx = {
    globalArgs: (model.globalArguments as { parse: (o: unknown) => unknown }).parse({
      applicationKeyId: "004keyid",
      applicationKey: "K004secret",
      bucketName: BUCKET_NAME,
      bucketId: BUCKET_ID,
      lifecycleRules: [{ fileNamePrefix: "", daysFromUploadingToHiding: null, daysFromHidingToDeleting: 1 }],
      notificationRules: [],
    }),
    logger: { info: () => {}, warn: () => {} },
    writeResource: (spec: string, name: string, data: Record<string, unknown>) => {
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

const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

const plans: Record<string, (i: number) => Response> = {
  sync: (i) => (i === 0 ? json(authBody()) : json({ buckets: [bucketBody()] })),
  create: (i) => (i === 0 ? json(authBody()) : json(bucketBody())),
  update: (i) => (i === 0 ? json(authBody()) : json(bucketBody())),
  delete: (i) => (i === 0 ? json(authBody()) : json({})),
  get_notification_rules: (i) => (i === 0 ? json(authBody()) : json({ bucketId: BUCKET_ID, eventNotificationRules: [] })),
  set_notification_rules: (i) => (i === 0 ? json(authBody()) : json({ bucketId: BUCKET_ID, eventNotificationRules: [] })),
};

const all: W[] = [];
const argsFor: Record<string, Record<string, unknown>> = {
  set_notification_rules: { rules: [] },
};
for (const [m, plan] of Object.entries(plans)) {
  const w = await run(m, plan, argsFor[m] ?? {});
  all.push(...w);
  console.log(`  ${m.padEnd(24)} -> ${w.map((x) => `${x.spec}:"${x.name}"`).join(", ") || "(no write)"}`);
}

console.log("\n--- 1 & 4. Schema-write conformance + field coverage ---");
let fail = 0;
for (const [spec, def] of Object.entries(model.resources as Record<string, { schema: { shape: Record<string, unknown> } }>)) {
  const schemaKeys = new Set(Object.keys(def.schema.shape));
  const writes = all.filter((w) => w.spec === spec);
  const writtenUnion = new Set<string>();
  for (const w of writes) for (const k of Object.keys(w.data)) writtenUnion.add(k);

  const neverWritten = [...schemaKeys].filter((k) => !writtenUnion.has(k));
  const notInSchema = [...writtenUnion].filter((k) => !schemaKeys.has(k));
  console.log(`  spec "${spec}": ${schemaKeys.size} schema fields, ${writes.length} writes observed`);
  if (neverWritten.length) { console.log(`    FAIL never written: ${neverWritten.join(", ")}`); fail++; }
  if (notInSchema.length) { console.log(`    FAIL written but not in schema: ${notInSchema.join(", ")}`); fail++; }

  // Per-write completeness: every schema field present in every write.
  for (const w of writes) {
    const missing = [...schemaKeys].filter((k) => !(k in w.data));
    if (missing.length) { console.log(`    FAIL write "${w.name}" missing: ${missing.join(", ")}`); fail++; }
  }
  if (!neverWritten.length && !notInSchema.length) console.log("    OK 1:1 coverage");
}

console.log("\n--- 3. Instance-name consistency ---");
const byName = new Map<string, Set<string>>();
for (const w of all) {
  if (!byName.has(w.name)) byName.set(w.name, new Set());
  byName.get(w.name)!.add(w.spec);
}
for (const [name, specs] of byName) {
  if (specs.size > 1) { console.log(`    FAIL "${name}" written by multiple specs: ${[...specs].join(", ")}`); fail++; }
}
if (![...byName.values()].some((s) => s.size > 1)) console.log("    OK no instance name is shared across specs");

console.log(fail === 0 ? "\nMECHANICAL: ALL PASS" : `\nMECHANICAL: ${fail} FAILURE(S)`);
