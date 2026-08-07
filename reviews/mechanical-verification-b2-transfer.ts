/**
 * Mechanical verification for b2-transfer, per the adversarial-review contract:
 * schema-write conformance, field coverage, instance-name consistency, honest
 * nulls and secret hygiene — executed, not read.
 *
 * Judgment-based review has missed this class of defect in this suite every
 * time, so run it rather than reason about it:
 *
 *   deno test --allow-all reviews/mechanical-verification-b2-transfer.ts
 *
 * The check that matters most here is #5. This model handles FOUR distinct
 * bearer credentials — the application key, the 24h account token, the
 * per-endpoint upload token, and the download authorization token — which is
 * more than any other model in the suite, and the download authorization is the
 * one the design promises never to persist. That promise is worth executing.
 */
import { model } from "../extensions/models/b2-transfer/b2_transfer.ts";
import { z } from "npm:zod@4";

const BUCKET_NAME = "example-backup-bucket";
const BUCKET_ID = "4a48fe8875c6214145260818";
const ACCOUNT_ID = "a1b2c3d4e5f6";
const API = "https://api002.backblazeb2.com";
const DOWNLOAD = "https://f002.backblazeb2.com";
const LARGE_FILE_ID = "4_zexamplelargefileid00001";

/** Every secret this harness plants, so #5 can grep for all of them. */
const SECRETS = {
  applicationKey: "K004secretApplicationKeyValue0000000",
  accountToken: "4_004accountAuthorizationTokenValue0",
  uploadToken: "4_004uploadEndpointTokenValue000000",
  downloadAuthToken: "4_004downloadAuthorizationTokenValu",
};

function authBody() {
  return {
    accountId: ACCOUNT_ID,
    authorizationToken: SECRETS.accountToken,
    apiInfo: {
      storageApi: {
        apiUrl: API,
        downloadUrl: DOWNLOAD,
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

const HELLO_SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

function fileBody(over: Record<string, unknown> = {}) {
  return {
    accountId: ACCOUNT_ID,
    action: "upload",
    bucketId: BUCKET_ID,
    contentLength: 5,
    contentSha1: HELLO_SHA1,
    contentType: "text/plain",
    fileId: "4_zexamplefileid0000000001",
    fileInfo: {},
    fileName: "canary.txt",
    uploadTimestamp: 1754000000000,
    ...over,
  };
}

function unfinishedBody(over: Record<string, unknown> = {}) {
  return {
    accountId: ACCOUNT_ID,
    action: "start",
    bucketId: BUCKET_ID,
    contentType: "application/octet-stream",
    fileId: LARGE_FILE_ID,
    fileInfo: {},
    fileName: "data/00/pack-interrupted",
    uploadTimestamp: 1754000000000,
    ...over,
  };
}

type Written = { spec: string; name: string; data: Record<string, unknown> };

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/** Route by B2 operation, matching upload/download endpoints on their URL. */
function install(routes: Record<string, unknown>) {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const op = url.split("/b2api/v4/")[1]?.split("?")[0] ?? "";
    let key = op;
    if (url.includes("/b2_upload_file/")) key = "upload_endpoint";
    if (url.startsWith(`${DOWNLOAD}/file/`)) key = "download_by_name";
    if (key === "b2_authorize_account") return Promise.resolve(json(authBody()));
    const route = routes[key];
    if (route === undefined) {
      return Promise.resolve(json({ code: "unexpected", message: key }, 400));
    }
    return Promise.resolve(
      route instanceof Response ? route : json(route),
    );
  }) as typeof globalThis.fetch;
  return () => {
    globalThis.fetch = original;
  };
}

/** A context whose writeResource validates against the real spec schema. */
function makeContext(globals: Record<string, unknown> = {}) {
  const written: Written[] = [];
  const logs: string[] = [];
  return {
    written,
    logs,
    context: {
      globalArgs: model.globalArguments.parse({
        applicationKeyId: "004exampleKeyId",
        applicationKey: SECRETS.applicationKey,
        bucketName: BUCKET_NAME,
        bucketId: BUCKET_ID,
        ...globals,
      }),
      logger: {
        info: (m: string, p?: Record<string, unknown>) =>
          logs.push(`${m} ${JSON.stringify(p ?? {})}`),
        warn: (m: string, p?: Record<string, unknown>) =>
          logs.push(`${m} ${JSON.stringify(p ?? {})}`),
      },
      writeResource: (
        spec: string,
        name: string,
        data: Record<string, unknown>,
      ) => {
        const rs = (model.resources as Record<string, { schema: z.ZodType }>)[
          spec
        ];
        if (!rs) throw new Error(`unknown spec "${spec}"`);
        const parsed = rs.schema.safeParse(data);
        if (!parsed.success) {
          throw new Error(
            `writeResource("${spec}","${name}") rejected by its own schema: ` +
              JSON.stringify(parsed.error.issues),
          );
        }
        written.push({ spec, name, data });
        return Promise.resolve({ name });
      },
    },
  };
}

const ROUTES: Record<string, unknown> = {
  b2_list_buckets: {
    buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
  },
  b2_list_unfinished_large_files: {
    files: [unfinishedBody()],
    nextFileId: null,
  },
  b2_get_upload_url: {
    bucketId: BUCKET_ID,
    uploadUrl: `${API}/b2api/v4/b2_upload_file/${BUCKET_ID}/x`,
    authorizationToken: SECRETS.uploadToken,
  },
  b2_get_upload_part_url: {
    fileId: LARGE_FILE_ID,
    uploadUrl: `${API}/b2api/v4/b2_upload_file/${BUCKET_ID}/part`,
    authorizationToken: SECRETS.uploadToken,
  },
  upload_endpoint: fileBody(),
  b2_start_large_file: fileBody({ fileId: LARGE_FILE_ID, contentSha1: "none" }),
  b2_finish_large_file: fileBody({ contentSha1: "none" }),
  b2_list_parts: {
    parts: [{ partNumber: 1, contentLength: 5_000_000 }],
    nextPartNumber: null,
  },
  b2_copy_part: { fileId: LARGE_FILE_ID, partNumber: 1, contentLength: 900 },
  b2_cancel_large_file: { fileId: LARGE_FILE_ID, fileName: "x" },
  b2_get_download_authorization: {
    authorizationToken: SECRETS.downloadAuthToken,
  },
};

let fail = 0;
const all: Written[] = [];
const perRun: Written[][] = [];
const allLogs: string[] = [];

console.log("--- 0. Every method executed against a mocked B2 ---");

const CASES: Array<[string, Record<string, unknown>, Record<string, unknown>]> =
  [
    ["scan", {}, {}],
    ["scan (countParts)", { countParts: true }, {}],
    ["upload (small)", { fileName: "canary.txt", content: "hello" }, {}],
    ["upload (large)", {
      fileName: "canary.txt",
      content: "hello",
      forceLarge: true,
    }, {}],
    ["authorize_download", { fileNamePrefix: "data/", verify: false }, {}],
    ["list_parts", { fileId: LARGE_FILE_ID }, {}],
    ["copy_part", {
      fileName: "assembled.bin",
      sources: [{ sourceFileId: "4_zx", range: "bytes=0-4999999" }],
    }, {}],
    ["delete", { fileId: LARGE_FILE_ID, allowTransferDestruction: true }, {}],
  ];

for (const [label, args, globals] of CASES) {
  const method = label.split(" ")[0];
  const restore = install(ROUTES);
  try {
    const { context, written, logs } = makeContext(globals);
    // deno-lint-ignore no-explicit-any
    await (model.methods as any)[method].execute(args, context);
    all.push(...written);
    perRun.push(written);
    allLogs.push(...logs);
    console.log(
      `  ${label.padEnd(24)} -> ${
        written.map((w) => `${w.spec}:"${w.name}"`).join(", ") || "(none)"
      }`,
    );
  } catch (e) {
    console.log(`  ${label.padEnd(24)} -> THREW ${(e as Error).message}`);
    fail++;
  } finally {
    restore();
  }
}

// A download needs a streamed body rather than JSON, so it gets its own mock.
{
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = String(input);
    if (url.includes("b2_authorize_account")) {
      return Promise.resolve(json(authBody()));
    }
    return Promise.resolve(
      new Response("hello", {
        status: 200,
        headers: {
          "Content-Length": "5",
          "X-Bz-Content-Sha1": HELLO_SHA1,
          "X-Bz-File-Name": "canary.txt",
          "X-Bz-File-Id": "4_zexamplefileid0000000001",
          "Content-Type": "text/plain",
        },
      }),
    );
  }) as typeof globalThis.fetch;
  try {
    const { context, written, logs } = makeContext();
    await model.methods.download.execute(
      { fileId: "4_zexamplefileid0000000001" },
      context,
    );
    all.push(...written);
    perRun.push(written);
    allLogs.push(...logs);
    console.log(
      `  ${"download".padEnd(24)} -> ${
        written.map((w) => `${w.spec}:"${w.name}"`).join(", ")
      }`,
    );
  } catch (e) {
    console.log(`  download -> THREW ${(e as Error).message}`);
    fail++;
  } finally {
    globalThis.fetch = original;
  }
}

console.log("\n--- 1 & 4. Schema-write conformance + field coverage ---");
for (const [spec, def] of Object.entries(model.resources)) {
  const writes = all.filter((w) => w.spec === spec);
  const schemaKeys = new Set(
    Object.keys((def.schema as unknown as z.ZodObject).shape),
  );
  console.log(
    `  spec "${spec}": ${schemaKeys.size} schema fields, ${writes.length} writes observed`,
  );
  if (writes.length === 0) {
    console.log("    FAIL no write observed — this spec is unverified");
    fail++;
    continue;
  }
  let ok = true;
  for (const w of writes) {
    const written = new Set(Object.keys(w.data));
    for (const k of schemaKeys) {
      if (!written.has(k)) {
        console.log(`    FAIL "${w.name}" omits schema field "${k}"`);
        ok = false;
        fail++;
      }
    }
    for (const k of written) {
      if (!schemaKeys.has(k)) {
        console.log(`    FAIL "${w.name}" writes unknown field "${k}"`);
        ok = false;
        fail++;
      }
    }
  }
  if (ok) console.log("    OK 1:1 coverage, every write schema-valid");
}

console.log("\n--- 2. Honest nulls ---");
{
  // scan must NOT claim a part count it never measured.
  const scanned = perRun[0].filter((w) => w.spec === "unfinished-upload");
  if (scanned.every((w) => w.data.partCount === null)) {
    console.log("    OK scan leaves partCount null, not 0");
  } else {
    console.log("    FAIL scan reported a partCount it never measured");
    fail++;
  }
  // countParts must populate it.
  const counted = perRun[1].filter((w) => w.spec === "unfinished-upload");
  if (counted.every((w) => typeof w.data.partCount === "number")) {
    console.log("    OK countParts populates partCount");
  } else {
    console.log("    FAIL countParts left partCount unmeasured");
    fail++;
  }
  // A large upload returns "none" for its SHA-1 — not comparable, so null.
  const large = perRun[3].find((w) => w.spec === "transfer");
  if (large && large.data.sha1Verified === null) {
    console.log("    OK an uncomparable SHA-1 is null, not false");
  } else {
    console.log(
      `    FAIL large upload reported sha1Verified=${
        JSON.stringify(large?.data.sha1Verified)
      }`,
    );
    fail++;
  }
  // copy_part hashes nothing locally, so it can claim no verdict.
  const copied = perRun[6].find((w) => w.spec === "transfer");
  if (copied && copied.data.sha1Verified === null) {
    console.log("    OK copy_part claims no SHA-1 verdict");
  } else {
    console.log("    FAIL copy_part claimed a verdict it could not have");
    fail++;
  }
}

console.log("\n--- 3. Instance-name consistency ---");
{
  const bySpec = new Map<string, Set<string>>();
  for (const w of all) {
    if (!bySpec.has(w.spec)) bySpec.set(w.spec, new Set());
    bySpec.get(w.spec)?.add(w.name);
  }
  const specs = [...bySpec.keys()];
  let shared = false;
  for (let i = 0; i < specs.length; i++) {
    for (let j = i + 1; j < specs.length; j++) {
      for (const n of bySpec.get(specs[i]) as Set<string>) {
        if ((bySpec.get(specs[j]) as Set<string>).has(n)) {
          console.log(
            `    FAIL "${n}" is written by both "${specs[i]}" and "${specs[j]}"`,
          );
          shared = true;
          fail++;
        }
      }
    }
  }
  if (!shared) console.log("    OK no instance name is shared across specs");

  let clobber = false;
  for (const run of perRun) {
    if (new Set(run.map((w) => w.name)).size !== run.length) {
      console.log("    FAIL one execution wrote the same instance twice");
      clobber = true;
      fail++;
    }
  }
  if (!clobber) console.log("    OK no execution clobbers one of its own instances");

  if (all.some((w) => w.name === "latest")) {
    console.log('    FAIL an instance was named the reserved literal "latest"');
    fail++;
  } else {
    console.log('    OK no instance is named "latest"');
  }
}

console.log("\n--- 5. Secret hygiene (four distinct bearer credentials) ---");
{
  const blob = JSON.stringify(all) + JSON.stringify(allLogs);
  let leaked = false;
  for (const [name, secret] of Object.entries(SECRETS)) {
    if (blob.includes(secret)) {
      console.log(`    FAIL ${name} reached a snapshot or a log line`);
      leaked = true;
      fail++;
    }
  }
  if (!leaked) {
    console.log(
      "    OK none of applicationKey / accountToken / uploadToken / " +
        "downloadAuthToken appears in any snapshot or log",
    );
  }
  const auth = all.find((w) => w.spec === "download-auth");
  if (auth && auth.data.tokenPersisted === false) {
    console.log("    OK download-auth asserts tokenPersisted=false in its data");
  } else {
    console.log("    FAIL download-auth did not record tokenPersisted=false");
    fail++;
  }
}

console.log(
  fail === 0 ? "\nMECHANICAL: ALL PASS" : `\nMECHANICAL: ${fail} FAILURE(S)`,
);
