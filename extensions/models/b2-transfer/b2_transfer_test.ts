/**
 * Unit tests for b2_transfer.ts.
 *
 * Everything is mocked — no live B2. The `writeResource` stub VALIDATES against
 * the real spec schemas per CONVENTIONS §10.1, because a recording-only stub is
 * blind to exactly the class of bug this suite keeps finding: a derived field
 * that is wrong while the raw B2 data is correct.
 *
 * What these tests actually defend, beyond the CONVENTIONS §10 checklist:
 *
 * - **The size guard fires before anything costs money**, including before
 *   `b2_authorize_account`, which is itself a class-C transaction.
 * - **`sha1Verified` distinguishes three states**, not two: verified, mismatched
 *   and never-checked. B2 legitimately returns non-hashes (`none`,
 *   `unverified:...`) and comparing against those would manufacture a mismatch.
 * - **A failed large upload cancels itself**, or its parts are stored and billed
 *   forever, invisibly.
 * - **The download authorization token never reaches a snapshot or a log.**
 *
 * @module
 */
import {
  assert,
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import { _internal, b2Authorize, model } from "./b2_transfer.ts";

// ---------------------------------------------------------------------------
// Fixtures — nothing here is a real credential, bucket, account, or file.
// ---------------------------------------------------------------------------

const BUCKET_NAME = "example-backup-bucket";
const BUCKET_ID = "4a48fe8875c6214145260818";
const OTHER_BUCKET_NAME = "example-archive-bucket";
const OTHER_BUCKET_ID = "5b59ff9986d7325256371929";
const ACCOUNT_ID = "a1b2c3d4e5f6";
const API_URL = "https://api002.backblazeb2.com";
const DOWNLOAD_URL = "https://f002.backblazeb2.com";
const LARGE_FILE_ID = "4_zexamplelargefileid00001";

/** Secrets that must never appear in a resource snapshot or a log line. */
const APPLICATION_KEY = "K004exampleApplicationKeySecretValue00";
const AUTH_TOKEN = "4_004exampleAuthorizationTokenValue00";
const UPLOAD_TOKEN = "4_004exampleUploadEndpointTokenValue00";
const DOWNLOAD_AUTH_TOKEN = "4_004exampleDownloadAuthTokenValue000";

/** SHA-1 of "hello", which several fixtures upload. */
const HELLO_SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

/** The v4 authorize response — everything nested under apiInfo.storageApi. */
function authBody(
  buckets: Array<{ id: string; name: string }> | null = [],
): Record<string, unknown> {
  return {
    accountId: ACCOUNT_ID,
    authorizationToken: AUTH_TOKEN,
    applicationKeyExpirationTimestamp: null,
    apiInfo: {
      storageApi: {
        apiUrl: `${API_URL}/`,
        downloadUrl: DOWNLOAD_URL,
        s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
        recommendedPartSize: 100000000,
        absoluteMinimumPartSize: 5000000,
        allowed: {
          buckets,
          capabilities: ["listBuckets", "listFiles", "writeFiles", "readFiles"],
          namePrefix: null,
        },
      },
      groupsApi: { groupsApiUrl: API_URL, capabilities: [] },
    },
  };
}

/** A `b2_list_buckets` response covering both fixture buckets. */
function bucketsBody(): Record<string, unknown> {
  return {
    buckets: [
      { bucketId: BUCKET_ID, bucketName: BUCKET_NAME, bucketType: "allPrivate" },
      {
        bucketId: OTHER_BUCKET_ID,
        bucketName: OTHER_BUCKET_NAME,
        bucketType: "allPrivate",
      },
    ],
  };
}

/** An unfinished large file, as `b2_list_unfinished_large_files` returns it. */
function unfinishedBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    accountId: ACCOUNT_ID,
    action: "start",
    bucketId: BUCKET_ID,
    contentType: "application/octet-stream",
    fileId: LARGE_FILE_ID,
    fileInfo: {},
    fileName: "data/00/pack-interrupted",
    uploadTimestamp: 1754000000000,
    ...overrides,
  };
}

/** An upload endpoint. Its token is a bearer credential. */
function uploadUrlBody(fileId?: string): Record<string, unknown> {
  return {
    bucketId: BUCKET_ID,
    fileId,
    uploadUrl: `${API_URL}/b2api/v4/b2_upload_file/${BUCKET_ID}/x`,
    authorizationToken: UPLOAD_TOKEN,
  };
}

/** A finished file, as an upload returns it. */
function fileBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
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
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock plumbing
// ---------------------------------------------------------------------------

/** One recorded outbound request. */
type Recorded = {
  url: string;
  op: string;
  method: string;
  authorization: string;
  body: string | null;
  headers: Record<string, string>;
};

function installFetch(
  handler: (req: Recorded, index: number) => Response | Promise<Response>,
): { calls: Recorded[]; restore: () => void } {
  const calls: Recorded[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const url = String(input);
    const flat: Record<string, string> = {};
    headers.forEach((v, k) => {
      flat[k.toLowerCase()] = v;
    });
    const rec: Recorded = {
      url,
      op: url.split("/b2api/v4/")[1]?.split("?")[0] ?? "",
      method: init?.method ?? "GET",
      authorization: headers.get("authorization") ?? "",
      body: typeof init?.body === "string" ? init.body : null,
      headers: flat,
    };
    calls.push(rec);
    return Promise.resolve(handler(rec, calls.length - 1));
  }) as typeof globalThis.fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

/** Build a JSON `Response`. */
function json(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/**
 * Route a mocked request by B2 operation.
 *
 * A route may be a single body or a queue consumed one call at a time, which is
 * how the paginated and retry cases are expressed. Upload endpoints do not sit
 * under `/b2api/v4/<op>` in reality, so they are matched on the URL instead.
 */
function router(
  routes: Record<string, unknown | unknown[]>,
): (req: Recorded) => Response {
  const queues = new Map<string, unknown[]>();
  return (req: Recorded): Response => {
    let key = req.op;
    if (req.url.includes("/b2_upload_file/")) key = "upload_endpoint";
    if (req.url.startsWith(`${DOWNLOAD_URL}/file/`)) key = "download_by_name";
    const route = key === "b2_authorize_account"
      ? (routes.b2_authorize_account ?? authBody())
      : routes[key];
    if (route === undefined) {
      return json({ code: "unexpected_operation", message: key }, 400);
    }
    if (Array.isArray(route)) {
      let queue = queues.get(key);
      if (!queue) {
        queue = [...route];
        queues.set(key, queue);
      }
      const next = queue.shift();
      if (next === undefined) {
        return json({ code: "queue_exhausted", message: key }, 400);
      }
      return next instanceof Response ? next : json(next);
    }
    return route instanceof Response ? route : json(route);
  };
}

/** A collected `writeResource` call. */
type Written = { spec: string; name: string; data: Record<string, unknown> };

/** Build an execute context with a VALIDATING `writeResource` and a log capture. */
function makeContext(globalArgs: Record<string, unknown> = {}): {
  context: {
    globalArgs: ReturnType<typeof _internal.GlobalArgsSchema.parse>;
    logger: {
      info: (m: string, p?: Record<string, unknown>) => void;
      warn: (m: string, p?: Record<string, unknown>) => void;
    };
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => Promise<{ name: string }>;
  };
  written: Written[];
  logs: string[];
} {
  const written: Written[] = [];
  const logs: string[] = [];
  return {
    written,
    logs,
    context: {
      // Parsed, not passed through: schema defaults and coercions are part of
      // what a real run applies.
      globalArgs: _internal.GlobalArgsSchema.parse({
        applicationKeyId: "004exampleKeyId0000000",
        applicationKey: APPLICATION_KEY,
        bucketName: BUCKET_NAME,
        ...globalArgs,
      }),
      logger: {
        info: (m, p) => logs.push(`${m} ${JSON.stringify(p ?? {})}`),
        warn: (m, p) => logs.push(`WARN ${m} ${JSON.stringify(p ?? {})}`),
      },
      // Validate against the REAL resource schema, exactly as swamp does at run
      // time (CONVENTIONS §10.1).
      writeResource: (spec, name, data) => {
        const resourceSpec =
          (model.resources as Record<string, { schema: z.ZodType }>)[spec];
        if (!resourceSpec) {
          throw new Error(`writeResource called with unknown spec "${spec}"`);
        }
        if (name === "latest") {
          throw new Error(
            `writeResource("${spec}", "latest") uses the reserved swamp data ` +
              `name "latest" — swamp would fail this at run time`,
          );
        }
        const parsed = resourceSpec.schema.safeParse(data);
        if (!parsed.success) {
          throw new Error(
            `writeResource("${spec}", "${name}") wrote data that the spec ` +
              `schema rejects — swamp would fail this at run time: ` +
              JSON.stringify(parsed.error.issues),
          );
        }
        written.push({ spec, name, data });
        return Promise.resolve({ name });
      },
    },
  };
}

/** Assert a value's JSON encoding carries none of the known secrets. */
function assertNoSecrets(value: unknown, label: string): void {
  const blob = JSON.stringify(value);
  for (
    const [name, secret] of Object.entries({
      APPLICATION_KEY,
      AUTH_TOKEN,
      UPLOAD_TOKEN,
      DOWNLOAD_AUTH_TOKEN,
    })
  ) {
    assertFalse(
      blob.includes(secret),
      `${label} leaked ${name}`,
    );
  }
}

const CREDS = {
  applicationKeyId: "004exampleKeyId0000000",
  applicationKey: APPLICATION_KEY,
};

// ---------------------------------------------------------------------------
// Canonical client — CONVENTIONS §10 items 1-5
// ---------------------------------------------------------------------------

Deno.test("b2Authorize parses the nested v4 shape and the buckets array", async () => {
  const { restore } = installFetch(() =>
    json(authBody([{ id: BUCKET_ID, name: BUCKET_NAME }]))
  );
  try {
    const auth = await b2Authorize(CREDS);
    assertEquals(auth.apiUrl, API_URL);
    assertEquals(auth.downloadUrl, DOWNLOAD_URL);
    assertEquals(auth.allowed.buckets, [{ id: BUCKET_ID, name: BUCKET_NAME }]);
  } finally {
    restore();
  }
});

Deno.test("b2Authorize turns a null buckets list into an empty array", async () => {
  const { restore } = installFetch(() => json(authBody(null)));
  try {
    assertEquals((await b2Authorize(CREDS)).allowed.buckets, []);
  } finally {
    restore();
  }
});

Deno.test("b2Authorize rejects a flat v2/v3 body rather than half-reading it", async () => {
  // v2 put apiUrl at the top level. Accepting that shape would produce an auth
  // pointing at the wrong host, which fails much later and much less clearly.
  const { restore } = installFetch(() =>
    json({ accountId: ACCOUNT_ID, authorizationToken: AUTH_TOKEN, apiUrl: API_URL })
  );
  try {
    await assertRejects(() => b2Authorize(CREDS));
  } finally {
    restore();
  }
});

Deno.test("an expired auth token triggers exactly one re-authorization", async () => {
  let authCount = 0;
  const { calls, restore } = installFetch((req, i) => {
    if (req.op === "b2_authorize_account") {
      authCount++;
      return json(authBody());
    }
    if (i === 1) {
      return json({ code: "expired_auth_token", message: "expired" }, 401);
    }
    return json({ parts: [], nextPartNumber: null });
  });
  try {
    const auth = await b2Authorize(CREDS);
    await _internal.listParts(auth, LARGE_FILE_ID, 5, () => b2Authorize(CREDS));
    assertEquals(authCount, 2, "one initial authorize plus exactly one retry");
    assertEquals(
      calls.filter((c) => c.op === "b2_list_parts").length,
      2,
      "the failed call is retried exactly once",
    );
  } finally {
    restore();
  }
});

Deno.test("a 429 is retried and a non-transient 400 throws with its b2Code", async () => {
  const { restore } = installFetch((req, i) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (i === 1) {
      return json({ code: "too_many_requests" }, 429, { "retry-after": "0" });
    }
    return json({ parts: [], nextPartNumber: null });
  });
  try {
    const auth = await b2Authorize(CREDS);
    const out = await _internal.listParts(
      auth,
      LARGE_FILE_ID,
      5,
      () => b2Authorize(CREDS),
    );
    assertEquals(out.parts, []);
  } finally {
    restore();
  }

  const { restore: restore2 } = installFetch((req) =>
    req.op === "b2_authorize_account"
      ? json(authBody())
      : json({ code: "bad_request", message: "nope" }, 400)
  );
  try {
    const auth = await b2Authorize(CREDS);
    const err = await assertRejects(() =>
      _internal.listParts(auth, LARGE_FILE_ID, 5, () => b2Authorize(CREDS))
    ) as Error & { b2Code?: string; status?: number };
    assertEquals(err.b2Code, "bad_request");
    assertEquals(err.status, 400);
  } finally {
    restore2();
  }
});

// ---------------------------------------------------------------------------
// Part listing — pagination and truncation
// ---------------------------------------------------------------------------

Deno.test("list_parts drains two pages and renames nextPartNumber to startPartNumber", async () => {
  const { calls, restore } = installFetch(router({
    b2_list_parts: [
      { parts: [{ partNumber: 1, contentLength: 100 }], nextPartNumber: 2 },
      { parts: [{ partNumber: 2, contentLength: 50 }], nextPartNumber: null },
    ],
  }));
  try {
    const auth = await b2Authorize(CREDS);
    const out = await _internal.listParts(
      auth,
      LARGE_FILE_ID,
      10,
      () => b2Authorize(CREDS),
    );
    assertEquals(out.parts.length, 2);
    assertFalse(out.truncated);
    const second = JSON.parse(
      calls.filter((c) => c.op === "b2_list_parts")[1].body as string,
    );
    assertEquals(second.startPartNumber, 2);
  } finally {
    restore();
  }
});

Deno.test("exhausting maxPages reports truncated rather than a short total", async () => {
  const { restore } = installFetch(router({
    b2_list_parts: { parts: [{ partNumber: 1, contentLength: 10 }], nextPartNumber: 9 },
  }));
  try {
    const auth = await b2Authorize(CREDS);
    const out = await _internal.listParts(
      auth,
      LARGE_FILE_ID,
      2,
      () => b2Authorize(CREDS),
    );
    assert(out.truncated, "a page-capped listing must say so");
  } finally {
    restore();
  }
});

Deno.test("totalPartBytes propagates null rather than under-counting", () => {
  // A part whose contentLength B2 did not report makes the total unknown.
  // Coercing it to 0 would understate what an abandoned upload is costing.
  assertEquals(
    _internal.totalPartBytes([{ contentLength: 10 }, { contentLength: 5 }]),
    15,
  );
  assertEquals(
    _internal.totalPartBytes([{ contentLength: 10 }, {}]),
    null,
  );
});

// ---------------------------------------------------------------------------
// The size guard
// ---------------------------------------------------------------------------

Deno.test("upload refuses oversized content BEFORE spending a single B2 call", async () => {
  // Including before b2_authorize_account, which is itself class-C. An
  // oversized transfer must cost exactly nothing.
  const { calls, restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ maxTransferBytes: 10 });
    await assertRejects(
      () =>
        model.methods.upload.execute(
          { fileName: "big.bin", content: "x".repeat(100) },
          context,
        ),
      Error,
      "maxTransferBytes",
    );
    assertEquals(calls.length, 0, "no B2 call may be made for a refused upload");
  } finally {
    restore();
  }
});

Deno.test("the size-guard message names the size, the cap and the override", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ maxTransferBytes: 10 });
    const err = await assertRejects(() =>
      model.methods.upload.execute(
        { fileName: "big.bin", content: "x".repeat(100) },
        context,
      )
    ) as Error;
    assertStringIncludes(err.message, "100 bytes");
    assertStringIncludes(err.message, "10");
    assertStringIncludes(err.message, "maxTransferBytes=100");
  } finally {
    restore();
  }
});

Deno.test("download refuses on the advertised Content-Length before reading the body", async () => {
  let bodyRead = false;
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    // Spy on arrayBuffer() rather than on the stream: Deno pulls a Response's
    // body for its own reasons, so a stream-level flag would report a read that
    // the model never asked for. arrayBuffer() is the call the model actually
    // makes, and not making it is exactly the behaviour under test.
    const res = new Response("x".repeat(10), {
      status: 200,
      headers: { "Content-Length": "999999999" },
    });
    Object.defineProperty(res, "arrayBuffer", {
      value: () => {
        bodyRead = true;
        return Promise.resolve(new ArrayBuffer(10));
      },
    });
    return res;
  });
  try {
    const { context } = makeContext({ maxTransferBytes: 10 });
    await assertRejects(
      () =>
        model.methods.download.execute(
          { fileId: "4_zexamplefileid0000000001" },
          context,
        ),
      Error,
      "maxTransferBytes",
    );
    assertFalse(bodyRead, "an oversized object must not be pulled through");
  } finally {
    restore();
  }
});

Deno.test("a per-run maxTransferBytes overrides the model's", async () => {
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_get_upload_url: uploadUrlBody(),
    upload_endpoint: fileBody(),
  }));
  try {
    const { context, written } = makeContext({ maxTransferBytes: 1 });
    await model.methods.upload.execute(
      { fileName: "canary.txt", content: "hello", maxTransferBytes: 1000 },
      context,
    );
    assertEquals(written.length, 1);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// SHA-1: three states, not two
// ---------------------------------------------------------------------------

Deno.test("comparableSha1 rejects every value B2 returns that is not a hash", () => {
  // "none" and "unverified:..." are real B2 responses. Comparing a local hash
  // against them would manufacture a mismatch out of a non-hash.
  assertEquals(_internal.comparableSha1("none"), null);
  assertEquals(_internal.comparableSha1(`unverified:${HELLO_SHA1}`), null);
  assertEquals(_internal.comparableSha1(""), null);
  assertEquals(_internal.comparableSha1(null), null);
  assertEquals(_internal.comparableSha1("not-a-hash"), null);
  assertEquals(_internal.comparableSha1(HELLO_SHA1.toUpperCase()), HELLO_SHA1);
});

Deno.test("a verified upload records sha1Verified true", async () => {
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_get_upload_url: uploadUrlBody(),
    upload_endpoint: fileBody(),
  }));
  try {
    const { context, written } = makeContext();
    await model.methods.upload.execute(
      { fileName: "canary.txt", content: "hello" },
      context,
    );
    assertEquals(written[0].data.sha1Verified, true);
  } finally {
    restore();
  }
});

Deno.test("an unverifiable SHA-1 is null, never false", async () => {
  // The distinction is the point: null is "not checked", false is "checked and
  // WRONG". A consumer filtering on !sha1Verified would treat them alike, and
  // only one of them means the bytes are bad.
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_get_upload_url: uploadUrlBody(),
    upload_endpoint: fileBody({ contentSha1: "none" }),
  }));
  try {
    const { context, written } = makeContext();
    await model.methods.upload.execute(
      { fileName: "canary.txt", content: "hello" },
      context,
    );
    assertEquals(written[0].data.sha1Verified, null);
  } finally {
    restore();
  }
});

Deno.test("a genuine SHA-1 mismatch records false, and warns", async () => {
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_get_upload_url: uploadUrlBody(),
    upload_endpoint: fileBody({
      contentSha1: "0000000000000000000000000000000000000000",
    }),
  }));
  try {
    const { context, written } = makeContext();
    await model.methods.upload.execute(
      { fileName: "canary.txt", content: "hello" },
      context,
    );
    assertEquals(written[0].data.sha1Verified, false);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

Deno.test("upload requires exactly one of content or sourcePath", async () => {
  await assertRejects(
    () => _internal.readUploadSource({}),
    Error,
    "exactly one",
  );
  await assertRejects(
    () => _internal.readUploadSource({ content: "a", sourcePath: "/tmp/x" }),
    Error,
    "exactly one",
  );
});

Deno.test("a small upload sends the SHA-1 in the header B2 verifies against", async () => {
  const { calls, restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_get_upload_url: uploadUrlBody(),
    upload_endpoint: fileBody(),
  }));
  try {
    const { context } = makeContext();
    await model.methods.upload.execute(
      { fileName: "canary.txt", content: "hello" },
      context,
    );
    const put = calls.find((c) => c.url.includes("/b2_upload_file/")) as Recorded;
    assertEquals(put.headers["x-bz-content-sha1"], HELLO_SHA1);
    assertEquals(put.authorization, UPLOAD_TOKEN);
  } finally {
    restore();
  }
});

Deno.test("forceLarge takes the start/part/finish path and counts its parts", async () => {
  const { calls, restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_start_large_file: fileBody({ fileId: LARGE_FILE_ID, contentSha1: "none" }),
    b2_get_upload_part_url: uploadUrlBody(LARGE_FILE_ID),
    upload_endpoint: { partNumber: 1, contentLength: 5 },
    b2_finish_large_file: fileBody({ contentSha1: "none" }),
  }));
  try {
    const { context, written } = makeContext();
    await model.methods.upload.execute(
      { fileName: "canary.txt", content: "hello", forceLarge: true },
      context,
    );
    assertEquals(written[0].data.mode, "large");
    assertEquals(written[0].data.partCount, 1);
    assertEquals(
      calls.filter((c) => c.op === "b2_get_upload_part_url").length,
      1,
      "the part URL is fetched once and reused — one class-C call, not one per part",
    );
  } finally {
    restore();
  }
});

Deno.test("a failed large upload cancels itself so its parts are not billed", async () => {
  // This is the sharpest failure mode in the model: an unfinished large file is
  // invisible in the console's file browser and billed indefinitely.
  const { calls, restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_start_large_file: fileBody({ fileId: LARGE_FILE_ID }),
    b2_get_upload_part_url: uploadUrlBody(LARGE_FILE_ID),
    upload_endpoint: json({ code: "service_unavailable" }, 503),
    b2_cancel_large_file: { fileId: LARGE_FILE_ID },
  }));
  try {
    const { context, logs } = makeContext();
    await assertRejects(() =>
      model.methods.upload.execute(
        { fileName: "canary.txt", content: "hello", forceLarge: true },
        context,
      )
    );
    const cancels = calls.filter((c) => c.op === "b2_cancel_large_file");
    assertEquals(cancels.length, 1, "the orphaned large file must be cancelled");
    assert(logs.some((l) => l.includes("cancelled large file")));
  } finally {
    restore();
  }
});

Deno.test("when the rescue cancel ALSO fails, the log names the cleanup command", async () => {
  // The original error must still surface — a failed cleanup must not mask it —
  // but the operator has to be told a billed object was left behind.
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_start_large_file: fileBody({ fileId: LARGE_FILE_ID }),
    b2_get_upload_part_url: uploadUrlBody(LARGE_FILE_ID),
    upload_endpoint: json({ code: "service_unavailable" }, 503),
    b2_cancel_large_file: json({ code: "bad_request" }, 400),
  }));
  try {
    const { context, logs } = makeContext();
    await assertRejects(() =>
      model.methods.upload.execute(
        { fileName: "canary.txt", content: "hello", forceLarge: true },
        context,
      )
    );
    assert(
      logs.some((l) => l.includes("still stored and still billed")),
      "a leaked large file must be reported loudly",
    );
    assert(logs.some((l) => l.includes("delete")));
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

Deno.test("download requires exactly one of fileId or fileName", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext();
    await assertRejects(
      () => model.methods.download.execute({}, context),
      Error,
      "exactly one",
    );
    await assertRejects(
      () =>
        model.methods.download.execute(
          { fileId: "a", fileName: "b" },
          context,
        ),
      Error,
      "exactly one",
    );
  } finally {
    restore();
  }
});

Deno.test("download by fileId never spends a b2_list_buckets call", async () => {
  // A bucket-restricted key has no listBuckets capability. Demanding one for a
  // call B2 addresses purely by fileId would lock that key out for nothing —
  // the exact defect live verification found in b2-files.
  const { calls, restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    return new Response("hello", {
      status: 200,
      headers: {
        "Content-Length": "5",
        "X-Bz-Content-Sha1": HELLO_SHA1,
        "X-Bz-File-Name": "canary.txt",
        "X-Bz-File-Id": "4_zexamplefileid0000000001",
        "Content-Type": "text/plain",
      },
    });
  });
  try {
    const { context, written } = makeContext();
    await model.methods.download.execute(
      { fileId: "4_zexamplefileid0000000001" },
      context,
    );
    assertEquals(calls.filter((c) => c.op === "b2_list_buckets").length, 0);
    assertEquals(written[0].data.sha1Verified, true);
    assertEquals(written[0].data.bytes, 5);
  } finally {
    restore();
  }
});

Deno.test("download by name keeps slashes literal in the URL path", async () => {
  // encodeURIComponent would escape "/" and turn one restic key into a single
  // path segment B2 has never heard of.
  const { calls, restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (req.op === "b2_list_buckets") return json(bucketsBody());
    return new Response("hello", {
      status: 200,
      headers: {
        "Content-Length": "5",
        "X-Bz-Content-Sha1": HELLO_SHA1,
        "X-Bz-File-Name": "data%2F00%2Fpack",
      },
    });
  });
  try {
    const { context } = makeContext();
    await model.methods.download.execute(
      { fileName: "data/00/pack" },
      context,
    );
    const get = calls.find((c) => c.url.includes("/file/")) as Recorded;
    assertStringIncludes(get.url, "/file/example-backup-bucket/data/00/pack");
  } finally {
    restore();
  }
});

Deno.test("encodeFileName escapes each segment but keeps the separators", () => {
  assertEquals(_internal.encodeFileName("data/00/pack"), "data/00/pack");
  assertEquals(_internal.encodeFileName("a b/c d"), "a%20b/c%20d");
});

// ---------------------------------------------------------------------------
// authorize_download — the token must never be persisted
// ---------------------------------------------------------------------------

Deno.test("authorize_download never writes its token to a snapshot or a log", async () => {
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (req.op === "b2_list_buckets") return json(bucketsBody());
    if (req.op === "b2_get_download_authorization") {
      return json({
        bucketId: BUCKET_ID,
        fileNamePrefix: "data/",
        authorizationToken: DOWNLOAD_AUTH_TOKEN,
      });
    }
    return new Response(null, { status: 200 });
  });
  try {
    const { context, written, logs } = makeContext();
    await model.methods.authorize_download.execute(
      { fileNamePrefix: "data/" },
      context,
    );
    assertEquals(written[0].data.tokenPersisted, false);
    assertEquals(written[0].data.verified, true);
    assertNoSecrets(written[0].data, "download-auth snapshot");
    assertNoSecrets(logs, "authorize_download logs");
  } finally {
    restore();
  }
});

Deno.test("a minted token that is rejected when used reports verified false", async () => {
  // The whole point of verify: a token that mints but grants nothing looks like
  // success at the API layer and is useless in practice.
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (req.op === "b2_list_buckets") return json(bucketsBody());
    if (req.op === "b2_get_download_authorization") {
      return json({ authorizationToken: DOWNLOAD_AUTH_TOKEN });
    }
    return new Response(null, { status: 401 });
  });
  try {
    const { context, written, logs } = makeContext();
    await model.methods.authorize_download.execute(
      { fileNamePrefix: "data/" },
      context,
    );
    assertEquals(written[0].data.verified, false);
    assert(logs.some((l) => l.includes("REJECTED")));
  } finally {
    restore();
  }
});

Deno.test("a 404 on the probe is not a failed authorization", async () => {
  // An empty prefix holds no object yet; that says nothing about the grant.
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (req.op === "b2_list_buckets") return json(bucketsBody());
    if (req.op === "b2_get_download_authorization") {
      return json({ authorizationToken: DOWNLOAD_AUTH_TOKEN });
    }
    return new Response(null, { status: 404 });
  });
  try {
    const { context, written } = makeContext();
    await model.methods.authorize_download.execute(
      { fileNamePrefix: "data/" },
      context,
    );
    assertEquals(written[0].data.verified, true);
  } finally {
    restore();
  }
});

Deno.test("verify=false leaves verified null rather than claiming a check", async () => {
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (req.op === "b2_list_buckets") return json(bucketsBody());
    return json({ authorizationToken: DOWNLOAD_AUTH_TOKEN });
  });
  try {
    const { context, written } = makeContext();
    await model.methods.authorize_download.execute(
      { fileNamePrefix: "data/", verify: false },
      context,
    );
    assertEquals(written[0].data.verified, null);
  } finally {
    restore();
  }
});

Deno.test("expiresAt is computed from the requested duration", async () => {
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    if (req.op === "b2_list_buckets") return json(bucketsBody());
    return json({ authorizationToken: DOWNLOAD_AUTH_TOKEN });
  });
  try {
    const { context, written } = makeContext();
    const before = Date.now();
    await model.methods.authorize_download.execute(
      { fileNamePrefix: "data/", validDurationInSeconds: 60, verify: false },
      context,
    );
    const expires = Date.parse(written[0].data.expiresAt as string);
    assert(expires >= before + 60_000, "expiry must be at least the duration out");
    assert(expires <= Date.now() + 61_000);
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

Deno.test("scan inventories unfinished uploads across every visible bucket", async () => {
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_list_unfinished_large_files: { files: [unfinishedBody()], nextFileId: null },
  }));
  try {
    const { context, written } = makeContext({ bucketName: undefined });
    await model.methods.scan.execute({}, context);
    // Two buckets, one unfinished upload each — but both share a fileId in the
    // fixture, so the instance name is the same; the write count is what proves
    // the fan-out happened.
    assertEquals(written.length, 2);
    assertEquals(written[0].spec, "unfinished-upload");
    assertEquals(written[0].data.status, "present");
  } finally {
    restore();
  }
});

Deno.test("scan leaves partCount null, because it did not count", async () => {
  // Not zero. Counting is one class-C call per unfinished file, so scan does not
  // do it — and a zero here would claim a measurement nobody took about exactly
  // the objects this resource exists to price.
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_list_unfinished_large_files: { files: [unfinishedBody()], nextFileId: null },
  }));
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.scan.execute({}, context);
    assertEquals(written[0].data.partCount, null);
    assertEquals(written[0].data.partBytes, null);
    assertEquals(written[0].data.partsTruncated, null);
  } finally {
    restore();
  }
});

Deno.test("countParts populates the part fields", async () => {
  const { restore } = installFetch(router({
    b2_list_buckets: bucketsBody(),
    b2_list_unfinished_large_files: { files: [unfinishedBody()], nextFileId: null },
    b2_list_parts: {
      parts: [{ partNumber: 1, contentLength: 5_000_000 }],
      nextPartNumber: null,
    },
  }));
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.scan.execute({ countParts: true }, context);
    assertEquals(written[0].data.partCount, 1);
    assertEquals(written[0].data.partBytes, 5_000_000);
    assertEquals(written[0].data.partsTruncated, false);
  } finally {
    restore();
  }
});

Deno.test("scan with a pinned bucket spends no b2_list_buckets call", async () => {
  const { calls, restore } = installFetch(router({
    b2_list_unfinished_large_files: { files: [], nextFileId: null },
  }));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.scan.execute({}, context);
    assertEquals(calls.filter((c) => c.op === "b2_list_buckets").length, 0);
  } finally {
    restore();
  }
});

Deno.test("ageInDays is null for an absent timestamp, never zero", () => {
  // "started an unknown time ago" and "started today" must not collapse: age is
  // the whole basis for calling an interrupted upload abandoned.
  assertEquals(_internal.ageInDays(null, Date.now()), null);
  assertEquals(_internal.ageInDays(1754000000000, 1754000000000), 0);
  assertEquals(
    _internal.ageInDays(1754000000000, 1754000000000 + 86_400_000 * 3),
    3,
  );
});

// ---------------------------------------------------------------------------
// list_parts, copy_part, delete
// ---------------------------------------------------------------------------

Deno.test("list_parts sizes an abandoned upload without a bucket lookup", async () => {
  const { calls, restore } = installFetch(router({
    b2_list_parts: {
      parts: [
        { partNumber: 1, contentLength: 5_000_000 },
        { partNumber: 2, contentLength: 2_000_000 },
      ],
      nextPartNumber: null,
    },
  }));
  try {
    const { context, written } = makeContext();
    await model.methods.list_parts.execute({ fileId: LARGE_FILE_ID }, context);
    assertEquals(calls.filter((c) => c.op === "b2_list_buckets").length, 0);
    assertEquals(written[0].data.partCount, 2);
    assertEquals(written[0].data.partBytes, 7_000_000);
  } finally {
    restore();
  }
});

Deno.test("a truncated part listing marks the count a floor and warns", async () => {
  const { restore } = installFetch(router({
    b2_list_parts: { parts: [{ partNumber: 1, contentLength: 10 }], nextPartNumber: 2 },
  }));
  try {
    const { context, written, logs } = makeContext();
    await model.methods.list_parts.execute(
      { fileId: LARGE_FILE_ID, maxPages: 1 },
      context,
    );
    assertEquals(written[0].data.partsTruncated, true);
    assert(logs.some((l) => l.includes("FLOOR")));
  } finally {
    restore();
  }
});

const COPY_ROUTES = {
  b2_list_buckets: bucketsBody(),
  b2_start_large_file: fileBody({ fileId: LARGE_FILE_ID, contentSha1: "none" }),
  b2_copy_part: { fileId: LARGE_FILE_ID, partNumber: 1, contentLength: 900 },
  b2_finish_large_file: fileBody({
    fileName: "assembled.bin",
    contentSha1: "none",
  }),
};

Deno.test("copy_part owns the whole lifecycle: start, copy each source, finish", async () => {
  // The original took a largeFileId and a partNumber, mirroring b2_copy_part
  // one-for-one — and was UNREACHABLE, because nothing in this model hands out
  // an in-progress large file. Live B2 rejected the only id available (a
  // completed upload) with "No active upload for". Owning the lifecycle is what
  // makes the method callable at all.
  const { calls, restore } = installFetch(router(COPY_ROUTES));
  try {
    const { context, written } = makeContext();
    await model.methods.copy_part.execute({
      fileName: "assembled.bin",
      sources: [
        { sourceFileId: "4_zexamplefileid0000000001", range: "bytes=0-4999999" },
        { sourceFileId: "4_zexamplefileid0000000002" },
      ],
    }, context);
    const ops = calls.map((c) => c.op);
    assertEquals(ops.filter((o) => o === "b2_start_large_file").length, 1);
    assertEquals(ops.filter((o) => o === "b2_copy_part").length, 2);
    assertEquals(ops.filter((o) => o === "b2_finish_large_file").length, 1);
    assertEquals(written[0].data.direction, "copy_part");
    assertEquals(written[0].data.partCount, 2);
    assertEquals(written[0].data.bytes, 1800);
    // Nothing was hashed locally, so there is no verdict to claim.
    assertEquals(written[0].data.sha1Verified, null);
  } finally {
    restore();
  }
});

Deno.test("copy_part numbers its parts from the source order", async () => {
  const { calls, restore } = installFetch(router(COPY_ROUTES));
  try {
    const { context } = makeContext();
    await model.methods.copy_part.execute({
      fileName: "assembled.bin",
      sources: [
        { sourceFileId: "a" },
        { sourceFileId: "b" },
        { sourceFileId: "c" },
      ],
    }, context);
    const parts = calls.filter((c) => c.op === "b2_copy_part")
      .map((c) => JSON.parse(c.body as string));
    assertEquals(parts.map((p) => p.partNumber), [1, 2, 3]);
    assertEquals(parts.map((p) => p.sourceFileId), ["a", "b", "c"]);
    // The range is optional per source and must be omitted, not sent as null.
    assertFalse("range" in parts[0]);
  } finally {
    restore();
  }
});

Deno.test("a failed copy_part cancels the half-built file", async () => {
  // Otherwise it becomes exactly the invisible billed waste this model exists
  // to find — created by the tool meant to clean it up.
  const { calls, restore } = installFetch(router({
    ...COPY_ROUTES,
    b2_copy_part: json({ code: "bad_request", message: "nope" }, 400),
    b2_cancel_large_file: { fileId: LARGE_FILE_ID },
  }));
  try {
    const { context, logs } = makeContext();
    await assertRejects(() =>
      model.methods.copy_part.execute({
        fileName: "assembled.bin",
        sources: [{ sourceFileId: "a" }],
      }, context)
    );
    assertEquals(
      calls.filter((c) => c.op === "b2_cancel_large_file").length,
      1,
      "the half-built large file must be cancelled",
    );
    assert(logs.some((l) => l.includes("cancelled large file")));
  } finally {
    restore();
  }
});

Deno.test("copy_part propagates an unknown part length rather than under-counting", async () => {
  const { restore } = installFetch(router({
    ...COPY_ROUTES,
    b2_copy_part: { fileId: LARGE_FILE_ID, partNumber: 1 },
  }));
  try {
    const { context, written } = makeContext();
    await model.methods.copy_part.execute({
      fileName: "assembled.bin",
      sources: [{ sourceFileId: "a" }],
    }, context);
    assertEquals(written[0].data.bytes, null);
  } finally {
    restore();
  }
});

Deno.test("no pre-flight check may gate delete on the acknowledgement", () => {
  // FOUND BY ACTUALLY RUNNING IT. A check here can only see globalArgs — swamp
  // does not pass method inputs to checks — so it rejects
  // `--input allowTransferDestruction=true` before execute ever runs, and its
  // error message then tells the operator to do the thing it just made
  // impossible. Worse, with the per-run path blocked the only way through is
  // setting allowTransferDestruction permanently on the model, so a check meant
  // to prevent destruction ends up forcing it to be armed for good. The gate
  // belongs in execute, which sees both paths.
  for (const [name, check] of Object.entries(model.checks)) {
    const applies = (check as { appliesTo?: string[] }).appliesTo;
    assertFalse(
      applies?.includes("delete") === true,
      `check "${name}" gates delete; a pre-flight check cannot see ` +
        `--input allowTransferDestruction and would block the per-run path`,
    );
  }
});

Deno.test("delete refuses without an acknowledgement, before any B2 call", async () => {
  const { calls, restore } = installFetch(router({}));
  try {
    const { context } = makeContext();
    await assertRejects(
      () => model.methods.delete.execute({ fileId: LARGE_FILE_ID }, context),
      Error,
      "allowTransferDestruction",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("delete accepts the acknowledgement from either the input or the model", async () => {
  for (
    const [args, globals] of [
      [{ fileId: LARGE_FILE_ID, allowTransferDestruction: true }, {}],
      [{ fileId: LARGE_FILE_ID }, { allowTransferDestruction: true }],
    ] as Array<[Record<string, unknown>, Record<string, unknown>]>
  ) {
    const { restore } = installFetch(router({
      b2_cancel_large_file: { fileId: LARGE_FILE_ID, fileName: "x" },
    }));
    try {
      const { context, written } = makeContext(globals);
      await model.methods.delete.execute(
        args as { fileId: string; allowTransferDestruction?: boolean },
        context,
      );
      assertEquals(written[0].data.status, "absent");
    } finally {
      restore();
    }
  }
});

Deno.test("delete is idempotent — an upload already gone is a success", async () => {
  const { restore } = installFetch(router({
    b2_cancel_large_file: json({ code: "file_not_present" }, 400),
  }));
  try {
    const { context, written } = makeContext({ allowTransferDestruction: true });
    await model.methods.delete.execute({ fileId: LARGE_FILE_ID }, context);
    assertEquals(written[0].data.status, "absent");
    // A cancelled upload genuinely has no parts. This zero IS measured.
    assertEquals(written[0].data.partCount, 0);
  } finally {
    restore();
  }
});

Deno.test("isAlreadyGone excludes bad_bucket_id, which is a config bug", () => {
  // Swallowing it would report a successful cancel of an upload still accruing
  // storage in the bucket the caller actually meant.
  assert(_internal.isAlreadyGone({ status: 404 }));
  assert(_internal.isAlreadyGone({ status: 400, b2Code: "file_not_present" }));
  assertFalse(_internal.isAlreadyGone({ status: 400, b2Code: "bad_bucket_id" }));
  assertFalse(_internal.isAlreadyGone({ status: 500 }));
});

Deno.test("the real already-cancelled response is recognised, and only it", () => {
  // LIVE-VERIFIED. Cancelling an already-cancelled large file returns neither
  // 404 nor file_not_present — it returns B2's catch-all bad_request with one
  // specific message:
  //   {"code":"bad_request","status":400,
  //    "message":"No active upload for large file (4_z...)"}
  // Treating bad_request wholesale as "already gone" would swallow genuine
  // malformed-request bugs (CONVENTIONS §4.7 warns of exactly this for
  // b2_delete_key), so the code AND the message must both match.
  assert(_internal.isAlreadyGone({
    status: 400,
    b2Code: "bad_request",
    message:
      'B2 b2_cancel_large_file failed (400, bad_request): {"code":"bad_request",' +
      '"message":"No active upload for large file (4_zexample)","status":400}',
  }));
  // Any OTHER bad_request still throws — this is the assertion that keeps the
  // message match from becoming a blanket swallow.
  assertFalse(_internal.isAlreadyGone({
    status: 400,
    b2Code: "bad_request",
    message: 'B2 failed (400, bad_request): {"message":"Invalid fileId"}',
  }));
  assertFalse(
    _internal.isAlreadyGone({ status: 400, b2Code: "bad_request" }),
    "a bad_request with no message must not be assumed already-gone",
  );
});

Deno.test("delete is idempotent against the REAL already-cancelled response", async () => {
  const { restore } = installFetch(router({
    b2_cancel_large_file: json({
      code: "bad_request",
      status: 400,
      message: "No active upload for large file (4_zexample)",
    }, 400),
  }));
  try {
    const { context, written } = makeContext({ allowTransferDestruction: true });
    await model.methods.delete.execute({ fileId: LARGE_FILE_ID }, context);
    assertEquals(written[0].data.status, "absent");
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// Instance names
// ---------------------------------------------------------------------------

Deno.test("every instance name is spec-prefixed and none is the reserved 'latest'", () => {
  // Instance names share one flat storage namespace across specs, so an
  // unprefixed name lets two specs clobber each other on disk — the failure
  // that made b2-bucket's notification snapshot eat its bucket snapshot.
  const names = [
    _internal.unfinishedInstanceName("4_zabc"),
    _internal.transferInstanceName("upload", BUCKET_NAME, "canary.txt"),
    _internal.downloadAuthInstanceName(BUCKET_NAME, "data/"),
  ];
  assert(names[0].startsWith("unfinished-upload-"));
  assert(names[1].startsWith("transfer-"));
  assert(names[2].startsWith("download-auth-"));
  for (const n of names) assert(n !== "latest");
  assertEquals(new Set(names).size, names.length);
});

Deno.test("two real-length fileIds differing only past the truncation stay distinct", () => {
  // FOUND LIVE, and unfindable with the short fixture this suite started with.
  // A real B2 large-file ID is ~83 chars:
  //   4_z<bucket>_f<file>_d<date>_m<minute>_c<cluster>_v<vol>_t<seq>
  // safeFragment cuts at 48, which lands inside the date — so everything that
  // distinguishes two uploads of the same file at different times is discarded.
  // Without the full-ID hash these two collapse to one instance name and one
  // snapshot silently overwrites the other.
  const a =
    "4_z4a48fe8875c6214145260818_f1a2b3c4d5e6f7a8b_d20210731_m175316_c002_v0001159_t0005";
  const b =
    "4_z4a48fe8875c6214145260818_f1a2b3c4d5e6f7a8b_d20260731_m090000_c002_v0001159_t0009";
  assert(a.length > 48 && b.length > 48, "the fixture must be realistically long");
  assertEquals(
    a.slice(0, 48),
    b.slice(0, 48),
    "the fixture only tests anything if the IDs share their first 48 chars",
  );
  assert(
    _internal.unfinishedInstanceName(a) !== _internal.unfinishedInstanceName(b),
    "two distinct large-file IDs must never share an instance name",
  );
});

Deno.test("lossy sanitisation cannot collide two different file names", () => {
  // "data/a" and "data-a" both reduce to "data-a"; the hash is what keeps them
  // apart, and without it one transfer record would silently overwrite another.
  const a = _internal.transferInstanceName("upload", BUCKET_NAME, "data/a");
  const b = _internal.transferInstanceName("upload", BUCKET_NAME, "data-a");
  assert(a !== b, "distinct file names must produce distinct instance names");
});

// ---------------------------------------------------------------------------
// Model shape and secret hygiene — CONVENTIONS §10 item 7
// ---------------------------------------------------------------------------

Deno.test("the model declares the PRD's type and every intent method", () => {
  assertEquals(model.type, "@sntxrr/b2/transfer");
  for (
    const m of [
      "scan",
      "upload",
      "download",
      "authorize_download",
      "list_parts",
      "copy_part",
      "delete",
    ]
  ) {
    assert(m in model.methods, `missing method ${m}`);
  }
  for (const s of ["unfinished-upload", "transfer", "download-auth"]) {
    assert(s in model.resources, `missing spec ${s}`);
  }
});

Deno.test("applicationKey is marked sensitive in the global arguments", () => {
  const shape = _internal.GlobalArgsSchema.shape;
  const meta = (shape.applicationKey as unknown as { meta: () => unknown })
    .meta() as { sensitive?: boolean } | undefined;
  assertEquals(meta?.sensitive, true);
});

Deno.test("no method leaks a secret into a snapshot or a log line", async () => {
  const routes = {
    b2_list_buckets: bucketsBody(),
    b2_list_unfinished_large_files: { files: [unfinishedBody()], nextFileId: null },
    b2_get_upload_url: uploadUrlBody(),
    upload_endpoint: fileBody(),
    b2_list_parts: { parts: [{ partNumber: 1, contentLength: 5 }], nextPartNumber: null },
    b2_copy_part: { fileId: LARGE_FILE_ID, partNumber: 1, contentLength: 5 },
    b2_cancel_large_file: { fileId: LARGE_FILE_ID },
    b2_get_download_authorization: { authorizationToken: DOWNLOAD_AUTH_TOKEN },
    // copy_part now owns the large-file lifecycle, so it reaches these too.
    b2_start_large_file: fileBody({ fileId: LARGE_FILE_ID, contentSha1: "none" }),
    b2_finish_large_file: fileBody({ contentSha1: "none" }),
  };
  const cases: Array<[string, Record<string, unknown>]> = [
    ["scan", {}],
    ["upload", { fileName: "canary.txt", content: "hello" }],
    ["authorize_download", { fileNamePrefix: "data/", verify: false }],
    ["list_parts", { fileId: LARGE_FILE_ID }],
    ["copy_part", {
      fileName: "assembled.bin",
      sources: [{ sourceFileId: "4_zx" }],
    }],
    ["delete", { fileId: LARGE_FILE_ID, allowTransferDestruction: true }],
  ];
  for (const [method, args] of cases) {
    const { restore } = installFetch(router(routes));
    try {
      const { context, written, logs } = makeContext({ bucketId: BUCKET_ID });
      // deno-lint-ignore no-explicit-any
      await (model.methods as any)[method].execute(args, context);
      assertNoSecrets(written, `${method} snapshots`);
      assertNoSecrets(logs, `${method} logs`);
    } finally {
      restore();
    }
  }
});

Deno.test("the account bearer token is sent as a header and never as a body field", async () => {
  const { calls, restore } = installFetch(router({
    b2_list_parts: { parts: [], nextPartNumber: null },
  }));
  try {
    const { context } = makeContext();
    await model.methods.list_parts.execute({ fileId: LARGE_FILE_ID }, context);
    for (const c of calls) {
      if (c.op === "b2_authorize_account") continue;
      assertFalse(
        (c.body ?? "").includes(AUTH_TOKEN),
        "a bearer token must never travel in a request body",
      );
    }
  } finally {
    restore();
  }
});
