/**
 * Unit tests for b2_files.ts.
 *
 * Every test mocks `fetch` — no live Backblaze B2 calls. Coverage follows
 * CONVENTIONS.md §10 (v4 auth shape, pagination, page-cap truncation, expired
 * token re-auth, transient retry, idempotent delete, no secret leaks) plus the
 * paths specific to this model:
 *
 * - the current-versus-non-current fold, including the case that costs money:
 *   a hide marker at the head of a name, under which every upload is billed
 *   and unreachable;
 * - the honest-null contract — listing by name reports non-current metrics as
 *   `null`, never `0`, because it cannot see them;
 * - authorization-wrapped `fileRetention` / `legalHold`, where an unreadable
 *   value must never be counted as "off";
 * - the destruction and compliance-retention gates, on both the global-argument
 *   and the method-input path;
 * - `update` re-reading the file, because the two update operations return a
 *   slim body that would otherwise hollow out the snapshot.
 *
 * The `writeResource` stub validates every write against the real spec schema
 * (CONVENTIONS §10.1) — a recording-only stub is blind to exactly the class of
 * derived-field bug this suite keeps producing.
 *
 * Fixtures use example.com and fake-but-plausible B2 identifiers only.
 *
 * @module
 */
import {
  assert,
  assertEquals,
  assertFalse,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import { _internal, b2Authorize, b2Fetch, model } from "./b2_files.ts";

// ---------------------------------------------------------------------------
// Fixtures — nothing here is a real credential, bucket, account, or file.
// ---------------------------------------------------------------------------

const BUCKET_NAME = "example-backup-bucket";
const BUCKET_ID = "4a48fe8875c6214145260818";
const OTHER_BUCKET_NAME = "example-archive-bucket";
const OTHER_BUCKET_ID = "5b59ff9986d7325256371929";
const ACCOUNT_ID = "a1b2c3d4e5f6";
const API_URL = "https://api002.backblazeb2.com";

/** Secrets that must never appear in a resource snapshot or a log line. */
const APPLICATION_KEY = "K004exampleApplicationKeySecretValue00";
const AUTH_TOKEN = "4_004exampleAuthorizationTokenValue00";

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
        downloadUrl: "https://f002.backblazeb2.com",
        s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
        recommendedPartSize: 100000000,
        absoluteMinimumPartSize: 5000000,
        allowed: {
          buckets,
          capabilities: ["listBuckets", "listFiles", "deleteFiles"],
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
      {
        bucketId: BUCKET_ID,
        bucketName: BUCKET_NAME,
        bucketType: "allPrivate",
      },
      {
        bucketId: OTHER_BUCKET_ID,
        bucketName: OTHER_BUCKET_NAME,
        bucketType: "allPrivate",
      },
    ],
  };
}

/** A B2 file version. Defaults to a readable, unlocked restic pack file. */
function fileBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
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
    // The real wire shape: authorization-wrapped. A fixture that returns a bare
    // value here would hide the wrapper-versus-value bug entirely.
    fileRetention: {
      isClientAuthorizedToRead: true,
      value: { mode: null, retainUntilTimestamp: null },
    },
    legalHold: { isClientAuthorizedToRead: true, value: "off" },
    replicationStatus: null,
    serverSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
    uploadTimestamp: 1754000000000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test harness — mocked fetch, validating writeResource, logger capture
// ---------------------------------------------------------------------------

/** One captured outbound HTTP request. */
type Recorded = {
  url: string;
  op: string;
  method: string;
  authorization: string;
  body: string | null;
};

/** Install a mocked global `fetch`; returns the call log plus a restore hook. */
function installFetch(
  handler: (req: Recorded, index: number) => Response | Promise<Response>,
): { calls: Recorded[]; restore: () => void } {
  const calls: Recorded[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const url = String(input);
    const rec: Recorded = {
      url,
      op: url.split("/b2api/v4/")[1]?.split("?")[0] ?? "",
      method: init?.method ?? "GET",
      authorization: headers.get("authorization") ?? "",
      body: typeof init?.body === "string" ? init.body : null,
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
 * A route may be a single response body or a queue consumed one call at a time,
 * which is how the paginated and retry cases are expressed.
 */
function router(
  routes: Record<string, unknown | unknown[]>,
): (req: Recorded) => Response {
  const queues = new Map<string, unknown[]>();
  return (req: Recorded): Response => {
    const route = req.op === "b2_authorize_account"
      ? (routes.b2_authorize_account ?? authBody())
      : routes[req.op];
    if (route === undefined) {
      return json({ code: "unexpected_operation", message: req.op }, 400);
    }
    if (Array.isArray(route)) {
      let queue = queues.get(req.op);
      if (!queue) {
        queue = [...route];
        queues.set(req.op, queue);
      }
      const next = queue.shift();
      if (next === undefined) {
        return json({ code: "queue_exhausted", message: req.op }, 400);
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
      // what a real run applies, and skipping them tests a shape swamp never
      // actually hands the model.
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
      // time (CONVENTIONS §10.1). A stub that only records what it was handed
      // proves nothing about it, and every bug mechanical review has found in
      // this suite lived in a derived field a recording stub cannot see.
      writeResource: (spec, name, data) => {
        const resourceSpec =
          (model.resources as Record<string, { schema: z.ZodType }>)[spec];
        if (!resourceSpec) {
          throw new Error(`writeResource called with unknown spec "${spec}"`);
        }
        // "latest" is reserved by swamp's data layer and rejected at run time
        // only. Model it here so a reserved-name bug fails in CI instead of
        // against a real bucket.
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
      applicationKey: APPLICATION_KEY,
      authorizationToken: AUTH_TOKEN,
    })
  ) {
    assertFalse(
      blob.includes(secret),
      `${label} must not contain the ${name} secret`,
    );
  }
  assertFalse(
    blob.includes('"applicationKey"'),
    `${label} must not carry an applicationKey field`,
  );
  assertFalse(
    blob.includes('"authorizationToken"'),
    `${label} must not carry an authorizationToken field`,
  );
}

/** Parse a recorded request body. */
function bodyOf(rec: Recorded): Record<string, unknown> {
  return JSON.parse(rec.body ?? "{}") as Record<string, unknown>;
}

/** The single aggregate written for the bucket-wide total. */
function totalAggregate(written: Written[]): Record<string, unknown> {
  const totals = written.filter((w) =>
    w.spec === "aggregate" && w.data.group === null
  );
  assertEquals(totals.length, 1, "expected exactly one bucket-total aggregate");
  return totals[0].data;
}

// ===========================================================================
// CONVENTIONS §10.1 — prove the harness bites
// ===========================================================================

Deno.test("harness: writeResource rejects a write the spec schema refuses", () => {
  const { context } = makeContext();
  assertThrows(
    () =>
      context.writeResource("aggregate", "aggregate-x", {
        bucketName: BUCKET_NAME,
        // currentBytes must be a number; a stringified count is exactly the
        // shape of derived-field bug that a recording-only stub waves through.
        currentBytes: "1024",
      }),
    Error,
    "spec schema rejects",
  );
});

Deno.test("harness: writeResource rejects the reserved data name 'latest'", () => {
  const { context } = makeContext();
  assertThrows(
    () => context.writeResource("file", "latest", {}),
    Error,
    "reserved swamp data name",
  );
});

Deno.test("harness: writeResource rejects an unknown spec", () => {
  const { context } = makeContext();
  assertThrows(
    () => context.writeResource("nope", "x", {}),
    Error,
    'unknown spec "nope"',
  );
});

// ===========================================================================
// CONVENTIONS §10.1–7 — the canonical client
// ===========================================================================

Deno.test("b2Authorize parses the nested v4 shape and strips trailing slashes", async () => {
  const { calls, restore } = installFetch(() =>
    json(authBody([{ id: BUCKET_ID, name: BUCKET_NAME }]))
  );
  try {
    const auth = await b2Authorize({
      applicationKeyId: "004exampleKeyId0000000",
      applicationKey: APPLICATION_KEY,
    });
    assertEquals(auth.accountId, ACCOUNT_ID);
    assertEquals(auth.apiUrl, API_URL, "trailing slash must be stripped");
    assertEquals(auth.allowed.buckets, [{ id: BUCKET_ID, name: BUCKET_NAME }]);
    assertStringIncludes(calls[0].url, "/b2api/v4/b2_authorize_account");
    assertStringIncludes(calls[0].authorization, "Basic ");
  } finally {
    restore();
  }
});

Deno.test("b2Authorize normalizes a null allowed.buckets to an empty array", async () => {
  const { restore } = installFetch(() => json(authBody(null)));
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    assertEquals(auth.allowed.buckets, []);
  } finally {
    restore();
  }
});

Deno.test("b2Authorize rejects a v2/v3-style flat body with an explanatory error", async () => {
  const { restore } = installFetch(() =>
    json({
      accountId: ACCOUNT_ID,
      authorizationToken: AUTH_TOKEN,
      apiUrl: API_URL,
    })
  );
  try {
    await assertRejects(
      () =>
        b2Authorize({
          applicationKeyId: "id",
          applicationKey: APPLICATION_KEY,
        }),
      Error,
      "apiInfo.storageApi",
    );
  } finally {
    restore();
  }
});

Deno.test("listFilePages drains a cursor and renames next* to start*", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_list_file_versions: [
        {
          files: [fileBody({ fileName: "a", fileId: "id-a" })],
          nextFileName: "b",
          nextFileId: "id-b",
        },
        { files: [fileBody({ fileName: "b", fileId: "id-b" })] },
      ],
    }),
  );
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    const page = await _internal.listFilePages(
      auth,
      "b2_list_file_versions",
      { bucketId: BUCKET_ID },
      10,
    );
    assertEquals(page.files.length, 2);
    assertEquals(page.pages, 2);
    assertFalse(page.truncated);
    // Both halves of the versions cursor must carry forward — sending only
    // startFileName would re-read the first version of "b" forever.
    const second = bodyOf(calls[2]);
    assertEquals(second.startFileName, "b");
    assertEquals(second.startFileId, "id-b");
  } finally {
    restore();
  }
});

Deno.test("listFilePages sets truncated when it exhausts maxPages", async () => {
  const { restore } = installFetch(
    router({
      b2_list_file_versions: {
        files: [fileBody()],
        nextFileName: "next",
        nextFileId: "next-id",
      },
    }),
  );
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    const page = await _internal.listFilePages(
      auth,
      "b2_list_file_versions",
      { bucketId: BUCKET_ID },
      3,
    );
    assert(page.truncated, "hitting the page cap must be reported");
    assertEquals(page.pages, 3);
  } finally {
    restore();
  }
});

Deno.test("listFilePages stops early on the item budget and reports it as truncated", async () => {
  const { restore } = installFetch(
    router({
      b2_list_file_versions: {
        files: [fileBody(), fileBody({ fileId: "second" })],
        nextFileName: "next",
        nextFileId: "next-id",
      },
    }),
  );
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    const page = await _internal.listFilePages(
      auth,
      "b2_list_file_versions",
      { bucketId: BUCKET_ID },
      50,
      2,
    );
    assertEquals(page.pages, 1, "the item budget must stop paging immediately");
    assert(page.truncated, "stopping with a live cursor is truncation");
  } finally {
    restore();
  }
});

Deno.test("listFilePages bills one class-C transaction per 1000 files returned", async () => {
  const many = Array.from(
    { length: 2500 },
    (_, i) => fileBody({ fileId: `id-${i}`, fileName: `data/${i}` }),
  );
  const { restore } = installFetch(
    router({ b2_list_file_versions: { files: many } }),
  );
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    const page = await _internal.listFilePages(
      auth,
      "b2_list_file_versions",
      { bucketId: BUCKET_ID },
      10,
    );
    assertEquals(
      page.classCTransactions,
      3,
      "2500 files is three billed units",
    );
  } finally {
    restore();
  }
});

Deno.test("b2Fetch re-authorizes exactly once on an expired token", async () => {
  let authorizeCount = 0;
  const { calls, restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") {
      authorizeCount++;
      return json(authBody());
    }
    return calls.filter((c) => c.op === "b2_get_file_info").length === 1
      ? json({ code: "expired_auth_token" }, 401)
      : json(fileBody());
  });
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    authorizeCount = 0;
    const file = await b2Fetch<Record<string, unknown>>(
      auth,
      "POST",
      "b2_get_file_info",
      { fileId: "x" },
      () =>
        b2Authorize({
          applicationKeyId: "id",
          applicationKey: APPLICATION_KEY,
        }),
    );
    assertEquals(file.fileId, "4_zexamplefileid0000000001");
    assertEquals(authorizeCount, 1, "exactly one re-authorization");
  } finally {
    restore();
  }
});

Deno.test("b2Fetch retries a 429 honoring Retry-After, then succeeds", async () => {
  let attempts = 0;
  const { restore } = installFetch((req) => {
    if (req.op === "b2_authorize_account") return json(authBody());
    attempts++;
    return attempts === 1
      ? json({ code: "too_many_requests" }, 429, { "retry-after": "0" })
      : json(fileBody());
  });
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    const file = await b2Fetch<Record<string, unknown>>(
      auth,
      "POST",
      "b2_get_file_info",
      { fileId: "x" },
    );
    assertEquals(attempts, 2);
    assertEquals(file.action, "upload");
  } finally {
    restore();
  }
});

Deno.test("b2Fetch throws a non-transient 400 with status and b2Code populated", async () => {
  const { restore } = installFetch((req) =>
    req.op === "b2_authorize_account"
      ? json(authBody())
      : json({ code: "bad_request", message: "nope" }, 400)
  );
  try {
    const auth = await b2Authorize({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    });
    const err = await assertRejects(
      () => b2Fetch(auth, "POST", "b2_get_file_info", { fileId: "x" }),
      Error,
      "bad_request",
    ) as Error & { status: number; b2Code: string };
    assertEquals(err.status, 400);
    assertEquals(err.b2Code, "bad_request");
  } finally {
    restore();
  }
});

// ===========================================================================
// The current-versus-non-current fold — the arithmetic this model exists for
// ===========================================================================

Deno.test("tallyFiles: newest upload is current, older uploads are not", () => {
  const { total } = _internal.tallyFiles([
    { fileName: "a", action: "upload", contentLength: 100 },
    { fileName: "a", action: "upload", contentLength: 90 },
    { fileName: "a", action: "upload", contentLength: 80 },
  ], "none");
  assertEquals(total.currentFileCount, 1);
  assertEquals(total.currentBytes, 100);
  assertEquals(total.nonCurrentFileCount, 2);
  assertEquals(total.nonCurrentBytes, 170);
});

Deno.test("tallyFiles: a hide marker at the head makes EVERY upload below it non-current", () => {
  // This is the case that costs money: restic pruned the pack file, B2 wrote a
  // hide marker, and the bytes underneath are still stored and still billed.
  const { total, current } = _internal.tallyFiles([
    { fileName: "a", action: "hide", contentLength: 0 },
    { fileName: "a", action: "upload", contentLength: 100 },
    { fileName: "a", action: "upload", contentLength: 90 },
  ], "none");
  assertEquals(
    total.currentFileCount,
    0,
    "a hidden file has no current version",
  );
  assertEquals(total.currentBytes, 0);
  assertEquals(total.nonCurrentFileCount, 2);
  assertEquals(total.nonCurrentBytes, 190);
  assertEquals(total.hideMarkerCount, 1);
  assertEquals(current, [false, false, false]);
});

Deno.test("tallyFiles: a hide marker BELOW a newer upload is history, not a deletion", () => {
  const { total } = _internal.tallyFiles([
    { fileName: "a", action: "upload", contentLength: 100 },
    { fileName: "a", action: "hide", contentLength: 0 },
    { fileName: "a", action: "upload", contentLength: 90 },
  ], "none");
  assertEquals(total.currentFileCount, 1, "the newest upload is still current");
  assertEquals(total.currentBytes, 100);
  assertEquals(total.nonCurrentBytes, 90);
});

Deno.test("tallyFiles: an unfinished large upload does not shadow the current version", () => {
  const { total, current } = _internal.tallyFiles([
    { fileName: "a", action: "start", contentLength: 0 },
    { fileName: "a", action: "upload", contentLength: 100 },
  ], "none");
  assertEquals(total.unfinishedCount, 1);
  assertEquals(
    total.currentFileCount,
    1,
    "the upload beneath is still readable",
  );
  assertEquals(total.currentBytes, 100);
  assertEquals(current, [false, true]);
});

Deno.test("tallyFiles: each file name is judged independently", () => {
  const { total } = _internal.tallyFiles([
    { fileName: "a", action: "upload", contentLength: 10 },
    { fileName: "a", action: "upload", contentLength: 5 },
    { fileName: "b", action: "hide", contentLength: 0 },
    { fileName: "b", action: "upload", contentLength: 7 },
    { fileName: "c", action: "upload", contentLength: 3 },
  ], "none");
  assertEquals(total.currentFileCount, 2, "a and c; b is hidden");
  assertEquals(total.currentBytes, 13);
  assertEquals(total.nonCurrentFileCount, 2);
  assertEquals(total.nonCurrentBytes, 12);
  assertEquals(total.fileCount, 5);
});

Deno.test("tallyFiles: a synthetic folder entry contributes no bytes", () => {
  const { total } = _internal.tallyFiles([
    { fileName: "data/", action: "folder", contentLength: 0 },
    { fileName: "data/x", action: "upload", contentLength: 42 },
  ], "none");
  assertEquals(total.currentBytes, 42);
  assertEquals(total.currentFileCount, 1);
  assertEquals(total.fileCount, 2);
});

Deno.test("tallyFiles: groupBy topLevel splits by first path segment and totals still agree", () => {
  const { groups, total } = _internal.tallyFiles([
    { fileName: "data/00/p1", action: "upload", contentLength: 100 },
    { fileName: "data/01/p2", action: "upload", contentLength: 200 },
    { fileName: "index/i1", action: "upload", contentLength: 10 },
    { fileName: "config", action: "upload", contentLength: 1 },
  ], "topLevel");
  assertEquals(groups.get("data/")?.currentBytes, 300);
  assertEquals(groups.get("index/")?.currentBytes, 10);
  assertEquals(groups.get("")?.currentBytes, 1, "root files group under ''");
  assertEquals(total.currentBytes, 311, "groups must sum to the total");
});

Deno.test("groupFor derives the top-level segment including its slash", () => {
  assertEquals(_internal.groupFor("data/00/pack", "topLevel"), "data/");
  assertEquals(_internal.groupFor("config", "topLevel"), "");
  assertEquals(_internal.groupFor("data/00/pack", "none"), null);
});

// ===========================================================================
// The honest-null contract
// ===========================================================================

Deno.test("aggregate: listing by name reports non-current metrics as null, never zero", () => {
  // Reporting 0 here would be indistinguishable from a bucket with no debt,
  // which is exactly how `unprunedPrefixes: []` shipped as a bug once already.
  const tally = _internal.newTally();
  tally.currentFileCount = 3;
  tally.currentBytes = 300;
  const data = _internal.toAggregateResource(tally, {
    bucketName: BUCKET_NAME,
    bucketId: BUCKET_ID,
    prefix: "",
    group: null,
    scanMode: "aggregate",
    listing: "names",
    truncated: false,
    pagesFetched: 1,
    classCTransactions: 1,
    observedAt: new Date().toISOString(),
  });
  assertEquals(data.nonCurrentFileCount, null);
  assertEquals(data.nonCurrentBytes, null);
  assertEquals(data.hideMarkerCount, null);
  assertEquals(data.unfinishedCount, null);
  assertEquals(
    data.totalBytes,
    null,
    "a total that silently omits non-current bytes understates the bill",
  );
  assertEquals(
    data.currentBytes,
    300,
    "current data IS measured by name listing",
  );
});

Deno.test("aggregate: listing by version reports real numbers including a zero", () => {
  const tally = _internal.newTally();
  tally.currentFileCount = 3;
  tally.currentBytes = 300;
  const data = _internal.toAggregateResource(tally, {
    bucketName: BUCKET_NAME,
    bucketId: BUCKET_ID,
    prefix: "",
    group: null,
    scanMode: "aggregate",
    listing: "versions",
    truncated: false,
    pagesFetched: 1,
    classCTransactions: 1,
    observedAt: new Date().toISOString(),
  });
  assertEquals(data.nonCurrentBytes, 0, "measured and genuinely zero");
  assertEquals(data.totalBytes, 300);
});

// ===========================================================================
// Authorization wrappers — "cannot see" is not "off"
// ===========================================================================

Deno.test("unwrapAuthorized distinguishes absent, unreadable, and readable", () => {
  assertEquals(_internal.unwrapAuthorized(undefined), {
    authorized: null,
    value: null,
  });
  assertEquals(
    _internal.unwrapAuthorized({
      isClientAuthorizedToRead: false,
      value: null,
    }),
    { authorized: false, value: null },
  );
  assertEquals(
    _internal.unwrapAuthorized({ isClientAuthorizedToRead: true, value: "on" }),
    { authorized: true, value: "on" },
  );
});

Deno.test("tallyFiles counts an unreadable legal hold separately from an off one", () => {
  const { total } = _internal.tallyFiles([
    {
      fileName: "a",
      action: "upload",
      contentLength: 1,
      legalHold: { isClientAuthorizedToRead: false, value: null },
    },
    {
      fileName: "b",
      action: "upload",
      contentLength: 1,
      legalHold: { isClientAuthorizedToRead: true, value: "off" },
    },
    {
      fileName: "c",
      action: "upload",
      contentLength: 1,
      legalHold: { isClientAuthorizedToRead: true, value: "on" },
    },
  ], "none");
  assertEquals(total.legalHoldOnCount, 1);
  assertEquals(
    total.legalHoldUnreadableCount,
    1,
    "an unreadable hold must never be silently counted as off",
  );
});

Deno.test("tallyFiles counts an unreadable retention separately from an unset one", () => {
  const { total } = _internal.tallyFiles([
    {
      fileName: "a",
      action: "upload",
      contentLength: 1,
      fileRetention: { isClientAuthorizedToRead: false, value: null },
    },
    {
      fileName: "b",
      action: "upload",
      contentLength: 1,
      fileRetention: { isClientAuthorizedToRead: true, value: { mode: null } },
    },
    {
      fileName: "c",
      action: "upload",
      contentLength: 1,
      fileRetention: {
        isClientAuthorizedToRead: true,
        value: { mode: "compliance", retainUntilTimestamp: 1893456000000 },
      },
    },
  ], "none");
  assertEquals(total.retentionSetCount, 1);
  assertEquals(total.retentionUnreadableCount, 1);
});

Deno.test("tallyFiles counts versions B2 reported no lock fields for at all", () => {
  // Verified against live B2 2026-08-05: a list response over a bucket WITHOUT
  // Object Lock omits legalHold and fileRetention entirely. Without this
  // counter, legalHoldOnCount: 0 reads as "nothing is locked" when the truth is
  // "nothing was reported" — the same ambiguity that made `unprunedPrefixes:
  // []` a bug. The mock fixtures were richer than reality and hid it.
  const { total } = _internal.tallyFiles([
    { fileName: "a", action: "upload", contentLength: 1 },
    { fileName: "b", action: "upload", contentLength: 1 },
    {
      fileName: "c",
      action: "upload",
      contentLength: 1,
      legalHold: { isClientAuthorizedToRead: true, value: "on" },
      fileRetention: { isClientAuthorizedToRead: true, value: { mode: null } },
    },
  ], "none");
  assertEquals(total.lockFieldsAbsentCount, 2);
  assertEquals(total.legalHoldOnCount, 1);
  assertEquals(
    total.legalHoldUnreadableCount,
    0,
    "absent is not the same fact as unreadable",
  );
});

Deno.test("toFileResource keeps the authorization flag beside the value", () => {
  const data = _internal.toFileResource(
    BUCKET_NAME,
    BUCKET_ID,
    fileBody({
      legalHold: { isClientAuthorizedToRead: false, value: null },
      fileRetention: { isClientAuthorizedToRead: false, value: null },
    }),
    new Date().toISOString(),
  );
  assertEquals(data.legalHoldAuthorized, false);
  assertEquals(data.legalHold, null);
  assertEquals(data.retentionAuthorized, false);
  assertEquals(data.retentionMode, null);
});

Deno.test("toFileResource renders timestamps as ISO alongside the raw epoch", () => {
  const data = _internal.toFileResource(
    BUCKET_NAME,
    BUCKET_ID,
    fileBody({
      uploadTimestamp: 1754000000000,
      fileRetention: {
        isClientAuthorizedToRead: true,
        value: { mode: "governance", retainUntilTimestamp: 1893456000000 },
      },
    }),
    new Date().toISOString(),
  );
  assertEquals(data.uploadTimestamp, 1754000000000);
  assertEquals(data.uploadedAt, new Date(1754000000000).toISOString());
  assertEquals(data.retentionMode, "governance");
  assertEquals(data.retainUntil, new Date(1893456000000).toISOString());
});

Deno.test("toFileResource produces a schema-valid tombstone for a missing file", () => {
  const data = _internal.toFileResource(
    BUCKET_NAME,
    BUCKET_ID,
    null,
    new Date().toISOString(),
    { fileName: "data/gone" },
  );
  assertEquals(data.exists, false);
  assertEquals(data.fileId, null);
  assertEquals(data.fileName, "data/gone");
  assert(
    _internal.FileResourceSchema.safeParse(data).success,
    "a tombstone must satisfy the file spec schema",
  );
});

// ===========================================================================
// Instance naming
// ===========================================================================

Deno.test("aggregate instance names are spec-prefixed and distinguish total from group", () => {
  const total = _internal.aggregateInstanceName(BUCKET_NAME, null);
  const root = _internal.aggregateInstanceName(BUCKET_NAME, "");
  assert(total.startsWith("aggregate-"));
  assert(root.startsWith("aggregate-"));
  assert(
    total !== root,
    "the bucket total must not collide with the root-prefix group",
  );
});

Deno.test("aggregate instance names are stable across runs and unique per prefix", () => {
  assertEquals(
    _internal.aggregateInstanceName(BUCKET_NAME, "data/"),
    _internal.aggregateInstanceName(BUCKET_NAME, "data/"),
  );
  // Both sanitize to the same readable fragment; only the hash separates them.
  assert(
    _internal.aggregateInstanceName(BUCKET_NAME, "data/") !==
      _internal.aggregateInstanceName(BUCKET_NAME, "data_"),
    "prefixes that sanitize alike must still get distinct instances",
  );
});

Deno.test("file instance names key on fileId, and fall back without one", () => {
  assertEquals(
    _internal.fileInstanceName(BUCKET_NAME, "4_zabc", "data/x"),
    "file-4_zabc",
  );
  const absent = _internal.fileInstanceName(BUCKET_NAME, null, "data/x");
  assert(absent.startsWith("file-absent-"));
  assertEquals(
    absent,
    _internal.fileInstanceName(BUCKET_NAME, null, "data/x"),
    "the absent name must be stable across runs",
  );
});

Deno.test("no instance name this model builds is the reserved literal 'latest'", () => {
  for (const group of [null, "", "latest", "data/"]) {
    assert(_internal.aggregateInstanceName("latest", group) !== "latest");
  }
  assert(_internal.fileInstanceName("latest", "latest", "latest") !== "latest");
  assert(_internal.fileInstanceName("latest", null, "latest") !== "latest");
});

// ===========================================================================
// scan
// ===========================================================================

Deno.test("scan writes one aggregate per bucket across the whole account by default", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: bucketsBody(),
      b2_list_file_versions: {
        files: [
          fileBody({ fileName: "data/a", fileId: "1", contentLength: 100 }),
          fileBody({
            fileName: "data/a",
            fileId: "2",
            contentLength: 40,
            action: "hide",
          }),
        ],
      },
    }),
  );
  try {
    // bucketName unset — the fleet-audit path.
    const { context, written, logs } = makeContext({ bucketName: undefined });
    await model.methods.scan.execute({}, context);
    const aggregates = written.filter((w) => w.spec === "aggregate");
    assertEquals(aggregates.length, 2, "one aggregate per discovered bucket");
    assertEquals(
      aggregates.map((a) => a.data.bucketName).sort(),
      [OTHER_BUCKET_NAME, BUCKET_NAME].sort(),
    );
    assertEquals(written.filter((w) => w.spec === "file").length, 0);
    assertNoSecrets(written, "scan output");
    assertNoSecrets(logs, "scan logs");
  } finally {
    restore();
  }
});

Deno.test("scan sizes the hidden-version debt and warns about it", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_versions: {
        files: [
          // "data/a" was pruned by restic: a hide marker on top of 300 bytes
          // that B2 still stores and still bills.
          fileBody({
            fileName: "data/a",
            fileId: "h",
            action: "hide",
            contentLength: 0,
          }),
          fileBody({ fileName: "data/a", fileId: "1", contentLength: 200 }),
          fileBody({ fileName: "data/a", fileId: "2", contentLength: 100 }),
          fileBody({ fileName: "data/b", fileId: "3", contentLength: 50 }),
        ],
      },
    }),
  );
  try {
    const { context, written, logs } = makeContext();
    await model.methods.scan.execute({}, context);
    const data = totalAggregate(written);
    assertEquals(data.currentFileCount, 1);
    assertEquals(data.currentBytes, 50);
    assertEquals(data.nonCurrentFileCount, 2);
    assertEquals(data.nonCurrentBytes, 300);
    assertEquals(data.totalBytes, 350);
    assertEquals(data.hideMarkerCount, 1);
    assertFalse(data.truncated as boolean);
    assert(
      logs.some((l) => l.includes("WARN") && l.includes("non-current")),
      "a bucket carrying non-current bytes must say so loudly",
    );
  } finally {
    restore();
  }
});

Deno.test("scan with groupBy topLevel writes a total plus one aggregate per group", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_versions: {
        files: [
          fileBody({ fileName: "data/a", fileId: "1", contentLength: 100 }),
          fileBody({ fileName: "index/i", fileId: "2", contentLength: 10 }),
        ],
      },
    }),
  );
  try {
    const { context, written } = makeContext();
    await model.methods.scan.execute({ groupBy: "topLevel" }, context);
    const aggregates = written.filter((w) => w.spec === "aggregate");
    assertEquals(aggregates.length, 3, "total plus data/ plus index/");
    const groups = aggregates.map((a) => a.data.group);
    assert(
      groups.includes(null) && groups.includes("data/") &&
        groups.includes("index/"),
    );
    // Distinct instances, or the second group silently clobbers the first.
    assertEquals(new Set(aggregates.map((a) => a.name)).size, 3);
  } finally {
    restore();
  }
});

Deno.test("scan by name listing reports non-current metrics as null end to end", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_names: {
        files: [
          fileBody({ fileName: "data/a", fileId: "1", contentLength: 100 }),
        ],
      },
    }),
  );
  try {
    const { context, written } = makeContext();
    await model.methods.scan.execute({ includeVersions: false }, context);
    const data = totalAggregate(written);
    assertEquals(data.listing, "names");
    assertEquals(data.nonCurrentBytes, null);
    assertEquals(data.totalBytes, null);
    assertEquals(data.currentBytes, 100);
    assert(
      calls.some((c) => c.op === "b2_list_file_names"),
      "includeVersions false must use the names endpoint",
    );
  } finally {
    restore();
  }
});

Deno.test("scan reports a page-capped bucket as truncated and says the counts are a floor", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_versions: {
        files: [fileBody({ contentLength: 10 })],
        nextFileName: "more",
        nextFileId: "more-id",
      },
    }),
  );
  try {
    const { context, written, logs } = makeContext();
    await model.methods.scan.execute({ maxPages: 2 }, context);
    const data = totalAggregate(written);
    assert(data.truncated, "a partial inventory must never look complete");
    assertEquals(data.pagesFetched, 2);
    assert(logs.some((l) => l.includes("WARN") && l.includes("FLOOR")));
  } finally {
    restore();
  }
});

Deno.test("scan writes a truncated aggregate for a bucket it was asked for but cannot see", async () => {
  const { restore } = installFetch(
    router({ b2_list_buckets: { buckets: [] } }),
  );
  try {
    const { context, written, logs } = makeContext({ bucketName: undefined });
    await model.methods.scan.execute(
      { bucketNames: ["ghost-bucket"] },
      context,
    );
    const data = totalAggregate(written);
    assertEquals(data.bucketName, "ghost-bucket");
    assertEquals(data.bucketId, null);
    assert(
      data.truncated,
      "nothing was listed, so zero files is not a fact this run established",
    );
    assert(logs.some((l) => l.includes("WARN") && l.includes("not found")));
  } finally {
    restore();
  }
});

Deno.test("scan detailed refuses to run without a prefix", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext();
    await assertRejects(
      () =>
        model.methods.scan.execute({ mode: "detailed", maxFiles: 10 }, context),
      Error,
      "requires an explicit prefix",
    );
  } finally {
    restore();
  }
});

Deno.test("scan detailed refuses to run without maxFiles", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext();
    await assertRejects(
      () =>
        model.methods.scan.execute(
          { mode: "detailed", prefix: "snapshots/" },
          context,
        ),
      Error,
      "requires maxFiles",
    );
  } finally {
    restore();
  }
});

Deno.test("scan detailed emits per-file resources up to maxFiles and records the count", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_versions: {
        files: [
          fileBody({ fileName: "snapshots/a", fileId: "1", contentLength: 10 }),
          fileBody({ fileName: "snapshots/b", fileId: "2", contentLength: 20 }),
          fileBody({ fileName: "snapshots/c", fileId: "3", contentLength: 30 }),
        ],
      },
    }),
  );
  try {
    const { context, written } = makeContext();
    await model.methods.scan.execute(
      { mode: "detailed", prefix: "snapshots/", maxFiles: 2 },
      context,
    );
    const files = written.filter((w) => w.spec === "file");
    assertEquals(files.length, 2, "maxFiles caps what is written");
    assertEquals(files.map((f) => f.name), ["file-1", "file-2"]);
    assertEquals(files[0].data.isCurrentVersion, true);
    const data = totalAggregate(written);
    assertEquals(data.emittedFileCount, 2);
    assertEquals(
      data.fileCount,
      3,
      "the aggregate still counts everything paid for",
    );
    // The prefix must reach B2 as a server-side filter, not be applied locally.
    const listCall = calls.find((c) => c.op === "b2_list_file_versions");
    assertEquals(bodyOf(listCall!).prefix, "snapshots/");
  } finally {
    restore();
  }
});

Deno.test("scan detailed marks a hidden version's uploads as not current", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_versions: {
        files: [
          fileBody({
            fileName: "data/a",
            fileId: "h",
            action: "hide",
            contentLength: 0,
          }),
          fileBody({ fileName: "data/a", fileId: "1", contentLength: 200 }),
        ],
      },
    }),
  );
  try {
    const { context, written } = makeContext();
    await model.methods.scan.execute(
      { mode: "detailed", prefix: "data/", maxFiles: 10 },
      context,
    );
    const files = written.filter((w) => w.spec === "file");
    assertEquals(files.length, 2);
    assertEquals(files[0].data.action, "hide");
    assertEquals(
      files[1].data.isCurrentVersion,
      false,
      "it is hidden, not current",
    );
  } finally {
    restore();
  }
});

Deno.test("scan skips b2_list_buckets when a single bucket is fully pinned", async () => {
  const { calls, restore } = installFetch(
    router({ b2_list_file_versions: { files: [] } }),
  );
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.scan.execute({}, context);
    assertFalse(
      calls.some((c) => c.op === "b2_list_buckets"),
      "pinning bucketName+bucketId must save the class-C lookup",
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// sync
// ===========================================================================

Deno.test("sync by fileId reports isCurrentVersion as null, because it cannot tell", async () => {
  const { restore } = installFetch(
    router({ b2_get_file_info: fileBody() }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.sync.execute(
      { fileId: "4_zexamplefileid0000000001" },
      context,
    );
    assertEquals(written.length, 1);
    assertEquals(written[0].data.exists, true);
    assertEquals(
      written[0].data.isCurrentVersion,
      null,
      "one version fetched without its siblings cannot be judged current",
    );
    assertNoSecrets(written, "sync output");
  } finally {
    restore();
  }
});

Deno.test("sync by name returns a hide marker rather than pretending the file is absent", async () => {
  const { restore } = installFetch(
    router({
      b2_list_file_versions: {
        files: [
          fileBody({ action: "hide", contentLength: 0, fileId: "marker" }),
        ],
      },
    }),
  );
  try {
    const { context, written, logs } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.sync.execute(
      { fileName: "data/00/pack-0001" },
      context,
    );
    assertEquals(written[0].data.action, "hide");
    assertEquals(written[0].data.exists, true, "the marker itself exists");
    assertEquals(
      written[0].data.isCurrentVersion,
      false,
      "a hide marker is not a readable version",
    );
    assert(logs.some((l) => l.includes("WARN") && l.includes("not readable")));
  } finally {
    restore();
  }
});

Deno.test("sync writes a tombstone when no version of the name exists", async () => {
  const { restore } = installFetch(
    router({ b2_list_file_versions: { files: [] } }),
  );
  try {
    const { context, written, logs } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.sync.execute({ fileName: "data/missing" }, context);
    assertEquals(written[0].data.exists, false);
    assert(written[0].name.startsWith("file-absent-"));
    assert(logs.some((l) => l.includes("WARN")));
  } finally {
    restore();
  }
});

Deno.test("sync ignores a prefix match that is not the exact file name", async () => {
  const { restore } = installFetch(
    router({
      // Asked for "data/a"; B2's prefix filter also matches "data/ab".
      b2_list_file_versions: { files: [fileBody({ fileName: "data/ab" })] },
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.sync.execute({ fileName: "data/a" }, context);
    assertEquals(
      written[0].data.exists,
      false,
      "a longer name sharing the prefix is a different file",
    );
  } finally {
    restore();
  }
});

Deno.test("sync needs a fileId or a fileName", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () => model.methods.sync.execute({}, context),
      Error,
      "needs a fileId or a fileName",
    );
  } finally {
    restore();
  }
});

Deno.test("sync by fileId never spends a b2_list_buckets call", async () => {
  // b2_get_file_info is addressed by fileId alone. Resolving a bucket ID here
  // would cost a class-C transaction and lock out a bucket-restricted key that
  // holds readFiles but not listBuckets — the shape of every per-host restic
  // key this suite manages.
  const { calls, restore } = installFetch(
    router({ b2_get_file_info: fileBody() }),
  );
  try {
    // bucketId deliberately NOT pinned.
    const { context, written } = makeContext();
    await model.methods.sync.execute({ fileId: "4_zabc" }, context);
    assertFalse(calls.some((c) => c.op === "b2_list_buckets"));
    assertEquals(written[0].data.bucketName, BUCKET_NAME);
    assertEquals(
      written[0].data.bucketId,
      BUCKET_ID,
      "the bucket ID comes free in the file payload",
    );
  } finally {
    restore();
  }
});

Deno.test("delete by fileId never spends a b2_list_buckets call", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_get_file_info: fileBody(),
      b2_delete_file_version: { fileId: "4_zabc" },
    }),
  );
  try {
    const { context } = makeContext({ allowFileDestruction: true });
    await model.methods.delete.execute({ fileId: "4_zabc" }, context);
    assertFalse(calls.some((c) => c.op === "b2_list_buckets"));
  } finally {
    restore();
  }
});

Deno.test("update by fileId never spends a b2_list_buckets call", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_update_file_legal_hold: { fileId: "4_zabc" },
      b2_get_file_info: fileBody(),
    }),
  );
  try {
    const { context } = makeContext();
    await model.methods.update.execute(
      { fileId: "4_zabc", fileName: "data/00/pack-0001", legalHold: "on" },
      context,
    );
    assertFalse(calls.some((c) => c.op === "b2_list_buckets"));
  } finally {
    restore();
  }
});

Deno.test("sync by NAME does resolve the bucket, because the listing needs its ID", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_list_buckets: bucketsBody(),
      b2_list_file_versions: { files: [fileBody()] },
    }),
  );
  try {
    const { context } = makeContext();
    await model.methods.sync.execute(
      { fileName: "data/00/pack-0001" },
      context,
    );
    assert(calls.some((c) => c.op === "b2_list_buckets"));
  } finally {
    restore();
  }
});

Deno.test("update warns when bypassGovernance cannot apply to the requested change", async () => {
  // Accepting the flag and quietly dropping it would let a caller believe a
  // governance lock had been overridden when nothing of the sort was attempted.
  const { restore } = installFetch(
    router({
      b2_update_file_legal_hold: { fileId: "4_zabc" },
      b2_get_file_info: fileBody(),
    }),
  );
  try {
    const { context, logs } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.update.execute(
      {
        fileId: "4_zabc",
        fileName: "data/00/pack-0001",
        legalHold: "on",
        bypassGovernance: true,
      },
      context,
    );
    assert(
      logs.some((l) => l.includes("WARN") && l.includes("bypassGovernance")),
      "a silently ignored input is how an operator ends up believing a lock was bypassed",
    );
  } finally {
    restore();
  }
});

Deno.test("file methods refuse to guess a bucket when bucketName is unset", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketName: undefined });
    await assertRejects(
      () => model.methods.sync.execute({ fileId: "x" }, context),
      Error,
      "globalArgs.bucketName is not set",
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// delete — the destruction gate and idempotency
// ===========================================================================

Deno.test("delete refuses without an acknowledgement, before making any B2 call", async () => {
  const { calls, restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () => model.methods.delete.execute({ fileId: "4_zabc" }, context),
      Error,
      "allowFileDestruction",
    );
    assertEquals(calls.length, 0, "the gate must fire before authorizing");
  } finally {
    restore();
  }
});

Deno.test("delete proceeds when the acknowledgement arrives as a method input", async () => {
  // This is the path a pre-flight check structurally cannot see, which is why
  // the guard lives in execute rather than only in the check.
  const { calls, restore } = installFetch(
    router({
      b2_get_file_info: fileBody(),
      b2_delete_file_version: {
        fileId: "4_zabc",
        fileName: "data/00/pack-0001",
      },
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.delete.execute(
      { fileId: "4_zabc", allowFileDestruction: true },
      context,
    );
    assert(calls.some((c) => c.op === "b2_delete_file_version"));
    assertEquals(written[0].data.exists, false, "delete writes a tombstone");
  } finally {
    restore();
  }
});

Deno.test("delete proceeds when the acknowledgement is a global argument", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_get_file_info: fileBody(),
      b2_delete_file_version: { fileId: "4_zabc" },
    }),
  );
  try {
    const { context } = makeContext({
      bucketId: BUCKET_ID,
      allowFileDestruction: true,
    });
    await model.methods.delete.execute({ fileId: "4_zabc" }, context);
    assert(calls.some((c) => c.op === "b2_delete_file_version"));
  } finally {
    restore();
  }
});

Deno.test("delete sends both fileName and fileId, resolving whichever half is missing", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_get_file_info: fileBody({ fileName: "data/00/pack-0001" }),
      b2_delete_file_version: { fileId: "4_zabc" },
    }),
  );
  try {
    const { context } = makeContext({
      bucketId: BUCKET_ID,
      allowFileDestruction: true,
    });
    await model.methods.delete.execute({ fileId: "4_zabc" }, context);
    const del = bodyOf(calls.find((c) => c.op === "b2_delete_file_version")!);
    assertEquals(del.fileId, "4_zabc");
    assertEquals(
      del.fileName,
      "data/00/pack-0001",
      "b2_delete_file_version requires both halves",
    );
  } finally {
    restore();
  }
});

Deno.test("delete treats a 404 as an idempotent success", async () => {
  const { restore } = installFetch(
    router({
      b2_get_file_info: fileBody(),
      b2_delete_file_version: json({ code: "not_found" }, 404),
    }),
  );
  try {
    const { context, written } = makeContext({
      bucketId: BUCKET_ID,
      allowFileDestruction: true,
    });
    await model.methods.delete.execute({ fileId: "4_zabc" }, context);
    assertEquals(written[0].data.exists, false);
  } finally {
    restore();
  }
});

Deno.test("delete treats a 400 file_not_present as an idempotent success", async () => {
  const { restore } = installFetch(
    router({
      b2_get_file_info: fileBody(),
      b2_delete_file_version: json({ code: "file_not_present" }, 400),
    }),
  );
  try {
    const { context, written } = makeContext({
      bucketId: BUCKET_ID,
      allowFileDestruction: true,
    });
    await model.methods.delete.execute({ fileId: "4_zabc" }, context);
    assertEquals(written[0].data.exists, false);
  } finally {
    restore();
  }
});

Deno.test("delete does NOT swallow a bad_bucket_id, which is a configuration bug", () => {
  // Swallowing this would report a successful delete of a file still sitting in
  // the bucket the caller actually meant.
  assertFalse(
    _internal.isAlreadyGone({ status: 400, b2Code: "bad_bucket_id" }),
  );
  assert(_internal.isAlreadyGone({ status: 404 }));
  assert(_internal.isAlreadyGone({ status: 400, b2Code: "no_such_file" }));
  assertFalse(_internal.isAlreadyGone({ status: 400, b2Code: "bad_request" }));
});

Deno.test("delete by name that resolves to nothing skips the call and still tombstones", async () => {
  const { calls, restore } = installFetch(
    router({ b2_list_file_versions: { files: [] } }),
  );
  try {
    const { context, written, logs } = makeContext({
      bucketId: BUCKET_ID,
      allowFileDestruction: true,
    });
    await model.methods.delete.execute({ fileName: "data/gone" }, context);
    assertFalse(calls.some((c) => c.op === "b2_delete_file_version"));
    assertEquals(written[0].data.exists, false);
    assert(logs.some((l) => l.includes("treating delete as successful")));
  } finally {
    restore();
  }
});

Deno.test("delete forwards bypassGovernance only when asked", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_get_file_info: fileBody(),
      b2_delete_file_version: { fileId: "4_zabc" },
    }),
  );
  try {
    const { context } = makeContext({
      bucketId: BUCKET_ID,
      allowFileDestruction: true,
    });
    await model.methods.delete.execute({ fileId: "4_zabc" }, context);
    assertEquals(
      bodyOf(calls.find((c) => c.op === "b2_delete_file_version")!)
        .bypassGovernance,
      undefined,
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// hide
// ===========================================================================

Deno.test("hide refuses without an acknowledgement", async () => {
  const { calls, restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () => model.methods.hide.execute({ fileName: "data/a" }, context),
      Error,
      "allowFileDestruction",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("hide writes the marker as the current version and warns about retained bytes", async () => {
  const { restore } = installFetch(
    router({
      b2_hide_file: fileBody({
        action: "hide",
        contentLength: 0,
        fileId: "4_zmarker",
        fileName: "data/a",
      }),
    }),
  );
  try {
    const { context, written, logs } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.hide.execute(
      { fileName: "data/a", allowFileDestruction: true },
      context,
    );
    assertEquals(written[0].name, "file-4_zmarker");
    assertEquals(written[0].data.action, "hide");
    assertEquals(written[0].data.isCurrentVersion, true);
    assert(
      logs.some((l) =>
        l.includes("WARN") && l.includes("still stored and billed")
      ),
      "hiding does not reclaim the storage, and must not read as if it does",
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// copy
// ===========================================================================

Deno.test("copy defaults the destination to this model's bucket", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_copy_file: fileBody({ fileId: "4_zcopy", fileName: "data/copy" }),
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.copy.execute(
      { sourceFileId: "4_zsrc", fileName: "data/copy" },
      context,
    );
    assertEquals(
      bodyOf(calls.find((c) => c.op === "b2_copy_file")!).destinationBucketId,
      BUCKET_ID,
    );
    assertEquals(written[0].data.bucketName, BUCKET_NAME);
    assertEquals(written[0].data.isCurrentVersion, true);
  } finally {
    restore();
  }
});

Deno.test("copy records the destination bucket's NAME, not its ID, in bucketName", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: bucketsBody(),
      b2_copy_file: fileBody({
        fileId: "4_zcopy",
        fileName: "data/copy",
        bucketId: OTHER_BUCKET_ID,
      }),
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.copy.execute(
      {
        sourceFileId: "4_zsrc",
        fileName: "data/copy",
        destinationBucketId: OTHER_BUCKET_ID,
      },
      context,
    );
    assertEquals(
      written[0].data.bucketName,
      OTHER_BUCKET_NAME,
      "a bucket ID wearing the bucketName field would corrupt any join on it",
    );
  } finally {
    restore();
  }
});

Deno.test("copy refuses an unresolvable destination BEFORE copying anything", async () => {
  const { calls, restore } = installFetch(
    router({ b2_list_buckets: bucketsBody(), b2_copy_file: fileBody() }),
  );
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () =>
        model.methods.copy.execute(
          {
            sourceFileId: "4_zsrc",
            fileName: "data/copy",
            destinationBucketId: "unknown-bucket-id",
          },
          context,
        ),
      Error,
      "does not match any bucket",
    );
    assertFalse(
      calls.some((c) => c.op === "b2_copy_file"),
      "a naming failure must not strand a completed copy behind a failed method",
    );
  } finally {
    restore();
  }
});

Deno.test("copy uses a supplied destinationBucketName without a lookup", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_copy_file: fileBody({ fileId: "4_zcopy", fileName: "data/copy" }),
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.copy.execute(
      {
        sourceFileId: "4_zsrc",
        fileName: "data/copy",
        destinationBucketId: OTHER_BUCKET_ID,
        destinationBucketName: OTHER_BUCKET_NAME,
      },
      context,
    );
    assertFalse(calls.some((c) => c.op === "b2_list_buckets"));
    assertEquals(written[0].data.bucketName, OTHER_BUCKET_NAME);
  } finally {
    restore();
  }
});

Deno.test("copy rejects metadataDirective REPLACE without a contentType", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () =>
        model.methods.copy.execute(
          {
            sourceFileId: "4_zsrc",
            fileName: "data/copy",
            metadataDirective: "REPLACE",
          },
          context,
        ),
      Error,
      "requires contentType",
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// update — legal hold, retention, and the slim-response trap
// ===========================================================================

Deno.test("update re-reads the file so the snapshot is not hollowed out by the slim response", async () => {
  // b2_update_file_legal_hold returns only the id, the name and the new hold.
  // Snapshotting that directly would drop contentLength, uploadTimestamp and
  // everything else the resource promises.
  const { calls, restore } = installFetch(
    router({
      b2_update_file_legal_hold: {
        fileId: "4_zabc",
        fileName: "data/00/pack-0001",
        legalHold: "on",
      },
      b2_get_file_info: fileBody({
        fileId: "4_zabc",
        legalHold: { isClientAuthorizedToRead: true, value: "on" },
      }),
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.update.execute(
      { fileId: "4_zabc", fileName: "data/00/pack-0001", legalHold: "on" },
      context,
    );
    assert(calls.some((c) => c.op === "b2_get_file_info"), "must re-read");
    assertEquals(written[0].data.legalHold, "on");
    assertEquals(
      written[0].data.contentLength,
      1024,
      "full state, not the stub",
    );
    assertEquals(written[0].data.uploadTimestamp, 1754000000000);
  } finally {
    restore();
  }
});

Deno.test("update sets governance retention with the retain-until date", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_update_file_retention: { fileId: "4_zabc" },
      b2_get_file_info: fileBody({
        fileRetention: {
          isClientAuthorizedToRead: true,
          value: { mode: "governance", retainUntilTimestamp: 1893456000000 },
        },
      }),
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.update.execute(
      {
        fileId: "4_zabc",
        fileName: "data/00/pack-0001",
        retentionMode: "governance",
        retainUntilTimestamp: 1893456000000,
      },
      context,
    );
    const sent = bodyOf(
      calls.find((c) => c.op === "b2_update_file_retention")!,
    );
    assertEquals(sent.fileRetention, {
      mode: "governance",
      retainUntilTimestamp: 1893456000000,
    });
    assertEquals(written[0].data.retentionMode, "governance");
  } finally {
    restore();
  }
});

Deno.test('update maps retentionMode "none" onto a null mode to clear the lock', async () => {
  const { calls, restore } = installFetch(
    router({
      b2_update_file_retention: { fileId: "4_zabc" },
      b2_get_file_info: fileBody(),
    }),
  );
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.update.execute(
      {
        fileId: "4_zabc",
        fileName: "data/00/pack-0001",
        retentionMode: "none",
      },
      context,
    );
    assertEquals(
      bodyOf(calls.find((c) => c.op === "b2_update_file_retention")!)
        .fileRetention,
      { mode: null, retainUntilTimestamp: null },
    );
  } finally {
    restore();
  }
});

Deno.test("update refuses a retention lock with no end date", async () => {
  const { restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () =>
        model.methods.update.execute(
          { fileId: "4_zabc", retentionMode: "governance" },
          context,
        ),
      Error,
      "requires retainUntilTimestamp",
    );
  } finally {
    restore();
  }
});

Deno.test("update refuses compliance retention without an acknowledgement", async () => {
  const { calls, restore } = installFetch(router({}));
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () =>
        model.methods.update.execute(
          {
            fileId: "4_zabc",
            retentionMode: "compliance",
            retainUntilTimestamp: 1893456000000,
          },
          context,
        ),
      Error,
      "never shortened or removed",
    );
    assertEquals(calls.length, 0, "the gate must fire before authorizing");
  } finally {
    restore();
  }
});

Deno.test("update allows compliance retention once acknowledged", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_update_file_retention: { fileId: "4_zabc" },
      b2_get_file_info: fileBody({
        fileRetention: {
          isClientAuthorizedToRead: true,
          value: { mode: "compliance", retainUntilTimestamp: 1893456000000 },
        },
      }),
    }),
  );
  try {
    const { context, written } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.update.execute(
      {
        fileId: "4_zabc",
        fileName: "data/00/pack-0001",
        retentionMode: "compliance",
        retainUntilTimestamp: 1893456000000,
        allowComplianceRetention: true,
      },
      context,
    );
    assert(calls.some((c) => c.op === "b2_update_file_retention"));
    assertEquals(written[0].data.retentionMode, "compliance");
  } finally {
    restore();
  }
});

Deno.test("update warns and changes nothing when given neither field", async () => {
  const { calls, restore } = installFetch(
    router({ b2_get_file_info: fileBody() }),
  );
  try {
    const { context, logs } = makeContext({ bucketId: BUCKET_ID });
    await model.methods.update.execute(
      { fileId: "4_zabc", fileName: "data/00/pack-0001" },
      context,
    );
    assertFalse(calls.some((c) => c.op === "b2_update_file_retention"));
    assertFalse(calls.some((c) => c.op === "b2_update_file_legal_hold"));
    assert(
      logs.some((l) => l.includes("WARN") && l.includes("nothing was changed")),
    );
  } finally {
    restore();
  }
});

Deno.test("update refuses to act on a file name that does not exist", async () => {
  const { restore } = installFetch(
    router({ b2_list_file_versions: { files: [] } }),
  );
  try {
    const { context } = makeContext({ bucketId: BUCKET_ID });
    await assertRejects(
      () =>
        model.methods.update.execute(
          { fileName: "data/gone", legalHold: "on" },
          context,
        ),
      Error,
      "nothing to update",
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// Checks
// ===========================================================================

Deno.test("credentials-present fails on an empty application key", async () => {
  const result = await model.checks["credentials-present"].execute({
    globalArgs: _internal.GlobalArgsSchema.parse({
      applicationKeyId: "id",
      applicationKey: "   ",
    }),
  });
  assertFalse(result.pass);
  assertStringIncludes(result.errors?.join(" ") ?? "", "vault.get");
});

Deno.test("no pre-flight check may block delete for want of the acknowledgement", async () => {
  // Replaces a test that asserted the OPPOSITE and so encoded the bug as
  // correct — the same failure as the wave-1 unprunedPrefixes test.
  //
  // A check can only ever see globalArgs; swamp does not pass method inputs to
  // checks. So a check gating on allowFileDestruction rejects
  // `--input allowFileDestruction=true` before execute runs, while its error
  // message instructs the operator to pass exactly that. Worse, it leaves
  // setting the flag permanently on the model as the only way to delete
  // anything — arming destruction for good on a model whose delete can corrupt
  // a restic repository. Verified against the published 2026.08.05.1.
  //
  // A well-configured model — bucket pinned, destruction NOT pre-authorised —
  // must pass every check, so the per-run acknowledgement can reach execute.
  const globalArgs = _internal.GlobalArgsSchema.parse({
    applicationKeyId: "id",
    applicationKey: APPLICATION_KEY,
    bucketName: BUCKET_NAME,
  });
  for (const [name, check] of Object.entries(model.checks)) {
    // Not every check declares appliesTo — one that omits it runs everywhere,
    // so an absent value must be treated as "applies to delete too".
    const applies = (check as { appliesTo?: string[] }).appliesTo ?? ["delete"];
    if (!applies.includes("delete")) continue;
    const result = await check.execute({ globalArgs });
    assert(
      result.pass,
      `check "${name}" blocks delete on a model that has not pre-authorised ` +
        `destruction, so --input allowFileDestruction=true can never reach ` +
        `execute: ${JSON.stringify(result.errors)}`,
    );
  }
});

Deno.test("single-bucket-for-file-methods requires a bucket for delete and update", async () => {
  const check = model.checks["single-bucket-for-file-methods"];
  assertEquals(check.appliesTo, ["delete", "update"]);
  const blocked = await check.execute({
    globalArgs: _internal.GlobalArgsSchema.parse({
      applicationKeyId: "id",
      applicationKey: APPLICATION_KEY,
    }),
  });
  assertFalse(blocked.pass);
});

// ===========================================================================
// Model shape and secret hygiene
// ===========================================================================

Deno.test("model declares the PRD's type and every intent method", () => {
  assertEquals(model.type, "@sntxrr/b2/files");
  assertEquals(
    Object.keys(model.methods).sort(),
    ["copy", "delete", "hide", "scan", "sync", "update"],
  );
  assertEquals(Object.keys(model.resources).sort(), ["aggregate", "file"]);
});

Deno.test("applicationKey is marked sensitive in the global arguments", () => {
  const shape = _internal.GlobalArgsSchema.shape;
  assertEquals(
    (shape.applicationKey.meta() as { sensitive?: boolean } | undefined)
      ?.sensitive,
    true,
  );
});

Deno.test("no method leaks a secret into a snapshot or a log line", async () => {
  const { restore } = installFetch(
    router({
      b2_list_buckets: bucketsBody(),
      b2_list_file_versions: { files: [fileBody()] },
      b2_get_file_info: fileBody(),
      b2_hide_file: fileBody({ action: "hide", fileId: "4_zmarker" }),
      b2_copy_file: fileBody({ fileId: "4_zcopy" }),
      b2_delete_file_version: { fileId: "4_zabc" },
      b2_update_file_legal_hold: { fileId: "4_zabc", legalHold: "on" },
      b2_update_file_retention: { fileId: "4_zabc" },
    }),
  );
  try {
    const runs: Array<[string, Record<string, unknown>]> = [
      ["scan", {}],
      ["scan", { mode: "detailed", prefix: "data/", maxFiles: 5 }],
      ["sync", { fileId: "4_zabc" }],
      ["delete", { fileId: "4_zabc", allowFileDestruction: true }],
      ["hide", { fileName: "data/a", allowFileDestruction: true }],
      ["copy", { sourceFileId: "4_zsrc", fileName: "data/copy" }],
      ["update", { fileId: "4_zabc", fileName: "data/a", legalHold: "on" }],
    ];
    for (const [method, args] of runs) {
      const { context, written, logs } = makeContext({ bucketId: BUCKET_ID });
      // Each method's `execute` is narrowly typed to its own argument schema;
      // this table drives all six through one loop, so the erasure is
      // deliberate rather than a papered-over mismatch.
      const methods = model.methods as unknown as Record<
        string,
        {
          execute: (
            a: Record<string, unknown>,
            c: typeof context,
          ) => Promise<unknown>;
        }
      >;
      await methods[method].execute(args, context);
      assertNoSecrets(written, `${method} snapshots`);
      assertNoSecrets(logs, `${method} logs`);
      assert(written.length > 0, `${method} must write at least one resource`);
    }
  } finally {
    restore();
  }
});

Deno.test("the bearer token is sent as a header and never as a body field", async () => {
  const { calls, restore } = installFetch(
    router({
      b2_list_buckets: {
        buckets: [{ bucketId: BUCKET_ID, bucketName: BUCKET_NAME }],
      },
      b2_list_file_versions: { files: [fileBody()] },
    }),
  );
  try {
    const { context } = makeContext();
    await model.methods.scan.execute({}, context);
    for (const call of calls.filter((c) => c.op !== "b2_authorize_account")) {
      assertEquals(call.authorization, AUTH_TOKEN);
      assertFalse(
        (call.body ?? "").includes(AUTH_TOKEN),
        "the token belongs in the header, not the payload",
      );
    }
  } finally {
    restore();
  }
});
