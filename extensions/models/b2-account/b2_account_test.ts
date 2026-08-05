/**
 * Unit tests for b2_account.ts — v4 nested authorize parsing, the
 * `allowed.buckets` array (and its null case), cluster-scoped URL
 * construction, unpaginated `b2_list_buckets` vs cursor-paginated
 * `b2_list_keys`, `truncated` on page-cap exhaustion, expired-token
 * re-authorization, transient retry, non-transient failure, and a hard
 * assertion that no snapshot ever carries a secret. `fetch` is mocked
 * throughout — no live B2 calls, no billed class C transactions.
 * @module
 */
import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import { _internal, model } from "./b2_account.ts";

/**
 * Test credentials. `APP_KEY` is a fake secret; the leak assertions below
 * search every written snapshot for this exact string.
 */
const APP_KEY = "K0dPr3t3ndS3cr3tValu3xxxxxxxxxxx";
const AUTH_TOKEN = "4_002ab1c2d3e4f5_pretend_bearer_token";
const ACCOUNT_ID = "4a48fe8875c6214145260818";
const API_URL = "https://api002.backblazeb2.example.com";

const G = {
  applicationKeyId: "0021a2b3c4d5e6f0000000001",
  applicationKey: APP_KEY,
  authHost: "https://api.backblazeb2.example.com",
};

/** Build a v4 authorize response body — everything under apiInfo.storageApi. */
function authorizeBody(
  allowedBuckets: Array<{ id: string; name: string }> | null = [],
): string {
  return JSON.stringify({
    accountId: ACCOUNT_ID,
    authorizationToken: AUTH_TOKEN,
    applicationKeyExpirationTimestamp: null,
    apiInfo: {
      storageApi: {
        apiUrl: API_URL,
        downloadUrl: "https://f002.backblazeb2.example.com",
        s3ApiUrl: "https://s3.us-west-002.backblazeb2.example.com",
        recommendedPartSize: 100000000,
        absoluteMinimumPartSize: 5000000,
        allowed: {
          buckets: allowedBuckets,
          capabilities: ["listBuckets", "listKeys", "readFiles"],
          namePrefix: null,
        },
      },
      groupsApi: { groupsApiUrl: "https://api002.backblazeb2.example.com" },
    },
  });
}

// deno-lint-ignore no-explicit-any
type AnyCtx = any;
function makeContext(globalArgs: Record<string, unknown> = G): {
  ctx: AnyCtx;
  writes: Array<{ spec: string; name: string; data: Record<string, unknown> }>;
} {
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const ctx = {
    // Parse rather than pass through: defaults and coercions declared on the
    // global-argument schema are part of the contract a real run applies.
    globalArgs: model.globalArguments.parse(globalArgs),
    logger: { info: () => {}, warn: () => {} },
    // Validate against the REAL resource schema, exactly as swamp does at run
    // time. A stub that only records cannot catch a schema-conformance bug:
    // reverting a genuine mapper fix in b2-bucket left every test green until
    // this validation was added. Every bug mechanical review has found in this
    // suite lived in a derived field, which is precisely what this catches.
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      const resourceSpec =
        (model.resources as Record<string, { schema: z.ZodType }>)[spec];
      if (!resourceSpec) {
        throw new Error(`writeResource called with unknown spec "${spec}"`);
      }
      // "latest" is reserved by swamp's data layer and is rejected at run
      // time only. Model it here so a reserved-name bug fails in CI rather
      // than against a real object.
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
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { ctx, writes };
}

type Call = { url: string; init: RequestInit };

async function withMockedFetch<T>(
  handler: (url: string, init: RequestInit) => Response,
  fn: (calls: Call[]) => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  const calls: Call[] = [];
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const i = init ?? {};
    calls.push({ url, init: i });
    return Promise.resolve(handler(url, i));
  }) as typeof globalThis.fetch;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

/** Route a mocked B2 call by operation name. */
function routeOp(url: string): string {
  const m = url.match(/\/b2api\/v4\/([a-z0-9_]+)/);
  return m ? m[1] : "";
}

const BUCKET_A = {
  accountId: ACCOUNT_ID,
  bucketId: "b1f2a3c4d5e6f708192a3b4c",
  bucketName: "restic-host-a",
  bucketType: "allPrivate",
  bucketInfo: {},
  corsRules: [],
  lifecycleRules: [{ fileNamePrefix: "", daysFromHidingToDeleting: 30 }],
  fileLockConfiguration: {
    isClientAuthorizedToRead: true,
    value: { isFileLockEnabled: false },
  },
  defaultServerSideEncryption: {
    isClientAuthorizedToRead: true,
    value: { mode: "none" },
  },
  replicationConfiguration: null,
  options: ["s3"],
  revision: 4,
};

const KEY_1 = {
  accountId: ACCOUNT_ID,
  applicationKeyId: "0021a2b3c4d5e6f0000000002",
  keyName: "restic-host-a",
  capabilities: ["listBuckets", "readFiles", "writeFiles"],
  bucketIds: ["b1f2a3c4d5e6f708192a3b4c"],
  namePrefix: null,
  expirationTimestamp: null,
  options: ["s3"],
};

const KEY_2 = {
  accountId: ACCOUNT_ID,
  applicationKeyId: "0021a2b3c4d5e6f0000000003",
  keyName: "master-audit",
  capabilities: ["listBuckets", "listKeys"],
  bucketIds: [],
  namePrefix: null,
  expirationTimestamp: 1798761600000,
  options: [],
};

// --- 1. Authorize: the nested v4 shape -------------------------------------

Deno.test("b2Authorize parses the nested v4 apiInfo.storageApi shape", async () => {
  const auth = await withMockedFetch(
    () =>
      new Response(
        authorizeBody([{ id: "b1f2a3c4d5e6f708192a3b4c", name: "restic-host-a" }]),
        { status: 200 },
      ),
    () => _internal.b2Authorize(G),
  );
  // The top level of a v4 response carries only accountId + token; everything
  // else is nested. Reading apiUrl from the top level would yield undefined.
  assertEquals(auth.accountId, ACCOUNT_ID);
  assertEquals(auth.apiUrl, API_URL);
  assertEquals(auth.downloadUrl, "https://f002.backblazeb2.example.com");
  assertEquals(
    auth.s3ApiUrl,
    "https://s3.us-west-002.backblazeb2.example.com",
  );
  // allowed.buckets is an ARRAY in v4 — a bucket-scoped key has exactly one.
  assert(Array.isArray(auth.allowed.buckets));
  assertEquals(auth.allowed.buckets.length, 1);
  assertEquals(auth.allowed.buckets[0].name, "restic-host-a");
  assertEquals(auth.allowed.capabilities, [
    "listBuckets",
    "listKeys",
    "readFiles",
  ]);
});

Deno.test("b2Authorize normalizes allowed.buckets: null to an empty array", async () => {
  const auth = await withMockedFetch(
    () => new Response(authorizeBody(null), { status: 200 }),
    () => _internal.b2Authorize(G),
  );
  assert(Array.isArray(auth.allowed.buckets));
  assertEquals(auth.allowed.buckets.length, 0);
});

Deno.test("b2Authorize uses the well-known authorize host with a Basic header", async () => {
  const calls = await withMockedFetch(
    () => new Response(authorizeBody(), { status: 200 }),
    async (calls) => {
      await _internal.b2Authorize(G);
      return calls;
    },
  );
  assertEquals(calls.length, 1);
  assertStringIncludes(calls[0].url, "/b2api/v4/b2_authorize_account");
  assertEquals(calls[0].init.method, "GET");
  const authHeader = (calls[0].init.headers as Record<string, string>)
    .Authorization;
  assertStringIncludes(authHeader, "Basic ");
  // The Basic blob is base64 of "keyId:key" — it must decode to the real pair,
  // proving the secret goes only into the header and nowhere else.
  assertEquals(atob(authHeader.slice(6)), `${G.applicationKeyId}:${APP_KEY}`);
});

Deno.test("b2Authorize throws with the status on a non-2xx", async () => {
  const err = await withMockedFetch(
    () =>
      new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
    async () => {
      try {
        await _internal.b2Authorize(G);
        return null;
      } catch (e) {
        return e as Error & { status: number };
      }
    },
  );
  assert(err !== null);
  assertEquals(err.status, 401);
  assertStringIncludes(err.message, "401");
});

// --- 1b. The v4 shape guard on a 2xx authorize ------------------------------

/**
 * Authorize against a mocked 2xx body and return the Error it threw.
 *
 * A 2xx whose body is not the v4 shape is the dangerous case: without the guard
 * `apiUrl` would be `undefined`, every later call would target
 * `undefined/b2api/v4/...`, and the failure would surface far from its cause.
 */
async function authorizeShapeError(body: string): Promise<Error> {
  const e = await withMockedFetch(
    () => new Response(body, { status: 200 }),
    async () => {
      try {
        await _internal.b2Authorize(G);
        return null;
      } catch (err) {
        return err as Error;
      }
    },
  );
  assert(e !== null, "a 2xx body without apiInfo.storageApi must throw");
  return e;
}

/** Assert the guard's message tells an operator what is wrong and where. */
function assertActionable(err: Error): void {
  assertStringIncludes(err.message, "apiInfo.storageApi");
  assertStringIncludes(err.message, "apiUrl / downloadUrl / s3ApiUrl");
  assertStringIncludes(err.message, "/b2api/v4/b2_authorize_account");
  // The message must never echo credentials while diagnosing a bad response.
  assert(!err.message.includes(APP_KEY));
  assert(!err.message.includes(G.applicationKeyId));
}

Deno.test("b2Authorize rejects a 2xx v2/v3-style FLAT body", async () => {
  // The v2/v3 shape: apiUrl at the top level, no apiInfo at all. Following an
  // older example produces exactly this and it must not be accepted.
  const flat = await authorizeShapeError(JSON.stringify({
    accountId: ACCOUNT_ID,
    authorizationToken: AUTH_TOKEN,
    apiUrl: API_URL,
    downloadUrl: "https://f002.backblazeb2.example.com",
    s3ApiUrl: "https://s3.us-west-002.backblazeb2.example.com",
    allowed: { capabilities: ["listBuckets"], bucketId: null },
  }));
  assertActionable(flat);

  // apiInfo present but storageApi missing (e.g. a groups-only response).
  const noStorageApi = await authorizeShapeError(JSON.stringify({
    accountId: ACCOUNT_ID,
    authorizationToken: AUTH_TOKEN,
    apiInfo: { groupsApi: { groupsApiUrl: API_URL } },
  }));
  assertActionable(noStorageApi);
});

Deno.test("b2Authorize rejects a storageApi missing downloadUrl", async () => {
  const err = await authorizeShapeError(JSON.stringify({
    accountId: ACCOUNT_ID,
    authorizationToken: AUTH_TOKEN,
    apiInfo: {
      storageApi: {
        apiUrl: API_URL,
        s3ApiUrl: "https://s3.us-west-002.backblazeb2.example.com",
        allowed: { buckets: [], capabilities: [], namePrefix: null },
      },
    },
  }));
  assertActionable(err);
});

Deno.test("b2Authorize rejects a storageApi missing s3ApiUrl", async () => {
  const err = await authorizeShapeError(JSON.stringify({
    accountId: ACCOUNT_ID,
    authorizationToken: AUTH_TOKEN,
    apiInfo: {
      storageApi: {
        apiUrl: API_URL,
        downloadUrl: "https://f002.backblazeb2.example.com",
        allowed: { buckets: [], capabilities: [], namePrefix: null },
      },
    },
  }));
  assertActionable(err);
});

Deno.test("b2Authorize succeeds when allowed is absent entirely", async () => {
  // The guard deliberately does NOT require `allowed` — the three URLs are what
  // every later call depends on. A response without it degrades to an empty
  // grant rather than failing the whole scan.
  const auth = await withMockedFetch(
    () =>
      new Response(
        JSON.stringify({
          accountId: ACCOUNT_ID,
          authorizationToken: AUTH_TOKEN,
          apiInfo: {
            storageApi: {
              apiUrl: API_URL,
              downloadUrl: "https://f002.backblazeb2.example.com",
              s3ApiUrl: "https://s3.us-west-002.backblazeb2.example.com",
            },
          },
        }),
        { status: 200 },
      ),
    () => _internal.b2Authorize(G),
  );
  assertEquals(auth.apiUrl, API_URL);
  assertEquals(auth.allowed.buckets, []);
  assertEquals(auth.allowed.capabilities, []);
  assertEquals(auth.allowed.namePrefix, null);
});

// --- 2. scan: buckets are unpaginated, keys are cursor-paginated ------------

Deno.test("scan authorizes, lists buckets once with no cursor, and lists keys", async () => {
  const { ctx, writes } = makeContext();
  const calls = await withMockedFetch(
    (url) => {
      switch (routeOp(url)) {
        case "b2_authorize_account":
          return new Response(authorizeBody(), { status: 200 });
        case "b2_list_buckets":
          return new Response(JSON.stringify({ buckets: [BUCKET_A] }), {
            status: 200,
          });
        case "b2_list_keys":
          return new Response(
            JSON.stringify({ keys: [KEY_1], nextApplicationKeyId: null }),
            { status: 200 },
          );
        default:
          throw new Error(`unexpected op: ${url}`);
      }
    },
    async (calls) => {
      await model.methods.scan.execute({}, ctx);
      return calls;
    },
  );

  const ops = calls.map((c) => routeOp(c.url));
  assertEquals(ops, [
    "b2_authorize_account",
    "b2_list_buckets",
    "b2_list_keys",
  ]);
  // b2_list_buckets is NOT paginated — exactly one call, never a second page.
  assertEquals(ops.filter((o) => o === "b2_list_buckets").length, 1);

  // Every post-authorize call targets the cluster apiUrl from the response,
  // never the well-known authorize host.
  for (const c of calls.slice(1)) {
    assertStringIncludes(c.url, API_URL);
    assertEquals(c.init.method, "POST");
    assertEquals(
      (c.init.headers as Record<string, string>).Authorization,
      AUTH_TOKEN,
    );
  }
  assertStringIncludes(String(calls[1].init.body), ACCOUNT_ID);

  // Three writes: one bucket, one key, one account summary. Every instance
  // name is spec-prefixed — the three specs share one flat storage namespace.
  assertEquals(writes.map((w) => w.spec), ["bucket", "key", "account"]);
  assertEquals(writes[0].name, "bucket-restic-host-a");
  assertEquals(writes[0].data.bucketId, BUCKET_A.bucketId);
  assertEquals(writes[0].data.options, ["s3"]);
  assertEquals(writes[0].data.revision, 4);
  assertEquals(writes[1].name, `key-${KEY_1.applicationKeyId}`);
  assertEquals(writes[1].data.bucketIds, [BUCKET_A.bucketId]);
  // The summary is keyed by the real account ID, never the literal "latest".
  assertEquals(writes[2].name, `account-${ACCOUNT_ID}`);
  assert(writes[2].name !== "latest");
  assertEquals(writes[2].data.bucketCount, 1);
  assertEquals(writes[2].data.keyCount, 1);
  assertEquals(writes[2].data.truncated, false);
  assertEquals(writes[2].data.keysTruncated, false);
});

Deno.test("scan drains two key pages, renaming nextApplicationKeyId to startApplicationKeyId", async () => {
  const { ctx, writes } = makeContext();
  const keyBodies: string[] = [];
  await withMockedFetch(
    (url, init) => {
      switch (routeOp(url)) {
        case "b2_authorize_account":
          return new Response(authorizeBody(), { status: 200 });
        case "b2_list_buckets":
          return new Response(JSON.stringify({ buckets: [] }), { status: 200 });
        case "b2_list_keys": {
          const body = String(init.body ?? "");
          keyBodies.push(body);
          const parsed = JSON.parse(body) as {
            startApplicationKeyId?: string;
          };
          if (!parsed.startApplicationKeyId) {
            return new Response(
              JSON.stringify({
                keys: [KEY_1],
                nextApplicationKeyId: KEY_2.applicationKeyId,
              }),
              { status: 200 },
            );
          }
          return new Response(
            JSON.stringify({ keys: [KEY_2], nextApplicationKeyId: null }),
            { status: 200 },
          );
        }
        default:
          throw new Error(`unexpected op: ${url}`);
      }
    },
    () => model.methods.scan.execute({}, ctx),
  );

  assertEquals(keyBodies.length, 2);
  // Page 1 carries no cursor; page 2 carries the renamed cursor.
  assert(!keyBodies[0].includes("startApplicationKeyId"));
  const page2 = JSON.parse(keyBodies[1]) as {
    startApplicationKeyId?: string;
    accountId?: string;
    maxKeyCount?: number;
  };
  assertEquals(page2.startApplicationKeyId, KEY_2.applicationKeyId);
  // The base payload is carried forward alongside the cursor.
  assertEquals(page2.accountId, ACCOUNT_ID);
  assertEquals(page2.maxKeyCount, 1000);

  // Both pages concatenate: two keys plus the summary, no buckets.
  assertEquals(writes.map((w) => w.spec), ["key", "key", "account"]);
  assertEquals(writes[0].name, `key-${KEY_1.applicationKeyId}`);
  assertEquals(writes[1].name, `key-${KEY_2.applicationKeyId}`);
  assertEquals(writes[2].data.keyCount, 2);
  assertEquals(writes[2].data.truncated, false);
});

Deno.test("scan sets truncated when the key listing exhausts maxKeyPages", async () => {
  const { ctx, writes } = makeContext();
  let keyPages = 0;
  await withMockedFetch(
    (url) => {
      switch (routeOp(url)) {
        case "b2_authorize_account":
          return new Response(authorizeBody(), { status: 200 });
        case "b2_list_buckets":
          return new Response(JSON.stringify({ buckets: [] }), { status: 200 });
        case "b2_list_keys":
          keyPages += 1;
          // Never stops handing back a cursor — only maxKeyPages ends it.
          return new Response(
            JSON.stringify({
              keys: [{ ...KEY_1, applicationKeyId: `key-${keyPages}` }],
              nextApplicationKeyId: `cursor-${keyPages}`,
            }),
            { status: 200 },
          );
        default:
          throw new Error(`unexpected op: ${url}`);
      }
    },
    () => model.methods.scan.execute({ maxKeyPages: 2 }, ctx),
  );

  assertEquals(keyPages, 2);
  const summary = writes.find((w) => w.spec === "account");
  assert(summary !== undefined);
  // A truncated inventory must say so — otherwise an audit reads the missing
  // keys as proof they do not exist.
  assertEquals(summary.data.truncated, true);
  assertEquals(summary.data.keysTruncated, true);
  assertEquals(summary.data.keyCount, 2);
});

Deno.test("scan forwards bucketTypes and maxKeyCount when supplied", async () => {
  const { ctx } = makeContext();
  const bodies: Record<string, string> = {};
  await withMockedFetch(
    (url, init) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      bodies[op] = String(init.body ?? "");
      if (op === "b2_list_buckets") {
        return new Response(JSON.stringify({ buckets: [] }), { status: 200 });
      }
      return new Response(JSON.stringify({ keys: [] }), { status: 200 });
    },
    () =>
      model.methods.scan.execute(
        { bucketTypes: ["allPrivate"], maxKeyCount: 250 },
        ctx,
      ),
  );
  assertStringIncludes(bodies.b2_list_buckets, '"bucketTypes":["allPrivate"]');
  assertStringIncludes(bodies.b2_list_keys, '"maxKeyCount":250');
});

Deno.test("scan omits bucketTypes entirely when not supplied", async () => {
  const { ctx } = makeContext();
  let bucketBody = "";
  await withMockedFetch(
    (url, init) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      if (op === "b2_list_buckets") {
        bucketBody = String(init.body ?? "");
        return new Response(JSON.stringify({ buckets: [] }), { status: 200 });
      }
      return new Response(JSON.stringify({ keys: [] }), { status: 200 });
    },
    () => model.methods.scan.execute({}, ctx),
  );
  assert(!bucketBody.includes("bucketTypes"));
});

// --- 3. Error handling ------------------------------------------------------

Deno.test("an expired auth token triggers exactly one re-authorization", async () => {
  const { ctx, writes } = makeContext();
  let authorizeCount = 0;
  let listKeysCount = 0;
  const ops = await withMockedFetch(
    (url) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        authorizeCount += 1;
        return new Response(authorizeBody(), { status: 200 });
      }
      if (op === "b2_list_buckets") {
        return new Response(JSON.stringify({ buckets: [] }), { status: 200 });
      }
      listKeysCount += 1;
      if (listKeysCount === 1) {
        return new Response(
          JSON.stringify({ code: "expired_auth_token", status: 401 }),
          { status: 401 },
        );
      }
      return new Response(JSON.stringify({ keys: [KEY_1] }), { status: 200 });
    },
    async (calls) => {
      await model.methods.scan.execute({}, ctx);
      return calls.map((c) => routeOp(c.url));
    },
  );
  // One authorize for the scan itself + exactly one re-authorize on expiry.
  assertEquals(authorizeCount, 2);
  assertEquals(listKeysCount, 2);
  assertEquals(ops, [
    "b2_authorize_account",
    "b2_list_buckets",
    "b2_list_keys",
    "b2_authorize_account",
    "b2_list_keys",
  ]);
  assertEquals(writes.map((w) => w.spec), ["key", "account"]);
});

Deno.test("a 429 with Retry-After is retried and then succeeds", async () => {
  const { ctx, writes } = makeContext();
  let bucketCalls = 0;
  await withMockedFetch(
    (url) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      if (op === "b2_list_buckets") {
        bucketCalls += 1;
        if (bucketCalls === 1) {
          return new Response(JSON.stringify({ code: "too_many_requests" }), {
            status: 429,
            headers: { "retry-after": "0" },
          });
        }
        return new Response(JSON.stringify({ buckets: [BUCKET_A] }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({ keys: [] }), { status: 200 });
    },
    () => model.methods.scan.execute({}, ctx),
  );
  assertEquals(bucketCalls, 2);
  assertEquals(writes[0].spec, "bucket");
  assertEquals(writes[0].name, "bucket-restic-host-a");
});

Deno.test("a non-transient 400 throws with b2Code populated and writes nothing", async () => {
  const { ctx, writes } = makeContext();
  const err = await withMockedFetch(
    (url) => {
      if (routeOp(url) === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      return new Response(
        JSON.stringify({ status: 400, code: "bad_bucket_id", message: "no" }),
        { status: 400 },
      );
    },
    async () => {
      try {
        await model.methods.scan.execute({}, ctx);
        return null;
      } catch (e) {
        return e as Error & { status: number; b2Code: string };
      }
    },
  );
  assert(err !== null);
  assertEquals(err.status, 400);
  assertEquals(err.b2Code, "bad_bucket_id");
  assertStringIncludes(err.message, "b2_list_buckets");
  assertEquals(writes.length, 0);
});

Deno.test("a 401 that is not expired_auth_token is not retried", async () => {
  const { ctx } = makeContext();
  let bucketCalls = 0;
  const err = await withMockedFetch(
    (url) => {
      if (routeOp(url) === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      bucketCalls += 1;
      return new Response(JSON.stringify({ code: "unauthorized" }), {
        status: 401,
      });
    },
    async () => {
      try {
        await model.methods.scan.execute({}, ctx);
        return null;
      } catch (e) {
        return e as Error & { b2Code: string };
      }
    },
  );
  assert(err !== null);
  // A missing capability is permanent, not transient — one call, no retry.
  assertEquals(bucketCalls, 1);
  assertEquals(err.b2Code, "unauthorized");
});

// --- 4. Mapping edge cases --------------------------------------------------

Deno.test("toKeyResource keeps bucketIds an array and degrades a v2 scalar bucketId", () => {
  const now = "2026-08-05T00:00:00.000Z";
  // v4 plural, account-wide key: empty array, not undefined.
  const wide = _internal.toKeyResource({ ...KEY_2 }, now);
  assertEquals(wide.bucketIds, []);
  // v4 plural, bucket-scoped key: one-element array.
  const scoped = _internal.toKeyResource({ ...KEY_1 }, now);
  assertEquals(scoped.bucketIds, [BUCKET_A.bucketId]);
  // A stale v2-shaped scalar must not silently read as account-wide.
  const legacy = _internal.toKeyResource(
    { applicationKeyId: "k", bucketId: "b-legacy", capabilities: [] },
    now,
  );
  assertEquals(legacy.bucketIds, ["b-legacy"]);
  // Missing entirely means unrestricted.
  const none = _internal.toKeyResource(
    { applicationKeyId: "k", capabilities: [] },
    now,
  );
  assertEquals(none.bucketIds, []);
});

Deno.test("toBucketResource carries the wrapped config blobs through verbatim", () => {
  const now = "2026-08-05T00:00:00.000Z";
  const r = _internal.toBucketResource({ ...BUCKET_A }, now);
  assertEquals(r.fileLockConfiguration, BUCKET_A.fileLockConfiguration);
  assertEquals(
    r.defaultServerSideEncryption,
    BUCKET_A.defaultServerSideEncryption,
  );
  assertEquals(r.lifecycleRules, BUCKET_A.lifecycleRules);
  assertEquals(r.observedAt, now);
  // Absent optional fields normalize to null rather than undefined.
  const sparse = _internal.toBucketResource(
    { bucketId: "b", bucketName: "n" },
    now,
  );
  assertEquals(sparse.corsRules, null);
  assertEquals(sparse.revision, null);
});

Deno.test('safeResourceName falls back off the reserved "latest" name', () => {
  // A bucket really can be named "latest"; keying a resource that way fails at
  // run time only, so the immutable ID is substituted.
  assertEquals(_internal.safeResourceName("latest", "fallback-id"), "fallback-id");
  assertEquals(_internal.safeResourceName("LATEST", "fallback-id"), "fallback-id");
  assertEquals(_internal.safeResourceName("", "fallback-id"), "fallback-id");
  assertEquals(_internal.safeResourceName(undefined, "fallback-id"), "fallback-id");
  assertEquals(_internal.safeResourceName("restic-host-a", "x"), "restic-host-a");
});

Deno.test('scan keys a bucket literally named "latest" by its bucket ID', async () => {
  const { ctx, writes } = makeContext();
  await withMockedFetch(
    (url) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      if (op === "b2_list_buckets") {
        return new Response(
          JSON.stringify({
            buckets: [{ ...BUCKET_A, bucketName: "latest" }],
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ keys: [] }), { status: 200 });
    },
    () => model.methods.scan.execute({}, ctx),
  );
  assertEquals(writes[0].spec, "bucket");
  assertEquals(writes[0].name, `bucket-${BUCKET_A.bucketId}`);
  assert(writes[0].name !== "latest");
  // The real name is still recorded in the snapshot body.
  assertEquals(writes[0].data.bucketName, "latest");
});

// --- 4b. Cross-spec instance-name uniqueness (CONVENTIONS §2) ---------------

Deno.test("no two specs can produce the same instance name", () => {
  // The three specs share one flat storage namespace. B2 bucket names are
  // user-chosen lowercase alphanumerics and hyphens, 6-63 characters, so a
  // bucket may legally be named exactly a 12-character account ID or a
  // 25-character application key ID. Unprefixed, that write clobbers a
  // snapshot on disk.
  const collidingKeys = [
    ACCOUNT_ID,
    KEY_1.applicationKeyId,
    BUCKET_A.bucketName,
    BUCKET_A.bucketId,
    "latest",
  ];
  const specs = ["bucket", "key", "account"] as const;
  const seen = new Map<string, string>();
  for (const spec of specs) {
    for (const key of collidingKeys) {
      const name = _internal.instanceName(spec, key);
      const prior = seen.get(name);
      assert(
        prior === undefined,
        `instance name "${name}" is produced by both ${prior} and ${spec}/${key}`,
      );
      seen.set(name, `${spec}/${key}`);
    }
  }
  assertEquals(seen.size, specs.length * collidingKeys.length);
  // No prefix is a prefix of another, which is what makes the collision
  // structurally impossible rather than merely unlikely.
  for (const a of specs) {
    for (const b of specs) {
      if (a === b) continue;
      assert(
        !`${a}-`.startsWith(`${b}-`),
        `spec prefix "${b}-" is a prefix of "${a}-"`,
      );
    }
  }
});

Deno.test("scan keeps every instance name distinct when a bucket is named like an account or key ID", async () => {
  const { ctx, writes } = makeContext();
  // The exact clobbering scenario: two buckets named after IDs from the other
  // two specs written in the same execution.
  const bucketNamedLikeAccount = {
    ...BUCKET_A,
    bucketId: "aaaaaaaaaaaaaaaaaaaaaaaa",
    bucketName: ACCOUNT_ID,
  };
  const bucketNamedLikeKey = {
    ...BUCKET_A,
    bucketId: "bbbbbbbbbbbbbbbbbbbbbbbb",
    bucketName: KEY_1.applicationKeyId,
  };
  await withMockedFetch(
    (url) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      if (op === "b2_list_buckets") {
        return new Response(
          JSON.stringify({
            buckets: [bucketNamedLikeAccount, bucketNamedLikeKey],
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ keys: [KEY_1], nextApplicationKeyId: null }),
        { status: 200 },
      );
    },
    () => model.methods.scan.execute({}, ctx),
  );

  assertEquals(writes.length, 4);
  const names = writes.map((w) => w.name);
  assertEquals(
    new Set(names).size,
    names.length,
    `scan wrote a duplicate instance name: ${names.join(", ")}`,
  );
  assertEquals(names, [
    `bucket-${ACCOUNT_ID}`,
    `bucket-${KEY_1.applicationKeyId}`,
    `key-${KEY_1.applicationKeyId}`,
    `account-${ACCOUNT_ID}`,
  ]);
  // The account summary survived a bucket sharing its natural key.
  const summary = writes.find((w) => w.spec === "account");
  assert(summary !== undefined);
  assertEquals(summary.data.bucketCount, 2);
});

// --- 5. Checks --------------------------------------------------------------

Deno.test("credentials-present check passes with both halves and fails without", () => {
  const check = model.checks["credentials-present"];
  assertEquals(check.execute({ globalArgs: G }).pass, true);

  const noKey = check.execute({ globalArgs: { ...G, applicationKey: "  " } });
  assertEquals(noKey.pass, false);
  assert(Array.isArray(noKey.errors));
  assertStringIncludes(noKey.errors[0], "applicationKey");

  const neither = check.execute({
    globalArgs: { applicationKeyId: "", applicationKey: "" },
  });
  assertEquals(neither.pass, false);
  assertEquals(neither.errors?.length, 2);
  // The failure message must never echo the secret it is complaining about.
  assert(!JSON.stringify(neither).includes(APP_KEY));
});

// --- 6. Secret hygiene (the load-bearing assertion) -------------------------

Deno.test("no written snapshot ever contains a secret", async () => {
  const { ctx, writes } = makeContext();
  await withMockedFetch(
    (url) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(
          authorizeBody([{ id: BUCKET_A.bucketId, name: BUCKET_A.bucketName }]),
          { status: 200 },
        );
      }
      if (op === "b2_list_buckets") {
        return new Response(JSON.stringify({ buckets: [BUCKET_A] }), {
          status: 200,
        });
      }
      // A hostile/legacy response that tries to hand back key material: even
      // then it must not reach a snapshot.
      return new Response(
        JSON.stringify({
          keys: [{ ...KEY_1, applicationKey: APP_KEY }, KEY_2],
        }),
        { status: 200 },
      );
    },
    () => model.methods.scan.execute({}, ctx),
  );

  assert(writes.length > 0, "scan must write something to be worth checking");
  for (const w of writes) {
    const serialized = JSON.stringify(w.data);
    assert(
      !serialized.includes(APP_KEY),
      `snapshot ${w.spec}/${w.name} leaked the application key`,
    );
    assert(
      !serialized.includes(AUTH_TOKEN),
      `snapshot ${w.spec}/${w.name} leaked the authorization token`,
    );
    // Match the exact JSON key, not a substring: the legitimate,
    // non-secret `applicationKeyId` field contains "applicationKey".
    for (const forbidden of ["applicationKey", "authorizationToken"]) {
      assert(
        !serialized.includes(`"${forbidden}":`),
        `snapshot ${w.spec}/${w.name} contains the forbidden field ${forbidden}`,
      );
    }
    assert(
      !serialized.includes("Basic "),
      `snapshot ${w.spec}/${w.name} contains a Basic auth header`,
    );
  }
  // The summary reports the key's grant, which is metadata, not credentials.
  const summary = writes.find((w) => w.spec === "account");
  assert(summary !== undefined);
  assertEquals(summary.data.allowedBuckets, [
    { id: BUCKET_A.bucketId, name: BUCKET_A.bucketName },
  ]);
});

Deno.test("logger output never carries a secret", async () => {
  const logged: string[] = [];
  const { ctx } = makeContext();
  ctx.logger = {
    info: (m: string, p?: Record<string, unknown>) =>
      logged.push(m + JSON.stringify(p ?? {})),
    warn: (m: string, p?: Record<string, unknown>) =>
      logged.push(m + JSON.stringify(p ?? {})),
  };
  await withMockedFetch(
    (url) => {
      const op = routeOp(url);
      if (op === "b2_authorize_account") {
        return new Response(authorizeBody(), { status: 200 });
      }
      if (op === "b2_list_buckets") {
        return new Response(JSON.stringify({ buckets: [BUCKET_A] }), {
          status: 200,
        });
      }
      return new Response(
        JSON.stringify({ keys: [KEY_1], nextApplicationKeyId: "c" }),
        { status: 200 },
      );
    },
    () => model.methods.scan.execute({ maxKeyPages: 1 }, ctx),
  );
  assert(logged.length > 0);
  const all = logged.join("\n");
  assert(!all.includes(APP_KEY), "a log line leaked the application key");
  assert(!all.includes(AUTH_TOKEN), "a log line leaked the auth token");
  // The truncation warning must actually fire, or the flag has no operator
  // visibility.
  assertStringIncludes(all, "INCOMPLETE");
});

// --- 7. Model shape ---------------------------------------------------------

Deno.test("model exposes exactly one read-only method and three resource specs", () => {
  assertEquals(model.type, "@sntxrr/b2/account");
  assertEquals(Object.keys(model.methods), ["scan"]);
  assertEquals(Object.keys(model.resources).sort(), [
    "account",
    "bucket",
    "key",
  ]);
  // Read-only root: no mutating verb may appear here.
  for (const verb of ["create", "update", "delete", "action"]) {
    assert(
      !(verb in model.methods),
      `${verb} must not exist on the read-only account model`,
    );
  }
});
