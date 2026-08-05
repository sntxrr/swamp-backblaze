/**
 * Unit tests for b2_bucket.ts.
 *
 * Every test mocks `fetch` — no live Backblaze B2 calls. Coverage follows
 * CONVENTIONS.md §10 (v4 auth shape, pagination, maxPages truncation, expired
 * token re-auth, transient retry, idempotent delete, no secret leaks) plus the
 * bucket-specific paths: a lifecycle-rule round trip, the GET-with-query-params
 * notification-rules read, idempotent delete on both `404` and `400
 * bad_bucket_id`, the hidden-version-retention policy check firing, and an
 * assertion that no written resource ever contains an application key, an
 * authorization token, an HMAC signing secret, or a custom header value.
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
} from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import {
  _internal,
  b2Authorize,
  b2Fetch,
  b2ListAll,
  model,
} from "./b2_bucket.ts";

// ---------------------------------------------------------------------------
// Fixtures — nothing here is a real credential, bucket, or account.
// ---------------------------------------------------------------------------

const BUCKET_NAME = "example-backup-bucket";
const BUCKET_ID = "4a48fe8875c6214145260818";
const ACCOUNT_ID = "a1b2c3d4e5f6";
const API_URL = "https://api002.backblazeb2.com";

/** Secrets that must never appear in a resource snapshot or a log line. */
const APPLICATION_KEY = "K004exampleApplicationKeySecretValue00";
const AUTH_TOKEN = "4_004exampleAuthorizationTokenValue00";
const SIGNING_SECRET = "abcdefghijklmnopqrstuvwxyz012345";
const HEADER_SECRET = "Bearer example-webhook-header-secret";

/** The v4 authorize response — everything nested under apiInfo.storageApi. */
function authBody(
  buckets: Array<{ id: string; name: string }> | null = [{
    id: BUCKET_ID,
    name: BUCKET_NAME,
  }],
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
          capabilities: ["listBuckets", "writeBuckets", "deleteBuckets"],
          namePrefix: null,
        },
      },
      groupsApi: { groupsApiUrl: "https://api002.backblazeb2.com", capabilities: [] },
    },
  };
}

/** A B2 bucket object with a restic-safe lifecycle rule. */
function bucketBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    accountId: ACCOUNT_ID,
    bucketId: BUCKET_ID,
    bucketName: BUCKET_NAME,
    bucketType: "allPrivate",
    bucketInfo: {},
    corsRules: [],
    lifecycleRules: [{
      fileNamePrefix: "",
      daysFromUploadingToHiding: null,
      daysFromHidingToDeleting: 1,
    }],
    fileLockConfiguration: {
      isClientAuthorizedToRead: true,
      value: { isFileLockEnabled: false, defaultRetention: { mode: null } },
    },
    defaultServerSideEncryption: {
      isClientAuthorizedToRead: true,
      value: { mode: "none", algorithm: null },
    },
    // The real wire shape: authorization-wrapped, value null when replication
    // is not configured. B2 never returns a bare `{}` here — a fixture that
    // does hides the wrapper-vs-value bug entirely.
    replicationConfiguration: { isClientAuthorizedToRead: true, value: null },
    revision: 4,
    options: ["s3"],
    ...overrides,
  };
}

const RESTIC_LIFECYCLE = [{
  fileNamePrefix: "",
  daysFromUploadingToHiding: null,
  daysFromHidingToDeleting: 1,
}];

// ---------------------------------------------------------------------------
// Test harness — mocked fetch, writeResource collector, logger stub
// ---------------------------------------------------------------------------

/** One captured outbound HTTP request. */
type Recorded = {
  url: string;
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
    const rec: Recorded = {
      url: String(input),
      method: init?.method ?? "GET",
      authorization: headers.get("authorization") ?? "",
      body: typeof init?.body === "string" ? init.body : null,
    };
    calls.push(rec);
    return Promise.resolve(handler(rec, calls.length - 1));
  }) as typeof globalThis.fetch;
  return { calls, restore: () => { globalThis.fetch = original; } };
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

/** A collected `writeResource` call. */
type Written = { spec: string; name: string; data: Record<string, unknown> };

/** Build an execute context with a recording `writeResource` and a log capture. */
function makeContext(globalArgs: Record<string, unknown>): {
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
      globalArgs: _internal.GlobalArgsSchema.parse(globalArgs),
      logger: {
        info: (m, p) => logs.push(`${m} ${JSON.stringify(p ?? {})}`),
        warn: (m, p) => logs.push(`WARN ${m} ${JSON.stringify(p ?? {})}`),
      },
      // Validate against the REAL resource schema, exactly as swamp does at
      // run time. A stub that only records cannot catch a schema-conformance
      // bug — and both bugs mechanical review found in this file were
      // schema-conformance bugs. Without this, loosening or tightening a
      // resource schema changes no test outcome at all.
      writeResource: (spec, name, data) => {
        const resourceSpec =
          (model.resources as Record<string, { schema: z.ZodType }>)[spec];
        if (!resourceSpec) {
          throw new Error(`writeResource called with unknown spec "${spec}"`);
        }
        // "latest" is reserved by swamp's data layer and is rejected at run
        // time only. Model it here so a reserved-name bug fails in CI rather
        // than against a real bucket.
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

/** Base global args every method test starts from. */
function baseGlobalArgs(
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    applicationKeyId: "004exampleKeyId0000000",
    applicationKey: APPLICATION_KEY,
    bucketName: BUCKET_NAME,
    ...extra,
  };
}

/** Assert a value's JSON encoding contains none of the known secrets. */
function assertNoSecrets(value: unknown, label: string): void {
  const blob = JSON.stringify(value);
  for (
    const [name, secret] of Object.entries({
      applicationKey: APPLICATION_KEY,
      authorizationToken: AUTH_TOKEN,
      hmacSha256SigningSecret: SIGNING_SECRET,
      customHeaderValue: HEADER_SECRET,
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

// ---------------------------------------------------------------------------
// 1. Auth — the nested v4 shape
// ---------------------------------------------------------------------------

Deno.test("b2Authorize parses the nested v4 apiInfo.storageApi shape", async () => {
  const f = installFetch(() => json(authBody()));
  try {
    const auth = await b2Authorize({
      applicationKeyId: "004exampleKeyId0000000",
      applicationKey: APPLICATION_KEY,
    });
    assertEquals(auth.accountId, ACCOUNT_ID);
    assertEquals(auth.authorizationToken, AUTH_TOKEN);
    // Trailing slash stripped; cluster URL taken from apiInfo.storageApi, never
    // the well-known authorize host.
    assertEquals(auth.apiUrl, API_URL);
    assertEquals(auth.downloadUrl, "https://f002.backblazeb2.com");
    // allowed.buckets is an ARRAY in v4 — v2's scalar bucketId is gone.
    assertEquals(auth.allowed.buckets, [{ id: BUCKET_ID, name: BUCKET_NAME }]);
    assert(auth.allowed.capabilities.includes("listBuckets"));

    assertEquals(f.calls.length, 1);
    assertEquals(f.calls[0].method, "GET");
    assertStringIncludes(
      f.calls[0].url,
      "https://api.backblazeb2.com/b2api/v4/b2_authorize_account",
    );
    assertStringIncludes(f.calls[0].authorization, "Basic ");
  } finally {
    f.restore();
  }
});

Deno.test("b2Authorize coerces a null allowed.buckets to an empty array", async () => {
  const f = installFetch(() => json(authBody(null)));
  try {
    const auth = await b2Authorize({
      applicationKeyId: "004exampleKeyId0000000",
      applicationKey: APPLICATION_KEY,
    });
    assertEquals(auth.allowed.buckets, []);
  } finally {
    f.restore();
  }
});

Deno.test("b2Authorize honours authHost and throws with the status attached", async () => {
  const f = installFetch(() => json({ code: "unauthorized" }, 401));
  try {
    const err = await assertRejects(
      () =>
        b2Authorize({
          applicationKeyId: "004exampleKeyId0000000",
          applicationKey: APPLICATION_KEY,
          authHost: "https://b2.example.com/",
        }),
      Error,
    ) as Error & { status: number };
    assertEquals(err.status, 401);
    assertStringIncludes(
      f.calls[0].url,
      "https://b2.example.com/b2api/v4/b2_authorize_account",
    );
  } finally {
    f.restore();
  }
});

// ---------------------------------------------------------------------------
// 1b. The v4 shape guard on a 2xx authorize
// ---------------------------------------------------------------------------

const SHAPE_CREDS = {
  applicationKeyId: "004exampleKeyId0000000",
  applicationKey: APPLICATION_KEY,
};

/**
 * Authorize against a mocked 2xx body and return the Error it threw.
 *
 * A 2xx that is not the v4 shape is the dangerous case: without the guard
 * `apiUrl` would be `undefined`, every later call would target
 * `undefined/b2api/v4/...`, and the real cause would be several frames away.
 */
async function authorizeShapeError(body: unknown): Promise<Error> {
  const f = installFetch(() => json(body));
  try {
    return await assertRejects(() => b2Authorize(SHAPE_CREDS), Error);
  } finally {
    f.restore();
  }
}

/** Assert the guard's message tells an operator what is wrong and where. */
function assertActionable(err: Error): void {
  assertStringIncludes(err.message, "apiInfo.storageApi");
  assertStringIncludes(err.message, "apiUrl / downloadUrl / s3ApiUrl");
  assertStringIncludes(err.message, "/b2api/v4/b2_authorize_account");
  // Diagnosing a bad response must never echo the credentials used.
  assertFalse(err.message.includes(APPLICATION_KEY));
  assertFalse(err.message.includes(SHAPE_CREDS.applicationKeyId));
}

Deno.test("b2Authorize rejects a 2xx v2/v3-style FLAT body", async () => {
  // The v2/v3 shape: apiUrl at the top level, no apiInfo at all. Copying an
  // older example produces exactly this, and it must not be accepted.
  assertActionable(
    await authorizeShapeError({
      accountId: ACCOUNT_ID,
      authorizationToken: AUTH_TOKEN,
      apiUrl: API_URL,
      downloadUrl: "https://f002.backblazeb2.com",
      s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
      allowed: { capabilities: ["listBuckets"], bucketId: null },
    }),
  );
  // apiInfo present but storageApi missing (e.g. a groups-only response).
  assertActionable(
    await authorizeShapeError({
      accountId: ACCOUNT_ID,
      authorizationToken: AUTH_TOKEN,
      apiInfo: { groupsApi: { groupsApiUrl: API_URL, capabilities: [] } },
    }),
  );
});

Deno.test("b2Authorize rejects a storageApi missing downloadUrl", async () => {
  assertActionable(
    await authorizeShapeError({
      accountId: ACCOUNT_ID,
      authorizationToken: AUTH_TOKEN,
      apiInfo: {
        storageApi: {
          apiUrl: API_URL,
          s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
          allowed: { buckets: [], capabilities: [], namePrefix: null },
        },
      },
    }),
  );
});

Deno.test("b2Authorize rejects a storageApi missing s3ApiUrl", async () => {
  assertActionable(
    await authorizeShapeError({
      accountId: ACCOUNT_ID,
      authorizationToken: AUTH_TOKEN,
      apiInfo: {
        storageApi: {
          apiUrl: API_URL,
          downloadUrl: "https://f002.backblazeb2.com",
          allowed: { buckets: [], capabilities: [], namePrefix: null },
        },
      },
    }),
  );
});

Deno.test("b2Authorize succeeds when allowed is absent entirely", async () => {
  // The guard deliberately does NOT require `allowed` — the three URLs are what
  // every later call depends on. A response without it degrades to an empty
  // grant rather than failing the whole run.
  const f = installFetch(() =>
    json({
      accountId: ACCOUNT_ID,
      authorizationToken: AUTH_TOKEN,
      apiInfo: {
        storageApi: {
          apiUrl: API_URL,
          downloadUrl: "https://f002.backblazeb2.com",
          s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
        },
      },
    })
  );
  try {
    const auth = await b2Authorize(SHAPE_CREDS);
    assertEquals(auth.apiUrl, API_URL);
    assertEquals(auth.allowed.buckets, []);
    assertEquals(auth.allowed.capabilities, []);
    assertEquals(auth.allowed.namePrefix, null);
  } finally {
    f.restore();
  }
});

// ---------------------------------------------------------------------------
// 2-3. Pagination and maxPages truncation
// ---------------------------------------------------------------------------

const FAKE_AUTH = {
  accountId: ACCOUNT_ID,
  authorizationToken: AUTH_TOKEN,
  apiUrl: API_URL,
  downloadUrl: "https://f002.backblazeb2.com",
  s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
  allowed: { buckets: [], capabilities: [], namePrefix: null },
};

Deno.test("b2ListAll drains two pages and renames next* cursors to start*", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json({ files: [{ fileName: "a" }], nextFileName: "b" })
      : json({ files: [{ fileName: "b" }], nextFileName: null })
  );
  try {
    const { items, truncated } = await b2ListAll<{ fileName: string }>(
      FAKE_AUTH,
      "b2_list_file_names",
      { bucketId: BUCKET_ID },
      "files",
    );
    assertEquals(items.map((i) => i.fileName), ["a", "b"]);
    assertFalse(truncated);
    assertEquals(f.calls.length, 2);
    // Page 2 must carry startFileName derived from page 1's nextFileName.
    const page2 = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(page2.startFileName, "b");
    assertEquals(page2.bucketId, BUCKET_ID);
  } finally {
    f.restore();
  }
});

Deno.test("b2ListAll stops at maxPages and reports truncated", async () => {
  const f = installFetch(() =>
    json({ files: [{ fileName: "x" }], nextFileName: "x" })
  );
  try {
    const { items, truncated } = await b2ListAll<{ fileName: string }>(
      FAKE_AUTH,
      "b2_list_file_names",
      { bucketId: BUCKET_ID },
      "files",
      3,
    );
    assertEquals(items.length, 3);
    assert(truncated, "hitting maxPages must surface truncated: true");
    assertEquals(f.calls.length, 3);
  } finally {
    f.restore();
  }
});

// ---------------------------------------------------------------------------
// 4-5. Re-auth, transient retry, non-transient failure
// ---------------------------------------------------------------------------

Deno.test("b2Fetch re-authorizes exactly once on 401 expired_auth_token", async () => {
  let reauthCount = 0;
  const f = installFetch((_req, i) =>
    i === 0
      ? json({ code: "expired_auth_token" }, 401)
      : json({ buckets: [bucketBody()] })
  );
  try {
    const res = await b2Fetch<{ buckets: unknown[] }>(
      FAKE_AUTH,
      "POST",
      "b2_list_buckets",
      { accountId: ACCOUNT_ID },
      () => {
        reauthCount++;
        return Promise.resolve({ ...FAKE_AUTH, authorizationToken: "4_004refreshed" });
      },
    );
    assertEquals(reauthCount, 1, "exactly one re-authorization");
    assertEquals(res.buckets.length, 1);
    assertEquals(f.calls.length, 2);
    assertEquals(f.calls[1].authorization, "4_004refreshed");
  } finally {
    f.restore();
  }
});

Deno.test("b2Fetch retries a 429 honouring Retry-After", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json({ code: "too_many_requests" }, 429, { "retry-after": "1" })
      : json({ buckets: [] })
  );
  try {
    const res = await b2Fetch<{ buckets: unknown[] }>(
      FAKE_AUTH,
      "POST",
      "b2_list_buckets",
      { accountId: ACCOUNT_ID },
    );
    assertEquals(res.buckets, []);
    assertEquals(f.calls.length, 2);
  } finally {
    f.restore();
  }
});

Deno.test("b2Fetch throws a non-transient 400 with b2Code populated", async () => {
  const f = installFetch(() => json({ code: "bad_bucket_id" }, 400));
  try {
    const err = await assertRejects(
      () =>
        b2Fetch(FAKE_AUTH, "POST", "b2_delete_bucket", {
          bucketId: BUCKET_ID,
        }),
      Error,
    ) as Error & { status: number; b2Code: string };
    assertEquals(err.status, 400);
    assertEquals(err.b2Code, "bad_bucket_id");
    assertEquals(f.calls.length, 1, "a 400 must not be retried");
  } finally {
    f.restore();
  }
});

Deno.test("b2Fetch does not retry a 401 unauthorized — a missing capability is not transient", async () => {
  const f = installFetch(() => json({ code: "unauthorized" }, 401));
  try {
    const err = await assertRejects(
      () =>
        b2Fetch(
          FAKE_AUTH,
          "GET",
          "b2_get_bucket_notification_rules",
          { bucketId: BUCKET_ID },
          () => Promise.resolve(FAKE_AUTH),
        ),
      Error,
    ) as Error & { status: number; b2Code: string };
    assertEquals(err.status, 401);
    assertEquals(err.b2Code, "unauthorized");
    assertEquals(f.calls.length, 1);
  } finally {
    f.restore();
  }
});

// ---------------------------------------------------------------------------
// 6. Lifecycle-rule analysis and round trip
// ---------------------------------------------------------------------------

Deno.test("analyzeHiddenVersionRetention distinguishes pruning from unpruned prefixes", () => {
  // No rules means every file accumulates hidden versions forever, so the
  // catch-all prefix is unpruned. This assertion previously expected [] — it
  // encoded the bug rather than catching it, and a live scan of a real
  // rule-less bucket is what exposed that.
  assertEquals(
    _internal.analyzeHiddenVersionRetention([]),
    {
      prunesHiddenVersions: false,
      minDaysFromHidingToDeleting: null,
      unprunedPrefixes: [""],
    },
  );
  assertEquals(
    _internal.analyzeHiddenVersionRetention([
      { fileNamePrefix: "", daysFromUploadingToHiding: 30 },
    ]),
    {
      prunesHiddenVersions: false,
      minDaysFromHidingToDeleting: null,
      unprunedPrefixes: [""],
    },
  );
  assertEquals(
    _internal.analyzeHiddenVersionRetention([
      { fileNamePrefix: "data/", daysFromHidingToDeleting: 7 },
      { fileNamePrefix: "keys/", daysFromHidingToDeleting: 1 },
      { fileNamePrefix: "logs/", daysFromHidingToDeleting: null },
    ]),
    {
      prunesHiddenVersions: true,
      minDaysFromHidingToDeleting: 1,
      unprunedPrefixes: ["logs/"],
    },
  );
});

Deno.test("create round-trips the restic lifecycle rule and snapshots the retention verdict", async () => {
  const f = installFetch((req, i) =>
    i === 0 ? json(authBody()) : json(bucketBody({
      // Echo back exactly what was submitted, as B2 does.
      lifecycleRules: JSON.parse(req.body ?? "{}").lifecycleRules,
    }))
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ lifecycleRules: RESTIC_LIFECYCLE }),
  );
  try {
    const out = await model.methods.create.execute({}, context);
    assertEquals(out.dataHandles, [{ name: BUCKET_NAME }]);

    // The create call is a POST with a JSON body carrying the rule verbatim.
    assertEquals(f.calls[1].method, "POST");
    assertStringIncludes(f.calls[1].url, "/b2api/v4/b2_create_bucket");
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(sent.accountId, ACCOUNT_ID);
    assertEquals(sent.bucketName, BUCKET_NAME);
    assertEquals(sent.bucketType, "allPrivate", "default must be allPrivate");
    assertEquals(sent.lifecycleRules, RESTIC_LIFECYCLE);

    // ... and comes back out of the snapshot unchanged, with the verdict.
    assertEquals(written.length, 1);
    assertEquals(written[0].spec, "bucket");
    assertEquals(written[0].name, BUCKET_NAME);
    assertEquals(written[0].data.lifecycleRules, RESTIC_LIFECYCLE);
    assertEquals(written[0].data.prunesHiddenVersions, true);
    assertEquals(written[0].data.minDaysFromHidingToDeleting, 1);
    assertEquals(written[0].data.unprunedPrefixes, []);
    assertEquals(written[0].data.exists, true);
    assertEquals(written[0].data.bucketId, BUCKET_ID);
    assertEquals(written[0].data.revision, 4);
    assertNoSecrets(written[0].data, "create bucket snapshot");
  } finally {
    f.restore();
  }
});

Deno.test("sync snapshots an unpruned bucket as prunesHiddenVersions=false and warns", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      buckets: [bucketBody({
        lifecycleRules: [{
          fileNamePrefix: "",
          daysFromUploadingToHiding: null,
          daysFromHidingToDeleting: null,
        }],
      })],
    })
  );
  const { context, written, logs } = makeContext(baseGlobalArgs());
  try {
    await model.methods.sync.execute({}, context);
    assertEquals(written[0].data.prunesHiddenVersions, false);
    assertEquals(written[0].data.minDaysFromHidingToDeleting, null);
    assertEquals(written[0].data.unprunedPrefixes, [""]);
    assert(
      logs.some((l) =>
        l.startsWith("WARN") && l.includes("daysFromHidingToDeleting")
      ),
      "sync must warn that hidden versions are retained forever",
    );
    // b2_list_buckets is filtered server-side by name — required for a
    // bucket-restricted key and it keeps the class-C call minimal.
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(sent.bucketName, BUCKET_NAME);
    assertNoSecrets(written[0].data, "sync bucket snapshot");
  } finally {
    f.restore();
  }
});

Deno.test("replicationConfigured unwraps .value — an authorized-but-unconfigured bucket reports false, not true", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json(authBody())
      : json({
        buckets: [bucketBody({
          replicationConfiguration: {
            isClientAuthorizedToRead: true,
            value: null,
          },
        })],
      })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    // Reading the wrapper instead of .value reported "configured" for all 24
    // buckets of a real account that had zero replication configured.
    assertEquals(written[0].data.replicationConfigured, false);
  } finally {
    f.restore();
  }
});

Deno.test("replicationConfigured is null — not false — when the key may not read it", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json(authBody())
      : json({
        buckets: [bucketBody({
          replicationConfiguration: {
            isClientAuthorizedToRead: false,
            value: null,
          },
        })],
      })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    // "Not authorized to see it" and "not configured" are different facts.
    // Collapsing them to false makes an audit quietly wrong.
    assertEquals(written[0].data.replicationConfigured, null);
  } finally {
    f.restore();
  }
});

Deno.test("replicationConfigured is true when replication is genuinely configured", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json(authBody())
      : json({
        buckets: [bucketBody({
          replicationConfiguration: {
            isClientAuthorizedToRead: true,
            value: { asReplicationSource: { replicationRules: [] } },
          },
        })],
      })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    assertEquals(written[0].data.replicationConfigured, true);
  } finally {
    f.restore();
  }
});

Deno.test("sync survives a bucket carrying a CORS rule whose element shape is unmodelled", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json(authBody())
      : json({
        buckets: [bucketBody({
          // A real B2 CORS rule, minus a field an over-strict schema would
          // have demanded. Structural typing here made sync hard-fail on the
          // first bucket that had any CORS rule at all.
          corsRules: [{
            corsRuleName: "downloadFromAnyOrigin",
            allowedOrigins: ["https://example.com"],
            allowedOperations: ["b2_download_file_by_id"],
          }],
        })],
      })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    assertEquals(written.length, 1, "sync must not reject the snapshot");
    assertEquals(
      (written[0].data.corsRules as unknown[]).length,
      1,
      "the rule must be passed through, not dropped",
    );
  } finally {
    f.restore();
  }
});

Deno.test("sync writes an exists=false snapshot when the bucket is absent", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ buckets: [] })
  );
  const { context, written } = makeContext(baseGlobalArgs());
  try {
    await model.methods.sync.execute({}, context);
    assertEquals(written[0].data.exists, false);
    assertEquals(written[0].data.bucketId, null);
    assertEquals(written[0].name, BUCKET_NAME);
  } finally {
    f.restore();
  }
});

Deno.test("update sends only supplied fields plus ifRevisionIs, and reuses globalArgs.bucketId", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json(bucketBody())
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID, lifecycleRules: RESTIC_LIFECYCLE }),
  );
  try {
    await model.methods.update.execute(
      { ifRevisionIs: 3, corsRules: undefined },
      context,
    );
    // Only two HTTP calls: authorize + update. No b2_list_buckets lookup,
    // because globalArgs.bucketId was supplied (saves a class-C transaction).
    assertEquals(f.calls.length, 2);
    assertStringIncludes(f.calls[1].url, "/b2api/v4/b2_update_bucket");
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(sent.bucketId, BUCKET_ID);
    assertEquals(sent.lifecycleRules, RESTIC_LIFECYCLE);
    assertEquals(sent.ifRevisionIs, 3);
    assertFalse("corsRules" in sent, "unsupplied fields must not be sent");
    assertFalse("defaultRetention" in sent);
    assertEquals(written[0].data.prunesHiddenVersions, true);
    assertNoSecrets(written[0].data, "update bucket snapshot");
  } finally {
    f.restore();
  }
});

Deno.test("update never sends an unrequested bucketType, so it cannot silently flip an allPublic bucket private", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json(bucketBody())
  );
  // An operator who only wants to fix lifecycle rules. bucketType is not
  // supplied here, nor in globalArgs. A schema-level .default("allPrivate")
  // used to make it present anyway, so this update would have flipped a live
  // allPublic bucket private without ever being asked to.
  const { context } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID, lifecycleRules: RESTIC_LIFECYCLE }),
  );
  try {
    await model.methods.update.execute({}, context);
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertFalse(
      "bucketType" in sent,
      "update must not send bucketType unless it was explicitly supplied",
    );
    assertEquals(sent.lifecycleRules, RESTIC_LIFECYCLE);
  } finally {
    f.restore();
  }
});

Deno.test("update still sends bucketType when it is explicitly supplied", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json(bucketBody())
  );
  const { context } = makeContext(baseGlobalArgs({ bucketId: BUCKET_ID }));
  try {
    await model.methods.update.execute({ bucketType: "allPrivate" }, context);
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(sent.bucketType, "allPrivate");
  } finally {
    f.restore();
  }
});

Deno.test("create still defaults to allPrivate when bucketType is unset", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json(bucketBody())
  );
  const { context } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.create.execute({}, context);
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(
      sent.bucketType,
      "allPrivate",
      "a new restic bucket must never default to allPublic",
    );
  } finally {
    f.restore();
  }
});

Deno.test("update fails loudly when the bucket does not exist", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ buckets: [] })
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ lifecycleRules: RESTIC_LIFECYCLE }),
  );
  try {
    await assertRejects(
      () => model.methods.update.execute({}, context),
      Error,
      "does not exist",
    );
    assertEquals(written.length, 0, "a failed update must write nothing");
  } finally {
    f.restore();
  }
});

// ---------------------------------------------------------------------------
// 7. Idempotent delete
// ---------------------------------------------------------------------------

Deno.test("delete succeeds normally and writes an exists=false snapshot", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json(bucketBody())
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  try {
    await model.methods.delete.execute({}, context);
    const sent = JSON.parse(f.calls[1].body ?? "{}");
    assertEquals(sent, { accountId: ACCOUNT_ID, bucketId: BUCKET_ID });
    assertEquals(written[0].data.exists, false);
    assertEquals(written[0].data.bucketId, null);
  } finally {
    f.restore();
  }
});

Deno.test("delete treats a 404 as an idempotent success", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ code: "not_found" }, 404)
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  try {
    await model.methods.delete.execute({}, context);
    // Two writes: the bucket tombstone, and a notificationRules tombstone so
    // infinite-lifetime webhook rules cannot outlive the bucket they targeted.
    assertEquals(written.length, 2);
    assertEquals(written[0].data.exists, false);
    assertEquals(written[1].name, `notification-rules-${BUCKET_NAME}`);
    assertEquals(written[1].data.ruleCount, 0);
    assertEquals(written[1].data.rules, []);
  } finally {
    f.restore();
  }
});

Deno.test("delete treats a 400 bad_bucket_id as an idempotent success", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ code: "bad_bucket_id" }, 400)
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  try {
    await model.methods.delete.execute({}, context);
    assertEquals(written.length, 2);
    assertEquals(written[0].data.exists, false);
    assertEquals(written[0].name, BUCKET_NAME);
    assertEquals(written[1].name, `notification-rules-${BUCKET_NAME}`);
  } finally {
    f.restore();
  }
});

Deno.test("delete tombstones notificationRules even when the bucketId never resolves", async () => {
  // The path the first version of this fix missed: no globalArgs.bucketId and
  // b2_list_buckets finds nothing. Guarding the tombstone on a resolved
  // bucketId left infinite-lifetime webhook rules alive on exactly the path
  // where the bucket is most likely to be a stale record already.
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody(null)) : json({ buckets: [] })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.delete.execute({}, context);
    assertEquals(written.length, 2, "both specs must be tombstoned");
    assertEquals(written[1].name, `notification-rules-${BUCKET_NAME}`);
    assertEquals(written[1].data.bucketId, null);
    assertEquals(written[1].data.ruleCount, 0);
  } finally {
    f.restore();
  }
});

Deno.test("delete short-circuits when the name resolves to no bucket", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ buckets: [] })
  );
  const { context, written } = makeContext(baseGlobalArgs());
  try {
    await model.methods.delete.execute({}, context);
    // authorize + list only — no b2_delete_bucket call at all.
    assertEquals(f.calls.length, 2);
    assertEquals(written[0].data.exists, false);
  } finally {
    f.restore();
  }
});

Deno.test("delete still propagates a genuine failure", async () => {
  const f = installFetch((_req, i) =>
    i === 0
      ? json(authBody())
      : json({ code: "cannot_delete_non_empty_bucket" }, 400)
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  try {
    await assertRejects(
      () => model.methods.delete.execute({}, context),
      Error,
      "cannot_delete_non_empty_bucket",
    );
    assertEquals(written.length, 0);
  } finally {
    f.restore();
  }
});

Deno.test("isAlreadyGone accepts only 404 and 400/bad_bucket_id", () => {
  assert(_internal.isAlreadyGone({ status: 404 }));
  assert(_internal.isAlreadyGone({ status: 400, b2Code: "bad_bucket_id" }));
  assertFalse(_internal.isAlreadyGone({ status: 400, b2Code: "bad_request" }));
  assertFalse(_internal.isAlreadyGone({ status: 401, b2Code: "unauthorized" }));
  assertFalse(_internal.isAlreadyGone(new Error("boom")));
});

// ---------------------------------------------------------------------------
// 8. Notification rules — GET with query params, POST, and redaction
// ---------------------------------------------------------------------------

/** A notification rule as B2 returns it, including the two secret fields. */
function notificationRuleBody(): Record<string, unknown> {
  return {
    name: "restic-prune-watch",
    eventTypes: ["b2:ObjectDeleted:*", "b2:HideMarkerCreated:Hide"],
    isEnabled: true,
    isSuspended: false,
    suspensionReason: "",
    objectNamePrefix: "",
    maxEventsPerBatch: 10,
    targetConfiguration: {
      targetType: "webhook",
      url: "https://hooks.example.com/b2",
      customHeaders: [{ name: "Authorization", value: HEADER_SECRET }],
      hmacSha256SigningSecret: SIGNING_SECRET,
    },
  };
}

Deno.test("get_notification_rules issues a GET with query parameters, not a POST body", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      bucketId: BUCKET_ID,
      eventNotificationRules: [notificationRuleBody()],
    })
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  try {
    await model.methods.get_notification_rules.execute({}, context);
    const call = f.calls[1];
    assertEquals(call.method, "GET");
    assertEquals(call.body, null, "a GET must carry no request body");
    assertEquals(
      call.url,
      `${API_URL}/b2api/v4/b2_get_bucket_notification_rules?bucketId=${BUCKET_ID}`,
    );
    assertEquals(written[0].spec, "notificationRules");
    // Instance names map onto storage paths and must be unique across ALL
    // specs — sharing the bare bucket name with the `bucket` spec would make
    // this write silently clobber the bucket snapshot on disk.
    assertEquals(written[0].name, `notification-rules-${BUCKET_NAME}`);
    assertEquals(written[0].data.ruleCount, 1);
  } finally {
    f.restore();
  }
});

Deno.test("notification-rule snapshots redact the signing secret and header values", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      bucketId: BUCKET_ID,
      eventNotificationRules: [notificationRuleBody()],
    })
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  try {
    await model.methods.get_notification_rules.execute({}, context);
    const rule = (written[0].data.rules as Record<string, unknown>[])[0];
    assertEquals(rule.name, "restic-prune-watch");
    assertEquals(rule.url, "https://hooks.example.com/b2");
    assertEquals(rule.eventTypes, [
      "b2:ObjectDeleted:*",
      "b2:HideMarkerCreated:Hide",
    ]);
    // Presence is recorded; the secret itself is not.
    assertEquals(rule.hasSigningSecret, true);
    assertEquals(rule.customHeaderNames, ["Authorization"]);
    assertFalse(
      "hmacSha256SigningSecret" in rule,
      "the signing secret field must not survive into a snapshot",
    );
    assertFalse("customHeaders" in rule, "header values must not survive");
    assertNoSecrets(written[0].data, "notification rules snapshot");
  } finally {
    f.restore();
  }
});

Deno.test("set_notification_rules POSTs the full replacement set and stores it redacted", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      bucketId: BUCKET_ID,
      eventNotificationRules: [notificationRuleBody()],
    })
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketId: BUCKET_ID }),
  );
  const rules = [
    _internal.NotificationRuleInputSchema.parse({
      name: "restic-prune-watch",
      eventTypes: ["b2:ObjectDeleted:*"],
      targetConfiguration: {
        url: "https://hooks.example.com/b2",
        customHeaders: [{ name: "Authorization", value: HEADER_SECRET }],
        hmacSha256SigningSecret: SIGNING_SECRET,
      },
    }),
  ];
  try {
    await model.methods.set_notification_rules.execute({ rules }, context);
    const call = f.calls[1];
    assertEquals(call.method, "POST");
    assertStringIncludes(call.url, "/b2api/v4/b2_set_bucket_notification_rules");
    const sent = JSON.parse(call.body ?? "{}");
    assertEquals(sent.bucketId, BUCKET_ID);
    // The secret IS sent to B2 — that is the whole point of the operation ...
    assertEquals(
      sent.eventNotificationRules[0].targetConfiguration
        .hmacSha256SigningSecret,
      SIGNING_SECRET,
    );
    assertEquals(sent.eventNotificationRules[0].objectNamePrefix, "");
    assertEquals(sent.eventNotificationRules[0].isEnabled, true);
    // ... but it must never reach a snapshot.
    assertNoSecrets(written[0].data, "set_notification_rules snapshot");
  } finally {
    f.restore();
  }
});

Deno.test("the notification-rule schema rejects a malformed event type", () => {
  const bad = _internal.NotificationRuleInputSchema.safeParse({
    name: "bad",
    eventTypes: ["s3:ObjectCreated:Put"],
    targetConfiguration: { url: "https://hooks.example.com/b2" },
  });
  assertFalse(bad.success, "only b2:<Category>:<Event|*> event types are legal");
  const good = _internal.NotificationRuleInputSchema.safeParse({
    name: "good",
    eventTypes: ["b2:ObjectCreated:*"],
    targetConfiguration: { url: "https://hooks.example.com/b2" },
  });
  assert(good.success);
});

// ---------------------------------------------------------------------------
// 9. The hidden-version-retention policy check
// ---------------------------------------------------------------------------

const retentionCheck = model.checks["lifecycle-hidden-version-retention"];

/** Minimal check context; `dataRepository` is omitted unless a test needs it. */
function checkContext(
  globalArgs: Record<string, unknown>,
  getContent?: () => Promise<Uint8Array | null>,
): Parameters<typeof retentionCheck.execute>[0] {
  return {
    globalArgs: _internal.GlobalArgsSchema.parse(globalArgs),
    modelType: "@sntxrr/b2/bucket",
    modelId: "model-id",
    logger: { info: () => {}, warn: () => {} },
    dataRepository: getContent ? { getContent } : undefined,
  };
}

Deno.test("the policy check is labelled and scoped to create/update only", () => {
  assertEquals(retentionCheck.labels, ["policy"]);
  assertEquals(retentionCheck.appliesTo, ["create", "update"]);
});

Deno.test("the policy check fails when the declared rules never delete hidden versions", async () => {
  const result = await retentionCheck.execute(checkContext(baseGlobalArgs({
    lifecycleRules: [{
      fileNamePrefix: "",
      daysFromUploadingToHiding: 30,
      daysFromHidingToDeleting: null,
    }],
  })));
  assertFalse(result.pass);
  assertStringIncludes(result.errors?.[0] ?? "", "daysFromHidingToDeleting");
  assertStringIncludes(result.errors?.[0] ?? "", "forever");
});

Deno.test("the policy check passes on a restic-safe rule", async () => {
  const result = await retentionCheck.execute(
    checkContext(baseGlobalArgs({ lifecycleRules: RESTIC_LIFECYCLE })),
  );
  assert(result.pass);
});

Deno.test("the policy check fails when nothing is declared and nothing was observed", async () => {
  const result = await retentionCheck.execute(checkContext(baseGlobalArgs()));
  assertFalse(result.pass);
  assertStringIncludes(result.errors?.[0] ?? "", "no lifecycleRules are declared");
});

Deno.test("the policy check accepts a prior snapshot proving the bucket prunes", async () => {
  const stored = new TextEncoder().encode(
    JSON.stringify({ attributes: { prunesHiddenVersions: true } }),
  );
  const result = await retentionCheck.execute(
    checkContext(baseGlobalArgs(), () => Promise.resolve(stored)),
  );
  assert(result.pass);
});

Deno.test("the policy check rejects a prior snapshot that proves the opposite", async () => {
  const stored = new TextEncoder().encode(
    JSON.stringify({ prunesHiddenVersions: false }),
  );
  const result = await retentionCheck.execute(
    checkContext(baseGlobalArgs(), () => Promise.resolve(stored)),
  );
  assertFalse(result.pass);
});

Deno.test("the policy check is waived by allowUnprunedHiddenVersions", async () => {
  const result = await retentionCheck.execute(
    checkContext(baseGlobalArgs({ allowUnprunedHiddenVersions: true })),
  );
  assert(result.pass);
});

// ---------------------------------------------------------------------------
// 10. Model shape and global no-secret sweep
// ---------------------------------------------------------------------------

Deno.test("the two resource specs never share an instance name", () => {
  assertEquals(
    _internal.notificationRulesInstanceName(BUCKET_NAME),
    `notification-rules-${BUCKET_NAME}`,
  );
  assert(
    _internal.notificationRulesInstanceName(BUCKET_NAME) !== BUCKET_NAME,
    "sharing an instance name across specs overwrites data on disk",
  );
});

Deno.test("the model exposes the six documented methods and is not keyed on 'latest'", () => {
  assertEquals(model.type, "@sntxrr/b2/bucket");
  assertEquals(Object.keys(model.methods).sort(), [
    "create",
    "delete",
    "get_notification_rules",
    "set_notification_rules",
    "sync",
    "update",
  ]);
  // Resource spec keys must not contain hyphens.
  for (const spec of Object.keys(model.resources)) {
    assertFalse(spec.includes("-"), `resource spec "${spec}" must not contain '-'`);
  }
});

Deno.test("applicationKey is marked sensitive in the global argument schema", () => {
  const shape = _internal.GlobalArgsSchema.shape;
  assertEquals(
    (shape.applicationKey.meta() as { sensitive?: boolean } | undefined)
      ?.sensitive,
    true,
  );
});

Deno.test("no method writes a resource containing a secret", async () => {
  const scenarios: Array<{
    name: string;
    run: (ctx: ReturnType<typeof makeContext>["context"]) => Promise<unknown>;
    respond: (req: Recorded, i: number) => Response;
    globals: Record<string, unknown>;
  }> = [
    {
      name: "sync",
      globals: baseGlobalArgs({ bucketId: BUCKET_ID }),
      respond: (_r, i) =>
        i === 0 ? json(authBody()) : json({ buckets: [bucketBody()] }),
      run: (ctx) => model.methods.sync.execute({}, ctx),
    },
    {
      name: "create",
      globals: baseGlobalArgs({ lifecycleRules: RESTIC_LIFECYCLE }),
      respond: (_r, i) => i === 0 ? json(authBody()) : json(bucketBody()),
      run: (ctx) => model.methods.create.execute({}, ctx),
    },
    {
      name: "update",
      globals: baseGlobalArgs({
        bucketId: BUCKET_ID,
        lifecycleRules: RESTIC_LIFECYCLE,
      }),
      respond: (_r, i) => i === 0 ? json(authBody()) : json(bucketBody()),
      run: (ctx) => model.methods.update.execute({}, ctx),
    },
    {
      name: "delete",
      globals: baseGlobalArgs({ bucketId: BUCKET_ID }),
      respond: (_r, i) => i === 0 ? json(authBody()) : json(bucketBody()),
      run: (ctx) => model.methods.delete.execute({}, ctx),
    },
    {
      name: "get_notification_rules",
      globals: baseGlobalArgs({ bucketId: BUCKET_ID }),
      respond: (_r, i) =>
        i === 0 ? json(authBody()) : json({
          bucketId: BUCKET_ID,
          eventNotificationRules: [notificationRuleBody()],
        }),
      run: (ctx) => model.methods.get_notification_rules.execute({}, ctx),
    },
    {
      name: "set_notification_rules",
      globals: baseGlobalArgs({ bucketId: BUCKET_ID }),
      respond: (_r, i) =>
        i === 0 ? json(authBody()) : json({
          bucketId: BUCKET_ID,
          eventNotificationRules: [notificationRuleBody()],
        }),
      run: (ctx) =>
        model.methods.set_notification_rules.execute({
          rules: [
            _internal.NotificationRuleInputSchema.parse({
              name: "r",
              eventTypes: ["b2:ObjectDeleted:*"],
              targetConfiguration: {
                url: "https://hooks.example.com/b2",
                hmacSha256SigningSecret: SIGNING_SECRET,
                customHeaders: [{ name: "Authorization", value: HEADER_SECRET }],
              },
            }),
          ],
        }, ctx),
    },
  ];

  for (const scenario of scenarios) {
    const f = installFetch(scenario.respond);
    const { context, written, logs } = makeContext(scenario.globals);
    try {
      await scenario.run(context);
      assert(written.length > 0, `${scenario.name} must write a snapshot`);
      for (const w of written) {
        assertNoSecrets(w.data, `${scenario.name} -> ${w.spec}`);
        assert(
          w.name !== "latest",
          `${scenario.name} must not key a resource as the reserved name "latest"`,
        );
        // Every instance name is derived from the real bucket name, and the
        // two specs never share one (shared names overwrite each other).
        assertStringIncludes(w.name, BUCKET_NAME);
        assertEquals(
          w.name,
          w.spec === "bucket"
            ? BUCKET_NAME
            : _internal.notificationRulesInstanceName(BUCKET_NAME),
        );
      }
      assertNoSecrets(logs, `${scenario.name} log lines`);
    } finally {
      f.restore();
    }
  }
});

Deno.test("a bucket legitimately named 'latest' does not wedge on the reserved data name", async () => {
  // "latest" is 6 characters, so it is a legal B2 bucket name (6-63) and the
  // namespace is global — someone owns it. swamp reserves "latest" as a data
  // name and rejects it at run time only, so keying the snapshot on the bare
  // bucket name makes this bucket unmanageable with an opaque failure.
  const f = installFetch((_req, i) =>
    i === 0
      ? json(authBody([{ id: BUCKET_ID, name: "latest" }]))
      : json({ buckets: [bucketBody({ bucketName: "latest" })] })
  );
  const { context, written } = makeContext(
    baseGlobalArgs({ bucketName: "latest" }),
  );
  try {
    await model.methods.sync.execute({}, context);
    const bucketWrite = written.find((w) => w.spec === "bucket");
    assert(bucketWrite, "sync must write a bucket snapshot");
    assertEquals(
      bucketWrite.name,
      "bucket-latest",
      "the reserved name must be aliased, not passed through",
    );
    // The snapshot still records the real bucket name; only the key is aliased.
    assertEquals(bucketWrite.data.bucketName, "latest");
  } finally {
    f.restore();
  }
});

Deno.test("every method that snapshots a bucket named 'latest' aliases the key", async () => {
  // A guard that covers `sync` but not the tombstone path would leave the one
  // case it was written for broken: `delete` must write a snapshot even when
  // the bucket was never found and no bucketId ever resolved.
  const cases: Array<{ label: string; method: string; handler: (i: number) => Response }> = [
    {
      label: "sync",
      method: "sync",
      handler: (i) =>
        i === 0
          ? json(authBody([{ id: BUCKET_ID, name: "latest" }]))
          : json({ buckets: [bucketBody({ bucketName: "latest" })] }),
    },
    {
      label: "create",
      method: "create",
      handler: (i) =>
        i === 0
          ? json(authBody([{ id: BUCKET_ID, name: "latest" }]))
          : json(bucketBody({ bucketName: "latest" })),
    },
    {
      label: "update",
      method: "update",
      handler: (i) =>
        i === 0
          ? json(authBody([{ id: BUCKET_ID, name: "latest" }]))
          : json(bucketBody({ bucketName: "latest" })),
    },
    {
      label: "delete (bucket already gone — bucketId never resolves)",
      method: "delete",
      handler: (i) =>
        i === 0
          ? json(authBody([{ id: BUCKET_ID, name: "latest" }]))
          : json({ code: "not_found" }, 404),
    },
  ];

  for (const c of cases) {
    const f = installFetch((_req, i) => c.handler(i));
    const { context, written } = makeContext(
      baseGlobalArgs({
        bucketName: "latest",
        bucketId: BUCKET_ID,
        lifecycleRules: RESTIC_LIFECYCLE,
      }),
    );
    try {
      await (model.methods as Record<string, {
        execute: (a: unknown, c: unknown) => Promise<unknown>;
      }>)[c.method].execute({}, context);
      const bucketWrite = written.find((w) => w.spec === "bucket");
      assert(bucketWrite, `${c.label} must write a bucket snapshot`);
      assertEquals(
        bucketWrite.name,
        "bucket-latest",
        `${c.label} must alias the reserved name`,
      );
      assertEquals(
        bucketWrite.data.bucketName,
        "latest",
        `${c.label} must keep the real bucket name in the snapshot`,
      );
    } finally {
      f.restore();
    }
  }
});

Deno.test("sync survives a bucketInfo value B2 did not return as a string", async () => {
  // bucketInfo is free-form, user-supplied metadata. Typing the read-back
  // strictly as Record<string,string> makes the whole snapshot unwritable when
  // one value is not a string — the same trap documented on corsRules, and the
  // sibling b2-account model already types this exact B2 field permissively.
  // Strict on what we SEND, permissive on what we READ.
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      buckets: [bucketBody({
        bucketInfo: { owner: "restic", retentionDays: 30, archived: null },
      })],
    })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    const snap = written.find((w) => w.spec === "bucket");
    assert(snap, "sync must write a bucket snapshot");
    assertEquals(snap.data.bucketInfo, {
      owner: "restic",
      retentionDays: 30,
      archived: null,
    }, "the metadata must round-trip verbatim, not be coerced or dropped");
  } finally {
    f.restore();
  }
});

Deno.test("sync survives an options element B2 did not return as a string", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      buckets: [bucketBody({ options: ["s3", 42] })],
    })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    const snap = written.find((w) => w.spec === "bucket");
    assert(snap, "sync must write a bucket snapshot");
    // Coerced, not dropped: losing an element would understate what B2 reported.
    assertEquals(snap.data.options, ["s3", "42"]);
  } finally {
    f.restore();
  }
});

Deno.test("bucketInfo is permissive on read but still strict on what we send", () => {
  // The asymmetry is deliberate — do not "fix" the send side to match. B2
  // requires string values on create/update, so sending an unmodelled value
  // would fail at the API instead of at the schema, with a worse message.
  const g = _internal.GlobalArgsSchema;
  assertEquals(
    g.safeParse({
      applicationKeyId: "x",
      applicationKey: "y",
      bucketName: BUCKET_NAME,
      bucketInfo: { retentionDays: 30 },
    }).success,
    false,
    "globalArgs.bucketInfo must reject a non-string value",
  );
  assertEquals(
    _internal.BucketResourceSchema.safeParse({
      ..._internal.toBucketResource(BUCKET_NAME, bucketBody(), "2026-01-01T00:00:00Z"),
      bucketInfo: { retentionDays: 30 },
    }).success,
    true,
    "the resource schema must accept what B2 actually returned",
  );
});

Deno.test("the snapshot records the Object Lock retention period, not just the mode", async () => {
  // The model can SET defaultRetention.period but recorded only the mode, so a
  // sync could not verify what it had just written and an audit could not tell
  // a 1-day immutability window from a 10-year one — the difference between a
  // usable ransomware guard and data that cannot be deleted for a decade.
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({
      buckets: [bucketBody({
        fileLockConfiguration: {
          isClientAuthorizedToRead: true,
          value: {
            isFileLockEnabled: true,
            defaultRetention: {
              mode: "governance",
              period: { duration: 7, unit: "days" },
            },
          },
        },
      })],
    })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    const snap = written.find((w) => w.spec === "bucket");
    assert(snap, "sync must write a bucket snapshot");
    assertEquals(snap.data.fileLockEnabled, true);
    assertEquals(snap.data.defaultRetentionMode, "governance");
    assertEquals(snap.data.defaultRetentionPeriod, {
      duration: 7,
      unit: "days",
    });
  } finally {
    f.restore();
  }
});

Deno.test("a bucket with no default retention records a null period, not a missing field", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ buckets: [bucketBody()] })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    const snap = written.find((w) => w.spec === "bucket");
    assert(snap, "sync must write a bucket snapshot");
    assertEquals(snap.data.defaultRetentionMode, null);
    assertEquals(snap.data.defaultRetentionPeriod, null);
  } finally {
    f.restore();
  }
});

Deno.test("a half-read retention period is reported as null, not as a concrete window", () => {
  // "7" with no unit is not a 7-day lock and not a 7-year one. Reporting the
  // duration alone would read as a verified immutability window that nothing
  // verified; null at least says "unknown".
  const half = _internal.toBucketResource(
    BUCKET_NAME,
    bucketBody({
      fileLockConfiguration: {
        isClientAuthorizedToRead: true,
        value: {
          isFileLockEnabled: true,
          defaultRetention: { mode: "governance", period: { duration: 7 } },
        },
      },
    }),
    "2026-01-01T00:00:00Z",
  );
  assertEquals(half.defaultRetentionMode, "governance");
  assertEquals(half.defaultRetentionPeriod, null);
  assertEquals(
    _internal.BucketResourceSchema.safeParse(half).success,
    true,
    "a half-read period must still produce a writable snapshot",
  );
});

Deno.test("a bucket with NO lifecycle rules reports every prefix as unpruned", () => {
  // Live finding, 2026-08-05: a real bucket with lifecycleRules: [] snapshotted
  // unprunedPrefixes: [] — which reads as "no prefix accumulates hidden
  // versions" when the truth is that ALL of them do. A consumer looking for
  // bleeding buckets with `unprunedPrefixes.length > 0` would skip exactly the
  // worst case: a bucket with no retention rule at all.
  //
  // No rules is semantically identical to one rule covering every file that
  // never deletes, so it must report the same way: [""].
  const none = _internal.analyzeHiddenVersionRetention([]);
  assertEquals(none.prunesHiddenVersions, false);
  assertEquals(none.minDaysFromHidingToDeleting, null);
  assertEquals(
    none.unprunedPrefixes,
    [""],
    'no rules means all files accumulate — the empty prefix, not an empty list',
  );

  // An explicit catch-all rule that never deletes must produce the same answer.
  const explicit = _internal.analyzeHiddenVersionRetention([
    { fileNamePrefix: "", daysFromUploadingToHiding: null, daysFromHidingToDeleting: null },
  ]);
  assertEquals(explicit.unprunedPrefixes, none.unprunedPrefixes);
  assertEquals(explicit.prunesHiddenVersions, none.prunesHiddenVersions);
});

Deno.test("sync of a rule-less bucket writes the all-files unpruned marker", async () => {
  const f = installFetch((_req, i) =>
    i === 0 ? json(authBody()) : json({ buckets: [bucketBody({ lifecycleRules: [] })] })
  );
  const { context, written } = makeContext(baseGlobalArgs({}));
  try {
    await model.methods.sync.execute({}, context);
    const snap = written.find((w) => w.spec === "bucket");
    assert(snap);
    assertEquals(snap.data.prunesHiddenVersions, false);
    assertEquals(snap.data.unprunedPrefixes, [""]);
  } finally {
    f.restore();
  }
});
