/**
 * Unit tests for b2_key.ts — v4 auth shape, cursor pagination, retry/reauth
 * semantics, idempotent delete, the fail-closed `create` gate, the 1Password
 * Connect destructive-replace trap, and secret hygiene. `fetch` is mocked
 * throughout; no live B2 or Connect calls are made.
 * @module
 */
import { assert, assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import {
  b2Authorize,
  b2Fetch,
  b2ListAll,
  isAlreadyGone,
  mergeSecretFields,
  model,
  toKeyResource,
} from "./b2_key.ts";

// Fake, non-real identifiers (CONVENTIONS §8: published-surface hygiene).
const KEY_ID = "4a48fe8875c6214145260818";
const NEW_KEY_ID = "0021eb9c3dcf1120000000003";
const SECRET = "K004ZZZZfakefakefakefakefakefake";
const API_URL = "https://api002.backblazeb2.com";
const CONNECT = "http://connect.example.com:8080";
const VAULT_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const ITEM_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbb";

const AUTH = {
  accountId: "abc123def456",
  authorizationToken: "4_002_fake_auth_token",
  apiUrl: API_URL,
  downloadUrl: "https://f002.backblazeb2.com",
  s3ApiUrl: "https://s3.us-west-002.backblazeb2.com",
  allowed: { buckets: [], capabilities: ["listKeys"], namePrefix: null },
};

const BASE_GLOBALS = {
  applicationKeyId: KEY_ID,
  applicationKey: "K004fakefakefakefakefakefakefake",
  accountId: "abc123def456",
  connectItemCategory: "API_CREDENTIAL",
  connectKeyIdFieldLabel: "applicationKeyId",
  connectKeyFieldLabel: "applicationKey",
  connectTimeoutMs: 5000,
};

const CONNECT_GLOBALS = {
  ...BASE_GLOBALS,
  connectHost: CONNECT,
  connectToken: "fake-connect-token",
  connectVaultId: VAULT_ID,
  connectItemTitle: "b2-restic-example",
};

// deno-lint-ignore no-explicit-any
type AnyCtx = any;

function makeContext(globalArgs: Record<string, unknown>): {
  ctx: AnyCtx;
  writes: Array<{ spec: string; name: string; data: Record<string, unknown> }>;
  warnings: string[];
} {
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const warnings: string[] = [];
  const ctx = {
    // Parse rather than pass through: defaults and coercions declared on the
    // global-argument schema are part of the contract a real run applies.
    globalArgs: model.globalArguments.parse(globalArgs),
    logger: {
      info: () => {},
      warn: (m: string) => {
        warnings.push(m);
      },
    },
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
  return { ctx, writes, warnings };
}

type Call = { url: string; init: RequestInit };

async function withMockedFetch<T>(
  handler: (url: string, init: RequestInit, calls: Call[]) => Response,
  fn: (calls: Call[]) => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  const calls: Call[] = [];
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const i = init ?? {};
    calls.push({ url, init: i });
    return Promise.resolve(handler(url, i, calls));
  }) as typeof globalThis.fetch;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), { status, headers });
}

/** The v4 authorize body, with everything nested under apiInfo.storageApi. */
function authBody(
  buckets: Array<{ id: string; name: string }> | null = [{
    id: "b1",
    name: "example-bucket",
  }],
): unknown {
  return {
    accountId: AUTH.accountId,
    authorizationToken: AUTH.authorizationToken,
    applicationKeyExpirationTimestamp: null,
    apiInfo: {
      storageApi: {
        apiUrl: API_URL,
        downloadUrl: AUTH.downloadUrl,
        s3ApiUrl: AUTH.s3ApiUrl,
        recommendedPartSize: 100000000,
        absoluteMinimumPartSize: 5000000,
        allowed: {
          buckets,
          capabilities: ["listKeys", "writeKeys", "deleteKeys"],
          namePrefix: null,
        },
      },
    },
  };
}

// --- 1. v4 auth shape -------------------------------------------------------

Deno.test("b2Authorize reads the nested v4 apiInfo.storageApi shape", async () => {
  await withMockedFetch(
    () => json(authBody()),
    async (calls) => {
      const auth = await b2Authorize({
        applicationKeyId: KEY_ID,
        applicationKey: "secret",
      });
      assertEquals(auth.apiUrl, API_URL);
      assertEquals(auth.accountId, AUTH.accountId);
      // allowed.buckets is an ARRAY in v4; the removed scalar bucketId is gone.
      assertEquals(auth.allowed.buckets, [{ id: "b1", name: "example-bucket" }]);
      assertEquals(auth.allowed.capabilities.includes("writeKeys"), true);
      // Only b2_authorize_account uses the well-known host.
      assertStringIncludes(calls[0].url, "api.backblazeb2.com");
      assertStringIncludes(calls[0].url, "/b2api/v4/b2_authorize_account");
      const headers = calls[0].init.headers as Record<string, string>;
      assertStringIncludes(headers.Authorization, "Basic ");
    },
  );
});

Deno.test("b2Authorize normalizes a null allowed.buckets to an empty array", async () => {
  await withMockedFetch(
    () => json(authBody(null)),
    async () => {
      const auth = await b2Authorize({
        applicationKeyId: KEY_ID,
        applicationKey: "secret",
      });
      assertEquals(auth.allowed.buckets, []);
    },
  );
});

Deno.test("b2Authorize surfaces a non-2xx status", async () => {
  await withMockedFetch(
    () => new Response("nope", { status: 401 }),
    async () => {
      await assertRejects(
        () =>
          b2Authorize({ applicationKeyId: KEY_ID, applicationKey: "secret" }),
        Error,
        "B2 authorize failed (401)",
      );
    },
  );
});

// --- 1b. the v4 shape guard on a 2xx authorize ------------------------------

const SHAPE_CREDS = { applicationKeyId: KEY_ID, applicationKey: SECRET };

/**
 * Authorize against a mocked 2xx body and return the Error it threw.
 *
 * A 2xx that is not the v4 shape is the dangerous case: without the guard
 * `apiUrl` would be `undefined`, every later call would target
 * `undefined/b2api/v4/...`, and the real cause would be several frames away.
 */
async function authorizeShapeError(body: unknown): Promise<Error> {
  return await withMockedFetch(
    () => json(body),
    () => assertRejects(() => b2Authorize(SHAPE_CREDS), Error),
  );
}

/** Assert the guard's message tells an operator what is wrong and where. */
function assertActionable(err: Error): void {
  assertStringIncludes(err.message, "apiInfo.storageApi");
  assertStringIncludes(err.message, "apiUrl / downloadUrl / s3ApiUrl");
  assertStringIncludes(err.message, "/b2api/v4/b2_authorize_account");
  // Diagnosing a bad response must never echo the credentials used.
  assertEquals(err.message.includes(SECRET), false);
  assertEquals(err.message.includes(KEY_ID), false);
}

Deno.test("b2Authorize rejects a 2xx v2/v3-style FLAT body", async () => {
  // The v2/v3 shape: apiUrl at the top level, no apiInfo at all. Copying an
  // older example produces exactly this, and it must not be accepted.
  assertActionable(
    await authorizeShapeError({
      accountId: AUTH.accountId,
      authorizationToken: AUTH.authorizationToken,
      apiUrl: API_URL,
      downloadUrl: AUTH.downloadUrl,
      s3ApiUrl: AUTH.s3ApiUrl,
      allowed: { capabilities: ["listKeys"], bucketId: null },
    }),
  );
  // apiInfo present but storageApi missing (e.g. a groups-only response).
  assertActionable(
    await authorizeShapeError({
      accountId: AUTH.accountId,
      authorizationToken: AUTH.authorizationToken,
      apiInfo: { groupsApi: { groupsApiUrl: API_URL, capabilities: [] } },
    }),
  );
});

Deno.test("b2Authorize rejects a storageApi missing downloadUrl", async () => {
  assertActionable(
    await authorizeShapeError({
      accountId: AUTH.accountId,
      authorizationToken: AUTH.authorizationToken,
      apiInfo: {
        storageApi: {
          apiUrl: API_URL,
          s3ApiUrl: AUTH.s3ApiUrl,
          allowed: { buckets: [], capabilities: [], namePrefix: null },
        },
      },
    }),
  );
});

Deno.test("b2Authorize rejects a storageApi missing s3ApiUrl", async () => {
  assertActionable(
    await authorizeShapeError({
      accountId: AUTH.accountId,
      authorizationToken: AUTH.authorizationToken,
      apiInfo: {
        storageApi: {
          apiUrl: API_URL,
          downloadUrl: AUTH.downloadUrl,
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
  await withMockedFetch(
    () =>
      json({
        accountId: AUTH.accountId,
        authorizationToken: AUTH.authorizationToken,
        apiInfo: {
          storageApi: {
            apiUrl: API_URL,
            downloadUrl: AUTH.downloadUrl,
            s3ApiUrl: AUTH.s3ApiUrl,
          },
        },
      }),
    async () => {
      const auth = await b2Authorize(SHAPE_CREDS);
      assertEquals(auth.apiUrl, API_URL);
      assertEquals(auth.allowed.buckets, []);
      assertEquals(auth.allowed.capabilities, []);
      assertEquals(auth.allowed.namePrefix, null);
    },
  );
});

// --- 2/3. pagination --------------------------------------------------------

Deno.test("b2ListAll drains two pages and renames next* to start*", async () => {
  let page = 0;
  await withMockedFetch(
    () => {
      page += 1;
      return page === 1
        ? json({
          keys: [{ applicationKeyId: "k1" }],
          nextApplicationKeyId: "k2",
        })
        : json({ keys: [{ applicationKeyId: "k2" }], nextApplicationKeyId: null });
    },
    async (calls) => {
      const res = await b2ListAll<{ applicationKeyId: string }>(
        AUTH,
        "b2_list_keys",
        { accountId: AUTH.accountId },
        "keys",
      );
      assertEquals(res.truncated, false);
      assertEquals(res.items.map((k) => k.applicationKeyId), ["k1", "k2"]);
      // The second request must carry the renamed cursor.
      const second = JSON.parse(String(calls[1].init.body));
      assertEquals(second.startApplicationKeyId, "k2");
      assertEquals(second.accountId, AUTH.accountId);
      // b2_list_keys accepts POST with a JSON body in v4.
      assertEquals(calls[1].init.method, "POST");
      assertStringIncludes(calls[1].url, `${API_URL}/b2api/v4/b2_list_keys`);
    },
  );
});

Deno.test("b2ListAll sets truncated when maxPages is exhausted", async () => {
  await withMockedFetch(
    () => json({ keys: [{ applicationKeyId: "k" }], nextApplicationKeyId: "k+1" }),
    async () => {
      const res = await b2ListAll(AUTH, "b2_list_keys", {}, "keys", 3);
      assertEquals(res.truncated, true);
      assertEquals(res.items.length, 3);
    },
  );
});

// --- 4/5. reauth + retry ----------------------------------------------------

Deno.test("b2Fetch re-authorizes exactly once on expired_auth_token", async () => {
  let reauths = 0;
  let n = 0;
  await withMockedFetch(
    () => {
      n += 1;
      return n === 1
        ? json({ code: "expired_auth_token" }, 401)
        : json({ ok: true });
    },
    async (calls) => {
      const out = await b2Fetch<{ ok: boolean }>(
        AUTH,
        "POST",
        "b2_list_keys",
        {},
        () => {
          reauths += 1;
          return Promise.resolve(AUTH);
        },
      );
      assertEquals(out.ok, true);
      assertEquals(reauths, 1);
      assertEquals(calls.length, 2);
    },
  );
});

Deno.test("b2Fetch retries a 429 honoring Retry-After", async () => {
  let n = 0;
  await withMockedFetch(
    () => {
      n += 1;
      return n === 1
        ? json({ code: "too_many_requests" }, 429, { "retry-after": "1" })
        : json({ ok: true });
    },
    async (calls) => {
      const out = await b2Fetch<{ ok: boolean }>(AUTH, "POST", "b2_list_keys", {});
      assertEquals(out.ok, true);
      assertEquals(calls.length, 2);
    },
  );
});

Deno.test("b2Fetch throws a non-transient 400 with b2Code populated", async () => {
  await withMockedFetch(
    () => json({ code: "bad_request", message: "illegal value" }, 400),
    async (calls) => {
      const err = await assertRejects(
        () => b2Fetch(AUTH, "POST", "b2_create_key", {}),
        Error,
        "bad_request",
      ) as Error & { status: number; b2Code: string };
      assertEquals(err.status, 400);
      assertEquals(err.b2Code, "bad_request");
      assertEquals(calls.length, 1, "a 400 must not be retried");
    },
  );
});

Deno.test("a missing-capability 401 is not transient and is never retried", async () => {
  await withMockedFetch(
    () =>
      json({
        status: 401,
        code: "unauthorized",
        message: "not authorized to perform this operation",
      }, 401),
    async (calls) => {
      const err = await assertRejects(
        // A reauth closure IS supplied: only `expired_auth_token` may use it.
        () =>
          b2Fetch(AUTH, "POST", "b2_create_key", {}, () => {
            throw new Error("reauth must not be attempted for `unauthorized`");
          }),
        Error,
        "unauthorized",
      ) as Error & { status: number; b2Code: string };
      assertEquals(err.status, 401);
      assertEquals(err.b2Code, "unauthorized");
      assertEquals(calls.length, 1, "a capability 401 is permanent, not transient");
    },
  );
});

// --- 6. fail-closed create --------------------------------------------------

// Swamp applies zod defaults before calling execute, so allowDuplicateName is
// always present at runtime; the tests supply it explicitly for the same reason.
const CREATE_INPUT = {
  keyName: "restic-example",
  capabilities: ["listBuckets", "listFiles", "readFiles", "writeFiles", "deleteFiles"],
  bucketIds: ["b1"],
  allowDuplicateName: false,
};

Deno.test("create FAILS CLOSED when no 1Password Connect destination is configured", async () => {
  const { ctx, writes } = makeContext(BASE_GLOBALS);
  await withMockedFetch(
    () => {
      throw new Error("no network call may happen before the fail-closed gate");
    },
    async (calls) => {
      const err = await assertRejects(
        () => model.methods.create.execute(CREATE_INPUT, ctx),
        Error,
      );
      assertStringIncludes(err.message, "Refusing to mint");
      assertStringIncludes(err.message, "connectHost");
      assertStringIncludes(err.message, "exactly once");
      assertStringIncludes(err.message, "revoked");
      // Nothing was minted and nothing was recorded.
      assertEquals(calls.length, 0);
      assertEquals(writes.length, 0);
    },
  );
});

Deno.test("create fails closed when the Connect destination is only partly configured", async () => {
  const { ctx } = makeContext({
    ...BASE_GLOBALS,
    connectHost: CONNECT,
    connectToken: "fake-connect-token",
    // no vault, no item
  });
  await withMockedFetch(
    () => {
      throw new Error("unreachable");
    },
    async (calls) => {
      const err = await assertRejects(
        () => model.methods.create.execute(CREATE_INPUT, ctx),
        Error,
      );
      assertStringIncludes(err.message, "connectVaultId");
      assertEquals(calls.length, 0);
    },
  );
});

Deno.test("the secret-destination-configured check fails closed and is scoped to create", async () => {
  assertEquals(model.checks["secret-destination-configured"].appliesTo, [
    "create",
  ]);
  const bad = model.checks["secret-destination-configured"].execute({
    // deno-lint-ignore no-explicit-any
    globalArgs: BASE_GLOBALS as any,
  });
  assertEquals(bad.pass, false);
  assertStringIncludes(String(bad.errors?.[0]), "Refusing to mint");

  const good = model.checks["secret-destination-configured"].execute({
    // deno-lint-ignore no-explicit-any
    globalArgs: CONNECT_GLOBALS as any,
  });
  assertEquals(good.pass, true);
});

// --- 7. create success: metadata in, secret out -----------------------------

/**
 * Route a full happy-path `create`: Connect item lookup + write, B2 authorize,
 * b2_create_key.
 */
function createRouter(existingFields: unknown[] | null, existingKeys: unknown[] = []) {
  return (url: string, init: RequestInit): Response => {
    if (url.includes("b2_authorize_account")) return json(authBody());
    if (url.includes("b2_list_keys")) {
      return json({ keys: existingKeys, nextApplicationKeyId: null });
    }
    if (url.includes("b2_create_key")) {
      const body = JSON.parse(String(init.body));
      return json({
        accountId: AUTH.accountId,
        applicationKeyId: NEW_KEY_ID,
        applicationKey: SECRET, // one-shot secret
        keyName: body.keyName,
        capabilities: body.capabilities,
        bucketIds: body.bucketIds,
        namePrefix: body.namePrefix ?? undefined,
        expirationTimestamp: 1785000000000,
        options: ["s3"],
      });
    }
    // Connect: item search
    if (url.includes(`/v1/vaults/${VAULT_ID}/items?filter=`)) {
      return json(existingFields === null ? [] : [{ id: ITEM_ID }]);
    }
    // Connect: item fetch
    if (url.endsWith(`/v1/vaults/${VAULT_ID}/items/${ITEM_ID}`) && !init.method) {
      return json({
        id: ITEM_ID,
        title: "b2-restic-example",
        vault: { id: VAULT_ID },
        category: "API_CREDENTIAL",
        tags: ["homelab"],
        fields: existingFields,
      });
    }
    // Connect: item update (PUT) or create (POST)
    if (url.includes(`/v1/vaults/${VAULT_ID}/items`)) {
      return json({ id: ITEM_ID });
    }
    throw new Error(`unexpected request: ${init.method ?? "GET"} ${url}`);
  };
}

Deno.test("create snapshots metadata and provably NOT the secret", async () => {
  const { ctx, writes } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    createRouter(null),
    async () => {
      const out = await model.methods.create.execute(
        { ...CREATE_INPUT, namePrefix: "restic/" },
        ctx,
      );
      assertEquals(out.dataHandles.length, 1);
      assertEquals(writes.length, 1);
      const w = writes[0];
      // Keyed by the REAL applicationKeyId, never the reserved name "latest".
      assertEquals(w.spec, "key");
      assertEquals(w.name, NEW_KEY_ID);
      assert(w.name !== "latest");

      const d = w.data;
      assertEquals(d.applicationKeyId, NEW_KEY_ID);
      assertEquals(d.keyName, "restic-example");
      assertEquals(d.bucketIds, ["b1"]);
      assertEquals(d.namePrefix, "restic/");
      assertEquals(d.expirationTimestamp, 1785000000000);
      assertEquals(d.status, "present");
      assertEquals(d.secretDelivered, true);

      // Secret hygiene, asserted three ways.
      assertEquals(Object.hasOwn(d, "applicationKey"), false);
      const serialized = JSON.stringify(d);
      assertEquals(serialized.includes(SECRET), false);
      assertEquals(serialized.includes(AUTH.authorizationToken), false);
      assertEquals(serialized.includes("fake-connect-token"), false);
    },
  );
});

Deno.test("create sends bucketIds (plural) and never the removed singular bucketId", async () => {
  const { ctx } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    createRouter(null),
    async (calls) => {
      await model.methods.create.execute({
        ...CREATE_INPUT,
        validDurationInSeconds: 86400,
      }, ctx);
      const create = calls.find((c) => c.url.includes("b2_create_key"));
      assert(create, "b2_create_key must be called");
      const body = JSON.parse(String(create.init.body));
      assertEquals(body.bucketIds, ["b1"]);
      assertEquals(Object.hasOwn(body, "bucketId"), false);
      assertEquals(body.validDurationInSeconds, 86400);
      assertEquals(body.accountId, AUTH.accountId);
      assertEquals(body.keyName, "restic-example");
    },
  );
});

Deno.test("create rejects a keyName B2 would reject, before minting", async () => {
  const { ctx } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    createRouter(null),
    async (calls) => {
      await assertRejects(
        () =>
          model.methods.create.execute(
            { ...CREATE_INPUT, keyName: "restic key/2" },
            ctx,
          ),
        Error,
        "Invalid keyName",
      );
      assertEquals(
        calls.filter((c) => c.url.includes("b2_create_key")).length,
        0,
      );
    },
  );
});

Deno.test("create warns about a capability outside the known B2 vocabulary", async () => {
  const { ctx, warnings } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    createRouter(null),
    async () => {
      await model.methods.create.execute(
        { ...CREATE_INPUT, capabilities: ["readFiles", "wrtieFiles"] },
        ctx,
      );
      assert(
        warnings.some((w) => w.includes("known B2 vocabulary")),
        "a probable typo must be warned about",
      );
    },
  );
});

Deno.test("create surfaces an actionable error when the secret cannot be delivered", async () => {
  const { ctx, writes } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    (url, init) => {
      if (url.includes(`/v1/vaults/${VAULT_ID}/items`) && init.method === "POST") {
        return json({ message: "vault is read-only" }, 403);
      }
      return createRouter(null)(url, init);
    },
    async () => {
      const err = await assertRejects(
        () => model.methods.create.execute(CREATE_INPUT, ctx),
        Error,
      );
      assertStringIncludes(err.message, "was minted but its one-shot secret");
      assertStringIncludes(err.message, "unrecoverable");
      assertStringIncludes(err.message, NEW_KEY_ID);
      // The secret itself is never in the error text.
      assertEquals(err.message.includes(SECRET), false);
      // The orphaned key IS recorded — but honestly, as undelivered.
      assertEquals(writes.length, 1);
      assertEquals(writes[0].name, NEW_KEY_ID);
      assertEquals(writes[0].data.secretDelivered, false);
      assertEquals(writes[0].data.secretDestination, null);
      assertEquals(writes[0].data.status, "present");
      assertEquals(JSON.stringify(writes[0].data).includes(SECRET), false);
    },
  );
});

Deno.test("create refuses to silently orphan an existing key of the same name", async () => {
  const { ctx, writes } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    createRouter(null, [
      { applicationKeyId: "0021eb9c3dcf1120000000001", keyName: "restic-example" },
    ]),
    async (calls) => {
      const err = await assertRejects(
        () => model.methods.create.execute(CREATE_INPUT, ctx),
        Error,
      );
      assertStringIncludes(err.message, "already exists");
      assertStringIncludes(err.message, "0021eb9c3dcf1120000000001");
      assertStringIncludes(err.message, "allowDuplicateName");
      assertEquals(
        calls.filter((c) => c.url.includes("b2_create_key")).length,
        0,
        "nothing may be minted when the name already exists",
      );
      assertEquals(writes.length, 0);
    },
  );
});

Deno.test("create mints a same-named key when allowDuplicateName is set", async () => {
  const { ctx, writes } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    createRouter(null, [
      { applicationKeyId: "0021eb9c3dcf1120000000001", keyName: "restic-example" },
    ]),
    async () => {
      await model.methods.create.execute(
        { ...CREATE_INPUT, allowDuplicateName: true },
        ctx,
      );
      assertEquals(writes.length, 1);
      assertEquals(writes[0].name, NEW_KEY_ID);
    },
  );
});

Deno.test("create records truncated when the name-clash scan could not complete", async () => {
  const { ctx, writes, warnings } = makeContext(CONNECT_GLOBALS);
  await withMockedFetch(
    (url, init) => {
      if (url.includes("b2_list_keys")) {
        // Never-ending cursor: the drain always hits its page cap.
        return json({
          keys: [{ applicationKeyId: "other", keyName: "unrelated" }],
          nextApplicationKeyId: "cursor",
        });
      }
      return createRouter(null)(url, init);
    },
    async () => {
      await model.methods.create.execute(CREATE_INPUT, ctx);
      // The key is still minted, but the snapshot does not claim a clean check.
      assertEquals(writes[0].data.truncated, true);
      assert(warnings.some((w) => w.includes("page cap")));
    },
  );
});

// --- 8. the Connect destructive-replace trap --------------------------------

Deno.test("mergeSecretFields preserves every pre-existing field, id, type and section", () => {
  const existing = [
    { id: "f1", label: "username", value: "restic", type: "STRING" },
    {
      id: "f2",
      label: "repo",
      value: "s3:s3.example.com/example-bucket",
      type: "STRING",
      section: { id: "sec1" },
    },
    { id: "f3", label: "notes", value: "hand-maintained", type: "STRING" },
  ];
  const merged = mergeSecretFields(
    existing,
    "applicationKeyId",
    NEW_KEY_ID,
    "applicationKey",
    SECRET,
  );
  // Three originals survive untouched, two new fields are appended.
  assertEquals(merged.length, 5);
  assertEquals(merged[0], existing[0]);
  assertEquals(merged[1].section, { id: "sec1" });
  assertEquals(merged[1].value, "s3:s3.example.com/example-bucket");
  assertEquals(merged[2].label, "notes");
  assertEquals(
    merged.find((f) => f.label === "applicationKeyId")?.value,
    NEW_KEY_ID,
  );
  const secretField = merged.find((f) => f.label === "applicationKey");
  assertEquals(secretField?.value, SECRET);
  assertEquals(secretField?.type, "CONCEALED");
});

Deno.test("mergeSecretFields replaces in place rather than duplicating a label", () => {
  const merged = mergeSecretFields(
    [
      { id: "f1", label: "applicationKey", value: "stale", type: "CONCEALED" },
      { id: "f2", label: "applicationKeyId", value: "stale-id", type: "STRING" },
    ],
    "applicationKeyId",
    NEW_KEY_ID,
    "applicationKey",
    SECRET,
  );
  assertEquals(merged.length, 2);
  assertEquals(merged[0].id, "f1", "the field id must be preserved");
  assertEquals(merged[0].value, SECRET);
  assertEquals(merged[1].value, NEW_KEY_ID);
});

Deno.test("create's Connect PUT re-sends the FULL pre-existing field set", async () => {
  const { ctx } = makeContext(CONNECT_GLOBALS);
  const existing = [
    { id: "f1", label: "username", value: "restic", type: "STRING" },
    { id: "f2", label: "password", value: "restic-repo-pw", type: "CONCEALED" },
    { id: "f3", label: "repo", value: "s3:s3.example.com/ex", type: "STRING" },
  ];
  await withMockedFetch(
    createRouter(existing),
    async (calls) => {
      await model.methods.create.execute(CREATE_INPUT, ctx);
      const put = calls.find((c) => c.init.method === "PUT");
      assert(put, "the existing item must be updated with PUT");
      const body = JSON.parse(String(put.init.body));
      const labels = (body.fields as Array<{ label: string }>).map((f) =>
        f.label
      );
      // Connect's update is a destructive replace: an omitted field is DELETED.
      for (const label of ["username", "password", "repo"]) {
        assert(
          labels.includes(label),
          `field "${label}" was dropped — Connect would silently delete it`,
        );
      }
      assert(labels.includes("applicationKeyId"));
      assert(labels.includes("applicationKey"));
      assertEquals(body.fields.length, 5);
      // Unrelated item metadata survives too.
      assertEquals(body.title, "b2-restic-example");
      assertEquals(body.tags, ["homelab"]);
      assertEquals(
        (body.fields as Array<{ label: string; value: string }>)
          .find((f) => f.label === "password")?.value,
        "restic-repo-pw",
      );
    },
  );
});

// --- 9. sync ----------------------------------------------------------------

Deno.test("sync finds the managed key via b2_list_keys and snapshots metadata only", async () => {
  const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) => {
      if (url.includes("b2_authorize_account")) return json(authBody());
      return json({
        keys: [
          { applicationKeyId: "other", keyName: "unrelated" },
          {
            applicationKeyId: KEY_ID,
            keyName: "restic-example",
            capabilities: ["listBuckets", "readFiles"],
            bucketIds: ["b1"],
            namePrefix: null,
            expirationTimestamp: null,
            options: ["s3"],
            accountId: AUTH.accountId,
            // A hostile/hypothetical response that echoes a secret must still
            // not reach the snapshot.
            applicationKey: SECRET,
          },
        ],
        nextApplicationKeyId: null,
      });
    },
    async () => {
      await model.methods.sync.execute({}, ctx);
      assertEquals(writes.length, 1);
      assertEquals(writes[0].name, KEY_ID);
      assertEquals(writes[0].data.status, "present");
      assertEquals(writes[0].data.keyName, "restic-example");
      assertEquals(writes[0].data.bucketIds, ["b1"]);
      assertEquals(writes[0].data.truncated, false);
      assertEquals(writes[0].data.secretDelivered, false);
      // The mapper is the choke point: no secret, even when echoed back.
      assertEquals(Object.hasOwn(writes[0].data, "applicationKey"), false);
      assertEquals(JSON.stringify(writes[0].data).includes(SECRET), false);
    },
  );
});

Deno.test("sync records absent when the key is not in the account", async () => {
  const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account")
        ? json(authBody())
        : json({ keys: [], nextApplicationKeyId: null }),
    async () => {
      await model.methods.sync.execute({}, ctx);
      assertEquals(writes[0].data.status, "absent");
      assertEquals(writes[0].data.applicationKeyId, KEY_ID);
    },
  );
});

Deno.test("sync requires managedKeyId", async () => {
  const { ctx } = makeContext(BASE_GLOBALS);
  await assertRejects(
    () => model.methods.sync.execute({}, ctx),
    Error,
    "requires globalArgs.managedKeyId",
  );
});

// --- 10. idempotent delete --------------------------------------------------

Deno.test("delete verifies the key first, then revokes it and marks it absent", async () => {
  const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) => {
      if (url.includes("b2_authorize_account")) return json(authBody());
      if (url.includes("b2_list_keys")) {
        return json({
          keys: [{ applicationKeyId: KEY_ID, keyName: "restic-example" }],
          nextApplicationKeyId: null,
        });
      }
      return json({ applicationKeyId: KEY_ID, keyName: "restic-example" });
    },
    async (calls) => {
      await model.methods.delete.execute({}, ctx);
      const del = calls.find((c) => c.url.includes("b2_delete_key"));
      assert(del, "b2_delete_key must be called for a present key");
      assertEquals(JSON.parse(String(del.init.body)).applicationKeyId, KEY_ID);
      assertEquals(writes[0].data.status, "absent");
      assertEquals(writes[0].name, KEY_ID);
    },
  );
});

Deno.test("delete is idempotent: an already-absent key succeeds without a delete call", async () => {
  const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account")
        ? json(authBody())
        : json({ keys: [], nextApplicationKeyId: null }),
    async (calls) => {
      await model.methods.delete.execute({}, ctx);
      assertEquals(
        calls.filter((c) => c.url.includes("b2_delete_key")).length,
        0,
      );
      assertEquals(writes.length, 1);
      assertEquals(writes[0].data.status, "absent");
    },
  );
});

Deno.test("delete tolerates the key vanishing between the list and the delete", async () => {
  const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) => {
      if (url.includes("b2_authorize_account")) return json(authBody());
      if (url.includes("b2_list_keys")) {
        return json({
          keys: [{ applicationKeyId: KEY_ID }],
          nextApplicationKeyId: null,
        });
      }
      return json({ code: "key_not_found", message: "gone" }, 400);
    },
    async () => {
      await model.methods.delete.execute({}, ctx);
      assertEquals(writes[0].data.status, "absent");
    },
  );
});

Deno.test("delete's completion log distinguishes a revocation from an already-absent key", async () => {
  /** Run delete against a routed mock and return the completion log's props. */
  async function completionProps(
    router: (url: string) => Response,
  ): Promise<Record<string, unknown>> {
    const { ctx } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
    const infos: Array<{ m: string; p: Record<string, unknown> }> = [];
    ctx.logger.info = (m: string, p?: Record<string, unknown>) => {
      infos.push({ m, p: p ?? {} });
    };
    await withMockedFetch(router, () => model.methods.delete.execute({}, ctx));
    const done = infos.find((l) => l.m.includes("(revoked="));
    assert(done, "delete must log a completion line");
    return done.p;
  }

  // A key that was live and is now revoked by THIS run.
  const revoked = await completionProps((url) => {
    if (url.includes("b2_authorize_account")) return json(authBody());
    if (url.includes("b2_list_keys")) {
      return json({
        keys: [{ applicationKeyId: KEY_ID }],
        nextApplicationKeyId: null,
      });
    }
    return json({ applicationKeyId: KEY_ID });
  });
  assertEquals(revoked.revoked, true);

  // A key that was already gone: the end state is identical, so a flag that is
  // always true would carry no information at all.
  const alreadyGone = await completionProps((url) =>
    url.includes("b2_authorize_account")
      ? json(authBody())
      : json({ keys: [], nextApplicationKeyId: null })
  );
  assertEquals(alreadyGone.revoked, false);

  // The narrow race — vanished between the list and the delete — is not a
  // revocation this run performed either.
  const raced = await completionProps((url) => {
    if (url.includes("b2_authorize_account")) return json(authBody());
    if (url.includes("b2_list_keys")) {
      return json({
        keys: [{ applicationKeyId: KEY_ID }],
        nextApplicationKeyId: null,
      });
    }
    return json({ code: "key_not_found", message: "gone" }, 400);
  });
  assertEquals(raced.revoked, false);
});

Deno.test("delete refuses to claim absence when the key listing was truncated", async () => {
  const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account")
        ? json(authBody())
        : json({
          keys: [{ applicationKeyId: "other" }],
          nextApplicationKeyId: "cursor",
        }),
    async () => {
      await assertRejects(
        () => model.methods.delete.execute({}, ctx),
        Error,
        "cannot be confirmed absent",
      );
      assertEquals(writes.length, 0);
    },
  );
});

Deno.test("delete propagates a genuine bad_request instead of calling it success", async () => {
  const { ctx } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
  await withMockedFetch(
    (url) => {
      if (url.includes("b2_authorize_account")) return json(authBody());
      if (url.includes("b2_list_keys")) {
        return json({
          keys: [{ applicationKeyId: KEY_ID }],
          nextApplicationKeyId: null,
        });
      }
      return json({ code: "bad_request", message: "wrong fields" }, 400);
    },
    async () => {
      await assertRejects(
        () => model.methods.delete.execute({}, ctx),
        Error,
        "bad_request",
      );
    },
  );
});

Deno.test("isAlreadyGone accepts only unambiguous key-missing signals", () => {
  assertEquals(isAlreadyGone({ status: 404 }), true);
  assertEquals(isAlreadyGone({ status: 400, b2Code: "key_not_found" }), true);
  assertEquals(isAlreadyGone({ status: 400, b2Code: "no_such_key" }), true);
  // Generic bad_request must NOT be swallowed — it hides real request bugs.
  assertEquals(isAlreadyGone({ status: 400, b2Code: "bad_request" }), false);
  assertEquals(isAlreadyGone({ status: 401, b2Code: "unauthorized" }), false);
  assertEquals(isAlreadyGone(new Error("boom")), false);
});

// --- 11. model wiring -------------------------------------------------------

Deno.test("the model declares the expected type, methods and secret-free schema", () => {
  assertEquals(model.type, "@sntxrr/b2/key");
  assertEquals(Object.keys(model.methods).sort(), ["create", "delete", "sync"]);
  assertEquals(Object.keys(model.resources), ["key"]);
  const shape = Object.keys(model.resources.key.schema.shape);
  assertEquals(shape.includes("applicationKeyId"), true);
  assertEquals(shape.includes("bucketIds"), true);
  assertEquals(shape.includes("expirationTimestamp"), true);
  // The snapshot schema has no field capable of holding the secret.
  assertEquals(shape.includes("applicationKey"), false);
});

Deno.test("toKeyResource never copies applicationKey out of a raw response", () => {
  const out = toKeyResource(
    { applicationKeyId: KEY_ID, applicationKey: SECRET, keyName: "x" },
    {
      status: "present",
      secretDelivered: false,
      secretDestination: null,
      truncated: false,
      observedAt: "2026-08-05T00:00:00Z",
    },
  );
  assertEquals(Object.hasOwn(out, "applicationKey"), false);
  assertEquals(JSON.stringify(out).includes(SECRET), false);
});

Deno.test("an account-wide key reports bucketIds as [], never null", async () => {
  // Live finding, 2026-08-05: syncing a real account-wide key snapshotted
  // bucketIds: null, while the sibling b2-account model normalizes the same B2
  // field to []. Two models describing the same key disagreed about its shape,
  // so a consumer testing `bucketIds.length === 0` for "account-wide" works
  // against one and throws against the other. [] is the honest encoding:
  // b2_list_keys has no "unknown" case — absent means unrestricted.
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account")
        ? json(authBody())
        : json({ keys: [{
          applicationKeyId: KEY_ID,
          keyName: "example-account-wide",
          capabilities: ["listBuckets"],
          // B2 omits bucketIds entirely for an unrestricted key.
          namePrefix: null,
          expirationTimestamp: null,
          options: ["s3"],
          accountId: AUTH.accountId,
        }], nextApplicationKeyId: null }),
    async () => {
      const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
      await model.methods.sync.execute({}, ctx);
      assertEquals(writes.length, 1);
      assertEquals(
        writes[0].data.bucketIds,
        [],
        "absent bucketIds means account-wide, and must serialize as an empty array",
      );
    },
  );
});

Deno.test("a stale singular bucketId degrades to a one-element array", async () => {
  // Mirrors b2-account: a v2-style or proxied response carrying scalar
  // bucketId must not be read as an unrestricted key, which would misreport a
  // scoped key's blast radius as account-wide.
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account")
        ? json(authBody())
        : json({ keys: [{
          applicationKeyId: KEY_ID,
          keyName: "example-legacy",
          capabilities: ["listBuckets"],
          bucketId: "b1f2a3c4d5e6f708192a3b4c",
          namePrefix: null,
          expirationTimestamp: null,
          options: [],
          accountId: AUTH.accountId,
        }], nextApplicationKeyId: null }),
    async () => {
      const { ctx, writes } = makeContext({ ...BASE_GLOBALS, managedKeyId: KEY_ID });
      await model.methods.sync.execute({}, ctx);
      assertEquals(writes[0].data.bucketIds, ["b1f2a3c4d5e6f708192a3b4c"]);
    },
  );
});

/** A context whose dataRepository serves one prior snapshot for `keyId`. */
// deno-lint-ignore no-explicit-any
function makeContextWithPrior(
  globalArgs: Record<string, unknown>,
  keyId: string,
  prior: Record<string, unknown> | null,
  // deno-lint-ignore no-explicit-any
): any {
  const base = makeContext(globalArgs);
  base.ctx.readResource = (name: string) =>
    Promise.resolve(prior && name === keyId ? prior : null);
  return base;
}

Deno.test("sync preserves where a previously delivered secret lives", async () => {
  // Live finding, 2026-08-05: after `create` recorded
  // secretDestination: op://vault/item/applicationKey, a routine read-only
  // `sync` overwrote the snapshot with null. That destination is the ONLY
  // durable pointer to the credential, and data.latest() — the documented way
  // to read a model — returns the sync version. So syncing a key silently
  // destroyed the record of where its secret is stored.
  //
  // sync observes nothing about delivery, so it must not assert anything about
  // it. Carrying the prior value forward is the same rule already applied to
  // defaultRetentionPeriod and to the hygiene report: never encode "I did not
  // look" as "it is not there".
  const prior = {
    applicationKeyId: KEY_ID,
    secretDelivered: true,
    secretDestination: "op://vault-uuid/item-uuid/applicationKey",
  };
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account") ? json(authBody()) : json({
        keys: [{
          applicationKeyId: KEY_ID,
          keyName: "example",
          capabilities: ["listBuckets"],
          bucketIds: ["b1"],
          namePrefix: null,
          expirationTimestamp: null,
          options: [],
          accountId: AUTH.accountId,
        }],
        nextApplicationKeyId: null,
      }),
    async () => {
      const { ctx, writes } = makeContextWithPrior(
        { ...BASE_GLOBALS, managedKeyId: KEY_ID },
        KEY_ID,
        prior,
      );
      await model.methods.sync.execute({}, ctx);
      assertEquals(writes[0].data.secretDelivered, true);
      assertEquals(
        writes[0].data.secretDestination,
        "op://vault-uuid/item-uuid/applicationKey",
      );
    },
  );
});

Deno.test("sync of a key with no prior snapshot reports no delivery", async () => {
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account") ? json(authBody()) : json({
        keys: [{
          applicationKeyId: KEY_ID,
          keyName: "example",
          capabilities: ["listBuckets"],
          bucketIds: ["b1"],
          namePrefix: null,
          expirationTimestamp: null,
          options: [],
          accountId: AUTH.accountId,
        }],
        nextApplicationKeyId: null,
      }),
    async () => {
      const { ctx, writes } = makeContextWithPrior(
        { ...BASE_GLOBALS, managedKeyId: KEY_ID },
        KEY_ID,
        null,
      );
      await model.methods.sync.execute({}, ctx);
      assertEquals(writes[0].data.secretDelivered, false);
      assertEquals(writes[0].data.secretDestination, null);
    },
  );
});

Deno.test("delete keeps the destination so the stored secret can be cleaned up", async () => {
  // Revoking the key does not remove the 1Password item it was written to.
  // Nulling the destination here would destroy the only pointer to the orphaned
  // credential at the exact moment an operator needs it.
  const prior = {
    applicationKeyId: KEY_ID,
    secretDelivered: true,
    secretDestination: "op://vault-uuid/item-uuid/applicationKey",
  };
  await withMockedFetch(
    (url) =>
      url.includes("b2_authorize_account")
        ? json(authBody())
        : url.includes("b2_list_keys")
        ? json({
          keys: [{
            applicationKeyId: KEY_ID,
            keyName: "example",
            capabilities: ["listBuckets"],
            bucketIds: ["b1"],
            namePrefix: null,
            expirationTimestamp: null,
            options: [],
            accountId: AUTH.accountId,
          }],
          nextApplicationKeyId: null,
        })
        : json({ applicationKeyId: KEY_ID }),
    async () => {
      const { ctx, writes } = makeContextWithPrior(
        { ...BASE_GLOBALS, managedKeyId: KEY_ID },
        KEY_ID,
        prior,
      );
      await model.methods.delete.execute({}, ctx);
      const snap = writes[writes.length - 1].data;
      assertEquals(snap.status, "absent");
      assertEquals(
        snap.secretDestination,
        "op://vault-uuid/item-uuid/applicationKey",
        "revoking the key must not erase where its secret was stored",
      );
    },
  );
});
