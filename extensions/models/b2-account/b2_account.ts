/**
 * Backblaze B2 Account inventory — the read-only root of the `@sntxrr/b2/*`
 * suite.
 *
 * Wraps the **B2 Native API v4** (`/b2api/v4`) so a swamp model represents a
 * whole B2 account as queryable, typed state. A single factory method, `scan`,
 * authorizes once and fans out one resource per discovered object:
 *
 * - spec `bucket`, instance `bucket-<bucketName>` — every bucket the key can
 *   see (`b2_list_buckets`)
 * - spec `key`, instance `key-<applicationKeyId>` — every application key
 *   (`b2_list_keys`)
 * - spec `account`, instance `account-<accountId>` — a summary with counts and
 *   a truncation flag
 *
 * The instance names are spec-prefixed on purpose: instance names map onto
 * storage paths and share one flat namespace across **all** specs, so an
 * unprefixed scan could silently clobber one snapshot with another (see
 * `instanceName`).
 *
 * This model **never mutates**. Bucket and key lifecycle live in
 * `@sntxrr/b2/bucket` and `@sntxrr/b2/key`; provisioning a host's backup target
 * spans both and is therefore a workflow, not a method here.
 *
 * Two v4 shape traps this model is built around, because v2/v3 examples online
 * get them wrong:
 *
 * 1. `b2_authorize_account` nests the cluster URLs and the key's grant under
 *    `apiInfo.storageApi`, not at the top level.
 * 2. `allowed.buckets` (authorize) and `bucketIds` (list keys) are **arrays**.
 *    v2's scalar `bucketId`/`bucketName` were removed; a bucket-scoped key —
 *    which is what every per-host restic key is — appears as a one-element
 *    array, so code reading `allowed.bucketId` silently gets `undefined`.
 *
 * Cost note: every `b2_list_*` call is a **class C transaction** and is billed.
 * `b2_list_buckets` returns the whole account in one response, but
 * `b2_list_keys` is cursor-paginated and is capped by `maxKeyPages`. When that
 * cap is hit the account summary records `truncated: true` — a silently
 * truncated inventory reads as "nothing else exists", which is exactly the
 * failure mode that makes an audit lie.
 *
 * Secrets: the 24h `authorizationToken` and the `applicationKey` are never
 * written to a resource or a log line. `b2_list_keys` does not return key
 * material at all — only `b2_create_key` does, and that lives in
 * `@sntxrr/b2/key`.
 *
 * API reference: https://www.backblaze.com/apidocs/b2-native-api
 * @module
 */
// extensions/models/b2-account/b2_account.ts
import { z } from "npm:zod@4";

// --- Schemas ---------------------------------------------------------------
/** Global arguments shared by every method on the B2 account model. */
const GlobalArgsSchema = z.object({
  applicationKeyId: z.string().describe(
    "B2 application key ID (master or scoped). Needs the listBuckets and " +
      "listKeys capabilities for a full scan.",
  ),
  applicationKey: z.string().meta({ sensitive: true }).describe(
    "B2 application key — supply via vault.get(), never inline.",
  ),
  authHost: z.string().url().optional().describe(
    "Override the B2 authorize host (testing only). Defaults to " +
      "https://api.backblazeb2.com. The per-cluster apiUrl used for every " +
      "other call is always taken from the authorize response, never guessed.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Arguments for the `scan` factory method. */
const ScanArgsSchema = z.object({
  bucketTypes: z.array(z.string()).optional().describe(
    "Filter b2_list_buckets to these bucket types, e.g. " +
      '["allPrivate"] or ["all"]. Omit to list every type the key can see.',
  ),
  maxKeyCount: z.number().int().min(1).max(10000).optional().describe(
    "Application keys requested per b2_list_keys page (B2 max 10000, B2 " +
      "default 100). Defaults to 1000 here: each page is a billed class C " +
      "transaction, so larger pages mean fewer of them.",
  ),
  maxKeyPages: z.number().int().min(1).max(1000).optional().describe(
    "Hard cap on b2_list_keys pages. Defaults to 50. Hitting the cap sets " +
      "truncated=true on the account summary rather than silently returning " +
      "a partial inventory.",
  ),
});

/**
 * Snapshot of one B2 bucket, as returned by `b2_list_buckets`.
 *
 * The nested configuration blobs are carried through verbatim and typed
 * permissively: B2 filters `fileLockConfiguration` and
 * `defaultServerSideEncryption` by the calling key's capabilities, wrapping
 * each in `{ isClientAuthorizedToRead, value }`, and the inner shapes evolve
 * with the API. Never contains key material.
 */
const BucketSchema = z.object({
  accountId: z.string().nullable().optional().describe(
    "B2 account ID that owns the bucket.",
  ),
  bucketId: z.string().describe("Immutable B2 bucket ID."),
  bucketName: z.string().describe(
    "Globally unique bucket name. The instance is named bucket-<bucketName>.",
  ),
  bucketType: z.string().nullable().optional().describe(
    "Visibility: allPublic, allPrivate, snapshot, or a restricted marker.",
  ),
  bucketInfo: z.record(z.string(), z.unknown()).nullable().optional().describe(
    "User-supplied metadata stored with the bucket. Treat as untrusted " +
      "free-form data — never store a credential here.",
  ),
  corsRules: z.array(z.unknown()).nullable().optional().describe(
    "CORS rules configured on the bucket.",
  ),
  lifecycleRules: z.unknown().optional().describe(
    "Lifecycle rules (hide-then-delete day counts per file name prefix). " +
      "Carried through verbatim.",
  ),
  fileLockConfiguration: z.unknown().optional().describe(
    "Object Lock configuration, wrapped by B2 as " +
      "{ isClientAuthorizedToRead, value }.",
  ),
  defaultServerSideEncryption: z.unknown().optional().describe(
    "Default SSE configuration, wrapped by B2 as " +
      "{ isClientAuthorizedToRead, value }. B2 never returns SSE-C key " +
      "material.",
  ),
  replicationConfiguration: z.unknown().optional().describe(
    "Cloud-replication source/destination rules, if any.",
  ),
  options: z.array(z.string()).nullable().optional().describe(
    'Enabled bucket features. Contains "s3" when the bucket is reachable ' +
      "through the S3-compatible API — which is how restic addresses it.",
  ),
  revision: z.number().nullable().optional().describe(
    "Monotonic counter bumped on every bucket modification.",
  ),
  observedAt: z.string().describe(
    "Timestamp when this snapshot was taken (ISO 8601).",
  ),
});

/**
 * Snapshot of one B2 application key, as returned by `b2_list_keys`.
 *
 * `b2_list_keys` never returns the secret half of a key, so this snapshot
 * cannot contain one.
 */
const KeySchema = z.object({
  accountId: z.string().nullable().optional().describe(
    "B2 account ID that owns the key.",
  ),
  applicationKeyId: z.string().describe(
    "Application key ID. The instance is named key-<applicationKeyId>. Not a " +
      "secret — the secret half is returned only once, by b2_create_key.",
  ),
  keyName: z.string().nullable().optional().describe(
    "Human-readable key name; not unique and not an identifier.",
  ),
  capabilities: z.array(z.string()).describe(
    "Capabilities granted to the key, e.g. listBuckets, readFiles, " +
      "writeFiles, deleteFiles.",
  ),
  bucketIds: z.array(z.string()).describe(
    "Buckets this key is restricted to. **Plural array in v4** — v2's " +
      "scalar bucketId was removed. Empty means account-wide (unrestricted).",
  ),
  namePrefix: z.string().nullable().optional().describe(
    "File name prefix the key is restricted to, if any.",
  ),
  expirationTimestamp: z.number().nullable().optional().describe(
    "Expiry in milliseconds since the Unix epoch, or null if the key does " +
      "not expire.",
  ),
  options: z.array(z.string()).nullable().optional().describe(
    'Key options, e.g. "s3" when the key works against the S3-compatible ' +
      "API.",
  ),
  observedAt: z.string().describe(
    "Timestamp when this snapshot was taken (ISO 8601).",
  ),
});

/**
 * Account-level summary of one `scan`: what was found, and whether the
 * inventory is complete.
 *
 * The instance is named `account-<accountId>` — keyed by the real B2 account ID,
 * never by the literal `"latest"`, which is a reserved data name that fails at
 * run time only, and spec-prefixed so it cannot collide with a bucket of the
 * same name.
 */
const AccountSchema = z.object({
  accountId: z.string().describe(
    "B2 account ID this scan covered. The instance is named " +
      "account-<accountId>.",
  ),
  bucketCount: z.number().describe("Buckets discovered by this scan."),
  keyCount: z.number().describe("Application keys discovered by this scan."),
  truncated: z.boolean().describe(
    "True when any listing hit its page cap, so this inventory is " +
      "INCOMPLETE. Never read an absence as proof a bucket or key does not " +
      "exist while this is true.",
  ),
  keysTruncated: z.boolean().describe(
    "True when b2_list_keys specifically exhausted maxKeyPages. " +
      "b2_list_buckets is not paginated and can never truncate.",
  ),
  apiUrl: z.string().describe(
    "Cluster-specific B2 Native API base URL this scan used.",
  ),
  downloadUrl: z.string().describe("Cluster-specific download base URL."),
  s3ApiUrl: z.string().describe(
    "S3-compatible endpoint for this cluster — the one restic targets.",
  ),
  allowedCapabilities: z.array(z.string()).describe(
    "Capabilities of the scanning key. A missing listBuckets or listKeys " +
      "here explains an empty or partial inventory.",
  ),
  allowedBuckets: z.array(
    z.object({
      id: z.string().describe("Bucket ID the scanning key is scoped to."),
      name: z.string().describe("Bucket name the scanning key is scoped to."),
    }),
  ).describe(
    "Buckets the scanning key is restricted to. **Array in v4.** Empty " +
      "means the key is account-wide; one element means a bucket-scoped key, " +
      "which sees only its own bucket.",
  ),
  allowedNamePrefix: z.string().nullable().optional().describe(
    "File name prefix the scanning key is restricted to, if any.",
  ),
  observedAt: z.string().describe(
    "Timestamp when this scan ran (ISO 8601).",
  ),
});

// --- Backblaze B2 Native API v4 client — CANONICAL, copy byte-identical ------
// GlobalArgs must include: applicationKeyId, applicationKey, authHost?

/** A live B2 authorization: the cluster URL plus the bearer token. */
export type B2Auth = {
  accountId: string;
  authorizationToken: string;
  apiUrl: string;
  downloadUrl: string;
  s3ApiUrl: string;
  allowed: {
    buckets: Array<{ id: string; name: string }>;
    capabilities: string[];
    namePrefix: string | null;
  };
};

/** Credentials needed to authorize against B2. */
export type B2Credentials = {
  applicationKeyId: string;
  applicationKey: string;
  authHost?: string;
};

/**
 * Exchange an application key for a 24h authorization.
 *
 * The returned `apiUrl` is cluster-specific — every subsequent call must target
 * it. Never log or persist `authorizationToken`; it is a bearer credential.
 */
export async function b2Authorize(g: B2Credentials): Promise<B2Auth> {
  const host = (g.authHost ?? "https://api.backblazeb2.com").replace(
    /\/+$/,
    "",
  );
  const basic = btoa(`${g.applicationKeyId}:${g.applicationKey}`);
  const res = await fetch(`${host}/b2api/v4/b2_authorize_account`, {
    method: "GET",
    headers: { Authorization: `Basic ${basic}`, Accept: "application/json" },
  });
  const text = await res.text();
  if (!(res.status >= 200 && res.status < 300)) {
    // Never include `text` verbatim here — it is safe (no secret echoed back),
    // but keep the key id out of the message to avoid leaking it into logs.
    const err = new Error(
      `B2 authorize failed (${res.status}): ${text}`,
    ) as Error & { status: number };
    err.status = res.status;
    throw err;
  }
  const body = JSON.parse(text) as {
    accountId: string;
    authorizationToken: string;
    apiInfo: {
      storageApi: {
        apiUrl: string;
        downloadUrl: string;
        s3ApiUrl: string;
        allowed: {
          buckets: Array<{ id: string; name: string }> | null;
          capabilities: string[];
          namePrefix: string | null;
        };
      };
    };
  };
  const s = body?.apiInfo?.storageApi;
  if (
    !s || typeof s.apiUrl !== "string" ||
    typeof s.downloadUrl !== "string" || typeof s.s3ApiUrl !== "string"
  ) {
    throw new Error(
      "B2 authorize returned 2xx but apiInfo.storageApi is missing one of " +
        "apiUrl / downloadUrl / s3ApiUrl. Expected the v4 response shape; a " +
        "v2/v3-style flat body will hit this. Check that the request targeted " +
        "/b2api/v4/b2_authorize_account.",
    );
  }
  return {
    accountId: body.accountId,
    authorizationToken: body.authorizationToken,
    apiUrl: s.apiUrl.replace(/\/+$/, ""),
    downloadUrl: s.downloadUrl.replace(/\/+$/, ""),
    s3ApiUrl: s.s3ApiUrl.replace(/\/+$/, ""),
    allowed: {
      buckets: s.allowed?.buckets ?? [],
      capabilities: s.allowed?.capabilities ?? [],
      namePrefix: s.allowed?.namePrefix ?? null,
    },
  };
}

/**
 * Call a B2 Native API v4 operation against the authorized cluster.
 *
 * `GET` sends the payload as query parameters; `POST` sends it as a JSON body.
 * Retries 429/503/500 with bounded backoff honoring `Retry-After`, and
 * transparently re-authorizes once on an expired token.
 */
export async function b2Fetch<T>(
  auth: B2Auth,
  method: "GET" | "POST",
  op: string,
  payload?: Record<string, unknown>,
  reauth?: () => Promise<B2Auth>,
): Promise<T> {
  const maxAttempts = 3;
  let live = auth;
  for (let attempt = 1;; attempt++) {
    let url = `${live.apiUrl}/b2api/v4/${op}`;
    let body: string | undefined;
    if (method === "GET") {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(payload ?? {})) {
        if (v !== undefined && v !== null) qs.set(k, String(v));
      }
      const q = qs.toString();
      if (q) url += `?${q}`;
    } else {
      body = JSON.stringify(payload ?? {});
    }
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: live.authorizationToken,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body,
    });
    const text = await res.text();
    if (res.status >= 200 && res.status < 300) {
      return (text ? JSON.parse(text) : undefined) as T;
    }
    let b2Code = "";
    try {
      b2Code = String((JSON.parse(text) as { code?: string }).code ?? "");
    } catch { /* non-JSON error body */ }

    // An expired 24h token is recoverable exactly once per call.
    if (
      res.status === 401 && b2Code === "expired_auth_token" && reauth &&
      attempt < maxAttempts
    ) {
      live = await reauth();
      continue;
    }
    const transient = res.status === 429 || res.status === 503 ||
      res.status === 500;
    if (transient && attempt < maxAttempts) {
      const retryAfter = Number(res.headers.get("retry-after"));
      const delayMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 5000)
        : attempt * 250;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      continue;
    }
    const err = new Error(
      `B2 ${op} failed (${res.status}${transient ? ", transient" : ""}${
        b2Code ? `, ${b2Code}` : ""
      }): ${text}`,
    ) as Error & { status: number; b2Code: string };
    err.status = res.status;
    err.b2Code = b2Code;
    throw err;
  }
}

/**
 * Drain a cursor-paginated B2 list operation.
 *
 * Every B2 list response names its cursor `next<Thing>` and the matching
 * request parameter `start<Thing>`, so the cursor is carried forward
 * generically. `maxPages` is a hard stop: list calls are class C transactions
 * and an unbounded drain over a restic bucket is a real bill.
 */
export async function b2ListAll<T>(
  auth: B2Auth,
  op: string,
  payload: Record<string, unknown>,
  itemsKey: string,
  maxPages = 50,
  reauth?: () => Promise<B2Auth>,
): Promise<{ items: T[]; truncated: boolean }> {
  const items: T[] = [];
  let cursor: Record<string, unknown> = {};
  for (let page = 0; page < maxPages; page++) {
    const res = await b2Fetch<Record<string, unknown>>(
      auth,
      "POST",
      op,
      { ...payload, ...cursor },
      reauth,
    );
    const batch = (res[itemsKey] as T[] | undefined) ?? [];
    items.push(...batch);

    // Collect every `next*` cursor field and rename it to its `start*` request
    // parameter. A response whose cursors are all null is the last page.
    const nextCursor: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(res)) {
      if (
        k.startsWith("next") && k.length > 4 && v !== null && v !== undefined
      ) {
        nextCursor[`start${k.slice(4)}`] = v;
      }
    }
    if (Object.keys(nextCursor).length === 0) {
      return { items, truncated: false };
    }
    cursor = nextCursor;
  }
  return { items, truncated: true };
}

// --- Context types (canonical — see CONVENTIONS.md §6) ----------------------
type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};

type ExecuteContext = {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
};

// --- Helpers ---------------------------------------------------------------
/**
 * Pick a safe resource key.
 *
 * `"latest"` is a reserved swamp data name that fails at run time only, and B2
 * bucket names are user-chosen, so a real bucket could legitimately be called
 * `latest`. Fall back to the object's immutable ID in that case (and when the
 * natural key is missing) so a scan can never wedge on one badly named object.
 */
function safeResourceName(
  preferred: string | undefined,
  fallback: string,
): string {
  const trimmed = (preferred ?? "").trim();
  if (trimmed === "" || trimmed.toLowerCase() === "latest") return fallback;
  return trimmed;
}

/** The resource specs `scan` writes, in the order they are written. */
type SpecName = "bucket" | "key" | "account";

/**
 * Build the instance name for one spec's snapshot.
 *
 * Instance names map straight onto storage paths and must be unique across
 * **all** specs of a model, not just within one — `safeResourceName` guards
 * only the reserved `"latest"` literal and the empty string, not a collision
 * between specs. `scan` writes three specs in a single execution whose natural
 * keys share one flat namespace, and B2 bucket names are user-chosen (6-63
 * characters of lowercase alphanumerics and hyphens), so a bucket may be named
 * exactly a 12-character account ID or a 25-character application key ID.
 * Unprefixed, such a bucket would silently overwrite the `key` or `account`
 * snapshot on disk. No spec prefix here is a prefix of another, so prefixing
 * makes that collision structurally impossible while keeping every snapshot
 * addressable by its real B2 identifier.
 */
function instanceName(spec: SpecName, key: string): string {
  return `${spec}-${key}`;
}

/** Map a raw `b2_list_buckets` entry to a bucket snapshot. */
function toBucketResource(
  b: Record<string, unknown>,
  observedAt: string,
): Record<string, unknown> {
  return {
    accountId: (b.accountId as string) ?? null,
    bucketId: (b.bucketId as string) ?? "",
    bucketName: (b.bucketName as string) ?? "",
    bucketType: (b.bucketType as string) ?? null,
    bucketInfo: (b.bucketInfo as Record<string, unknown>) ?? null,
    corsRules: (b.corsRules as unknown[]) ?? null,
    lifecycleRules: b.lifecycleRules ?? null,
    fileLockConfiguration: b.fileLockConfiguration ?? null,
    defaultServerSideEncryption: b.defaultServerSideEncryption ?? null,
    replicationConfiguration: b.replicationConfiguration ?? null,
    options: (b.options as string[]) ?? null,
    revision: typeof b.revision === "number" ? b.revision : null,
    observedAt,
  };
}

/**
 * Map a raw `b2_list_keys` entry to a key snapshot.
 *
 * `bucketIds` is normalized to an array. v4 dropped v2's scalar `bucketId`, but
 * the singular field is still tolerated here so a stale or proxied response
 * degrades into a one-element array instead of silently reporting an
 * account-wide key — which would understate the blast radius of a scoped key.
 */
function toKeyResource(
  k: Record<string, unknown>,
  observedAt: string,
): Record<string, unknown> {
  const plural = k.bucketIds;
  const legacySingular = k.bucketId;
  const bucketIds = Array.isArray(plural)
    ? (plural as string[])
    : typeof legacySingular === "string" && legacySingular !== ""
    ? [legacySingular]
    : [];
  return {
    accountId: (k.accountId as string) ?? null,
    applicationKeyId: (k.applicationKeyId as string) ?? "",
    keyName: (k.keyName as string) ?? null,
    capabilities: (k.capabilities as string[]) ?? [],
    bucketIds,
    namePrefix: (k.namePrefix as string) ?? null,
    expirationTimestamp: typeof k.expirationTimestamp === "number"
      ? k.expirationTimestamp
      : null,
    options: (k.options as string[]) ?? null,
    observedAt,
  };
}

/** Build the account-level summary snapshot for one scan. */
function toAccountResource(
  auth: B2Auth,
  bucketCount: number,
  keyCount: number,
  keysTruncated: boolean,
  observedAt: string,
): Record<string, unknown> {
  return {
    accountId: auth.accountId,
    bucketCount,
    keyCount,
    truncated: keysTruncated,
    keysTruncated,
    apiUrl: auth.apiUrl,
    downloadUrl: auth.downloadUrl,
    s3ApiUrl: auth.s3ApiUrl,
    allowedCapabilities: auth.allowed.capabilities,
    allowedBuckets: auth.allowed.buckets,
    allowedNamePrefix: auth.allowed.namePrefix,
    observedAt,
  };
}

// --- Model -----------------------------------------------------------------
/** Backblaze B2 account model — read-only inventory of buckets and keys. */
export const model = {
  type: "@sntxrr/b2/account",
  version: "2026.08.05.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "bucket": {
      description:
        "Snapshot of one B2 bucket, instance-named bucket-<bucketName>",
      schema: BucketSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    "key": {
      description:
        "Snapshot of one B2 application key, instance-named key-<applicationKeyId>",
      schema: KeySchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    "account": {
      description:
        "Account-level summary of one scan (counts and completeness), instance-named account-<accountId>",
      schema: AccountSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  checks: {
    "credentials-present": {
      description:
        "Both halves of the B2 application key must be set — an empty applicationKey silently authorizes as nobody.",
      labels: ["policy"],
      execute: (
        context: { globalArgs: GlobalArgs },
      ): { pass: boolean; errors?: string[] } => {
        const errors: string[] = [];
        if (!context.globalArgs.applicationKeyId?.trim()) {
          errors.push(
            "globalArgs.applicationKeyId is empty — set the B2 application key ID.",
          );
        }
        if (!context.globalArgs.applicationKey?.trim()) {
          errors.push(
            "globalArgs.applicationKey is empty — wire it from a vault, e.g. " +
              "${{ vault.get(b2, B2_APPLICATION_KEY) }}.",
          );
        }
        return errors.length > 0 ? { pass: false, errors } : { pass: true };
      },
    },
  },
  methods: {
    scan: {
      description:
        "Factory discovery — inventory every bucket and application key in the B2 account, plus an account summary (read-only).",
      arguments: ScanArgsSchema,
      execute: async (
        args: z.infer<typeof ScanArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        // Logged before authorizing so a failed authorize still leaves a trace
        // of what was attempted. The key ID is an identifier, not a secret.
        logger.info("Scanning B2 account as key {keyId}", {
          keyId: g.applicationKeyId,
        });

        // One authorize per scan. `reauth` is handed to every list call so a
        // long-running scan survives the 24h token expiring mid-drain.
        const reauth = () => b2Authorize(g);
        const auth = await b2Authorize(g);
        logger.info("Authorized against B2 cluster {apiUrl}", {
          apiUrl: auth.apiUrl,
        });

        // b2_list_buckets returns the whole account in ONE response with no
        // cursor — b2ListAll would issue a pointless second class C call.
        const bucketPayload: Record<string, unknown> = {
          accountId: auth.accountId,
        };
        if (args.bucketTypes && args.bucketTypes.length > 0) {
          bucketPayload.bucketTypes = args.bucketTypes;
        }
        const bucketRes = await b2Fetch<
          { buckets?: Record<string, unknown>[] }
        >(
          auth,
          "POST",
          "b2_list_buckets",
          bucketPayload,
          reauth,
        );
        const buckets = bucketRes.buckets ?? [];

        // b2_list_keys IS cursor-paginated (nextApplicationKeyId ->
        // startApplicationKeyId), so it drains through b2ListAll under a cap.
        const { items: keys, truncated: keysTruncated } = await b2ListAll<
          Record<string, unknown>
        >(
          auth,
          "b2_list_keys",
          {
            accountId: auth.accountId,
            maxKeyCount: args.maxKeyCount ?? 1000,
          },
          "keys",
          args.maxKeyPages ?? 50,
          reauth,
        );

        logger.info(
          "Discovered {buckets} buckets and {keys} application keys",
          {
            buckets: buckets.length,
            keys: keys.length,
          },
        );
        if (keysTruncated) {
          logger.warn(
            "Application key listing hit maxKeyPages ({pages}) — this inventory is INCOMPLETE. Raise maxKeyPages before treating a missing key as deleted.",
            { pages: args.maxKeyPages ?? 50 },
          );
        }

        const observedAt = new Date().toISOString();
        const handles: Array<{ name: string }> = [];

        // Every instance name is spec-prefixed: the three specs share one flat
        // storage namespace, and a bucket may legally be named exactly an
        // account ID or an application key ID.
        for (const b of buckets) {
          const bucketId = (b.bucketId as string) ?? "";
          handles.push(
            await context.writeResource(
              "bucket",
              instanceName(
                "bucket",
                safeResourceName(b.bucketName as string, bucketId),
              ),
              toBucketResource(b, observedAt),
            ),
          );
        }
        for (const k of keys) {
          const keyId = (k.applicationKeyId as string) ?? "";
          handles.push(
            await context.writeResource(
              "key",
              instanceName("key", safeResourceName(keyId, keyId)),
              toKeyResource(k, observedAt),
            ),
          );
        }

        // Keyed by the real account ID, never the reserved literal "latest".
        handles.push(
          await context.writeResource(
            "account",
            instanceName("account", auth.accountId),
            toAccountResource(
              auth,
              buckets.length,
              keys.length,
              keysTruncated,
              observedAt,
            ),
          ),
        );

        logger.info(
          "Scan complete for account {accountId}: wrote {n} resources (truncated={truncated})",
          {
            accountId: auth.accountId,
            n: handles.length,
            truncated: keysTruncated,
          },
        );
        return { dataHandles: handles };
      },
    },
  },
};

/** Internal helpers exported only for unit testing. */
export const _internal = {
  b2Authorize,
  b2Fetch,
  b2ListAll,
  safeResourceName,
  instanceName,
  toBucketResource,
  toKeyResource,
  toAccountResource,
};
