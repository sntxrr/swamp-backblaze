/**
 * Backblaze B2 bucket management via the B2 Native API v4.
 *
 * A swamp model that manages **one** B2 bucket, keyed by its real bucket name.
 * Exposes `sync` (read current state), `create`, `update`, `delete` (idempotent),
 * `get_notification_rules`, and `set_notification_rules`.
 *
 * **Why this model exists.** The homelab backs up with restic into per-host B2
 * buckets. `restic forget --prune` deletes pack files, but B2 keeps every deleted
 * object as a *hidden version* — forever — unless the bucket carries a lifecycle
 * rule with `daysFromHidingToDeleting`. Without that rule you pay to store data
 * you already pruned, indefinitely. So `lifecycleRules` is modelled precisely,
 * surfaced in every snapshot as `prunesHiddenVersions`, and guarded by the
 * `lifecycle-hidden-version-retention` pre-flight check.
 *
 * **Security.** `applicationKey` is sensitive and wired from a vault. The 24h
 * `authorizationToken` returned by `b2_authorize_account` is a bearer credential
 * and is never logged nor written into a resource. Event-notification rules
 * carry an `hmacSha256SigningSecret` and arbitrary custom header values; both are
 * stripped before a snapshot is written (see `redactNotificationRule`).
 *
 * API reference: https://www.backblaze.com/apidocs/
 *
 * @module
 */
// extensions/models/b2-bucket/b2_bucket.ts
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Backblaze B2 Native API v4 client — CANONICAL, copied byte-identical from
// CONVENTIONS.md §5. Do not modify locally; changes are a lead-driven sweep.
// GlobalArgs must include: applicationKeyId, applicationKey, authHost?
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Shared context types (canonical — CONVENTIONS.md §6)
// ---------------------------------------------------------------------------

type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};

type ExecuteContext<G> = {
  globalArgs: G;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
};

// ---------------------------------------------------------------------------
// Schemas — bucket configuration
// ---------------------------------------------------------------------------

/**
 * One B2 bucket lifecycle rule.
 *
 * `daysFromHidingToDeleting` is the field that matters for a restic repository:
 * without it, every pack file restic prunes lingers as a hidden version and is
 * billed forever.
 */
const LifecycleRuleSchema = z.object({
  fileNamePrefix: z.string().describe(
    'File-name prefix the rule applies to. Use "" (empty string) to cover every object in the bucket.',
  ),
  daysFromUploadingToHiding: z.number().int().positive().nullable().optional()
    .describe(
      "Days after upload before B2 automatically hides a live file version. null (the restic-safe value) means B2 never hides files on its own — restic decides what to prune.",
    ),
  daysFromHidingToDeleting: z.number().int().positive().nullable().optional()
    .describe(
      "Days a hidden version is retained before B2 permanently deletes it. null means NEVER DELETE — pruned restic pack files are then stored and billed forever. Set this (e.g. 1) on any restic bucket.",
    ),
});
type LifecycleRule = z.infer<typeof LifecycleRuleSchema>;

/** One CORS rule attached to a bucket. */
const CorsRuleSchema = z.object({
  corsRuleName: z.string().describe(
    "Rule name, unique within the bucket (letters, digits and '-').",
  ),
  allowedOrigins: z.array(z.string()).describe(
    'Origins the rule matches, e.g. ["https://example.com"] or ["*"].',
  ),
  allowedOperations: z.array(z.string()).describe(
    'B2/S3 operations the rule permits, e.g. ["b2_download_file_by_name", "s3_get"].',
  ),
  allowedHeaders: z.array(z.string()).nullable().optional().describe(
    "Request headers a browser may send, or null for none.",
  ),
  exposeHeaders: z.array(z.string()).nullable().optional().describe(
    "Response headers exposed to the browser, or null for none.",
  ),
  maxAgeSeconds: z.number().int().nonnegative().describe(
    "How long a browser may cache the CORS pre-flight response, in seconds.",
  ),
});

/** Bucket-level default server-side encryption settings. */
const ServerSideEncryptionSchema = z.object({
  mode: z.enum(["SSE-B2", "none"]).nullable().describe(
    'Encryption mode: "SSE-B2" for B2-managed keys, "none" to disable.',
  ),
  algorithm: z.enum(["AES256"]).nullable().optional().describe(
    'Encryption algorithm — "AES256" when mode is SSE-B2, otherwise null.',
  ),
});

/** Bucket-level default Object Lock retention. */
const DefaultRetentionSchema = z.object({
  mode: z.enum(["governance", "compliance"]).nullable().describe(
    "Default Object Lock mode applied to new files. null disables default retention.",
  ),
  period: z.object({
    duration: z.number().int().positive().describe(
      "Retention duration, a positive integer.",
    ),
    unit: z.enum(["days", "years"]).describe("Unit for `duration`."),
  }).nullable().optional().describe(
    "How long new files are retained. Omit or null when mode is null.",
  ),
});

/**
 * Cloud Replication configuration, passed through to B2 unmodified.
 *
 * Kept as an open record rather than a hand-typed tree: the shape
 * (`asReplicationSource.replicationRules[]`, `asReplicationDestination
 * .sourceToDestinationKeyMapping`) is deep, rarely used in this estate, and a
 * partial typing would silently drop fields on write.
 */
const ReplicationConfigurationSchema = z.record(z.string(), z.unknown());

// ---------------------------------------------------------------------------
// Schemas — event notification rules
// ---------------------------------------------------------------------------

/**
 * Webhook target for an event notification rule.
 *
 * `hmacSha256SigningSecret` and custom header values are secrets: they are sent
 * to B2 but never written into a resource snapshot.
 */
const NotificationTargetSchema = z.object({
  targetType: z.literal("webhook").default("webhook").describe(
    'Target type. B2 currently supports only "webhook".',
  ),
  url: z.string().url().describe(
    "HTTPS endpoint B2 posts events to. Must not point at a Backblaze domain.",
  ),
  customHeaders: z.array(z.object({
    name: z.string().describe("Header name."),
    value: z.string().meta({ sensitive: true }).describe(
      "Header value. Treated as a secret — never persisted in a snapshot.",
    ),
  })).max(10).optional().describe(
    "Up to 10 extra headers B2 sends with each webhook call.",
  ),
  hmacSha256SigningSecret: z.string().meta({ sensitive: true }).optional()
    .describe(
      "32-character alphanumeric secret B2 uses to sign webhook payloads. Supply via vault.get(); never persisted in a snapshot.",
    ),
});

/** An event notification rule as submitted to `b2_set_bucket_notification_rules`. */
const NotificationRuleInputSchema = z.object({
  name: z.string().describe("Rule name, unique within the bucket."),
  eventTypes: z.array(
    z.string().regex(/^b2:[A-Za-z]+:([A-Za-z]+|\*)$/).describe(
      'An event type such as "b2:ObjectCreated:Upload" or the wildcard "b2:ObjectDeleted:*". The wildcard is legal only in the final component.',
    ),
  ).min(1).describe(
    "Event types that trigger the rule. Valid values: b2:ObjectCreated:{Upload,MultipartUpload,Copy,Replica,MultipartReplica,*}, b2:ObjectDeleted:{Delete,LifecycleRule,*}, b2:HideMarkerCreated:{Hide,LifecycleRule,*}, b2:MultipartUploadCreated:{LiveRead,*}.",
  ),
  objectNamePrefix: z.string().default("").describe(
    'Only objects whose name starts with this prefix trigger the rule. "" matches everything.',
  ),
  isEnabled: z.boolean().default(true).describe(
    "Whether the rule is active.",
  ),
  maxEventsPerBatch: z.number().int().min(1).max(50).optional().describe(
    "How many events B2 may batch into one webhook call (1-50, default 1).",
  ),
  targetConfiguration: NotificationTargetSchema.describe(
    "Where B2 delivers the events.",
  ),
});

/**
 * An event notification rule as stored in a snapshot — deliberately redacted.
 *
 * The signing secret and every custom header value are dropped; only header
 * *names* and a `hasSigningSecret` flag survive, so drift is still detectable
 * without persisting a credential.
 */
const StoredNotificationRuleSchema = z.object({
  name: z.string().describe("Rule name."),
  eventTypes: z.array(z.string()).describe(
    "Event types that trigger the rule.",
  ),
  objectNamePrefix: z.string().describe("Object-name prefix filter."),
  isEnabled: z.boolean().describe("Whether the rule is active."),
  isSuspended: z.boolean().nullable().optional().describe(
    "Whether B2 has suspended the rule (e.g. after repeated delivery failures).",
  ),
  suspensionReason: z.string().nullable().optional().describe(
    "Why B2 suspended the rule, when it has.",
  ),
  maxEventsPerBatch: z.number().nullable().optional().describe(
    "Events batched per webhook call.",
  ),
  targetType: z.string().describe('Target type, currently always "webhook".'),
  url: z.string().describe("Webhook URL the events are delivered to."),
  customHeaderNames: z.array(z.string()).describe(
    "Names of the custom headers configured. Values are redacted.",
  ),
  hasSigningSecret: z.boolean().describe(
    "Whether an hmacSha256SigningSecret is configured. The secret itself is never stored.",
  ),
});

// ---------------------------------------------------------------------------
// Schemas — resources
// ---------------------------------------------------------------------------

/** Snapshot of the managed bucket's observed state. */
const BucketResourceSchema = z.object({
  bucketName: z.string().describe("Bucket name — the resource key."),
  bucketId: z.string().nullable().describe(
    "B2 bucket ID, or null when the bucket does not exist.",
  ),
  accountId: z.string().nullable().describe("Owning B2 account ID."),
  bucketType: z.string().nullable().describe(
    'Bucket type: "allPrivate", "allPublic", "snapshot", "restricted" or "shared".',
  ),
  // Read-back is permissive for the same reason corsRules is: bucketInfo is
  // free-form, user-supplied metadata, and nothing stops a value arriving as a
  // number or null. Typing it Record<string,string> here makes the entire
  // snapshot unwritable over one odd value — losing all observability of the
  // bucket most worth looking at. `globalArgs.bucketInfo`, which is what this
  // model SENDS, stays strictly Record<string,string> because B2 requires that.
  // The sibling b2-account model already types this same B2 field this way.
  bucketInfo: z.record(z.string(), z.unknown()).describe(
    "User-defined bucket metadata (empty object when unset). Read back " +
      "unmodelled — B2 documents string values but this is user-controlled.",
  ),
  // Deliberately unstructured per CONVENTIONS §4.9: no bucket in any account
  // scanned so far has a CORS rule, so the element shape is unobserved. Typing
  // it structurally makes `sync` hard-fail on the first bucket that has one,
  // because a rule missing any "required" field fails schema validation and
  // writeResource rejects the whole snapshot.
  corsRules: z.array(z.unknown()).describe(
    "CORS rules on the bucket, passed through unmodelled until a live rule has been observed.",
  ),
  lifecycleRules: z.array(LifecycleRuleSchema).describe(
    "Lifecycle rules on the bucket.",
  ),
  prunesHiddenVersions: z.boolean().describe(
    "True when at least one lifecycle rule sets daysFromHidingToDeleting. False means restic-pruned pack files are retained — and billed — forever.",
  ),
  minDaysFromHidingToDeleting: z.number().nullable().describe(
    "Smallest daysFromHidingToDeleting across the bucket's rules, or null when no rule deletes hidden versions.",
  ),
  unprunedPrefixes: z.array(z.string()).describe(
    "fileNamePrefix values whose rule has no daysFromHidingToDeleting, i.e. prefixes that accumulate hidden versions forever.",
  ),
  fileLockEnabled: z.boolean().nullable().describe(
    "Whether Object Lock is enabled, or null when the key may not read it.",
  ),
  defaultRetentionMode: z.string().nullable().describe(
    'Default Object Lock retention mode ("governance"/"compliance"), or null.',
  ),
  // Read back permissively (duration a number, unit a bare string) rather than
  // reusing the strict send-side DefaultRetentionSchema: a unit B2 adds later
  // must not make the whole snapshot unwritable. Without this field a snapshot
  // could not distinguish a 1-day immutability window from a 10-year one, and
  // `sync` could not verify a period this very model had just set.
  defaultRetentionPeriod: z.object({
    duration: z.number().describe("Retention duration."),
    unit: z.string().describe('Unit for `duration` ("days"/"years").'),
  }).nullable().describe(
    "Default Object Lock retention period, or null when no default retention " +
      "is set or the key may not read the lock configuration.",
  ),
  defaultServerSideEncryptionMode: z.string().nullable().describe(
    'Default server-side encryption mode ("SSE-B2"/"none"), or null when the key may not read it.',
  ),
  replicationConfigured: z.boolean().nullable().describe(
    "Whether any Cloud Replication configuration is attached to the bucket, or null when the key may not read it. Null means unknown, never 'not configured' — the same distinction fileLockEnabled and defaultServerSideEncryptionMode make.",
  ),
  revision: z.number().nullable().describe(
    "Bucket revision counter — pass as `ifRevisionIs` on update for optimistic concurrency.",
  ),
  options: z.array(z.string()).describe(
    'Bucket options reported by B2, e.g. ["s3"] when the S3-compatible API is available.',
  ),
  exists: z.boolean().describe(
    "Whether the bucket existed as of observedAt. False after a successful delete.",
  ),
  observedAt: z.string().describe("ISO-8601 time this snapshot was taken."),
});

/** Snapshot of the managed bucket's event notification rules, with secrets removed. */
const NotificationRulesResourceSchema = z.object({
  bucketName: z.string().describe("Bucket name — the resource key."),
  bucketId: z.string().nullable().describe(
    "B2 bucket ID the rules belong to, or null when the bucket was deleted without its id ever resolving.",
  ),
  ruleCount: z.number().int().describe(
    "Number of notification rules configured.",
  ),
  rules: z.array(StoredNotificationRuleSchema).describe(
    "The configured rules, with signing secrets and header values redacted.",
  ),
  observedAt: z.string().describe("ISO-8601 time this snapshot was taken."),
});

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

/**
 * Desired-state configuration for the one bucket this model manages.
 *
 * Configuration lives in `globalArgs` (not only in method arguments) so the
 * `lifecycle-hidden-version-retention` pre-flight check can inspect it — checks
 * receive `globalArgs` but never the method's arguments. Every field can still
 * be overridden per run via the matching method argument.
 */
const GlobalArgsSchema = z.object({
  applicationKeyId: z.string().describe(
    "B2 application key ID (master or scoped). Wire with ${{ vault.get(b2, B2_APPLICATION_KEY_ID) }}.",
  ),
  applicationKey: z.string().meta({ sensitive: true }).describe(
    "B2 application key — supply via vault.get(), never inline.",
  ),
  authHost: z.string().url().optional().describe(
    "Override the B2 authorize host (testing only). Defaults to https://api.backblazeb2.com.",
  ),
  bucketName: z.string().min(6).max(63).describe(
    "Name of the bucket this model manages. B2 bucket names are globally unique and 6-63 characters.",
  ),
  bucketId: z.string().optional().describe(
    "B2 bucket ID. Optional: when omitted it is resolved from bucketName via b2_list_buckets, which costs one class-C transaction per run. Set it to avoid that call.",
  ),
  bucketType: z.enum(["allPrivate", "allPublic"]).optional()
    .describe(
      "Desired bucket type. `create` defaults to allPrivate when this is unset — a restic repository must never be allPublic. Deliberately NOT a schema-level default: a default here would make `update` send bucketType on every run, silently flipping an allPublic bucket private for an operator who only meant to set lifecycle rules.",
    ),
  lifecycleRules: z.array(LifecycleRuleSchema).optional().describe(
    'Desired lifecycle rules. For a restic bucket use [{ fileNamePrefix: "", daysFromUploadingToHiding: null, daysFromHidingToDeleting: 1 }].',
  ),
  corsRules: z.array(CorsRuleSchema).optional().describe(
    "Desired CORS rules. Omit to leave the bucket's CORS configuration untouched.",
  ),
  bucketInfo: z.record(z.string(), z.string()).optional().describe(
    "Desired user-defined bucket metadata (also carries Cache-Control policies).",
  ),
  fileLockEnabled: z.boolean().optional().describe(
    "Enable Object Lock on the bucket. Requires the writeBucketRetentions capability. Object Lock cannot be disabled once enabled.",
  ),
  defaultServerSideEncryption: ServerSideEncryptionSchema.optional().describe(
    "Desired default server-side encryption for new objects.",
  ),
  defaultRetention: DefaultRetentionSchema.optional().describe(
    "Desired default Object Lock retention for new objects (update only; the bucket must have Object Lock enabled).",
  ),
  replicationConfiguration: ReplicationConfigurationSchema.optional().describe(
    "Desired Cloud Replication configuration, passed through to B2 unmodified.",
  ),
  allowPublicBucket: z.boolean().default(false).describe(
    "Acknowledge that this bucket may be allPublic. Without it, create and " +
      "update refuse to set bucketType=allPublic. A backup repository must " +
      "never be public, and B2 makes the flip a one-liner that exposes every " +
      "object the moment it lands.",
  ),
  allowUnprunedHiddenVersions: z.boolean().default(false).describe(
    "Set true to acknowledge that this bucket intentionally retains hidden file versions forever, which disables the lifecycle-hidden-version-retention pre-flight check.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

/** Arguments shared by `create` and `update`: per-run overrides of globalArgs. */
const BucketConfigArgsSchema = z.object({
  allowPublicBucket: z.boolean().optional().describe(
    "Acknowledge, for this run only, that bucketType may be allPublic. " +
      "Overrides globalArgs.allowPublicBucket. Needed because `swamp model " +
      "method run` has no --global-arg flag, so without this the only way to " +
      "waive the guard would be to edit the model definition.",
  ),
  bucketType: z.enum(["allPrivate", "allPublic"]).optional().describe(
    "Override globalArgs.bucketType for this run.",
  ),
  lifecycleRules: z.array(LifecycleRuleSchema).optional().describe(
    "Override globalArgs.lifecycleRules for this run.",
  ),
  corsRules: z.array(CorsRuleSchema).optional().describe(
    "Override globalArgs.corsRules for this run.",
  ),
  bucketInfo: z.record(z.string(), z.string()).optional().describe(
    "Override globalArgs.bucketInfo for this run.",
  ),
  fileLockEnabled: z.boolean().optional().describe(
    "Override globalArgs.fileLockEnabled for this run.",
  ),
  defaultServerSideEncryption: ServerSideEncryptionSchema.optional().describe(
    "Override globalArgs.defaultServerSideEncryption for this run.",
  ),
  replicationConfiguration: ReplicationConfigurationSchema.optional().describe(
    "Override globalArgs.replicationConfiguration for this run.",
  ),
});

/** Arguments for `update` — the shared config overrides plus update-only fields. */
const UpdateArgsSchema = BucketConfigArgsSchema.extend({
  defaultRetention: DefaultRetentionSchema.optional().describe(
    "Override globalArgs.defaultRetention for this run.",
  ),
  ifRevisionIs: z.number().int().optional().describe(
    "Apply the update only if the bucket is still at this revision (optimistic concurrency). Read it from a prior snapshot's `revision`.",
  ),
});

/** Arguments for `set_notification_rules`. */
const SetNotificationRulesArgsSchema = z.object({
  rules: z.array(NotificationRuleInputSchema).describe(
    "The complete desired set of event notification rules. This REPLACES every existing rule on the bucket; pass [] to remove them all.",
  ),
});

// ---------------------------------------------------------------------------
// B2 response shapes
// ---------------------------------------------------------------------------

/**
 * A bucket object as returned by `b2_list_buckets` / `b2_create_bucket` /
 * `b2_update_bucket` / `b2_delete_bucket`.
 *
 * **THREE fields are authorization-wrapped** by B2 as
 * `{ isClientAuthorizedToRead, value }` — `fileLockConfiguration`,
 * `defaultServerSideEncryption`, and `replicationConfiguration`. A key without
 * the relevant capability sees `value: null`, which means *unknown*, never
 * "not configured". All three are modelled as wrappers deliberately: typing
 * `replicationConfiguration` as a bare `Record<string, unknown>` let
 * `deno check` pass while the code read the wrapper instead of `.value`, and
 * the wrapper is always truthy — so every live bucket reported replication
 * configured when none of them had it.
 */
type B2Bucket = {
  accountId?: string;
  bucketId?: string;
  bucketName?: string;
  bucketType?: string;
  bucketInfo?: Record<string, unknown> | null;
  corsRules?: unknown[] | null;
  lifecycleRules?: unknown[] | null;
  fileLockConfiguration?: {
    isClientAuthorizedToRead?: boolean;
    value?: {
      isFileLockEnabled?: boolean | null;
      defaultRetention?: {
        mode?: string | null;
        period?: { duration?: number | null; unit?: string | null } | null;
      } | null;
    } | null;
  } | null;
  defaultServerSideEncryption?: {
    isClientAuthorizedToRead?: boolean;
    value?: { mode?: string | null; algorithm?: string | null } | null;
  } | null;
  replicationConfiguration?: {
    isClientAuthorizedToRead?: boolean;
    value?: Record<string, unknown> | null;
  } | null;
  revision?: number | null;
  options?: string[] | null;
};

/** An event notification rule exactly as B2 returns it. */
type B2NotificationRule = {
  name?: string;
  eventTypes?: string[] | null;
  objectNamePrefix?: string | null;
  isEnabled?: boolean | null;
  isSuspended?: boolean | null;
  suspensionReason?: string | null;
  maxEventsPerBatch?: number | null;
  targetConfiguration?: {
    targetType?: string | null;
    url?: string | null;
    customHeaders?: Array<{ name?: string; value?: string }> | null;
    hmacSha256SigningSecret?: string | null;
  } | null;
};

// ---------------------------------------------------------------------------
// Lifecycle-rule analysis — the reason this suite exists
// ---------------------------------------------------------------------------

/**
 * Summarise what a set of lifecycle rules does to *hidden* file versions.
 *
 * B2 keeps a hidden version forever unless a lifecycle rule gives it a
 * `daysFromHidingToDeleting`. `restic forget --prune` only hides pack files, so
 * a restic bucket without such a rule grows monotonically and is billed for
 * data that was logically deleted.
 */
export function analyzeHiddenVersionRetention(
  rules: LifecycleRule[],
): {
  prunesHiddenVersions: boolean;
  minDaysFromHidingToDeleting: number | null;
  unprunedPrefixes: string[];
} {
  // No rules at all is the worst case, not a neutral one: every file in the
  // bucket accumulates hidden versions forever. It is semantically identical to
  // a single catch-all rule that never deletes, so report it identically —
  // [""] — rather than []. An empty list reads as "no prefix is accumulating",
  // which is the exact opposite of the truth, and would hide precisely the
  // buckets a consumer scanning `unprunedPrefixes` is looking for.
  if (rules.length === 0) {
    return {
      prunesHiddenVersions: false,
      minDaysFromHidingToDeleting: null,
      unprunedPrefixes: [""],
    };
  }

  const pruning: number[] = [];
  const unprunedPrefixes: string[] = [];
  for (const rule of rules) {
    const days = rule.daysFromHidingToDeleting;
    if (typeof days === "number") pruning.push(days);
    else unprunedPrefixes.push(rule.fileNamePrefix);
  }
  return {
    prunesHiddenVersions: pruning.length > 0,
    minDaysFromHidingToDeleting: pruning.length > 0
      ? Math.min(...pruning)
      : null,
    unprunedPrefixes,
  };
}

/** Coerce B2's loosely-typed `lifecycleRules` array into typed rules. */
export function parseLifecycleRules(raw: unknown): LifecycleRule[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((r) => {
    const o = (r ?? {}) as Record<string, unknown>;
    const toDays = (v: unknown): number | null =>
      typeof v === "number" ? v : null;
    return {
      fileNamePrefix: typeof o.fileNamePrefix === "string"
        ? o.fileNamePrefix
        : "",
      daysFromUploadingToHiding: toDays(o.daysFromUploadingToHiding),
      daysFromHidingToDeleting: toDays(o.daysFromHidingToDeleting),
    };
  });
}

/**
 * Normalize the Object Lock `defaultRetention.period` B2 reports.
 *
 * Returns null unless both halves are present and well-formed: a half-read
 * period ("7" with no unit) is worse than no answer, because it reads as a
 * concrete immutability window that nothing verified.
 */
function toRetentionPeriod(
  period: { duration?: number | null; unit?: string | null } | null | undefined,
): { duration: number; unit: string } | null {
  if (!period) return null;
  const { duration, unit } = period;
  if (typeof duration !== "number" || typeof unit !== "string") return null;
  return { duration, unit };
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/**
 * Build a `bucket` resource snapshot from a B2 bucket object.
 *
 * Nothing secret reaches this function: `bucketName` is public, and the
 * authorization token never appears in a B2 bucket payload.
 */
export function toBucketResource(
  bucketName: string,
  bucket: B2Bucket | null,
  observedAt: string,
): Record<string, unknown> {
  if (bucket === null) {
    return {
      bucketName,
      bucketId: null,
      accountId: null,
      bucketType: null,
      bucketInfo: {},
      corsRules: [],
      lifecycleRules: [],
      prunesHiddenVersions: false,
      minDaysFromHidingToDeleting: null,
      unprunedPrefixes: [],
      fileLockEnabled: null,
      defaultRetentionMode: null,
      defaultRetentionPeriod: null,
      defaultServerSideEncryptionMode: null,
      replicationConfigured: false,
      revision: null,
      options: [],
      exists: false,
      observedAt,
    };
  }
  const lifecycleRules = parseLifecycleRules(bucket.lifecycleRules);
  const retention = analyzeHiddenVersionRetention(lifecycleRules);
  const lock = bucket.fileLockConfiguration?.value ?? null;
  const sse = bucket.defaultServerSideEncryption?.value ?? null;
  // replicationConfiguration is authorization-wrapped exactly like
  // fileLockConfiguration and defaultServerSideEncryption above — unwrap
  // `.value`, never the wrapper. Reading the wrapper reports "configured" for
  // every live bucket, because the wrapper is always a non-empty object even
  // when `value` is null (verified against a real account: 0/24 buckets had
  // replication, the wrapper check claimed 24/24).
  const replicationWrapper = bucket.replicationConfiguration ?? null;
  const replicationReadable =
    replicationWrapper?.isClientAuthorizedToRead !== false;
  const replication = (replicationWrapper?.value ?? null) as
    | Record<string, unknown>
    | null;
  return {
    bucketName: bucket.bucketName ?? bucketName,
    bucketId: bucket.bucketId ?? null,
    accountId: bucket.accountId ?? null,
    bucketType: bucket.bucketType ?? null,
    bucketInfo: bucket.bucketInfo ?? {},
    corsRules: Array.isArray(bucket.corsRules) ? bucket.corsRules : [],
    lifecycleRules,
    prunesHiddenVersions: retention.prunesHiddenVersions,
    minDaysFromHidingToDeleting: retention.minDaysFromHidingToDeleting,
    unprunedPrefixes: retention.unprunedPrefixes,
    fileLockEnabled: typeof lock?.isFileLockEnabled === "boolean"
      ? lock.isFileLockEnabled
      : null,
    defaultRetentionMode: lock?.defaultRetention?.mode ?? null,
    defaultRetentionPeriod: toRetentionPeriod(lock?.defaultRetention?.period),
    defaultServerSideEncryptionMode: sse?.mode ?? null,
    replicationConfigured: replicationReadable
      ? replication !== null && Object.keys(replication).length > 0
      : null,
    revision: typeof bucket.revision === "number" ? bucket.revision : null,
    // Coerced rather than passed through: `options` stays a string array for
    // consumers, but one non-string element must not sink the whole snapshot.
    // Coercing keeps the element count honest where filtering would understate
    // what B2 reported.
    options: Array.isArray(bucket.options)
      ? bucket.options.map((o) => typeof o === "string" ? o : String(o))
      : [],
    exists: true,
    observedAt,
  };
}

/**
 * Strip every secret out of an event notification rule before it is stored.
 *
 * `hmacSha256SigningSecret` is dropped entirely (only its presence survives),
 * and custom header *values* are dropped while their names are kept — a custom
 * header is a common place to put a bearer token.
 */
export function redactNotificationRule(
  rule: B2NotificationRule,
): Record<string, unknown> {
  const target = rule.targetConfiguration ?? {};
  return {
    name: rule.name ?? "",
    eventTypes: Array.isArray(rule.eventTypes) ? rule.eventTypes : [],
    objectNamePrefix: rule.objectNamePrefix ?? "",
    isEnabled: rule.isEnabled ?? false,
    isSuspended: rule.isSuspended ?? null,
    suspensionReason: rule.suspensionReason ?? null,
    maxEventsPerBatch: typeof rule.maxEventsPerBatch === "number"
      ? rule.maxEventsPerBatch
      : null,
    targetType: target.targetType ?? "webhook",
    url: target.url ?? "",
    customHeaderNames: (target.customHeaders ?? []).map((h) => h?.name ?? ""),
    hasSigningSecret: typeof target.hmacSha256SigningSecret === "string" &&
      target.hmacSha256SigningSecret.length > 0,
  };
}

/**
 * Refuse to make a bucket public unless it was explicitly acknowledged.
 *
 * This lives in the METHOD, not only in a pre-flight check, and that is
 * deliberate. swamp gives checks the model's global arguments but never the
 * method's inputs, so a check cannot see `--input bucketType=allPublic` — which
 * is precisely the invocation that exposes a bucket. A check alone would pass
 * the one case it exists to stop. The sibling `bucket-visibility` check catches
 * the globalArgs path early, before any B2 call; this is what enforces.
 */
export function assertPublicBucketAllowed(
  desiredBucketType: string | undefined,
  g: { bucketName: string; allowPublicBucket?: boolean },
  argAllowPublicBucket?: boolean,
): void {
  if (desiredBucketType !== "allPublic") return;
  if (argAllowPublicBucket ?? g.allowPublicBucket) return;
  throw new Error(
    `Refusing to set bucket "${g.bucketName}" to allPublic: everything in it ` +
      `becomes readable by anyone who learns the bucket name, and a restic ` +
      `repository must never be public. If this bucket genuinely should be ` +
      `public, acknowledge it with --input allowPublicBucket=true for a single ` +
      `run, or set allowPublicBucket=true on the model to make it permanent.`,
  );
}

/**
 * Instance name for a `notificationRules` snapshot.
 *
 * Instance names map straight onto storage paths and must be unique across
 * **all** specs of a model, not just within one — writing `bucket` and
 * `notificationRules` under the same plain bucket name would make the second
 * write silently clobber the first on disk. The prefix keeps both keyed by the
 * real bucket name while staying distinct.
 */
export function notificationRulesInstanceName(bucketName: string): string {
  return `notification-rules-${bucketName}`;
}

/**
 * Instance name for a `bucket` snapshot.
 *
 * Normally the bare bucket name, so a snapshot stays addressable by the thing
 * an operator actually types. The one exception is `"latest"`: swamp reserves
 * it as a data name and rejects it at write time only, while B2 bucket names
 * are 6-63 characters from a global namespace — `"latest"` is six, so it is a
 * legal name that somebody owns. Left bare, that bucket would be unmanageable
 * by this model, failing every method with an opaque run-time error.
 *
 * The alias is a fixed string rather than a fallback to `bucketId` because the
 * `delete` tombstone has to be written even when the bucket was never found and
 * no ID ever resolved. Aliasing cannot collide with a real bucket named
 * `bucket-latest`: resources are namespaced per model instance, and one
 * instance manages exactly one bucket.
 */
export function bucketInstanceName(bucketName: string): string {
  return bucketName === "latest" ? "bucket-latest" : bucketName;
}

/** Build a `notificationRules` resource snapshot with every secret removed. */
export function toNotificationRulesResource(
  bucketName: string,
  bucketId: string | null,
  rules: B2NotificationRule[],
  observedAt: string,
): Record<string, unknown> {
  return {
    bucketName,
    bucketId,
    ruleCount: rules.length,
    rules: rules.map(redactNotificationRule),
    observedAt,
  };
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/** Open a B2 session and return it alongside a `reauth` callback for `b2Fetch`. */
async function session(
  g: GlobalArgs,
): Promise<{ auth: B2Auth; reauth: () => Promise<B2Auth> }> {
  const reauth = () => b2Authorize(g);
  return { auth: await b2Authorize(g), reauth };
}

/**
 * Look the managed bucket up by name via `b2_list_buckets`.
 *
 * Always filters server-side by `bucketName`: it is one class-C transaction
 * either way, but a bucket-restricted application key *requires* the filter.
 * Returns null when the bucket does not exist.
 */
export async function findBucket(
  auth: B2Auth,
  bucketName: string,
  reauth?: () => Promise<B2Auth>,
): Promise<B2Bucket | null> {
  const res = await b2Fetch<{ buckets?: B2Bucket[] }>(
    auth,
    "POST",
    "b2_list_buckets",
    { accountId: auth.accountId, bucketName },
    reauth,
  );
  const buckets = res.buckets ?? [];
  return buckets.find((b) => b.bucketName === bucketName) ?? buckets[0] ?? null;
}

/**
 * Resolve the bucket ID the mutating operations need.
 *
 * Prefers `globalArgs.bucketId` (free); otherwise looks the name up, costing one
 * class-C `b2_list_buckets` transaction. Returns null when the bucket does not
 * exist, which `delete` treats as an idempotent success.
 */
async function resolveBucketId(
  auth: B2Auth,
  g: GlobalArgs,
  reauth: () => Promise<B2Auth>,
): Promise<string | null> {
  if (g.bucketId) return g.bucketId;
  const bucket = await findBucket(auth, g.bucketName, reauth);
  return bucket?.bucketId ?? null;
}

/** Merge globalArgs desired state with per-run method overrides. */
function pick<T>(
  override: T | undefined,
  fallback: T | undefined,
): T | undefined {
  return override !== undefined ? override : fallback;
}

/**
 * Decide whether a thrown `b2Fetch` error means "the bucket is already gone".
 *
 * Per CONVENTIONS §3: a `404`, or a `400` whose `b2Code` is `bad_bucket_id`.
 */
export function isAlreadyGone(e: unknown): boolean {
  const err = e as { status?: number; b2Code?: string };
  if (err.status === 404) return true;
  return err.status === 400 && err.b2Code === "bad_bucket_id";
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/**
 * Backblaze B2 bucket model — manages one bucket (keyed by `bucketName`) over
 * the B2 Native API v4, including its lifecycle rules and event notification
 * rules.
 */
export const model = {
  type: "@sntxrr/b2/bucket",
  version: "2026.08.05.2",
  globalArguments: GlobalArgsSchema,
  resources: {
    "bucket": {
      description:
        "Snapshot of the managed B2 bucket's configuration and state",
      schema: BucketResourceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    "notificationRules": {
      description:
        "Snapshot of the bucket's event notification rules, with signing secrets and header values redacted",
      schema: NotificationRulesResourceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
  },
  methods: {
    "sync": {
      description:
        "Read the managed bucket's current state (b2_list_buckets filtered by bucketName) and snapshot it. Records whether the bucket prunes hidden file versions. Requires the listBuckets capability.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const bucket = await findBucket(auth, g.bucketName, reauth);
        const data = toBucketResource(
          g.bucketName,
          bucket,
          new Date().toISOString(),
        );
        if (bucket === null) {
          logger.warn("Bucket {bucketName} does not exist", {
            bucketName: g.bucketName,
          });
        } else if (data.prunesHiddenVersions !== true) {
          logger.warn(
            "Bucket {bucketName} has no lifecycle rule with daysFromHidingToDeleting — hidden file versions are retained, and billed, forever",
            { bucketName: g.bucketName },
          );
        }
        const handle = await context.writeResource(
          "bucket",
          bucketInstanceName(g.bucketName),
          data,
        );
        logger.info("Synced bucket {bucketName} (exists={exists})", {
          bucketName: g.bucketName,
          exists: data.exists,
        });
        return { dataHandles: [handle] };
      },
    },
    "create": {
      description:
        "Create the managed bucket (b2_create_bucket) with the declared bucketType, lifecycleRules, corsRules, fileLockEnabled and defaultServerSideEncryption. Not idempotent: an existing name fails with duplicate_bucket_name rather than silently adopting a bucket with different settings. Requires writeBuckets (plus writeBucketRetentions for fileLockEnabled).",
      arguments: BucketConfigArgsSchema,
      execute: async (
        args: z.infer<typeof BucketConfigArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const payload: Record<string, unknown> = {
          accountId: auth.accountId,
          bucketName: g.bucketName,
          bucketType: (() => {
            const t = pick(args.bucketType, g.bucketType) ?? "allPrivate";
            assertPublicBucketAllowed(t, g, args.allowPublicBucket);
            return t;
          })(),
        };
        const lifecycleRules = pick(args.lifecycleRules, g.lifecycleRules);
        if (lifecycleRules !== undefined) {
          payload.lifecycleRules = lifecycleRules;
        }
        const corsRules = pick(args.corsRules, g.corsRules);
        if (corsRules !== undefined) payload.corsRules = corsRules;
        const bucketInfo = pick(args.bucketInfo, g.bucketInfo);
        if (bucketInfo !== undefined) payload.bucketInfo = bucketInfo;
        const fileLockEnabled = pick(args.fileLockEnabled, g.fileLockEnabled);
        if (fileLockEnabled !== undefined) {
          payload.fileLockEnabled = fileLockEnabled;
        }
        const sse = pick(
          args.defaultServerSideEncryption,
          g.defaultServerSideEncryption,
        );
        if (sse !== undefined) payload.defaultServerSideEncryption = sse;
        const replication = pick(
          args.replicationConfiguration,
          g.replicationConfiguration,
        );
        if (replication !== undefined) {
          payload.replicationConfiguration = replication;
        }

        logger.info("Creating bucket {bucketName} ({bucketType})", {
          bucketName: g.bucketName,
          bucketType: payload.bucketType,
        });
        const bucket = await b2Fetch<B2Bucket>(
          auth,
          "POST",
          "b2_create_bucket",
          payload,
          reauth,
        );
        const handle = await context.writeResource(
          "bucket",
          bucketInstanceName(g.bucketName),
          toBucketResource(g.bucketName, bucket, new Date().toISOString()),
        );
        logger.info("Created bucket {bucketName} (bucketId={bucketId})", {
          bucketName: g.bucketName,
          bucketId: bucket.bucketId ?? null,
        });
        return { dataHandles: [handle] };
      },
    },
    "update": {
      description:
        "Update the managed bucket (b2_update_bucket): lifecycle rules, bucket type, CORS rules, replication configuration, Object Lock and default encryption/retention. Only fields you supply are sent; everything else is left untouched. Requires writeBuckets.",
      arguments: UpdateArgsSchema,
      execute: async (
        args: z.infer<typeof UpdateArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const bucketId = await resolveBucketId(auth, g, reauth);
        if (bucketId === null) {
          throw new Error(
            `Cannot update bucket "${g.bucketName}": it does not exist. Run create first.`,
          );
        }
        const payload: Record<string, unknown> = {
          accountId: auth.accountId,
          bucketId,
        };
        const bucketType = pick(args.bucketType, g.bucketType);
        if (bucketType !== undefined) {
          assertPublicBucketAllowed(bucketType, g, args.allowPublicBucket);
          payload.bucketType = bucketType;
        }
        const lifecycleRules = pick(args.lifecycleRules, g.lifecycleRules);
        if (lifecycleRules !== undefined) {
          payload.lifecycleRules = lifecycleRules;
        }
        const corsRules = pick(args.corsRules, g.corsRules);
        if (corsRules !== undefined) payload.corsRules = corsRules;
        const bucketInfo = pick(args.bucketInfo, g.bucketInfo);
        if (bucketInfo !== undefined) payload.bucketInfo = bucketInfo;
        const fileLockEnabled = pick(args.fileLockEnabled, g.fileLockEnabled);
        if (fileLockEnabled !== undefined) {
          payload.fileLockEnabled = fileLockEnabled;
        }
        const sse = pick(
          args.defaultServerSideEncryption,
          g.defaultServerSideEncryption,
        );
        if (sse !== undefined) payload.defaultServerSideEncryption = sse;
        const defaultRetention = pick(
          args.defaultRetention,
          g.defaultRetention,
        );
        if (defaultRetention !== undefined) {
          payload.defaultRetention = defaultRetention;
        }
        const replication = pick(
          args.replicationConfiguration,
          g.replicationConfiguration,
        );
        if (replication !== undefined) {
          payload.replicationConfiguration = replication;
        }
        if (args.ifRevisionIs !== undefined) {
          payload.ifRevisionIs = args.ifRevisionIs;
        }
        if (Object.keys(payload).length === 2) {
          logger.warn(
            "No mutable fields supplied for {bucketName}; b2_update_bucket will return current state unchanged",
            { bucketName: g.bucketName },
          );
        }

        logger.info("Updating bucket {bucketName} (bucketId={bucketId})", {
          bucketName: g.bucketName,
          bucketId,
        });
        const bucket = await b2Fetch<B2Bucket>(
          auth,
          "POST",
          "b2_update_bucket",
          payload,
          reauth,
        );
        const data = toBucketResource(
          g.bucketName,
          bucket,
          new Date().toISOString(),
        );
        if (data.prunesHiddenVersions !== true) {
          logger.warn(
            "Bucket {bucketName} still has no lifecycle rule with daysFromHidingToDeleting after update",
            { bucketName: g.bucketName },
          );
        }
        const handle = await context.writeResource(
          "bucket",
          bucketInstanceName(g.bucketName),
          data,
        );
        logger.info("Updated bucket {bucketName}", {
          bucketName: g.bucketName,
        });
        return { dataHandles: [handle] };
      },
    },
    "delete": {
      description:
        "Delete the managed bucket (b2_delete_bucket). The bucket must already be empty. Idempotent: a 404, or a 400 with b2Code bad_bucket_id, is treated as success and still writes an exists=false snapshot. Requires deleteBuckets (and listBuckets unless globalArgs.bucketId is set).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const bucketId = await resolveBucketId(auth, g, reauth);
        if (bucketId === null) {
          logger.info(
            "Bucket {bucketName} is already absent; treating delete as successful",
            { bucketName: g.bucketName },
          );
        } else {
          logger.info("Deleting bucket {bucketName} (bucketId={bucketId})", {
            bucketName: g.bucketName,
            bucketId,
          });
          try {
            await b2Fetch<B2Bucket>(
              auth,
              "POST",
              "b2_delete_bucket",
              { accountId: auth.accountId, bucketId },
              reauth,
            );
          } catch (e) {
            // Already gone is the desired end state — an idempotent success.
            if (!isAlreadyGone(e)) throw e;
            logger.info(
              "Bucket {bucketName} was already gone; treating delete as successful",
              { bucketName: g.bucketName },
            );
          }
        }
        const deletedAt = new Date().toISOString();
        const handles = [
          await context.writeResource(
            "bucket",
            bucketInstanceName(g.bucketName),
            toBucketResource(g.bucketName, null, deletedAt),
          ),
        ];
        // The sibling notificationRules snapshot has lifetime "infinite", so
        // without this it would outlive the bucket forever — leaving webhook
        // targets for a bucket that no longer exists looking live in any
        // report that reads it. Tombstone it rather than deleting it, so the
        // rules that *were* configured stay auditable after the fact.
        // Unconditional: guarding this on a resolved bucketId left the
        // snapshot alive on exactly the path where the bucket could not be
        // found — the case most likely to be a stale record in the first
        // place. The spec schema allows a null bucketId for this reason.
        handles.push(
          await context.writeResource(
            "notificationRules",
            notificationRulesInstanceName(g.bucketName),
            toNotificationRulesResource(
              g.bucketName,
              bucketId,
              [],
              deletedAt,
            ),
          ),
        );
        logger.info("Deleted bucket {bucketName}", {
          bucketName: g.bucketName,
        });
        return { dataHandles: handles };
      },
    },
    "get_notification_rules": {
      description:
        "Read the bucket's event notification rules (b2_get_bucket_notification_rules — a GET with query parameters, not a POST) and snapshot them with signing secrets and header values redacted. Requires the readBucketNotifications capability.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const bucketId = await resolveBucketId(auth, g, reauth);
        if (bucketId === null) {
          throw new Error(
            `Cannot read notification rules for bucket "${g.bucketName}": it does not exist.`,
          );
        }
        // GET with query parameters — b2Fetch serialises the payload into the
        // query string when the method is "GET".
        const res = await b2Fetch<
          { bucketId?: string; eventNotificationRules?: B2NotificationRule[] }
        >(
          auth,
          "GET",
          "b2_get_bucket_notification_rules",
          { bucketId },
          reauth,
        );
        const rules = res.eventNotificationRules ?? [];
        const handle = await context.writeResource(
          "notificationRules",
          notificationRulesInstanceName(g.bucketName),
          toNotificationRulesResource(
            g.bucketName,
            res.bucketId ?? bucketId,
            rules,
            new Date().toISOString(),
          ),
        );
        logger.info("Read {n} notification rules for {bucketName}", {
          n: rules.length,
          bucketName: g.bucketName,
        });
        return { dataHandles: [handle] };
      },
    },
    "set_notification_rules": {
      description:
        "Replace the bucket's event notification rules (b2_set_bucket_notification_rules, POST). The supplied list REPLACES all existing rules; pass [] to remove them. Requires writeBucketNotifications. NOTE: pre-flight checks do NOT run for this method — swamp only auto-runs them before methods named create/update/delete/action.",
      arguments: SetNotificationRulesArgsSchema,
      execute: async (
        args: z.infer<typeof SetNotificationRulesArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const bucketId = await resolveBucketId(auth, g, reauth);
        if (bucketId === null) {
          throw new Error(
            `Cannot set notification rules for bucket "${g.bucketName}": it does not exist.`,
          );
        }
        logger.info(
          "Setting {n} notification rules on {bucketName} (replaces all existing rules)",
          { n: args.rules.length, bucketName: g.bucketName },
        );
        const res = await b2Fetch<
          { bucketId?: string; eventNotificationRules?: B2NotificationRule[] }
        >(
          auth,
          "POST",
          "b2_set_bucket_notification_rules",
          { bucketId, eventNotificationRules: args.rules },
          reauth,
        );
        const rules = res.eventNotificationRules ?? [];
        const handle = await context.writeResource(
          "notificationRules",
          notificationRulesInstanceName(g.bucketName),
          toNotificationRulesResource(
            g.bucketName,
            res.bucketId ?? bucketId,
            rules,
            new Date().toISOString(),
          ),
        );
        logger.info("Set {n} notification rules on {bucketName}", {
          n: rules.length,
          bucketName: g.bucketName,
        });
        return { dataHandles: [handle] };
      },
    },
  },
  checks: {
    "bucket-visibility": {
      description:
        "Refuse to create or update a bucket as allPublic unless allowPublicBucket=true acknowledges it. A restic repository must never be public. NOTE: this catches the global-argument path only — swamp does not give checks the method's inputs, so `--input bucketType=allPublic` is invisible here and is blocked inside create/update instead.",
      labels: ["policy"],
      appliesTo: ["create", "update"],
      // deno-lint-ignore require-await
      execute: async (
        context: { globalArgs: GlobalArgs },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const g = context.globalArgs;
        if (g.bucketType !== "allPublic" || g.allowPublicBucket) {
          return { pass: true };
        }
        return {
          pass: false,
          errors: [
            `Bucket "${g.bucketName}" is declared allPublic, which makes every object in it readable by anyone who learns the bucket name. A restic repository must never be public. Set allowPublicBucket=true to acknowledge this deliberately, or change bucketType to allPrivate.`,
          ],
        };
      },
    },
    "lifecycle-hidden-version-retention": {
      description:
        "Refuse to create or update a bucket that would be left with no lifecycle rule setting daysFromHidingToDeleting. B2 keeps every hidden file version forever without one, so a restic bucket silently accumulates — and is billed for — the pack files restic already pruned. Acknowledge the exception with globalArgs.allowUnprunedHiddenVersions=true or --skip-check lifecycle-hidden-version-retention.",
      labels: ["policy"],
      appliesTo: ["create", "update"],
      execute: async (
        context: {
          globalArgs: GlobalArgs;
          modelType: string;
          modelId: string;
          logger: Logger;
          dataRepository?: {
            getContent: (
              type: string,
              modelId: string,
              dataName: string,
              version?: number,
            ) => Promise<Uint8Array | null>;
          };
        },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const { globalArgs: g, logger } = context;
        const example =
          '[{ "fileNamePrefix": "", "daysFromUploadingToHiding": null, "daysFromHidingToDeleting": 1 }]';

        if (g.allowUnprunedHiddenVersions) {
          logger.warn(
            "Bucket {bucketName}: hidden-version retention check waived by allowUnprunedHiddenVersions",
            { bucketName: g.bucketName },
          );
          return { pass: true };
        }

        // 1. The model declares the desired rules — judge those.
        if (g.lifecycleRules !== undefined) {
          const declared = analyzeHiddenVersionRetention(g.lifecycleRules);
          if (!declared.prunesHiddenVersions) {
            return {
              pass: false,
              errors: [
                `Bucket "${g.bucketName}": none of the ${g.lifecycleRules.length} declared lifecycle rule(s) sets daysFromHidingToDeleting, so B2 will retain every hidden file version forever. Anything restic prunes stays billed. Add a rule such as ${example}, or set allowUnprunedHiddenVersions=true to accept this.`,
              ],
            };
          }
          if (declared.unprunedPrefixes.length > 0) {
            logger.warn(
              "Bucket {bucketName}: prefixes {prefixes} have no daysFromHidingToDeleting and will retain hidden versions forever",
              {
                bucketName: g.bucketName,
                prefixes: declared.unprunedPrefixes.join(", "),
              },
            );
          }
          return { pass: true };
        }

        // 2. Nothing declared: `update` leaves the bucket's rules untouched, so
        //    fall back to the last observed state written by `sync`.
        let observed: Record<string, unknown> | null = null;
        try {
          const bytes = await context.dataRepository?.getContent(
            context.modelType,
            context.modelId,
            g.bucketName,
          );
          if (bytes) {
            const parsed = JSON.parse(new TextDecoder().decode(bytes)) as
              & Record<string, unknown>
              & { attributes?: Record<string, unknown> };
            observed = parsed.attributes ?? parsed;
          }
        } catch {
          // No readable prior snapshot — fall through to the failure below.
        }
        if (observed?.prunesHiddenVersions === true) return { pass: true };

        return {
          pass: false,
          errors: [
            `Bucket "${g.bucketName}": no lifecycleRules are declared as a GLOBAL ARGUMENT, and no prior snapshot proves the bucket deletes hidden file versions, so this run could leave restic-pruned data billed forever. Declare them with --global-arg 'lifecycleRules=${example}', run sync first to record the bucket's real state, or set allowUnprunedHiddenVersions=true to accept this. NOTE: a --input lifecycleRules=... on this run cannot satisfy this check — swamp gives pre-flight checks the model's global arguments but not the method's inputs, so the check cannot see it. The method itself still honours the input; it is only this safety gate that is blind to it.`,
          ],
        };
      },
    },
  },
};

/**
 * Internal helpers and schemas, exported only for unit testing.
 */
export const _internal = {
  GlobalArgsSchema,
  LifecycleRuleSchema,
  NotificationRuleInputSchema,
  BucketResourceSchema,
  NotificationRulesResourceSchema,
  analyzeHiddenVersionRetention,
  parseLifecycleRules,
  toBucketResource,
  toNotificationRulesResource,
  notificationRulesInstanceName,
  bucketInstanceName,
  assertPublicBucketAllowed,
  redactNotificationRule,
  findBucket,
  isAlreadyGone,
  pick,
};
