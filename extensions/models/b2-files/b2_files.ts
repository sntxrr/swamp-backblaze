/**
 * Backblaze B2 file inventory and file-version management via the B2 Native
 * API v4.
 *
 * **Why this model exists.** `@sntxrr/b2/bucket` can tell you a bucket has no
 * lifecycle rule deleting hidden file versions. It cannot tell you what that
 * costs. B2 keeps every version restic's `forget --prune` deletes — forever,
 * and billed — unless a lifecycle rule reaps it, and the only way to size that
 * debt is to enumerate the versions. That is what `scan` does: it separates
 * what a bucket currently holds (`currentBytes`) from what it is merely still
 * paying for (`nonCurrentBytes`).
 *
 * **`scan` defaults to aggregate mode, deliberately.** A restic repository
 * holds tens of thousands of pack files. Emitting one swamp resource per file
 * version would bury the repo in snapshots nobody reads, so the default writes
 * one `aggregate` resource per bucket — counts and byte totals, no per-file
 * state. Per-file resources require opting in with `mode: "detailed"`, which in
 * turn requires an explicit `prefix` and `maxFiles` cap.
 *
 * **Honest nulls.** Every count this model cannot actually measure is `null`,
 * never `0`. Listing with `includeVersions: false` sees only current files, so
 * `nonCurrentBytes` is `null` — "not measured" — because reporting `0` would
 * read as "nothing is accumulating" about precisely the buckets where
 * everything is. That exact bug shipped once in this suite already
 * (`unprunedPrefixes: []`), and mock tests could not see it.
 *
 * **Authorization wrappers.** `fileRetention` and `legalHold` arrive wrapped as
 * `{ isClientAuthorizedToRead, value }` and B2 nulls `value` when the calling
 * key lacks `readFileRetentions` / `readFileLegalHolds`. A `null` there means
 * "not allowed to see it", which is a different fact from "not set" — so every
 * snapshot carries a separate `*Authorized` flag, and the aggregate counts
 * unreadable entries separately from absent ones.
 *
 * **Destruction is gated.** `delete` and `hide` remove or mask a file version,
 * and doing either to a restic pack file corrupts the repository. Both refuse
 * to run without an explicit `allowFileDestruction` acknowledgement. So does
 * setting `compliance` retention, which is a one-way door: not even the account
 * owner can shorten it, so a mistake there is billed until the clock runs out.
 *
 * **Security.** `applicationKey` is sensitive and wired from a vault. The 24h
 * `authorizationToken` is a bearer credential and is never logged nor written
 * into a resource. B2 never returns SSE-C key material, so no file payload
 * carries a secret — but `fileInfo` is arbitrary user metadata and lands in a
 * snapshot verbatim, so it must never be used to store a credential.
 *
 * API reference: https://www.backblaze.com/apidocs/b2-native-api
 *
 * @module
 */
// extensions/models/b2-files/b2_files.ts
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
// Context types (canonical — see CONVENTIONS.md §6)
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
// Wire types — the raw shapes B2 returns
// ---------------------------------------------------------------------------

/**
 * A B2 file version as returned by `b2_list_file_names`,
 * `b2_list_file_versions`, `b2_get_file_info`, `b2_hide_file` and
 * `b2_copy_file`.
 *
 * `fileRetention` and `legalHold` are authorization-wrapped: B2 nulls `value`
 * when the calling key cannot read them, which is not the same as unset.
 */
type B2File = {
  accountId?: string;
  action?: string;
  bucketId?: string;
  contentLength?: number;
  contentMd5?: string | null;
  contentSha1?: string | null;
  contentType?: string | null;
  fileId?: string | null;
  fileInfo?: Record<string, unknown> | null;
  fileName?: string;
  fileRetention?: {
    isClientAuthorizedToRead?: boolean;
    value?: {
      mode?: string | null;
      retainUntilTimestamp?: number | null;
    } | null;
  } | null;
  legalHold?: {
    isClientAuthorizedToRead?: boolean;
    value?: string | null;
  } | null;
  replicationStatus?: string | null;
  serverSideEncryption?: { mode?: string | null; algorithm?: string | null };
  uploadTimestamp?: number | null;
};

/** A B2 bucket, as far as this model needs it: the name-to-ID mapping. */
type B2Bucket = {
  bucketId?: string;
  bucketName?: string;
};

// ---------------------------------------------------------------------------
// Schemas — global arguments
// ---------------------------------------------------------------------------

/**
 * Global arguments for the B2 files model.
 *
 * `bucketName` is optional on purpose. Left unset, `scan` inventories every
 * bucket the key can see in a single execution — which is what the fleet audit
 * wants, and what keeps the whole sweep behind one acquisition of the per-model
 * lock instead of N contending runs. The single-file methods (`sync`, `delete`,
 * `hide`, `copy`, `update`) all need exactly one bucket and say so.
 */
const GlobalArgsSchema = z.object({
  applicationKeyId: z.string().describe(
    "B2 application key ID (master or scoped). See the README for the " +
      "capabilities each method needs.",
  ),
  applicationKey: z.string().meta({ sensitive: true }).describe(
    "B2 application key — supply via vault.get(), never inline.",
  ),
  authHost: z.string().url().optional().describe(
    "Override the B2 authorize host (testing only). Defaults to " +
      "https://api.backblazeb2.com. The per-cluster apiUrl used for every " +
      "other call is always taken from the authorize response, never guessed.",
  ),
  bucketName: z.string().optional().describe(
    "Bucket this model manages. Required by sync/delete/hide/copy/update. " +
      "When omitted, scan inventories EVERY bucket the key can see in one " +
      "execution (the fleet-audit path).",
  ),
  bucketId: z.string().optional().describe(
    "Bucket ID matching bucketName. Supplying it saves one class-C " +
      "b2_list_buckets call per run and lets a bucket-restricted key work " +
      "without the listBuckets capability.",
  ),
  allowFileDestruction: z.boolean().optional().describe(
    "Acknowledge that delete and hide remove or mask a file version. Doing " +
      "either to a restic pack file corrupts the repository, so both methods " +
      "refuse to run without this set here or passed as a method input.",
  ),
  allowComplianceRetention: z.boolean().optional().describe(
    "Acknowledge that compliance-mode retention is irreversible — it cannot " +
      "be shortened or removed by anyone, including the account owner, so " +
      "the object is billed until the clock runs out. Required by update " +
      "before it will set mode=compliance.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Schemas — method arguments
// ---------------------------------------------------------------------------

/** Arguments for the `scan` factory method. */
const ScanArgsSchema = z.object({
  mode: z.enum(["aggregate", "detailed"]).optional().describe(
    'Defaults to "aggregate": one summary resource per bucket, no per-file ' +
      'resources. "detailed" additionally emits one resource per file ' +
      "version and REQUIRES both prefix and maxFiles — a restic repository " +
      "holds tens of thousands of pack files.",
  ),
  bucketNames: z.array(z.string()).optional().describe(
    "Scan exactly these buckets. Overrides globalArgs.bucketName. Omit both " +
      "to scan every bucket the key can see.",
  ),
  prefix: z.string().optional().describe(
    "Server-side file-name prefix filter. Optional in aggregate mode; " +
      "REQUIRED in detailed mode.",
  ),
  groupBy: z.enum(["none", "topLevel"]).optional().describe(
    'Defaults to "none" — one aggregate per bucket. "topLevel" additionally ' +
      "emits one aggregate per first path segment, which for a restic " +
      "repository separates data/ from index/, snapshots/, keys/ and locks/. " +
      "Grouping is computed client-side and costs no extra B2 calls.",
  ),
  includeVersions: z.boolean().optional().describe(
    "Defaults to true: list every file VERSION (b2_list_file_versions), " +
      "which is the only way to measure hidden and superseded versions. Set " +
      "false to list current files only (b2_list_file_names) — cheaper in " +
      "wall-clock on a bucket with deep history, but then every " +
      "non-current metric is reported as null, not zero.",
  ),
  maxFileCount: z.number().int().min(1).max(10000).optional().describe(
    "Files requested per list page. Defaults to 10000, the B2 maximum. B2 " +
      "bills a list call per 1000 files returned regardless of page size, so " +
      "a large page costs the same as ten small ones and makes a tenth as " +
      "many round trips.",
  ),
  maxPages: z.number().int().min(1).max(10000).optional().describe(
    "Hard cap on list pages per bucket. Defaults to 50 (up to 500,000 files " +
      "at the default page size). Hitting the cap sets truncated=true on the " +
      "aggregate rather than silently reporting a partial inventory as whole.",
  ),
  maxFiles: z.number().int().min(1).max(100000).optional().describe(
    "Maximum per-file resources to emit. REQUIRED in detailed mode; ignored " +
      "in aggregate mode. Listing also stops once this many files are in " +
      "hand, which sets truncated=true on the aggregate.",
  ),
});

/** Arguments identifying one file version. */
const FileRefArgsSchema = z.object({
  fileId: z.string().optional().describe(
    "The file version to act on. Exact and free of a lookup; prefer it when " +
      "known. Supply this or fileName.",
  ),
  fileName: z.string().optional().describe(
    "File name to resolve to its newest version via b2_list_file_versions " +
      "(one class-C transaction). Supply this or fileId.",
  ),
});

/** Arguments for `delete`. */
const DeleteArgsSchema = FileRefArgsSchema.extend({
  bypassGovernance: z.boolean().optional().describe(
    "Delete a version protected by GOVERNANCE-mode retention. Requires the " +
      "bypassGovernance capability. Has no effect on compliance mode, which " +
      "nothing can bypass.",
  ),
  allowFileDestruction: z.boolean().optional().describe(
    "Acknowledge the destruction for this run only. Equivalent to the global " +
      "argument of the same name, which makes it permanent.",
  ),
});

/** Arguments for `hide`. */
const HideArgsSchema = z.object({
  fileName: z.string().describe(
    "File name to hide. B2 writes a hide marker as a new version; the " +
      "underlying data is retained (and billed) until a lifecycle rule reaps " +
      "it. Hiding a restic pack file makes the repository unreadable.",
  ),
  allowFileDestruction: z.boolean().optional().describe(
    "Acknowledge the destruction for this run only. Equivalent to the global " +
      "argument of the same name, which makes it permanent.",
  ),
});

/** Arguments for `copy`. */
const CopyArgsSchema = z.object({
  sourceFileId: z.string().describe(
    "File version to copy from. Must be readable by the calling key.",
  ),
  fileName: z.string().describe("File name to create in the destination."),
  destinationBucketId: z.string().optional().describe(
    "Destination bucket ID. Defaults to this model's bucket. Both buckets " +
      "must belong to the same account. Supply destinationBucketName too, or " +
      "the run spends one class-C b2_list_buckets call resolving the name for " +
      "the snapshot.",
  ),
  destinationBucketName: z.string().optional().describe(
    "Name of the destination bucket, recorded in the snapshot. Resolved from " +
      "destinationBucketId when omitted; ignored when the copy lands in this " +
      "model's own bucket.",
  ),
  contentType: z.string().optional().describe(
    "Content type for the copy. Only meaningful with metadataDirective " +
      '"REPLACE".',
  ),
  fileInfo: z.record(z.string(), z.string()).optional().describe(
    "Replacement file metadata. Only meaningful with metadataDirective " +
      '"REPLACE". Never put a credential here — it is stored with the file ' +
      "and lands verbatim in a snapshot.",
  ),
  metadataDirective: z.enum(["COPY", "REPLACE"]).optional().describe(
    'Whether to carry the source metadata over ("COPY", the B2 default) or ' +
      'replace it ("REPLACE", which requires contentType).',
  ),
  range: z.string().optional().describe(
    'Byte range of the source to copy, e.g. "bytes=0-1023". Omit to copy the ' +
      "whole file.",
  ),
});

/** Arguments for `update` (legal hold and retention). */
const UpdateArgsSchema = FileRefArgsSchema.extend({
  legalHold: z.enum(["on", "off"]).optional().describe(
    "Set or clear the legal hold. A file under legal hold cannot be deleted " +
      "until it is cleared. Reversible, unlike compliance retention.",
  ),
  retentionMode: z.enum(["governance", "compliance", "none"]).optional()
    .describe(
      '"governance" can be bypassed by a key holding bypassGovernance; ' +
        '"compliance" cannot be shortened or removed by anyone, ever; ' +
        '"none" clears retention. Setting governance or compliance requires ' +
        "retainUntilTimestamp.",
    ),
  retainUntilTimestamp: z.number().int().optional().describe(
    "Retain-until instant in milliseconds since the Unix epoch. Required " +
      'when retentionMode is "governance" or "compliance".',
  ),
  bypassGovernance: z.boolean().optional().describe(
    "Shorten or clear an existing GOVERNANCE-mode retention. Requires the " +
      "bypassGovernance capability.",
  ),
  allowComplianceRetention: z.boolean().optional().describe(
    "Acknowledge irreversible compliance retention for this run only. " +
      "Equivalent to the global argument of the same name.",
  ),
});

// ---------------------------------------------------------------------------
// Schemas — resources
// ---------------------------------------------------------------------------

/**
 * Aggregate inventory of one bucket, or of one prefix group within it.
 *
 * This is the resource that sizes the hidden-version debt: `currentBytes` is
 * what the bucket actually holds, `nonCurrentBytes` is what it is still paying
 * for and no longer serving.
 *
 * Every count that depends on version listing is **nullable, and null means
 * "not measured"** — reported when `includeVersions` was false, because
 * `b2_list_file_names` cannot see a superseded or hidden version at all.
 * Reporting zero there would be indistinguishable from a bucket with no debt.
 */
const AggregateResourceSchema = z.object({
  bucketName: z.string().describe("Bucket this aggregate covers."),
  bucketId: z.string().nullable().describe(
    "B2 bucket ID, or null if it could not be resolved.",
  ),
  prefix: z.string().describe(
    "Server-side prefix filter applied to the listing. Empty means the whole " +
      "bucket.",
  ),
  group: z.string().nullable().describe(
    "Client-side prefix group this aggregate covers, or null for the " +
      'bucket-wide total. With groupBy "topLevel" it is the first path ' +
      'segment including its slash, e.g. "data/", or "" for files at the ' +
      "bucket root.",
  ),
  scanMode: z.enum(["aggregate", "detailed"]).describe(
    "Which scan mode produced this aggregate.",
  ),
  listing: z.enum(["versions", "names"]).describe(
    '"versions" (b2_list_file_versions) sees every version and can measure ' +
      'non-current data; "names" (b2_list_file_names) sees only current ' +
      "files, and every non-current metric below is null in that case.",
  ),
  fileCount: z.number().int().describe(
    "Total list entries counted, including hide and start markers.",
  ),
  currentFileCount: z.number().int().describe(
    "Files whose newest version is a readable upload — what the bucket " +
      "actually serves.",
  ),
  currentBytes: z.number().int().describe(
    "Bytes held by those current versions.",
  ),
  nonCurrentFileCount: z.number().int().nullable().describe(
    "Superseded and hidden upload versions. NULL means not measured " +
      "(includeVersions was false), never zero — do not read a null as " +
      '"nothing is accumulating".',
  ),
  nonCurrentBytes: z.number().int().nullable().describe(
    "Bytes held by superseded and hidden versions — the storage a bucket " +
      "with no daysFromHidingToDeleting lifecycle rule pays for forever. " +
      "NULL means not measured.",
  ),
  totalBytes: z.number().int().nullable().describe(
    "currentBytes + nonCurrentBytes: everything B2 bills for under this " +
      "prefix. NULL when non-current data was not measured, because a total " +
      "that silently omits it would understate the bill.",
  ),
  hideMarkerCount: z.number().int().nullable().describe(
    "Hide markers (action=hide) — files deleted at the restic layer but " +
      "still stored underneath. NULL means not measured.",
  ),
  unfinishedCount: z.number().int().nullable().describe(
    "Large uploads started and never finished or cancelled (action=start). " +
      "Their parts are billed. NULL means not measured.",
  ),
  largestFileBytes: z.number().int().nullable().describe(
    "Size of the largest upload version seen, or null if none were seen.",
  ),
  largestFileName: z.string().nullable().describe(
    "Name of that largest version, or null if none were seen.",
  ),
  oldestUploadTimestamp: z.number().int().nullable().describe(
    "Earliest uploadTimestamp seen, in milliseconds since the Unix epoch.",
  ),
  newestUploadTimestamp: z.number().int().nullable().describe(
    "Latest uploadTimestamp seen, in milliseconds since the Unix epoch. On a " +
      "restic bucket this is effectively the last successful backup.",
  ),
  oldestUploadedAt: z.string().nullable().describe(
    "oldestUploadTimestamp rendered as ISO 8601, or null.",
  ),
  newestUploadedAt: z.string().nullable().describe(
    "newestUploadTimestamp rendered as ISO 8601, or null.",
  ),
  legalHoldOnCount: z.number().int().describe(
    "Versions with legal hold readably on. Undeletable until it is cleared.",
  ),
  legalHoldUnreadableCount: z.number().int().describe(
    "Versions whose legal hold the calling key may not read " +
      "(isClientAuthorizedToRead false). Counted separately because " +
      '"cannot see" is not "off" — grant readFileLegalHolds to resolve it.',
  ),
  retentionSetCount: z.number().int().describe(
    "Versions with a readable retention mode set (governance or compliance).",
  ),
  retentionUnreadableCount: z.number().int().describe(
    "Versions whose retention the calling key may not read. Grant " +
      "readFileRetentions to resolve it.",
  ),
  lockFieldsAbsentCount: z.number().int().describe(
    "Versions for which B2 returned NO legalHold and NO fileRetention field " +
      "at all — confirmed live: a list response omits both on a bucket " +
      "without Object Lock. Read this beside the counts above: a zero " +
      "legalHoldOnCount over a population that is entirely absent here means " +
      '"B2 did not report any lock state", not "nothing is locked". Use ' +
      "@sntxrr/b2/bucket's fileLockEnabled to tell which it is.",
  ),
  emittedFileCount: z.number().int().describe(
    "Per-file resources this scan wrote for this bucket. Always 0 in " +
      "aggregate mode; capped by maxFiles in detailed mode.",
  ),
  truncated: z.boolean().describe(
    "True when listing stopped with more pages available, so these counts " +
      "are a FLOOR, not a total. Never read a byte count as complete while " +
      "this is true.",
  ),
  pagesFetched: z.number().int().describe(
    "List pages actually retrieved for this bucket.",
  ),
  classCTransactions: z.number().int().describe(
    "Billed class-C transactions this bucket's listing cost. B2 bills one " +
      "per 1000 files returned, so a 10000-file page counts as ten.",
  ),
  observedAt: z.string().describe(
    "Timestamp when this aggregate was computed (ISO 8601).",
  ),
});

/**
 * Snapshot of one B2 file version.
 *
 * Written by `scan` in detailed mode and by every single-file method. Keyed by
 * `fileId`, because a file NAME can have arbitrarily many versions and keying
 * by name would make the versions of one file silently overwrite each other.
 */
const FileResourceSchema = z.object({
  bucketName: z.string().describe("Bucket holding this file version."),
  bucketId: z.string().nullable().describe("B2 bucket ID, or null."),
  fileId: z.string().nullable().describe(
    "Immutable ID of this file version, or null when the file was not found.",
  ),
  fileName: z.string().describe("File name. Not unique across versions."),
  action: z.string().nullable().describe(
    '"upload" for real data, "hide" for a delete marker, "start" for an ' +
      "unfinished large upload, or null when the file was not found.",
  ),
  isCurrentVersion: z.boolean().nullable().describe(
    "True when this version is what a download of fileName returns. False " +
      "when it is superseded, hidden, or a marker. NULL when it was not " +
      "determined — sync by fileId fetches one version without looking at " +
      "its siblings, and cannot tell.",
  ),
  contentLength: z.number().int().nullable().describe(
    "Stored size in bytes. Zero for hide markers; zero for start markers, " +
      "whose already-uploaded parts are billed but not reported here.",
  ),
  contentType: z.string().nullable().describe("MIME type recorded by B2."),
  contentSha1: z.string().nullable().describe(
    'SHA-1 of the content, or "none" for a large file assembled from parts.',
  ),
  contentMd5: z.string().nullable().describe("MD5 of the content, if known."),
  fileInfo: z.record(z.string(), z.unknown()).describe(
    "User-supplied metadata stored with the file, carried through verbatim. " +
      "Treat as untrusted free-form data and never store a credential in it.",
  ),
  uploadTimestamp: z.number().int().nullable().describe(
    "Upload instant in milliseconds since the Unix epoch.",
  ),
  uploadedAt: z.string().nullable().describe(
    "uploadTimestamp rendered as ISO 8601, or null.",
  ),
  legalHoldAuthorized: z.boolean().nullable().describe(
    "Whether the calling key may read the legal hold. NULL when B2 returned " +
      "no legalHold field at all (the bucket has no Object Lock).",
  ),
  legalHold: z.string().nullable().describe(
    '"on" or "off". NULL when unreadable OR absent — check ' +
      "legalHoldAuthorized before concluding a file is unprotected.",
  ),
  retentionAuthorized: z.boolean().nullable().describe(
    "Whether the calling key may read the retention setting. NULL when B2 " +
      "returned no fileRetention field at all.",
  ),
  retentionMode: z.string().nullable().describe(
    '"governance", "compliance", or null for none. NULL is also what an ' +
      "unreadable retention looks like — check retentionAuthorized.",
  ),
  retainUntilTimestamp: z.number().int().nullable().describe(
    "Retain-until instant in milliseconds since the Unix epoch, or null.",
  ),
  retainUntil: z.string().nullable().describe(
    "retainUntilTimestamp rendered as ISO 8601, or null.",
  ),
  serverSideEncryptionMode: z.string().nullable().describe(
    'Server-side encryption mode, e.g. "SSE-B2". B2 never returns SSE-C key ' +
      "material.",
  ),
  replicationStatus: z.string().nullable().describe(
    "Cloud-replication status for this version, if replication is set up.",
  ),
  exists: z.boolean().describe(
    "False for a tombstone: the file version was not found, or was deleted " +
      "by this run.",
  ),
  observedAt: z.string().describe(
    "Timestamp when this snapshot was taken (ISO 8601).",
  ),
});

// ---------------------------------------------------------------------------
// Helpers — naming
// ---------------------------------------------------------------------------

/**
 * A short, deterministic disambiguator for an instance name.
 *
 * FNV-1a 32-bit. This is a collision breaker, not a security hash: prefix
 * groups get sanitized into a storage-path-safe form, and two different
 * prefixes can sanitize to the same string, so the raw input is hashed and
 * appended to keep the result unique. Deterministic across runs, so the same
 * group keeps writing to the same instance and its versions accumulate.
 */
export function shortHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/**
 * Reduce arbitrary text to a storage-path-safe fragment.
 *
 * Instance names map straight onto file paths, and a B2 file-name prefix may
 * contain slashes, dots and unicode. Never used alone — always paired with
 * `shortHash` of the raw value, because this mapping is lossy.
 */
export function safeFragment(input: string, maxLength = 24): string {
  const cleaned = input.toLowerCase().replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned.slice(0, maxLength) || "root";
}

/**
 * Instance name for an `aggregate` snapshot.
 *
 * Instance names share one flat namespace across **all** specs of a model, so
 * the spec prefix is mandatory (CONVENTIONS §2). Beyond that, one execution can
 * write an aggregate per bucket AND per prefix group, and the group is
 * user-controlled text — so the raw `(bucket, group)` pair is hashed in.
 * `null` (the bucket-wide total) is encoded with a control character that no
 * B2 file-name prefix can contain, which makes a total-versus-group collision
 * structurally impossible rather than merely unlikely.
 */
export function aggregateInstanceName(
  bucketName: string,
  group: string | null,
): string {
  const raw = `${bucketName} ${group === null ? "TOTAL" : group}`;
  const label = group === null ? "all" : safeFragment(group);
  return `aggregate-${safeFragment(bucketName, 40)}-${label}-${shortHash(raw)}`;
}

/**
 * Instance name for a `file` snapshot.
 *
 * Keyed by `fileId` because that is what identifies a file VERSION — a name
 * has many. B2 file IDs are URL-safe already. When there is no fileId (the file
 * was never found, so there is nothing to key on) the name is hashed instead,
 * which keeps the "this file is absent" snapshot addressable and stable across
 * runs without pretending it is a version.
 */
export function fileInstanceName(
  bucketName: string,
  fileId: string | null,
  fileName: string,
): string {
  if (fileId) return `file-${fileId}`;
  return `file-absent-${safeFragment(fileName, 40)}-${
    shortHash(`${bucketName} ${fileName}`)
  }`;
}

// ---------------------------------------------------------------------------
// Helpers — mapping
// ---------------------------------------------------------------------------

/** Render an epoch-milliseconds instant as ISO 8601, tolerating junk. */
export function toIso(ms: number | null): string | null {
  if (ms === null || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Read a numeric field, returning null for anything that is not a number. */
function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Unwrap B2's `{ isClientAuthorizedToRead, value }` envelope.
 *
 * Returns `authorized: null` when the field is absent entirely, which means the
 * bucket has no Object Lock rather than that the key is unprivileged. Returns
 * `authorized: false` with a null value when the key may not read it — never
 * conflate that with "not set", which is the trap CONVENTIONS §4.3 records.
 */
export function unwrapAuthorized<T>(
  wrapper:
    | { isClientAuthorizedToRead?: boolean; value?: T | null }
    | null
    | undefined,
): { authorized: boolean | null; value: T | null } {
  if (wrapper === null || wrapper === undefined) {
    return { authorized: null, value: null };
  }
  const authorized = typeof wrapper.isClientAuthorizedToRead === "boolean"
    ? wrapper.isClientAuthorizedToRead
    : null;
  if (authorized === false) return { authorized: false, value: null };
  return { authorized, value: wrapper.value ?? null };
}

/**
 * Build a `file` resource snapshot from a B2 file object.
 *
 * `file` may be null, which produces a tombstone: `exists: false` with every
 * observed field nulled. `isCurrentVersion` is passed in rather than derived,
 * because whether a version is current depends on its siblings — information a
 * single-file fetch does not have, and `null` is the honest answer there.
 */
export function toFileResource(
  bucketName: string,
  bucketId: string | null,
  file: B2File | null,
  observedAt: string,
  options: { fileName?: string; isCurrentVersion?: boolean | null } = {},
): Record<string, unknown> {
  if (file === null) {
    return {
      bucketName,
      bucketId,
      fileId: null,
      fileName: options.fileName ?? "",
      action: null,
      isCurrentVersion: options.isCurrentVersion ?? null,
      contentLength: null,
      contentType: null,
      contentSha1: null,
      contentMd5: null,
      fileInfo: {},
      uploadTimestamp: null,
      uploadedAt: null,
      legalHoldAuthorized: null,
      legalHold: null,
      retentionAuthorized: null,
      retentionMode: null,
      retainUntilTimestamp: null,
      retainUntil: null,
      serverSideEncryptionMode: null,
      replicationStatus: null,
      exists: false,
      observedAt,
    };
  }
  const hold = unwrapAuthorized<string>(file.legalHold);
  const retention = unwrapAuthorized<
    { mode?: string | null; retainUntilTimestamp?: number | null }
  >(file.fileRetention);
  const uploadTimestamp = num(file.uploadTimestamp);
  const retainUntilTimestamp = num(retention.value?.retainUntilTimestamp);
  return {
    bucketName,
    bucketId: file.bucketId ?? bucketId,
    fileId: file.fileId ?? null,
    fileName: file.fileName ?? options.fileName ?? "",
    action: file.action ?? null,
    isCurrentVersion: options.isCurrentVersion ?? null,
    contentLength: num(file.contentLength),
    contentType: file.contentType ?? null,
    contentSha1: file.contentSha1 ?? null,
    contentMd5: file.contentMd5 ?? null,
    fileInfo: (file.fileInfo && typeof file.fileInfo === "object")
      ? file.fileInfo
      : {},
    uploadTimestamp,
    uploadedAt: toIso(uploadTimestamp),
    legalHoldAuthorized: hold.authorized,
    legalHold: hold.value ?? null,
    retentionAuthorized: retention.authorized,
    retentionMode: retention.value?.mode ?? null,
    retainUntilTimestamp,
    retainUntil: toIso(retainUntilTimestamp),
    serverSideEncryptionMode: file.serverSideEncryption?.mode ?? null,
    replicationStatus: file.replicationStatus ?? null,
    exists: true,
    observedAt,
  };
}

// ---------------------------------------------------------------------------
// Helpers — aggregation
// ---------------------------------------------------------------------------

/** Running totals for one prefix group, before they become a resource. */
type Tally = {
  fileCount: number;
  currentFileCount: number;
  currentBytes: number;
  nonCurrentFileCount: number;
  nonCurrentBytes: number;
  hideMarkerCount: number;
  unfinishedCount: number;
  largestFileBytes: number | null;
  largestFileName: string | null;
  oldestUploadTimestamp: number | null;
  newestUploadTimestamp: number | null;
  legalHoldOnCount: number;
  legalHoldUnreadableCount: number;
  retentionSetCount: number;
  retentionUnreadableCount: number;
  lockFieldsAbsentCount: number;
  emittedFileCount: number;
};

/** A fresh zeroed tally. */
function newTally(): Tally {
  return {
    fileCount: 0,
    currentFileCount: 0,
    currentBytes: 0,
    nonCurrentFileCount: 0,
    nonCurrentBytes: 0,
    hideMarkerCount: 0,
    unfinishedCount: 0,
    largestFileBytes: null,
    largestFileName: null,
    oldestUploadTimestamp: null,
    newestUploadTimestamp: null,
    legalHoldOnCount: 0,
    legalHoldUnreadableCount: 0,
    retentionSetCount: 0,
    retentionUnreadableCount: 0,
    lockFieldsAbsentCount: 0,
    emittedFileCount: 0,
  };
}

/**
 * Derive the prefix group a file name belongs to.
 *
 * `"none"` puts everything in the bucket-wide total. `"topLevel"` groups by the
 * first path segment including its trailing slash — for a restic repository
 * that is exactly `data/`, `index/`, `keys/`, `locks/` and `snapshots/`, which
 * is the split that says whether the debt is pack files or bookkeeping. A name
 * with no slash groups under `""`, meaning the bucket root.
 */
export function groupFor(
  fileName: string,
  groupBy: "none" | "topLevel",
): string | null {
  if (groupBy === "none") return null;
  const slash = fileName.indexOf("/");
  return slash === -1 ? "" : fileName.slice(0, slash + 1);
}

/**
 * Fold one file-version listing into per-group tallies, deciding for each entry
 * whether it is the current version of its name.
 *
 * B2 returns versions newest-first and groups every version of a file name
 * contiguously, which is what makes a single forward pass sufficient. For each
 * name the first entry decides the fate of the rest:
 *
 * - newest is an `upload` → that upload is current, every upload below it is
 *   superseded and therefore non-current;
 * - newest is a `hide` marker → the file is deleted, so **every** upload below
 *   it is non-current. This is the case that costs money and that a
 *   `b2_list_file_names` listing cannot see at all;
 * - newest is a `start` marker → an unfinished large upload does not shadow
 *   anything, so the next upload below it is still the current version.
 *
 * Returns the per-entry `isCurrentVersion` verdicts alongside the tallies so
 * detailed mode can record them without a second pass.
 */
export function tallyFiles(
  files: B2File[],
  groupBy: "none" | "topLevel",
): { groups: Map<string | null, Tally>; total: Tally; current: boolean[] } {
  const groups = new Map<string | null, Tally>();
  const total = newTally();
  const current: boolean[] = [];

  let seenName: string | null = null;
  let nameIsDeleted = false;
  let nameHasCurrent = false;

  for (const f of files) {
    const fileName = f.fileName ?? "";
    if (fileName !== seenName) {
      seenName = fileName;
      nameIsDeleted = false;
      nameHasCurrent = false;
    }
    const action = f.action ?? "upload";

    const targets: Tally[] = [total];
    if (groupBy !== "none") {
      const key = groupFor(fileName, groupBy);
      let tally = groups.get(key);
      if (!tally) {
        tally = newTally();
        groups.set(key, tally);
      }
      targets.push(tally);
    }
    for (const t of targets) t.fileCount++;

    // A `folder` entry is a synthetic directory placeholder returned only when
    // a delimiter is requested. This model never requests one, but counting a
    // placeholder's bytes would inflate the total, so skip it explicitly.
    if (action === "folder") {
      current.push(false);
      continue;
    }
    if (action === "hide") {
      // Only the newest version of a name can be the marker that deletes it; a
      // hide marker further down is history under a newer upload.
      if (!nameHasCurrent && !nameIsDeleted) nameIsDeleted = true;
      for (const t of targets) t.hideMarkerCount++;
      current.push(false);
      continue;
    }
    if (action === "start") {
      for (const t of targets) t.unfinishedCount++;
      current.push(false);
      continue;
    }

    const bytes = num(f.contentLength) ?? 0;
    const isCurrent = !nameHasCurrent && !nameIsDeleted;
    if (isCurrent) {
      nameHasCurrent = true;
      for (const t of targets) {
        t.currentFileCount++;
        t.currentBytes += bytes;
      }
    } else {
      for (const t of targets) {
        t.nonCurrentFileCount++;
        t.nonCurrentBytes += bytes;
      }
    }
    current.push(isCurrent);

    const uploadedMs = num(f.uploadTimestamp);
    const hold = unwrapAuthorized<string>(f.legalHold);
    const retention = unwrapAuthorized<{ mode?: string | null }>(
      f.fileRetention,
    );
    for (const t of targets) {
      if (t.largestFileBytes === null || bytes > t.largestFileBytes) {
        t.largestFileBytes = bytes;
        t.largestFileName = fileName;
      }
      if (uploadedMs !== null) {
        if (
          t.oldestUploadTimestamp === null ||
          uploadedMs < t.oldestUploadTimestamp
        ) {
          t.oldestUploadTimestamp = uploadedMs;
        }
        if (
          t.newestUploadTimestamp === null ||
          uploadedMs > t.newestUploadTimestamp
        ) {
          t.newestUploadTimestamp = uploadedMs;
        }
      }
      if (hold.authorized === false) t.legalHoldUnreadableCount++;
      else if (hold.value === "on") t.legalHoldOnCount++;
      if (retention.authorized === false) t.retentionUnreadableCount++;
      else if (retention.value?.mode) t.retentionSetCount++;
      // Neither wrapper present at all. Verified live 2026-08-05: B2 omits
      // both from a list response on a bucket without Object Lock, so a zero
      // in the counts above would otherwise read as "nothing is locked" when
      // the truth is "nothing was reported".
      if (hold.authorized === null && retention.authorized === null) {
        t.lockFieldsAbsentCount++;
      }
    }
  }
  return { groups, total, current };
}

/**
 * Turn a tally into an `aggregate` resource.
 *
 * Every version-derived metric is nulled when the listing was `names`, because
 * `b2_list_file_names` returns only current files: it cannot observe a hidden
 * or superseded version, so its zero would be a claim the data does not
 * support. `totalBytes` goes null with them rather than silently equalling
 * `currentBytes`, which would understate the bill.
 */
export function toAggregateResource(
  tally: Tally,
  context: {
    bucketName: string;
    bucketId: string | null;
    prefix: string;
    group: string | null;
    scanMode: "aggregate" | "detailed";
    listing: "versions" | "names";
    truncated: boolean;
    pagesFetched: number;
    classCTransactions: number;
    observedAt: string;
  },
): Record<string, unknown> {
  const measured = context.listing === "versions";
  return {
    bucketName: context.bucketName,
    bucketId: context.bucketId,
    prefix: context.prefix,
    group: context.group,
    scanMode: context.scanMode,
    listing: context.listing,
    fileCount: tally.fileCount,
    currentFileCount: tally.currentFileCount,
    currentBytes: tally.currentBytes,
    nonCurrentFileCount: measured ? tally.nonCurrentFileCount : null,
    nonCurrentBytes: measured ? tally.nonCurrentBytes : null,
    totalBytes: measured ? tally.currentBytes + tally.nonCurrentBytes : null,
    hideMarkerCount: measured ? tally.hideMarkerCount : null,
    unfinishedCount: measured ? tally.unfinishedCount : null,
    largestFileBytes: tally.largestFileBytes,
    largestFileName: tally.largestFileName,
    oldestUploadTimestamp: tally.oldestUploadTimestamp,
    newestUploadTimestamp: tally.newestUploadTimestamp,
    oldestUploadedAt: toIso(tally.oldestUploadTimestamp),
    newestUploadedAt: toIso(tally.newestUploadTimestamp),
    legalHoldOnCount: tally.legalHoldOnCount,
    legalHoldUnreadableCount: tally.legalHoldUnreadableCount,
    retentionSetCount: tally.retentionSetCount,
    retentionUnreadableCount: tally.retentionUnreadableCount,
    lockFieldsAbsentCount: tally.lockFieldsAbsentCount,
    emittedFileCount: tally.emittedFileCount,
    truncated: context.truncated,
    pagesFetched: context.pagesFetched,
    classCTransactions: context.classCTransactions,
    observedAt: context.observedAt,
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
 * Page through a B2 file listing, reporting what it cost.
 *
 * Deliberately not `b2ListAll`. Two things this needs that the canonical
 * drainer does not provide, and that must not be bolted onto it because it is
 * copied byte-identical into every model in the suite:
 *
 * 1. **Cost reporting.** `b2ListAll` returns items and a truncation flag but
 *    not how many pages it fetched, and this model's whole point is putting a
 *    number on what an inventory costs.
 * 2. **An item budget.** Detailed mode caps the files it emits, and paying to
 *    list a million versions in order to throw all but the first thousand away
 *    is a bill for nothing.
 *
 * The cursor handling is otherwise identical to `b2ListAll`: collect every
 * `next*` field and rename it to its `start*` request parameter, which carries
 * `nextFileName` and `nextFileId` together as `b2_list_file_versions` requires.
 */
export async function listFilePages(
  auth: B2Auth,
  op: "b2_list_file_names" | "b2_list_file_versions",
  payload: Record<string, unknown>,
  maxPages: number,
  stopAfter?: number,
  reauth?: () => Promise<B2Auth>,
): Promise<{
  files: B2File[];
  truncated: boolean;
  pages: number;
  classCTransactions: number;
}> {
  const files: B2File[] = [];
  let cursor: Record<string, unknown> = {};
  let pages = 0;
  let classCTransactions = 0;

  for (let page = 0; page < maxPages; page++) {
    const res = await b2Fetch<Record<string, unknown>>(
      auth,
      "POST",
      op,
      { ...payload, ...cursor },
      reauth,
    );
    pages++;
    const batch = (res.files as B2File[] | undefined) ?? [];
    files.push(...batch);
    // B2 bills a list call per 1000 files returned, so one 10000-file page is
    // ten transactions — and an empty page is still one.
    classCTransactions += Math.max(1, Math.ceil(batch.length / 1000));

    const nextCursor: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(res)) {
      if (
        k.startsWith("next") && k.length > 4 && v !== null && v !== undefined
      ) {
        nextCursor[`start${k.slice(4)}`] = v;
      }
    }
    // No cursor means B2 has nothing more to give: a complete listing.
    if (Object.keys(nextCursor).length === 0) {
      return { files, truncated: false, pages, classCTransactions };
    }
    // Stopping on our own budget leaves the cursor live, so this IS truncated.
    if (stopAfter !== undefined && files.length >= stopAfter) {
      return { files, truncated: true, pages, classCTransactions };
    }
    cursor = nextCursor;
  }
  return { files, truncated: true, pages, classCTransactions };
}

/**
 * List every bucket the calling key can see.
 *
 * `b2_list_buckets` returns the whole account in one response with no cursor,
 * so this is a single class-C transaction regardless of account size.
 */
export async function listAllBuckets(
  auth: B2Auth,
  reauth?: () => Promise<B2Auth>,
): Promise<Array<{ bucketName: string; bucketId: string | null }>> {
  const res = await b2Fetch<{ buckets?: B2Bucket[] }>(
    auth,
    "POST",
    "b2_list_buckets",
    { accountId: auth.accountId },
    reauth,
  );
  return (res.buckets ?? []).map((b) => ({
    bucketName: b.bucketName ?? "",
    bucketId: b.bucketId ?? null,
  })).filter((b) => b.bucketName !== "");
}

/**
 * Resolve the bucket name/ID pairs a run should operate on.
 *
 * Skips `b2_list_buckets` entirely when a single bucket is fully specified by
 * global arguments, which is both one class-C transaction cheaper and the only
 * way a bucket-restricted key without `listBuckets` can use this model at all.
 *
 * Selection order is explicit `wanted` names, then `globalArgs.bucketName`,
 * then the whole account. Callers that need the account regardless of what the
 * model is pointed at want `listAllBuckets` instead — passing `undefined` here
 * does NOT widen the search, it narrows it to the model's own bucket.
 */
export async function resolveBuckets(
  auth: B2Auth,
  g: GlobalArgs,
  wanted: string[] | undefined,
  reauth: () => Promise<B2Auth>,
): Promise<Array<{ bucketName: string; bucketId: string | null }>> {
  const names = (wanted && wanted.length > 0)
    ? wanted
    : g.bucketName
    ? [g.bucketName]
    : [];

  if (names.length === 1 && names[0] === g.bucketName && g.bucketId) {
    return [{ bucketName: g.bucketName, bucketId: g.bucketId }];
  }

  const all = await listAllBuckets(auth, reauth);
  if (names.length === 0) return all;
  // A requested bucket the key cannot see still gets an entry with a null ID,
  // so the run reports "asked for, not found" rather than silently skipping it.
  return names.map((name) =>
    all.find((b) => b.bucketName === name) ??
      { bucketName: name, bucketId: null }
  );
}

/**
 * Assert that exactly one bucket is named, without paying to resolve its ID.
 *
 * Several operations — `b2_get_file_info`, `b2_delete_file_version` and both
 * update calls — are addressed purely by `fileId` and `fileName` and never need
 * a bucket ID. Demanding one anyway would cost a class-C `b2_list_buckets` per
 * run and, worse, would lock out a bucket-restricted key that holds `readFiles`
 * but not `listBuckets` — exactly the shape of the per-host restic keys this
 * suite exists to manage. The name is still required, because it is what the
 * snapshot is filed under.
 */
export function requireBucketName(g: GlobalArgs): string {
  if (!g.bucketName) {
    throw new Error(
      "This method acts on one file in one bucket, but globalArgs.bucketName " +
        "is not set. Set it on the model. (Leaving it unset is only valid for " +
        "scan, which then inventories every bucket the key can see.)",
    );
  }
  return g.bucketName;
}

/**
 * Resolve the single bucket the file-level methods act on, ID included.
 *
 * Throws rather than guessing: these methods mutate or read one specific file,
 * and picking a bucket for the caller is how you delete the right file name out
 * of the wrong repository. Use `requireBucketName` on the paths that address a
 * file by ID and therefore never need the bucket ID at all.
 */
export async function requireBucket(
  auth: B2Auth,
  g: GlobalArgs,
  reauth: () => Promise<B2Auth>,
): Promise<{ bucketName: string; bucketId: string }> {
  const bucketName = requireBucketName(g);
  if (g.bucketId) return { bucketName, bucketId: g.bucketId };
  const resolved = await resolveBuckets(auth, g, [bucketName], reauth);
  const bucketId = resolved[0]?.bucketId;
  if (!bucketId) {
    throw new Error(
      `Bucket "${bucketName}" was not found in this account, or the ` +
        `application key cannot see it. Check the name, or set ` +
        `globalArgs.bucketId if the key lacks the listBuckets capability.`,
    );
  }
  return { bucketName, bucketId };
}

/**
 * Find the newest version of one file name.
 *
 * Uses `b2_list_file_versions`, not `b2_list_file_names`, so a file whose
 * newest version is a hide marker comes back as the marker rather than as
 * "not found" — those are different facts, and only one of them means the data
 * is gone. Returns null when the name does not exist at all.
 */
export async function findNewestVersion(
  auth: B2Auth,
  bucketId: string,
  fileName: string,
  reauth?: () => Promise<B2Auth>,
): Promise<B2File | null> {
  const res = await b2Fetch<{ files?: B2File[] }>(
    auth,
    "POST",
    "b2_list_file_versions",
    { bucketId, startFileName: fileName, prefix: fileName, maxFileCount: 1 },
    reauth,
  );
  const first = (res.files ?? [])[0];
  return first && first.fileName === fileName ? first : null;
}

/**
 * Decide whether a thrown `b2Fetch` error means "the file version is already
 * gone".
 *
 * Per CONVENTIONS §3: a `404`, or a `400` whose `b2Code` names a missing file.
 * `bad_bucket_id` is deliberately NOT in this list — a wrong bucket ID is a
 * configuration bug, and swallowing it would report a successful delete of a
 * file that is still there.
 */
export function isAlreadyGone(e: unknown): boolean {
  const err = e as { status?: number; b2Code?: string };
  if (err.status === 404) return true;
  return err.status === 400 &&
    (err.b2Code === "file_not_present" || err.b2Code === "no_such_file");
}

/**
 * Refuse to destroy or mask a file version unless it was explicitly
 * acknowledged.
 *
 * This lives in the METHOD, not only in a pre-flight check, and that is
 * deliberate: swamp gives checks the model's global arguments but never the
 * method's inputs, so a check cannot see `--input fileName=...` and cannot be
 * the thing that enforces. The sibling check catches the global-argument path
 * early, before any B2 call; this is what actually stops the run.
 */
export function assertDestructionAllowed(
  operation: string,
  target: string,
  g: GlobalArgs,
  argAllow?: boolean,
): void {
  if (argAllow ?? g.allowFileDestruction) return;
  throw new Error(
    `Refusing to ${operation} "${target}" in bucket "${
      g.bucketName ?? "?"
    }": this removes or masks a stored file version, and doing it to a restic ` +
      `pack file leaves the repository unreadable with no error until the next ` +
      `restore. Acknowledge it with --input allowFileDestruction=true for a ` +
      `single run, or set allowFileDestruction=true on the model to make it ` +
      `permanent.`,
  );
}

/**
 * Refuse to set compliance-mode retention unless it was explicitly
 * acknowledged.
 *
 * Compliance mode is the one setting in this suite that cannot be undone.
 * Governance mode can be bypassed by a privileged key and legal hold can be
 * cleared, but a compliance retain-until date can be extended and never
 * shortened — not by the account owner, not by support. The object is stored,
 * and billed, until it expires.
 */
export function assertComplianceAllowed(
  mode: string | undefined,
  retainUntilTimestamp: number | undefined,
  g: GlobalArgs,
  argAllow?: boolean,
): void {
  if (mode !== "compliance") return;
  if (argAllow ?? g.allowComplianceRetention) return;
  const until = retainUntilTimestamp !== undefined
    ? toIso(retainUntilTimestamp) ?? String(retainUntilTimestamp)
    : "the requested date";
  throw new Error(
    `Refusing to set compliance-mode retention until ${until}: compliance ` +
      `retention can be extended but never shortened or removed, by anyone, ` +
      `so this object is stored and billed until it expires even if it turns ` +
      `out to be a mistake. Use governance mode if you want a reversible ` +
      `lock, or acknowledge this with --input allowComplianceRetention=true ` +
      `for a single run.`,
  );
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/**
 * Backblaze B2 files model — inventories a bucket's file versions in aggregate
 * (the default) or in detail, and manages individual versions over the B2
 * Native API v4.
 */
export const model = {
  type: "@sntxrr/b2/files",
  version: "2026.08.06.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "aggregate": {
      description:
        "Per-bucket (and optionally per-prefix) file inventory: current versus non-current object counts and bytes, with a truncation flag",
      schema: AggregateResourceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    "file": {
      description:
        "Snapshot of one B2 file version, instance-named file-<fileId>",
      schema: FileResourceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
  },
  methods: {
    "scan": {
      description:
        "Factory discovery — inventory file versions and write one aggregate " +
        "per bucket (and per prefix group with groupBy=topLevel), separating " +
        "current bytes from the non-current bytes a bucket with no " +
        "hidden-version lifecycle rule pays for forever. Read-only. Defaults " +
        "to every bucket the key can see when globalArgs.bucketName is unset. " +
        "mode=detailed additionally emits one resource per file version and " +
        "requires prefix and maxFiles. Requires listFiles, plus listBuckets " +
        "unless a single bucket is pinned by bucketName+bucketId, plus " +
        "readFileRetentions/readFileLegalHolds for the lock columns to be " +
        "readable.",
      arguments: ScanArgsSchema,
      execute: async (
        args: z.infer<typeof ScanArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const scanMode = args.mode ?? "aggregate";
        const groupBy = args.groupBy ?? "none";
        const includeVersions = args.includeVersions ?? true;
        const listing = includeVersions ? "versions" : "names";
        const prefix = args.prefix ?? "";
        const maxPages = args.maxPages ?? 50;
        const maxFileCount = args.maxFileCount ?? 10000;

        // Enforced here rather than in the argument schema so the failure is a
        // sentence explaining the cost, not a schema error — and so it holds
        // even if the caller reaches execute without a refinement running.
        if (scanMode === "detailed") {
          if (!args.prefix) {
            throw new Error(
              "scan mode=detailed requires an explicit prefix. Emitting one " +
                "resource per file version across a whole restic bucket " +
                "would write tens of thousands of snapshots; narrow it, e.g. " +
                'prefix="snapshots/".',
            );
          }
          if (args.maxFiles === undefined) {
            throw new Error(
              "scan mode=detailed requires maxFiles, a hard cap on the " +
                "per-file resources it may write (and on how many file " +
                "versions it will pay to list).",
            );
          }
        }

        const { auth, reauth } = await session(g);
        const buckets = await resolveBuckets(auth, g, args.bucketNames, reauth);
        if (buckets.length === 0) {
          throw new Error(
            "No buckets to scan: the application key can see none, and none " +
              "were named via globalArgs.bucketName or the bucketNames " +
              "argument.",
          );
        }
        logger.info(
          "Scanning {count} bucket(s) in {mode} mode, listing {listing}",
          { count: buckets.length, mode: scanMode, listing },
        );

        const op = includeVersions
          ? "b2_list_file_versions"
          : "b2_list_file_names";
        const handles: Array<{ name: string }> = [];
        let anyTruncated = false;
        let totalTransactions = 0;

        for (const bucket of buckets) {
          if (bucket.bucketId === null) {
            const observedAt = new Date().toISOString();
            logger.warn(
              "Bucket {bucketName} was requested but not found; writing an empty aggregate rather than skipping it silently",
              { bucketName: bucket.bucketName },
            );
            handles.push(
              await context.writeResource(
                "aggregate",
                aggregateInstanceName(bucket.bucketName, null),
                toAggregateResource(newTally(), {
                  bucketName: bucket.bucketName,
                  bucketId: null,
                  prefix,
                  group: null,
                  scanMode,
                  listing,
                  // Nothing was listed, so nothing is known — reporting this as
                  // a complete inventory of zero files would be a lie about a
                  // bucket that may well be full.
                  truncated: true,
                  pagesFetched: 0,
                  classCTransactions: 0,
                  observedAt,
                }),
              ),
            );
            anyTruncated = true;
            continue;
          }

          const payload: Record<string, unknown> = {
            bucketId: bucket.bucketId,
            maxFileCount,
          };
          if (prefix !== "") payload.prefix = prefix;

          const page = await listFilePages(
            auth,
            op,
            payload,
            maxPages,
            scanMode === "detailed" ? args.maxFiles : undefined,
            reauth,
          );
          // Stamped after the listing, not before it: a 50-page drain takes
          // real time, and an observedAt from before the first call would date
          // the snapshot to a state B2 had already moved on from.
          const observedAt = new Date().toISOString();
          totalTransactions += page.classCTransactions;
          if (page.truncated) anyTruncated = true;

          const { groups, total, current } = tallyFiles(page.files, groupBy);

          // Detailed mode emits per-file resources before the aggregates, so
          // the aggregate's emittedFileCount reports what was actually written.
          if (scanMode === "detailed") {
            const limit = Math.min(args.maxFiles ?? 0, page.files.length);
            for (let i = 0; i < limit; i++) {
              const f = page.files[i];
              const fileName = f.fileName ?? "";
              handles.push(
                await context.writeResource(
                  "file",
                  fileInstanceName(
                    bucket.bucketName,
                    f.fileId ?? null,
                    fileName,
                  ),
                  toFileResource(
                    bucket.bucketName,
                    bucket.bucketId,
                    f,
                    observedAt,
                    { isCurrentVersion: current[i] },
                  ),
                ),
              );
            }
            total.emittedFileCount = limit;
            // Groups count only the files they actually contributed, so a
            // per-group emitted count stays consistent with the total.
            for (let i = 0; i < limit; i++) {
              const key = groupFor(page.files[i].fileName ?? "", groupBy);
              const tally = groups.get(key);
              if (tally) tally.emittedFileCount++;
            }
          }

          const shared = {
            bucketName: bucket.bucketName,
            bucketId: bucket.bucketId,
            prefix,
            scanMode,
            listing,
            truncated: page.truncated,
            pagesFetched: page.pages,
            classCTransactions: page.classCTransactions,
            observedAt,
          } as const;

          handles.push(
            await context.writeResource(
              "aggregate",
              aggregateInstanceName(bucket.bucketName, null),
              toAggregateResource(total, { ...shared, group: null }),
            ),
          );
          for (const [group, tally] of groups) {
            handles.push(
              await context.writeResource(
                "aggregate",
                aggregateInstanceName(bucket.bucketName, group),
                toAggregateResource(tally, { ...shared, group }),
              ),
            );
          }

          if (page.truncated) {
            logger.warn(
              "Bucket {bucketName} listing stopped early ({pages} pages) — its counts are a FLOOR, not a total. Raise maxPages (or maxFiles) before treating them as complete.",
              { bucketName: bucket.bucketName, pages: page.pages },
            );
          }
          if (includeVersions && total.nonCurrentBytes > 0) {
            logger.warn(
              "Bucket {bucketName} holds {bytes} bytes across {count} non-current versions — storage that is billed and no longer served. A lifecycle rule with daysFromHidingToDeleting is what reaps it.",
              {
                bucketName: bucket.bucketName,
                bytes: total.nonCurrentBytes,
                count: total.nonCurrentFileCount,
              },
            );
          }
          logger.info(
            "Bucket {bucketName}: {current} current file(s), {currentBytes} current bytes",
            {
              bucketName: bucket.bucketName,
              current: total.currentFileCount,
              currentBytes: total.currentBytes,
            },
          );
        }

        logger.info(
          "Scan complete: {n} resource(s) across {buckets} bucket(s), {tx} billed class-C transaction(s), truncated={truncated}",
          {
            n: handles.length,
            buckets: buckets.length,
            tx: totalTransactions,
            truncated: anyTruncated,
          },
        );
        return { dataHandles: handles };
      },
    },
    "sync": {
      description:
        "Read one file's current state and snapshot it. By fileId this is a cheap class-B b2_get_file_info; by fileName it is one class-C b2_list_file_versions that reports the NEWEST version, so a deleted file comes back as its hide marker rather than as not-found. Requires readFiles (fileId path) or listFiles (fileName path).",
      arguments: FileRefArgsSchema,
      execute: async (
        args: z.infer<typeof FileRefArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        if (!args.fileId && !args.fileName) {
          throw new Error(
            "sync needs a fileId or a fileName to identify what to read.",
          );
        }
        const bucketName = requireBucketName(g);
        const { auth, reauth } = await session(g);

        let file: B2File | null;
        let isCurrentVersion: boolean | null;
        // Resolved only on the by-name path: b2_get_file_info is addressed by
        // fileId alone, so demanding a bucket ID here would spend a class-C
        // lookup and lock out a key without listBuckets for no benefit.
        let bucketId: string | null = g.bucketId ?? null;
        if (args.fileId) {
          file = await b2Fetch<B2File>(
            auth,
            "POST",
            "b2_get_file_info",
            { fileId: args.fileId },
            reauth,
          );
          bucketId = file.bucketId ?? bucketId;
          // One version was fetched without looking at its siblings, so whether
          // it is the current one is genuinely unknown here. Null says so.
          isCurrentVersion = null;
        } else {
          const bucket = await requireBucket(auth, g, reauth);
          bucketId = bucket.bucketId;
          file = await findNewestVersion(
            auth,
            bucket.bucketId,
            args.fileName as string,
            reauth,
          );
          // This IS the newest version, so it is current exactly when it is a
          // real upload rather than a hide or start marker.
          isCurrentVersion = file === null
            ? null
            : (file.action ?? "upload") === "upload";
        }

        const fileName = file?.fileName ?? args.fileName ?? "";
        if (file === null) {
          logger.warn(
            "No version of {fileName} exists in bucket {bucketName}",
            { fileName, bucketName },
          );
        } else if (isCurrentVersion === false) {
          logger.warn(
            "Newest version of {fileName} is a {action} marker — the file is not readable",
            { fileName, action: file.action },
          );
        }
        const handle = await context.writeResource(
          "file",
          fileInstanceName(bucketName, file?.fileId ?? null, fileName),
          toFileResource(
            bucketName,
            bucketId,
            file,
            new Date().toISOString(),
            { fileName, isCurrentVersion },
          ),
        );
        logger.info("Synced {fileName} (exists={exists})", {
          fileName,
          exists: file !== null,
        });
        return { dataHandles: [handle] };
      },
    },
    "delete": {
      description:
        "Permanently delete one file version (b2_delete_file_version) and write an exists=false tombstone. DESTRUCTIVE and not recoverable: requires allowFileDestruction as a global argument or a method input. Idempotent — a 404, or a 400 with b2Code file_not_present or no_such_file, is treated as success. Requires deleteFiles, plus listFiles when identifying the file by name, plus bypassGovernance to delete through governance retention.",
      arguments: DeleteArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        if (!args.fileId && !args.fileName) {
          throw new Error(
            "delete needs a fileId or a fileName to identify what to remove.",
          );
        }
        assertDestructionAllowed(
          "delete",
          args.fileId ?? (args.fileName as string),
          g,
          args.allowFileDestruction,
        );
        const bucketName = requireBucketName(g);
        const { auth, reauth } = await session(g);

        let fileId = args.fileId ?? null;
        let fileName = args.fileName ?? "";
        // b2_delete_file_version is addressed by fileName + fileId, never by
        // bucket, so the bucket ID is resolved only when a NAME has to be
        // looked up. Keeps a listBuckets-less key working on the fileId path.
        let bucketId: string | null = g.bucketId ?? null;
        if (!fileId) {
          const bucket = await requireBucket(auth, g, reauth);
          bucketId = bucket.bucketId;
          const found = await findNewestVersion(
            auth,
            bucket.bucketId,
            fileName,
            reauth,
          );
          if (found === null) {
            logger.info(
              "No version of {fileName} exists; treating delete as successful",
              { fileName },
            );
          } else {
            fileId = found.fileId ?? null;
          }
        } else if (!fileName) {
          // b2_delete_file_version requires BOTH halves, so a caller who knew
          // only the ID needs the name looked up — one cheap class-B call.
          const info = await b2Fetch<B2File>(
            auth,
            "POST",
            "b2_get_file_info",
            { fileId },
            reauth,
          );
          fileName = info.fileName ?? "";
          bucketId = info.bucketId ?? bucketId;
        }

        if (fileId) {
          logger.info("Deleting version {fileId} of {fileName}", {
            fileId,
            fileName,
          });
          try {
            const payload: Record<string, unknown> = { fileName, fileId };
            if (args.bypassGovernance) payload.bypassGovernance = true;
            await b2Fetch<{ fileId?: string }>(
              auth,
              "POST",
              "b2_delete_file_version",
              payload,
              reauth,
            );
          } catch (e) {
            // Already gone is the desired end state — an idempotent success.
            if (!isAlreadyGone(e)) throw e;
            logger.info(
              "Version {fileId} was already gone; treating delete as successful",
              { fileId },
            );
          }
        }

        // A tombstone, not a snapshot of the deleted version: the point of this
        // resource after a delete is that the version is not there.
        const handle = await context.writeResource(
          "file",
          fileInstanceName(bucketName, fileId, fileName),
          toFileResource(
            bucketName,
            bucketId,
            null,
            new Date().toISOString(),
            { fileName, isCurrentVersion: false },
          ),
        );
        logger.info("Deleted {fileName}", { fileName });
        return { dataHandles: [handle] };
      },
    },
    "hide": {
      description:
        "Hide a file (b2_hide_file), writing a hide marker as its newest version so downloads by name stop resolving. The underlying data is retained and billed until a lifecycle rule reaps it. DESTRUCTIVE in effect — hiding a restic pack file makes the repository unreadable — so it requires allowFileDestruction as a global argument or a method input. Requires writeFiles. NOTE: pre-flight checks do not fire for a method named `hide`, so the guard is inside execute.",
      arguments: HideArgsSchema,
      execute: async (
        args: z.infer<typeof HideArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        assertDestructionAllowed(
          "hide",
          args.fileName,
          g,
          args.allowFileDestruction,
        );
        const { auth, reauth } = await session(g);
        const bucket = await requireBucket(auth, g, reauth);

        logger.info("Hiding {fileName} in bucket {bucketName}", {
          fileName: args.fileName,
          bucketName: bucket.bucketName,
        });
        const marker = await b2Fetch<B2File>(
          auth,
          "POST",
          "b2_hide_file",
          { bucketId: bucket.bucketId, fileName: args.fileName },
          reauth,
        );
        const handle = await context.writeResource(
          "file",
          fileInstanceName(
            bucket.bucketName,
            marker.fileId ?? null,
            args.fileName,
          ),
          toFileResource(
            bucket.bucketName,
            bucket.bucketId,
            marker,
            new Date().toISOString(),
            // A hide marker is the newest version by construction — that is the
            // whole mechanism by which it hides the file.
            { fileName: args.fileName, isCurrentVersion: true },
          ),
        );
        logger.warn(
          "Hid {fileName}: the data underneath is still stored and billed until a lifecycle rule deletes it",
          { fileName: args.fileName },
        );
        return { dataHandles: [handle] };
      },
    },
    "copy": {
      description:
        "Copy a file version server-side (b2_copy_file) into this model's bucket or another one, without moving bytes through swamp. Non-destructive: B2 writes a new version and never removes the source. Capped by B2 at 5 GB; larger files need the large-file copy path in @sntxrr/b2/transfer. Requires readFiles on the source and writeFiles on the destination.",
      arguments: CopyArgsSchema,
      execute: async (
        args: z.infer<typeof CopyArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        if (args.metadataDirective === "REPLACE" && !args.contentType) {
          throw new Error(
            'b2_copy_file with metadataDirective "REPLACE" requires ' +
              "contentType — B2 rejects the call otherwise, and the source " +
              "type is deliberately not reused for a REPLACE.",
          );
        }
        const { auth, reauth } = await session(g);
        const bucket = await requireBucket(auth, g, reauth);
        const destinationBucketId = args.destinationBucketId ?? bucket.bucketId;

        // Resolve the destination's NAME before copying, never after. The
        // snapshot must record a name in bucketName rather than a bucket ID
        // wearing that field, and a lookup that fails after the copy has
        // already landed would strand a completed side effect behind a failed
        // method.
        let destinationName = bucket.bucketName;
        if (destinationBucketId !== bucket.bucketId) {
          destinationName = args.destinationBucketName ??
            (await listAllBuckets(auth, reauth))
              .find((b) => b.bucketId === destinationBucketId)?.bucketName ??
            "";
          if (destinationName === "") {
            throw new Error(
              `Destination bucket ID "${destinationBucketId}" does not match ` +
                `any bucket this key can see, so the copy's snapshot would be ` +
                `mislabelled. Pass destinationBucketName explicitly, or check ` +
                `the ID.`,
            );
          }
        }

        const payload: Record<string, unknown> = {
          sourceFileId: args.sourceFileId,
          fileName: args.fileName,
          destinationBucketId,
        };
        if (args.contentType) payload.contentType = args.contentType;
        if (args.fileInfo) payload.fileInfo = args.fileInfo;
        if (args.metadataDirective) {
          payload.metadataDirective = args.metadataDirective;
        }
        if (args.range) payload.range = args.range;

        logger.info("Copying {sourceFileId} to {fileName}", {
          sourceFileId: args.sourceFileId,
          fileName: args.fileName,
        });
        const copied = await b2Fetch<B2File>(
          auth,
          "POST",
          "b2_copy_file",
          payload,
          reauth,
        );
        const handle = await context.writeResource(
          "file",
          fileInstanceName(
            destinationName,
            copied.fileId ?? null,
            args.fileName,
          ),
          toFileResource(
            destinationName,
            destinationBucketId,
            copied,
            new Date().toISOString(),
            // A freshly written version is the newest one for its name.
            { fileName: args.fileName, isCurrentVersion: true },
          ),
        );
        logger.info("Copied to {fileName} (fileId={fileId})", {
          fileName: args.fileName,
          fileId: copied.fileId,
        });
        return { dataHandles: [handle] };
      },
    },
    "update": {
      description:
        "Set or clear a file version's legal hold (b2_update_file_legal_hold) and Object Lock retention (b2_update_file_retention), then re-read the file so the snapshot carries its full state rather than the slim update response. Setting compliance retention is IRREVERSIBLE and requires allowComplianceRetention. Requires writeFileLegalHolds / writeFileRetentions to change them, readFiles for the re-read, and bypassGovernance to shorten an existing governance lock.",
      arguments: UpdateArgsSchema,
      execute: async (
        args: z.infer<typeof UpdateArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        if (!args.fileId && !args.fileName) {
          throw new Error(
            "update needs a fileId or a fileName to identify what to change.",
          );
        }
        if (
          (args.retentionMode === "governance" ||
            args.retentionMode === "compliance") &&
          args.retainUntilTimestamp === undefined
        ) {
          throw new Error(
            `retentionMode "${args.retentionMode}" requires ` +
              "retainUntilTimestamp (milliseconds since the Unix epoch) — a " +
              "retention lock with no end date is not a thing B2 accepts.",
          );
        }
        assertComplianceAllowed(
          args.retentionMode,
          args.retainUntilTimestamp,
          g,
          args.allowComplianceRetention,
        );

        const bucketName = requireBucketName(g);
        const { auth, reauth } = await session(g);

        // Both update operations are addressed by fileName + fileId and never
        // by bucket, so the bucket ID is resolved only when a NAME has to be
        // looked up.
        let fileId = args.fileId ?? null;
        let fileName = args.fileName ?? "";
        let bucketId: string | null = g.bucketId ?? null;
        if (!fileId) {
          const bucket = await requireBucket(auth, g, reauth);
          bucketId = bucket.bucketId;
          const found = await findNewestVersion(
            auth,
            bucket.bucketId,
            fileName,
            reauth,
          );
          if (found === null) {
            throw new Error(
              `No version of "${fileName}" exists in bucket ` +
                `"${bucketName}", so there is nothing to update.`,
            );
          }
          fileId = found.fileId ?? null;
        } else if (!fileName) {
          const info = await b2Fetch<B2File>(
            auth,
            "POST",
            "b2_get_file_info",
            { fileId },
            reauth,
          );
          fileName = info.fileName ?? "";
          bucketId = info.bucketId ?? bucketId;
        }
        if (!fileId) {
          throw new Error(
            `Could not resolve a fileId for "${fileName}" in bucket ` +
              `"${bucketName}".`,
          );
        }
        // bypassGovernance only reaches b2_update_file_retention. Accepting it
        // alongside a legal-hold-only change and quietly dropping it would let
        // a caller believe a governance lock had been overridden when nothing
        // of the sort was attempted.
        if (args.bypassGovernance && !args.retentionMode) {
          logger.warn(
            "bypassGovernance was supplied for {fileName} but no retentionMode was — it applies only to a retention change and is being ignored",
            { fileName },
          );
        }

        if (args.legalHold) {
          logger.info("Setting legal hold {legalHold} on {fileName}", {
            legalHold: args.legalHold,
            fileName,
          });
          await b2Fetch<Record<string, unknown>>(
            auth,
            "POST",
            "b2_update_file_legal_hold",
            { fileId, fileName, legalHold: args.legalHold },
            reauth,
          );
        }
        if (args.retentionMode) {
          const mode = args.retentionMode === "none"
            ? null
            : args.retentionMode;
          logger.info("Setting retention {mode} on {fileName}", {
            mode: mode ?? "none",
            fileName,
          });
          const payload: Record<string, unknown> = {
            fileId,
            fileName,
            fileRetention: {
              mode,
              retainUntilTimestamp: mode === null
                ? null
                : args.retainUntilTimestamp,
            },
          };
          if (args.bypassGovernance) payload.bypassGovernance = true;
          await b2Fetch<Record<string, unknown>>(
            auth,
            "POST",
            "b2_update_file_retention",
            payload,
            reauth,
          );
        }
        if (!args.legalHold && !args.retentionMode) {
          logger.warn(
            "update was called with neither legalHold nor retentionMode for {fileName}; nothing was changed and this run only re-reads the file",
            { fileName },
          );
        }

        // b2_update_file_legal_hold and b2_update_file_retention both return a
        // SLIM body — the id, the name, and the one field they changed. Writing
        // a snapshot from that would drop contentLength, uploadTimestamp and
        // everything else, so re-read the file. b2_get_file_info is class B and
        // costs a fraction of a list call.
        const file = await b2Fetch<B2File>(
          auth,
          "POST",
          "b2_get_file_info",
          { fileId },
          reauth,
        );
        const handle = await context.writeResource(
          "file",
          fileInstanceName(bucketName, fileId, fileName),
          toFileResource(
            bucketName,
            file.bucketId ?? bucketId,
            file,
            new Date().toISOString(),
            { fileName },
          ),
        );
        logger.info("Updated {fileName} (fileId={fileId})", {
          fileName,
          fileId,
        });
        return { dataHandles: [handle] };
      },
    },
  },
  checks: {
    "credentials-present": {
      description:
        "Both halves of the B2 application key must be set — an empty applicationKey silently authorizes as nobody.",
      labels: ["policy"],
      // deno-lint-ignore require-await
      execute: async (
        context: { globalArgs: GlobalArgs },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
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
    // THERE IS DELIBERATELY NO "file-destruction-acknowledged" PRE-FLIGHT
    // CHECK. One shipped in 2026.08.05.1 and was removed in 2026.08.06.1.
    //
    // swamp does not pass a method's inputs to its checks, so the check could
    // only ever read globalArgs. That made `--input allowFileDestruction=true`
    // — the acknowledgement its own error message told you to pass — invisible
    // to it, and the run was rejected before `execute` ever saw the flag.
    // Verified against the published version, not merely reasoned about.
    //
    // The consequence was worse than a self-contradicting message. With the
    // per-run path blocked, the ONLY way to delete anything was to set
    // allowFileDestruction: true permanently on the model definition — so a
    // check written to prevent accidental destruction was in practice forcing
    // operators to arm destruction for good, on a model whose delete can
    // corrupt a restic repository. It failed on the safe configuration and
    // passed on the dangerous one.
    //
    // The real gate is assertDestructionAllowed inside `delete` and `hide`,
    // which sees BOTH the method input and the global argument, runs before any
    // B2 call, and is covered by tests for each path. Note it also covers
    // `hide`, which no pre-flight check could ever guard: checks run only for
    // methods named create/update/delete/action.
    //
    // The test that accompanied this check asserted its behaviour was correct,
    // so the suite encoded the bug rather than catching it — the same failure
    // as the wave-1 unprunedPrefixes test. Its replacement asserts the
    // property that actually matters: no check may block delete for want of
    // the acknowledgement. Do not re-add it.
    "single-bucket-for-file-methods": {
      description:
        "delete and update act on one file in one bucket, so globalArgs.bucketName must be set. Only scan may leave it unset, and then it inventories every bucket the key can see.",
      labels: ["policy"],
      appliesTo: ["delete", "update"],
      // deno-lint-ignore require-await
      execute: async (
        context: { globalArgs: GlobalArgs },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        if (context.globalArgs.bucketName?.trim()) return { pass: true };
        return {
          pass: false,
          errors: [
            "globalArgs.bucketName is not set, but this method acts on one " +
            "file in one specific bucket. Set it on the model.",
          ],
        };
      },
    },
  },
};

/** Internal helpers and schemas, exported only for unit testing. */
export const _internal = {
  GlobalArgsSchema,
  ScanArgsSchema,
  AggregateResourceSchema,
  FileResourceSchema,
  shortHash,
  safeFragment,
  aggregateInstanceName,
  fileInstanceName,
  toIso,
  unwrapAuthorized,
  toFileResource,
  groupFor,
  tallyFiles,
  toAggregateResource,
  newTally,
  listFilePages,
  listAllBuckets,
  resolveBuckets,
  requireBucketName,
  requireBucket,
  findNewestVersion,
  isAlreadyGone,
  assertDestructionAllowed,
  assertComplianceAllowed,
};
