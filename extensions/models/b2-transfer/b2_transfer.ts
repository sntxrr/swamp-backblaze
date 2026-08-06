/**
 * Backblaze B2 data-plane transfers via the B2 Native API v4.
 *
 * Covers the thirteen upload, download and large-file operations that the rest
 * of this suite deliberately leaves alone, completing coverage of all 33.
 *
 * **This model is a deliberate misfit, and it is guarded rather than hidden.**
 * Streaming a multi-gigabyte object through a Deno subprocess produces no
 * meaningful typed state — restic already moves those bytes over the
 * S3-compatible API, faster and without swamp in the path. So `upload` and
 * `download` exist for completeness and for *validation*, not to be anybody's
 * data pipeline, and both refuse to move more than `maxTransferBytes` (100 MB
 * by default) without an explicit override. A model that cannot say no to a
 * 40 GB restic pack file has no business holding these methods.
 *
 * **What it is actually for.** Three jobs the rest of the suite cannot do:
 *
 * 1. **Prove a bucket is readable and writable independently of restic.**
 *    `upload` a canary, `download` it back, compare the SHA-1. That is a real
 *    end-to-end assertion about a backup destination, and it is the half of
 *    restore-validation that does not need restic installed.
 * 2. **Make the hygiene report's unfinished-upload findings actionable.**
 *    `scan` inventories interrupted large uploads — B2 stores and bills their
 *    parts indefinitely, and nothing in the console adds them up. `list_parts`
 *    sizes one, and `delete` cancels it.
 * 3. **Reach the large-file API at all**, so a caller is not forced back to the
 *    `b2` CLI for `copy_part` or a resumable upload.
 *
 * **Honest nulls, as everywhere in this suite.** A SHA-1 that was not checked
 * is `null`, never `false` — "not verified" and "verified as wrong" are
 * different facts and only one of them is an emergency. Byte counts B2 did not
 * report stay `null` rather than becoming `0`.
 *
 * **The download authorization is a secret, and is never persisted.**
 * `b2_get_download_authorization` returns a token granting read access to a
 * file-name prefix for up to a week. Unlike `b2-key`'s one-shot
 * `applicationKey`, it is **regenerable at will**, so there is no reason to
 * store it and every reason not to: swamp resources sync to a remote S3
 * datastore. The snapshot records the authorization's shape — prefix,
 * duration, expiry — and never its token. That is a deliberate divergence from
 * `b2-key`'s `secretDestination` pattern, and the difference is regenerability.
 *
 * **Destruction is gated.** `delete` cancels an in-flight large upload and
 * discards every part already sent. Against a restic backup mid-run that
 * destroys work with no error surfaced to restic, so it refuses without an
 * explicit `allowTransferDestruction` acknowledgement.
 *
 * **Security.** `applicationKey` is sensitive and wired from a vault. The 24h
 * `authorizationToken`, the per-endpoint upload tokens, and the download
 * authorization token are all bearer credentials: none is ever logged or
 * written into a resource. `fileInfo` is arbitrary user metadata and lands in a
 * snapshot verbatim, so it must never be used to store a credential.
 *
 * API reference: https://www.backblaze.com/apidocs/b2-native-api
 *
 * @module
 */
// extensions/models/b2-transfer/b2_transfer.ts
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

/** A B2 file version, as returned by upload, copy and download operations. */
type B2File = {
  accountId?: string;
  action?: string;
  bucketId?: string;
  contentLength?: number;
  contentSha1?: string | null;
  contentType?: string | null;
  fileId?: string | null;
  fileInfo?: Record<string, unknown> | null;
  fileName?: string;
  uploadTimestamp?: number | null;
};

/** One part of an in-progress large file, from `b2_list_parts`. */
type B2Part = {
  fileId?: string;
  partNumber?: number;
  contentLength?: number;
  contentSha1?: string | null;
  uploadTimestamp?: number | null;
};

/** An upload endpoint from `b2_get_upload_url` / `b2_get_upload_part_url`. */
type B2UploadUrl = {
  bucketId?: string;
  fileId?: string;
  uploadUrl: string;
  /** A bearer credential scoped to this endpoint. Never log or persist it. */
  authorizationToken: string;
};

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

/**
 * Model-level configuration.
 *
 * `maxTransferBytes` is the guard that makes this model safe to install. B2
 * objects in this estate are restic pack files, and nothing here should ever
 * pull one through a Deno process by accident.
 */
const GlobalArgsSchema = z.object({
  applicationKeyId: z.string().describe(
    "B2 application key ID (master or scoped). See the README for the " +
      "capabilities each method needs.",
  ),
  applicationKey: z.string().meta({ sensitive: true }).describe(
    "B2 application key — supply via vault.get(), never inline.",
  ),
  authHost: z.string().optional().describe(
    "Override the B2 authorize host (testing only). Defaults to " +
      "https://api.backblazeb2.com.",
  ),
  bucketName: z.string().optional().describe(
    "Bucket this model manages. Required by upload, download by name, " +
      "authorize_download and list_parts. Leave unset for a fleet-wide scan.",
  ),
  bucketId: z.string().optional().describe(
    "Bucket ID matching bucketName. Supplying it saves one class-C " +
      "b2_list_buckets call and lets a bucket-restricted key work without " +
      "the listBuckets capability.",
  ),
  maxTransferBytes: z.number().int().min(1).optional().describe(
    "Refuse any single upload or download larger than this many bytes. " +
      "Defaults to 100000000 (100 MB). This is the guard that keeps a model " +
      "designed for canaries and validation from being pointed at a " +
      "multi-gigabyte restic pack file; raise it deliberately, per run.",
  ),
  allowTransferDestruction: z.boolean().optional().describe(
    "Acknowledge that delete cancels an in-flight large upload and discards " +
      "every part already sent. Doing that to a backup mid-run destroys work " +
      "restic will not be told about. Required by delete.",
  ),
});

/** Parsed model-level configuration. */
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

/**
 * An interrupted large upload that B2 is still storing and still billing.
 *
 * A large upload that never reached `b2_finish_large_file` leaves its parts in
 * the bucket indefinitely. They do not appear in `b2_list_file_names`, they are
 * invisible in the console's file browser, and they are billed as storage — so
 * this is real money accumulating where nobody looks. `scan` finds them,
 * `list_parts` sizes one, `delete` cancels it.
 */
const UnfinishedUploadSchema = z.object({
  fileId: z.string().describe("The large file's ID — the B2 identifier."),
  fileName: z.string().describe("Name the interrupted upload was targeting."),
  bucketId: z.string().nullable().describe("B2 bucket ID, or null."),
  bucketName: z.string().describe("Bucket holding the interrupted upload."),
  contentType: z.string().nullable().describe(
    "Content type declared when the upload started, or null.",
  ),
  fileInfo: z.record(z.string(), z.unknown()).nullable().describe(
    "Arbitrary user metadata set at start. Lands here verbatim — never put a " +
      "credential in it.",
  ),
  uploadTimestamp: z.number().nullable().describe(
    "When the upload started, in milliseconds since the epoch, or null.",
  ),
  startedAt: z.string().nullable().describe(
    "uploadTimestamp as an ISO-8601 string, or null.",
  ),
  ageDays: z.number().nullable().describe(
    "Whole days since the upload started, or null when the timestamp is " +
      "absent. An interrupted upload older than a few days is never coming " +
      "back and is pure waste.",
  ),
  partCount: z.number().int().nullable().describe(
    "Parts uploaded so far. NULL means not measured — scan does not count " +
      "parts, because that is one class-C call per unfinished file. Run " +
      "list_parts to populate it. Never read a null here as zero parts.",
  ),
  partBytes: z.number().int().nullable().describe(
    "Total bytes across uploaded parts, or null when not measured. This is " +
      "what the interrupted upload is costing.",
  ),
  partsTruncated: z.boolean().nullable().describe(
    "True when the part listing hit its page cap, so partCount and partBytes " +
      "are a FLOOR. Null when parts were never listed.",
  ),
  status: z.string().describe(
    'Lifecycle status: "present", or "absent" after delete cancelled it.',
  ),
  observedAt: z.string().describe("ISO-8601 timestamp of this observation."),
});

/**
 * The record of one completed transfer.
 *
 * Deliberately records the transfer's *shape and outcome*, never its payload.
 * Uploading a 90 MB canary must not put 90 MB into a resource snapshot that
 * syncs to a remote datastore.
 */
const TransferSchema = z.object({
  direction: z.enum(["upload", "download", "copy_part"]).describe(
    "Which way the bytes moved.",
  ),
  bucketName: z.string().describe("Bucket the transfer targeted."),
  bucketId: z.string().nullable().describe("B2 bucket ID, or null."),
  fileName: z.string().describe("File name transferred."),
  fileId: z.string().nullable().describe(
    "B2 file ID, or null when the operation does not produce one.",
  ),
  bytes: z.number().int().nullable().describe(
    "Bytes moved, or null when B2 did not report a length.",
  ),
  contentType: z.string().nullable().describe(
    "Content type, or null when not reported.",
  ),
  contentSha1: z.string().nullable().describe(
    "SHA-1 B2 holds for the content, or null when not reported. B2 prefixes " +
      'multi-part files with "unverified:" or returns "none" for them — ' +
      "recorded verbatim rather than normalised, because the prefix is the " +
      "fact.",
  ),
  sha1Verified: z.boolean().nullable().describe(
    "Whether the SHA-1 computed locally matched what B2 reports. NULL means " +
      "NOT CHECKED — which is not the same as a failed check, and only one " +
      "of those is an emergency. False means computed and mismatched.",
  ),
  mode: z.enum(["small", "large", "copy_part"]).describe(
    'How it moved: "small" is a single b2_upload_file, "large" is the ' +
      "start/part/finish path.",
  ),
  partCount: z.number().int().nullable().describe(
    "Parts used by a large upload, or null for a single-part transfer.",
  ),
  durationMs: z.number().int().nullable().describe(
    "Wall-clock duration of the transfer in milliseconds, or null.",
  ),
  observedAt: z.string().describe("ISO-8601 timestamp of this transfer."),
});

/**
 * A minted download authorization — its shape, never its token.
 *
 * `b2_get_download_authorization` returns a bearer token granting read access
 * to every file under a prefix, for up to seven days. It is **not** recorded
 * here, and the divergence from `b2-key`'s `secretDestination` pattern is
 * deliberate: an application key's secret is returned exactly once and is lost
 * forever if not captured, whereas this token can be re-minted on demand. A
 * secret that is cheap to regenerate should never be persisted at all.
 */
const DownloadAuthSchema = z.object({
  bucketName: z.string().describe("Bucket the authorization is scoped to."),
  bucketId: z.string().nullable().describe("B2 bucket ID, or null."),
  fileNamePrefix: z.string().describe(
    "Prefix the authorization grants read access to. Empty means the whole " +
      "bucket, which is rarely what you want.",
  ),
  validDurationInSeconds: z.number().int().describe(
    "Lifetime requested, in seconds. B2 caps this at 604800 (7 days).",
  ),
  expiresAt: z.string().describe(
    "ISO-8601 time this authorization stops working, computed locally from " +
      "the mint time plus the duration.",
  ),
  verified: z.boolean().nullable().describe(
    "Whether the minted token was actually exercised against B2. NULL means " +
      "not checked. A token that mints but cannot read is the failure this " +
      "method exists to catch, so prefer verify=true.",
  ),
  tokenPersisted: z.literal(false).describe(
    "Always false, and present so the guarantee is visible in the data " +
      "rather than only in the docs: the authorization token is never " +
      "written to a snapshot.",
  ),
  observedAt: z.string().describe("ISO-8601 timestamp of this observation."),
});

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

/** Arguments for the fleet-wide unfinished-upload scan. */
const ScanArgsSchema = z.object({
  maxPages: z.number().int().min(1).max(10000).optional().describe(
    "Hard cap on list pages per bucket. Defaults to 50. Hitting the cap is " +
      "surfaced as a warning rather than silently reporting a partial " +
      "inventory as whole.",
  ),
  countParts: z.boolean().optional().describe(
    "Also call b2_list_parts for every unfinished upload found, populating " +
      "partCount and partBytes. Costs one extra class-C call per unfinished " +
      "file, so it is off by default; without it those fields are null, " +
      'meaning "not measured", never zero.',
  ),
});

/** Arguments for `upload`. */
const UploadArgsSchema = z.object({
  fileName: z.string().min(1).describe(
    "Destination file name within the bucket.",
  ),
  content: z.string().optional().describe(
    "Inline UTF-8 content to upload. Use this for canaries and validation. " +
      "Exactly one of content or sourcePath is required.",
  ),
  sourcePath: z.string().optional().describe(
    "Local file to upload. Requires Deno read permission for the path. " +
      "Exactly one of content or sourcePath is required.",
  ),
  contentType: z.string().optional().describe(
    'MIME type. Defaults to "b2/x-auto", which lets B2 infer from the name.',
  ),
  fileInfo: z.record(z.string(), z.string()).optional().describe(
    "Custom metadata to attach. Stored by B2 and returned on every read, so " +
      "never put a credential here.",
  ),
  partSizeBytes: z.number().int().min(5000000).optional().describe(
    "Part size for the large-file path, in bytes. Defaults to B2's " +
      "recommended size. B2's absolute minimum is 5000000 for every part " +
      "except the last.",
  ),
  forceLarge: z.boolean().optional().describe(
    "Use the start/part/finish large-file path even when the content would " +
      "fit in a single upload. Exists so the large-file path is testable " +
      "against real B2 without staging a 100 MB file.",
  ),
  maxTransferBytes: z.number().int().min(1).optional().describe(
    "Override globalArgs.maxTransferBytes for this run only.",
  ),
});

/** Arguments for `download`. */
const DownloadArgsSchema = z.object({
  fileId: z.string().optional().describe(
    "Download by file ID (b2_download_file_by_id). Exactly one of fileId or " +
      "fileName is required.",
  ),
  fileName: z.string().optional().describe(
    "Download by name (b2_download_file_by_name), which resolves to the " +
      "bucket's current version. Requires bucketName.",
  ),
  destinationPath: z.string().optional().describe(
    "Write the payload to this local path. Omit to verify and discard, " +
      "which is the default and the safe one: the point is proving the " +
      "bucket is readable, not staging data.",
  ),
  verifySha1: z.boolean().optional().describe(
    "Compute the SHA-1 of what arrived and compare it to what B2 reports. " +
      "Defaults to true. When B2 reports no comparable SHA-1 (large files " +
      'come back "none" or "unverified:..."), sha1Verified stays null rather ' +
      "than being forced to a boolean.",
  ),
  maxTransferBytes: z.number().int().min(1).optional().describe(
    "Override globalArgs.maxTransferBytes for this run only.",
  ),
});

/** Arguments for `authorize_download`. */
const AuthorizeDownloadArgsSchema = z.object({
  fileNamePrefix: z.string().describe(
    "Prefix to grant read access to. An empty string grants the whole " +
      "bucket — allowed, but you must pass it explicitly.",
  ),
  validDurationInSeconds: z.number().int().min(1).max(604800).optional()
    .describe(
      "Lifetime of the authorization. Defaults to 3600 (one hour). B2's " +
        "maximum is 604800 (7 days); prefer the shortest that works.",
    ),
  verify: z.boolean().optional().describe(
    "Exercise the minted token against B2 before reporting success. " +
      "Defaults to true — a token that mints but cannot read is exactly the " +
      "failure this method exists to catch.",
  ),
});

/** Arguments for `list_parts`. */
const ListPartsArgsSchema = z.object({
  fileId: z.string().min(1).describe(
    "The unfinished large file whose parts to list.",
  ),
  maxPages: z.number().int().min(1).max(10000).optional().describe(
    "Hard cap on list pages. Defaults to 50 (up to 50,000 parts).",
  ),
});

/** Arguments for `copy_part`. */
const CopyPartArgsSchema = z.object({
  sourceFileId: z.string().min(1).describe("File ID to copy bytes from."),
  largeFileId: z.string().min(1).describe(
    "The in-progress large file to copy into, from b2_start_large_file.",
  ),
  partNumber: z.number().int().min(1).max(10000).describe(
    "Which part this becomes, 1-10000.",
  ),
  range: z.string().optional().describe(
    'Byte range of the source to copy, e.g. "bytes=0-4999999". Omit to copy ' +
      "the whole source file.",
  ),
});

/** Arguments for `delete` — cancelling an unfinished large upload. */
const DeleteArgsSchema = z.object({
  fileId: z.string().min(1).describe(
    "The unfinished large file to cancel. Every part already uploaded is " +
      "discarded.",
  ),
  allowTransferDestruction: z.boolean().optional().describe(
    "Per-run acknowledgement that this discards uploaded parts. Either this " +
      "or the global argument is required.",
  ),
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** FNV-1a, rendered as 8 hex chars. Not a cryptographic hash. */
export function shortHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/**
 * Reduce arbitrary text to a path-safe fragment.
 *
 * Lossy on purpose — every instance name that uses this pairs it with a hash of
 * the raw input, because "data/" and "data_" reduce alike and must stay
 * distinct.
 */
export function safeFragment(input: string, maxLength = 24): string {
  const cleaned = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned.slice(0, maxLength) || "none";
}

/**
 * Instance name for an unfinished upload.
 *
 * Spec-prefixed per CONVENTIONS §2 — instance names share one flat namespace
 * across every spec in a model, so an unprefixed name would let this model's
 * three specs clobber each other on disk.
 *
 * The trailing hash covers the FULL `fileId`, and it is not decoration. A real
 * B2 large-file ID is ~83 characters —
 * `4_z<bucket>_f<file>_d<date>_m<minute>_c<cluster>_v<vol>_t<seq>` — so
 * `safeFragment` truncates it, and what it truncates away is the entire
 * timestamp tail. Two uploads whose IDs differ only past that cut would reduce
 * to the same name and silently clobber each other on disk, which is the exact
 * failure that made `b2-bucket`'s notification snapshot eat its bucket
 * snapshot. Found live: the mock fixture used a 25-character ID that never
 * reached the truncation, so no test could have caught this.
 */
export function unfinishedInstanceName(fileId: string): string {
  return `unfinished-upload-${safeFragment(fileId, 48)}-${shortHash(fileId)}`;
}

/**
 * Instance name for a transfer record.
 *
 * Includes a hash of the raw (direction, bucket, file) triple because
 * `safeFragment` is lossy and two different file names can reduce to the same
 * text. Without the hash, uploading `data/a.txt` and `data-a.txt` would write
 * the same instance and one would silently overwrite the other.
 */
export function transferInstanceName(
  direction: string,
  bucketName: string,
  fileName: string,
): string {
  const h = shortHash(`${direction} ${bucketName} ${fileName}`);
  return `transfer-${direction}-${safeFragment(fileName, 32)}-${h}`;
}

/** Instance name for a download authorization. */
export function downloadAuthInstanceName(
  bucketName: string,
  prefix: string,
): string {
  const h = shortHash(`${bucketName} ${prefix}`);
  return `download-auth-${safeFragment(bucketName, 24)}-${
    safeFragment(prefix, 24)
  }-${h}`;
}

/** Milliseconds since the epoch as an ISO-8601 string, or null. */
export function toIso(ms: number | null): string | null {
  if (ms === null || !Number.isFinite(ms)) return null;
  try {
    return new Date(ms).toISOString();
  } catch {
    return null;
  }
}

/**
 * Whole days between a start timestamp and now.
 *
 * Returns null rather than 0 for an absent timestamp, because "started an
 * unknown time ago" and "started today" would otherwise be indistinguishable —
 * and age is the whole basis for deciding an interrupted upload is abandoned.
 */
export function ageInDays(
  uploadTimestamp: number | null,
  nowMs: number,
): number | null {
  if (uploadTimestamp === null || !Number.isFinite(uploadTimestamp)) {
    return null;
  }
  const days = Math.floor((nowMs - uploadTimestamp) / 86_400_000);
  return days >= 0 ? days : 0;
}

/**
 * SHA-1 of a byte array, lowercase hex.
 *
 * Web Crypto only — CONVENTIONS §2 forbids npm dependencies, and B2 identifies
 * content by SHA-1 whatever anyone thinks of SHA-1 in 2026. It is used here as
 * a transfer-integrity checksum against a value B2 itself computed, not as a
 * security primitive, so its collision weakness is not in play.
 */
export async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-1",
    bytes as unknown as ArrayBuffer,
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decide whether B2's reported SHA-1 can be compared to a locally computed one.
 *
 * B2 returns `none` for large files assembled from parts, and prefixes
 * `unverified:` when the uploader did not supply a checksum. Neither is a
 * SHA-1, and comparing against them would manufacture a mismatch out of a value
 * that was never a hash. Returning null keeps "not comparable" distinct from
 * "compared and wrong".
 */
export function comparableSha1(reported: string | null): string | null {
  if (typeof reported !== "string") return null;
  const v = reported.trim().toLowerCase();
  if (v === "" || v === "none" || v.startsWith("unverified:")) return null;
  return /^[0-9a-f]{40}$/.test(v) ? v : null;
}

/**
 * Refuse a transfer larger than the configured guard.
 *
 * Throws a sentence naming the actual size, the limit and the override, because
 * the operator hitting this is almost always someone who pointed a validation
 * tool at a real backup and needs to be told that rather than handed a number.
 */
export function assertWithinTransferLimit(
  bytes: number,
  limit: number,
  what: string,
): void {
  if (bytes > limit) {
    throw new Error(
      `${what} is ${bytes} bytes, over this model's maxTransferBytes of ` +
        `${limit}. @sntxrr/b2/transfer exists for canaries and validation, ` +
        `not for moving backup data — restic already does that over the ` +
        `S3-compatible API, faster and without swamp in the path. If you ` +
        `really mean it, raise the cap for this run with ` +
        `--input maxTransferBytes=${bytes}.`,
    );
  }
}

/**
 * Refuse to cancel an upload without an explicit acknowledgement.
 *
 * Accepts the method input OR the global argument, because a pre-flight check
 * cannot see method inputs (swamp does not pass them), so the real enforcement
 * has to live here in `execute` where both are visible.
 */
export function assertDestructionAllowed(
  g: GlobalArgs,
  args: { allowTransferDestruction?: boolean },
): void {
  if (args.allowTransferDestruction === true) return;
  if (g.allowTransferDestruction === true) return;
  throw new Error(
    "delete cancels an in-flight large upload and discards every part " +
      "already sent. Against a backup mid-run that destroys work with no " +
      "error surfaced to the backup tool. Acknowledge it with " +
      "--input allowTransferDestruction=true for a single run, or set " +
      "allowTransferDestruction=true on the model.",
  );
}

/**
 * Treat "already gone" as success for an idempotent cancel.
 *
 * Deliberately narrow, and deliberately excludes `bad_bucket_id`: that is a
 * configuration error, and swallowing it would report a successful cancel of an
 * upload still accruing storage in the bucket the caller actually meant.
 */
export function isAlreadyGone(e: unknown): boolean {
  const err = e as { status?: number; b2Code?: string };
  if (err?.status === 404) return true;
  if (err?.status === 400) {
    return err.b2Code === "file_not_present" || err.b2Code === "no_such_file";
  }
  return false;
}

// ---------------------------------------------------------------------------
// Bucket resolution
// ---------------------------------------------------------------------------

/** Every bucket the key can see, as (name, id) pairs. */
export async function listAllBuckets(
  auth: B2Auth,
  reauth: () => Promise<B2Auth>,
): Promise<Array<{ bucketName: string; bucketId: string | null }>> {
  const res = await b2Fetch<{ buckets?: Array<Record<string, unknown>> }>(
    auth,
    "POST",
    "b2_list_buckets",
    { accountId: auth.accountId },
    reauth,
  );
  return (res.buckets ?? []).map((b) => ({
    bucketName: String(b.bucketName ?? ""),
    bucketId: (b.bucketId as string) ?? null,
  }));
}

/**
 * Require the bucket NAME this model manages, without resolving its ID.
 *
 * Used by the paths addressed purely by `fileId` — `b2_download_file_by_id`,
 * `b2_list_parts`, `b2_cancel_large_file` and `b2_copy_part` all take a file or
 * large-file ID and never a bucket. Demanding a bucket ID there would spend a
 * class-C `b2_list_buckets` call for nothing and lock out a bucket-restricted
 * key that has no `listBuckets` capability — the exact defect live verification
 * found in `b2-files`, fixed here by construction rather than after the fact.
 */
export function requireBucketName(g: GlobalArgs): string {
  const name = g.bucketName?.trim();
  if (!name) {
    throw new Error(
      "globalArgs.bucketName is not set. This model manages one bucket; set " +
        "bucketName on the model definition.",
    );
  }
  return name;
}

/**
 * Resolve the bucket this model manages to a (name, id) pair.
 *
 * Only for operations B2 genuinely addresses by bucket ID: `b2_get_upload_url`,
 * `b2_download_file_by_name` and `b2_get_download_authorization`. A supplied
 * `bucketId` short-circuits the lookup entirely, which is what lets a
 * bucket-restricted key work without `listBuckets`.
 */
export async function requireBucket(
  auth: B2Auth,
  g: GlobalArgs,
  reauth: () => Promise<B2Auth>,
): Promise<{ bucketName: string; bucketId: string }> {
  const bucketName = requireBucketName(g);
  if (g.bucketId) return { bucketName, bucketId: g.bucketId };
  const resolved = await listAllBuckets(auth, reauth);
  const bucketId = resolved.find((b) => b.bucketName === bucketName)?.bucketId;
  if (!bucketId) {
    throw new Error(
      `Bucket "${bucketName}" was not found in this account, or the ` +
        `application key cannot see it. Check the name, or set ` +
        `globalArgs.bucketId if the key lacks the listBuckets capability.`,
    );
  }
  return { bucketName, bucketId };
}

// ---------------------------------------------------------------------------
// Transfer primitives
// ---------------------------------------------------------------------------

/**
 * POST raw bytes to a B2 upload endpoint.
 *
 * Deliberately does NOT go through `b2Fetch`. Upload endpoints are not on the
 * cluster `apiUrl`, they carry their own single-use bearer token rather than
 * the account authorization, and the payload is a byte body rather than JSON —
 * three reasons the shared client does not fit. The token is passed in the
 * Authorization header and, like every other bearer credential in this suite,
 * never logged and never written to a snapshot.
 */
export async function postBytes<T>(
  endpoint: { uploadUrl: string; authorizationToken: string },
  headers: Record<string, string>,
  body: Uint8Array,
): Promise<T> {
  const res = await fetch(endpoint.uploadUrl, {
    method: "POST",
    headers: {
      Authorization: endpoint.authorizationToken,
      ...headers,
    },
    body: body as unknown as BodyInit,
  });
  const text = await res.text();
  if (!(res.status >= 200 && res.status < 300)) {
    let b2Code: string | undefined;
    try {
      b2Code = (JSON.parse(text) as { code?: string }).code;
    } catch {
      b2Code = undefined;
    }
    const err = new Error(
      `B2 upload failed (${res.status})${
        b2Code ? ` [${b2Code}]` : ""
      }: ${text}`,
    ) as Error & { status: number; b2Code?: string };
    err.status = res.status;
    err.b2Code = b2Code;
    throw err;
  }
  return JSON.parse(text) as T;
}

/**
 * Percent-encode a file name for a B2 URL path or header.
 *
 * `encodeURIComponent` escapes `/`, which B2 requires to stay literal in a file
 * name — a restic key like `data/ab/cdef` must remain three path segments.
 */
export function encodeFileName(fileName: string): string {
  return fileName.split("/").map(encodeURIComponent).join("/");
}

/** Read the payload to upload, from inline content or a local file. */
export async function readUploadSource(
  args: { content?: string; sourcePath?: string },
): Promise<{ bytes: Uint8Array; origin: string }> {
  const hasContent = typeof args.content === "string";
  const hasPath = typeof args.sourcePath === "string" &&
    args.sourcePath.length > 0;
  if (hasContent === hasPath) {
    throw new Error(
      "upload requires exactly one of content or sourcePath. content is for " +
        "canaries and validation; sourcePath reads a local file and needs " +
        "Deno read permission for it.",
    );
  }
  if (hasContent) {
    return {
      bytes: new TextEncoder().encode(args.content as string),
      origin: "content",
    };
  }
  const path = args.sourcePath as string;
  try {
    return { bytes: await Deno.readFile(path), origin: path };
  } catch (e) {
    throw new Error(
      `Could not read sourcePath "${path}": ${
        e instanceof Error ? e.message : String(e)
      }. The extension needs Deno read permission for that path.`,
    );
  }
}

/**
 * Upload in one call: `b2_get_upload_url` then `b2_upload_file`.
 *
 * B2 requires the SHA-1 up front in the `X-Bz-Content-Sha1` header, so it
 * verifies the transfer server-side and a corrupted upload fails rather than
 * landing silently.
 */
export async function uploadSmall(
  auth: B2Auth,
  bucketId: string,
  fileName: string,
  bytes: Uint8Array,
  contentType: string,
  fileInfo: Record<string, string>,
  reauth: () => Promise<B2Auth>,
): Promise<B2File> {
  const endpoint = await b2Fetch<B2UploadUrl>(
    auth,
    "POST",
    "b2_get_upload_url",
    { bucketId },
    reauth,
  );
  const sha1 = await sha1Hex(bytes);
  const headers: Record<string, string> = {
    "X-Bz-File-Name": encodeFileName(fileName),
    "Content-Type": contentType,
    "Content-Length": String(bytes.byteLength),
    "X-Bz-Content-Sha1": sha1,
  };
  for (const [k, v] of Object.entries(fileInfo)) {
    headers[`X-Bz-Info-${k}`] = encodeURIComponent(v);
  }
  return await postBytes<B2File>(endpoint, headers, bytes);
}

/**
 * Upload via the large-file path: start, N parts, finish.
 *
 * Parts are uploaded sequentially rather than in parallel. That is slower and
 * it is the right call here: this model is capped at 100 MB by default, so the
 * parallelism would buy little, and a sequential loop means a failure leaves a
 * cancellable large file with a known part count rather than an indeterminate
 * one. `b2_get_upload_part_url` is called once and reused across parts, which
 * is what B2 documents — a fresh URL per part would be one class-C call each.
 */
export async function uploadLarge(
  auth: B2Auth,
  bucketId: string,
  fileName: string,
  bytes: Uint8Array,
  contentType: string,
  fileInfo: Record<string, string>,
  partSize: number,
  reauth: () => Promise<B2Auth>,
  logger?: Logger,
): Promise<{ file: B2File; partCount: number }> {
  const started = await b2Fetch<B2File>(
    auth,
    "POST",
    "b2_start_large_file",
    { bucketId, fileName, contentType, fileInfo },
    reauth,
  );
  const largeFileId = started.fileId;
  if (!largeFileId) {
    throw new Error(
      "b2_start_large_file returned no fileId, so there is nothing to upload " +
        "parts into and nothing to cancel.",
    );
  }

  try {
    const endpoint = await b2Fetch<B2UploadUrl>(
      auth,
      "POST",
      "b2_get_upload_part_url",
      { fileId: largeFileId },
      reauth,
    );
    const hashes: string[] = [];
    let partNumber = 0;
    for (let offset = 0; offset < bytes.byteLength; offset += partSize) {
      partNumber++;
      const chunk = bytes.slice(offset, offset + partSize);
      const sha1 = await sha1Hex(chunk);
      hashes.push(sha1);
      await postBytes<B2Part>(endpoint, {
        "X-Bz-Part-Number": String(partNumber),
        "Content-Length": String(chunk.byteLength),
        "X-Bz-Content-Sha1": sha1,
      }, chunk);
      logger?.info("Uploaded part {partNumber} of {fileName} ({bytes} bytes)", {
        partNumber,
        fileName,
        bytes: chunk.byteLength,
      });
    }

    const finished = await b2Fetch<B2File>(
      auth,
      "POST",
      "b2_finish_large_file",
      { fileId: largeFileId, partSha1Array: hashes },
      reauth,
    );
    return { file: finished, partCount: partNumber };
  } catch (e) {
    // A large file left unfinished is billed for its parts indefinitely and is
    // invisible in the console's file browser. Cancelling on failure is the
    // difference between a failed run and a permanent, silent charge. The
    // cancel is best-effort: its own failure must not mask the real error.
    try {
      await b2Fetch(auth, "POST", "b2_cancel_large_file", {
        fileId: largeFileId,
      }, reauth);
      logger?.warn(
        "Upload of {fileName} failed; cancelled large file {fileId} so its " +
          "parts are not billed",
        { fileName, fileId: largeFileId },
      );
    } catch {
      logger?.warn(
        "Upload of {fileName} failed AND cancelling large file {fileId} also " +
          "failed — its uploaded parts are still stored and still billed. " +
          "Cancel it with: swamp model method run <model> delete " +
          "--input fileId={fileId}",
        { fileName, fileId: largeFileId },
      );
    }
    throw e;
  }
}

/**
 * Drain `b2_list_parts` for one large file.
 *
 * Returns the parts plus whether the listing was cut short, so a caller can
 * never read a part count as complete when it is a floor.
 */
export async function listParts(
  auth: B2Auth,
  fileId: string,
  maxPages: number,
  reauth: () => Promise<B2Auth>,
): Promise<{ parts: B2Part[]; truncated: boolean }> {
  const parts: B2Part[] = [];
  let startPartNumber: number | null = null;
  for (let page = 0; page < maxPages; page++) {
    const body: Record<string, unknown> = { fileId, maxPartCount: 1000 };
    if (startPartNumber !== null) body.startPartNumber = startPartNumber;
    const res = await b2Fetch<
      { parts?: B2Part[]; nextPartNumber?: number | null }
    >(auth, "POST", "b2_list_parts", body, reauth);
    parts.push(...(res.parts ?? []));
    if (res.nextPartNumber === null || res.nextPartNumber === undefined) {
      return { parts, truncated: false };
    }
    startPartNumber = res.nextPartNumber;
  }
  return { parts, truncated: true };
}

/**
 * Total the bytes across parts.
 *
 * Propagates null rather than coercing: a part whose `contentLength` B2 did not
 * report makes the total unknown, and reporting a smaller number as if it were
 * the whole is how an interrupted upload's cost gets understated.
 */
export function totalPartBytes(parts: B2Part[]): number | null {
  let acc = 0;
  for (const p of parts) {
    if (
      typeof p.contentLength !== "number" || !Number.isFinite(p.contentLength)
    ) {
      return null;
    }
    acc += p.contentLength;
  }
  return acc;
}

// ---------------------------------------------------------------------------
// Resource mappers
// ---------------------------------------------------------------------------

/**
 * Turn a raw unfinished large file into an `unfinished-upload` resource.
 *
 * The part fields default to null rather than 0. `scan` does not count parts —
 * that is one class-C call per unfinished file — so a zero there would claim a
 * measurement nobody took, about precisely the objects whose cost is the reason
 * this resource exists.
 */
export function toUnfinishedResource(
  f: B2File,
  extra: {
    bucketName: string;
    bucketId: string | null;
    partCount?: number | null;
    partBytes?: number | null;
    partsTruncated?: boolean | null;
    status?: string;
    nowMs: number;
    observedAt: string;
  },
): Record<string, unknown> {
  const uploadTimestamp = typeof f.uploadTimestamp === "number"
    ? f.uploadTimestamp
    : null;
  return {
    fileId: String(f.fileId ?? ""),
    fileName: String(f.fileName ?? ""),
    bucketId: (f.bucketId as string) ?? extra.bucketId,
    bucketName: extra.bucketName,
    contentType: (f.contentType as string) ?? null,
    fileInfo: f.fileInfo && typeof f.fileInfo === "object"
      ? f.fileInfo as Record<string, unknown>
      : null,
    uploadTimestamp,
    startedAt: toIso(uploadTimestamp),
    ageDays: ageInDays(uploadTimestamp, extra.nowMs),
    partCount: extra.partCount ?? null,
    partBytes: extra.partBytes ?? null,
    partsTruncated: extra.partsTruncated ?? null,
    status: extra.status ?? "present",
    observedAt: extra.observedAt,
  };
}

/** Turn a completed transfer into a `transfer` resource. */
export function toTransferResource(
  f: B2File,
  extra: {
    direction: "upload" | "download" | "copy_part";
    mode: "small" | "large" | "copy_part";
    bucketName: string;
    bucketId: string | null;
    fileName: string;
    bytes: number | null;
    sha1Verified: boolean | null;
    partCount: number | null;
    durationMs: number | null;
    observedAt: string;
  },
): Record<string, unknown> {
  return {
    direction: extra.direction,
    bucketName: extra.bucketName,
    bucketId: (f.bucketId as string) ?? extra.bucketId,
    fileName: String(f.fileName ?? extra.fileName),
    fileId: (f.fileId as string) ?? null,
    bytes: extra.bytes,
    contentType: (f.contentType as string) ?? null,
    contentSha1: (f.contentSha1 as string) ?? null,
    sha1Verified: extra.sha1Verified,
    mode: extra.mode,
    partCount: extra.partCount,
    durationMs: extra.durationMs,
    observedAt: extra.observedAt,
  };
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/** Open a B2 session plus a re-authorizing closure for the 24h token. */
async function session(
  g: GlobalArgs,
): Promise<{ auth: B2Auth; reauth: () => Promise<B2Auth> }> {
  const auth = await b2Authorize(g);
  return { auth, reauth: () => b2Authorize(g) };
}

/**
 * The `@sntxrr/b2/transfer` model — the B2 data plane, guarded.
 *
 * See the module docblock for why this exists and why its methods refuse to
 * move real backup data by default.
 */
export const model = {
  type: "@sntxrr/b2/transfer",
  version: "2026.08.06.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "unfinished-upload": {
      description:
        "An interrupted large upload B2 is still storing and still billing, instance-named unfinished-upload-<fileId>",
      schema: UnfinishedUploadSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    "transfer": {
      description:
        "The outcome of one upload, download or copy_part — its shape and integrity, never its payload",
      schema: TransferSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
    },
    "download-auth": {
      description:
        "A minted download authorization's scope and expiry. Never its token — the token is regenerable and is deliberately not persisted",
      schema: DownloadAuthSchema,
      lifetime: "infinite" as const,
      garbageCollection: 50,
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
    "transfer-destruction-acknowledged": {
      description:
        "Refuse to run delete without allowTransferDestruction. NOTE: this catches the global-argument path only — swamp does not give checks the method's inputs, so `--input allowTransferDestruction=true` is invisible here and the real enforcement lives inside delete. This check exists to fail fast, before any B2 call, when the model itself is not configured to destroy anything.",
      labels: ["policy"],
      appliesTo: ["delete"],
      // deno-lint-ignore require-await
      execute: async (
        context: { globalArgs: GlobalArgs },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        if (context.globalArgs.allowTransferDestruction) return { pass: true };
        return {
          pass: false,
          errors: [
            "Model does not set allowTransferDestruction, and delete cancels " +
            "an in-flight large upload, discarding every part already sent. " +
            "Acknowledge it with --input allowTransferDestruction=true for a " +
            "single run, or set allowTransferDestruction=true on the model.",
          ],
        };
      },
    },
    "transfer-limit-sane": {
      description:
        "A maxTransferBytes above 1 GiB defeats the guard that makes this model safe to install next to a restic estate.",
      labels: ["policy"],
      // deno-lint-ignore require-await
      execute: async (
        context: { globalArgs: GlobalArgs },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const limit = context.globalArgs.maxTransferBytes;
        if (limit === undefined || limit <= 1_073_741_824) {
          return { pass: true };
        }
        return {
          pass: false,
          errors: [
            `globalArgs.maxTransferBytes is ${limit}, over 1 GiB. This model ` +
            `pulls bytes through a Deno process to validate a bucket, not to ` +
            `move backups — restic does that over S3 without swamp in the ` +
            `path. Raise the cap per run with --input maxTransferBytes if a ` +
            `single large transfer is genuinely intended.`,
          ],
        };
      },
    },
  },
  methods: {
    "scan": {
      description:
        "Factory discovery — inventory interrupted large uploads across every " +
        "bucket the key can see (or just globalArgs.bucketName when set) and " +
        "write one unfinished-upload resource each. These are invisible in " +
        "the B2 console's file browser and billed as storage indefinitely. " +
        "Read-only. Requires listFiles, plus listBuckets unless a single " +
        "bucket is pinned by bucketName+bucketId. countParts=true adds one " +
        "class-C call per unfinished file to size each one.",
      arguments: ScanArgsSchema,
      execute: async (
        args: z.infer<typeof ScanArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const maxPages = args.maxPages ?? 50;
        const nowMs = Date.now();
        const observedAt = new Date(nowMs).toISOString();
        const { auth, reauth } = await session(g);

        // A pinned bucket needs no listBuckets call at all; without one, the
        // whole account is the scope, which is what makes this a factory.
        let targets: Array<{ bucketName: string; bucketId: string | null }>;
        if (g.bucketName && g.bucketId) {
          targets = [{ bucketName: g.bucketName, bucketId: g.bucketId }];
        } else {
          const all = await listAllBuckets(auth, reauth);
          targets = g.bucketName
            ? all.filter((b) => b.bucketName === g.bucketName)
            : all;
          if (g.bucketName && targets.length === 0) {
            throw new Error(
              `Bucket "${g.bucketName}" was not found in this account, or ` +
                `the application key cannot see it.`,
            );
          }
        }

        const handles: Array<{ name: string }> = [];
        let totalUnfinished = 0;
        for (const bucket of targets) {
          if (bucket.bucketId === null) {
            logger.warn(
              "Bucket {bucketName} has no readable bucketId, so its " +
                "unfinished uploads could not be listed — this is not " +
                "evidence that it has none",
              { bucketName: bucket.bucketName },
            );
            continue;
          }
          const found: B2File[] = [];
          let startFileId: string | null = null;
          let truncated = false;
          for (let page = 0; page < maxPages; page++) {
            const body: Record<string, unknown> = {
              bucketId: bucket.bucketId,
              maxFileCount: 100,
            };
            if (startFileId) body.startFileId = startFileId;
            const res = await b2Fetch<
              { files?: B2File[]; nextFileId?: string | null }
            >(auth, "POST", "b2_list_unfinished_large_files", body, reauth);
            found.push(...(res.files ?? []));
            if (!res.nextFileId) {
              truncated = false;
              break;
            }
            startFileId = res.nextFileId;
            truncated = true;
          }
          if (truncated) {
            logger.warn(
              "Bucket {bucketName} unfinished-upload listing stopped at the " +
                "page cap, so this is a FLOOR, not a total. Raise maxPages.",
              { bucketName: bucket.bucketName },
            );
          }

          for (const f of found) {
            let partCount: number | null = null;
            let partBytes: number | null = null;
            let partsTruncated: boolean | null = null;
            if (args.countParts && f.fileId) {
              const listed = await listParts(auth, f.fileId, maxPages, reauth);
              partCount = listed.parts.length;
              partBytes = totalPartBytes(listed.parts);
              partsTruncated = listed.truncated;
            }
            const resource = toUnfinishedResource(f, {
              bucketName: bucket.bucketName,
              bucketId: bucket.bucketId,
              partCount,
              partBytes,
              partsTruncated,
              nowMs,
              observedAt,
            });
            const name = unfinishedInstanceName(String(f.fileId ?? ""));
            handles.push(
              await context.writeResource(
                "unfinished-upload",
                name,
                resource,
              ),
            );
            totalUnfinished++;
          }
        }

        logger.info(
          "Scanned {buckets} bucket(s); found {n} interrupted large upload(s)",
          { buckets: targets.length, n: totalUnfinished },
        );
        return { dataHandles: handles };
      },
    },
    "upload": {
      description:
        "Upload one object, via b2_upload_file for small content or the " +
        "b2_start_large_file/b2_upload_part/b2_finish_large_file path for " +
        "large. Refuses anything over maxTransferBytes (100 MB default) — " +
        "this exists for canaries and validation, not for moving backups. " +
        "A failed large upload cancels itself so its parts are not billed. " +
        "Requires writeFiles.",
      arguments: UploadArgsSchema,
      execute: async (
        args: z.infer<typeof UploadArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const limit = args.maxTransferBytes ?? g.maxTransferBytes ??
          100_000_000;

        // Read and size-check BEFORE authorizing, so an oversized transfer
        // costs nothing at all — not even the class-C b2_authorize_account.
        const { bytes, origin } = await readUploadSource(args);
        assertWithinTransferLimit(
          bytes.byteLength,
          limit,
          `upload of ${origin}`,
        );

        const { auth, reauth } = await session(g);
        const bucket = await requireBucket(auth, g, reauth);
        const contentType = args.contentType ?? "b2/x-auto";
        const fileInfo = args.fileInfo ?? {};
        const partSize = args.partSizeBytes ?? 100_000_000;
        const useLarge = args.forceLarge === true ||
          bytes.byteLength > partSize;

        const startedMs = Date.now();
        let file: B2File;
        let partCount: number | null = null;
        if (useLarge) {
          const result = await uploadLarge(
            auth,
            bucket.bucketId,
            args.fileName,
            bytes,
            contentType,
            fileInfo,
            args.partSizeBytes ?? Math.max(5_000_000, partSize),
            reauth,
            logger,
          );
          file = result.file;
          partCount = result.partCount;
        } else {
          file = await uploadSmall(
            auth,
            bucket.bucketId,
            args.fileName,
            bytes,
            contentType,
            fileInfo,
            reauth,
          );
        }
        const durationMs = Date.now() - startedMs;

        // The SHA-1 was sent in the upload header and B2 rejects a mismatch
        // server-side, so a returned single-part file that echoes our hash is
        // genuinely verified. A large file comes back as "none" and is NOT
        // verified — null says so rather than claiming a check nobody ran.
        const localSha1 = await sha1Hex(bytes);
        const reported = comparableSha1((file.contentSha1 as string) ?? null);
        const sha1Verified = reported === null ? null : reported === localSha1;

        const resource = toTransferResource(file, {
          direction: "upload",
          mode: useLarge ? "large" : "small",
          bucketName: bucket.bucketName,
          bucketId: bucket.bucketId,
          fileName: args.fileName,
          bytes: bytes.byteLength,
          sha1Verified,
          partCount,
          durationMs,
          observedAt: new Date().toISOString(),
        });
        logger.info(
          "Uploaded {fileName} to {bucketName} ({bytes} bytes, {mode})",
          {
            fileName: args.fileName,
            bucketName: bucket.bucketName,
            bytes: bytes.byteLength,
            mode: useLarge ? "large" : "small",
          },
        );
        const name = transferInstanceName(
          "upload",
          bucket.bucketName,
          args.fileName,
        );
        return {
          dataHandles: [
            await context.writeResource("transfer", name, resource),
          ],
        };
      },
    },
    "download": {
      description:
        "Download one object by fileId (b2_download_file_by_id) or by name " +
        "(b2_download_file_by_name) and verify what arrived. Defaults to " +
        "verify-and-discard: the point is proving the bucket is readable, " +
        "not staging data. Refuses anything over maxTransferBytes. " +
        "Requires readFiles.",
      arguments: DownloadArgsSchema,
      execute: async (
        args: z.infer<typeof DownloadArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const limit = args.maxTransferBytes ?? g.maxTransferBytes ??
          100_000_000;
        const verifySha1 = args.verifySha1 ?? true;

        const byId = typeof args.fileId === "string" && args.fileId.length > 0;
        const byName = typeof args.fileName === "string" &&
          args.fileName.length > 0;
        if (byId === byName) {
          throw new Error(
            "download requires exactly one of fileId or fileName. fileId " +
              "addresses one immutable version; fileName resolves to the " +
              "bucket's current version, which is a different question.",
          );
        }

        const { auth, reauth } = await session(g);
        // Only the by-name path needs a bucket. Resolving one for a fileId
        // download would spend a class-C call B2 never asked for and lock out
        // a bucket-restricted key without listBuckets.
        let bucketName = g.bucketName ?? "";
        let bucketId: string | null = g.bucketId ?? null;
        let url: string;
        if (byId) {
          url = `${auth.downloadUrl}/b2api/v4/b2_download_file_by_id?fileId=${
            encodeURIComponent(args.fileId as string)
          }`;
        } else {
          const bucket = await requireBucket(auth, g, reauth);
          bucketName = bucket.bucketName;
          bucketId = bucket.bucketId;
          url = `${auth.downloadUrl}/file/${
            encodeURIComponent(bucket.bucketName)
          }/${encodeFileName(args.fileName as string)}`;
        }

        const startedMs = Date.now();
        const res = await fetch(url, {
          method: "GET",
          headers: { Authorization: auth.authorizationToken },
        });
        if (!(res.status >= 200 && res.status < 300)) {
          const text = await res.text();
          const err = new Error(
            `B2 download failed (${res.status}): ${text}`,
          ) as Error & { status: number };
          err.status = res.status;
          throw err;
        }

        // Check the advertised size BEFORE reading the body, so an oversized
        // object is refused without pulling a single byte of it through this
        // process. Content-Length absent is not permission to proceed blindly;
        // the post-read check below is the backstop.
        const advertised = Number(res.headers.get("Content-Length"));
        if (Number.isFinite(advertised) && advertised > 0) {
          assertWithinTransferLimit(advertised, limit, "download");
        }
        const bytes = new Uint8Array(await res.arrayBuffer());
        assertWithinTransferLimit(bytes.byteLength, limit, "download");
        const durationMs = Date.now() - startedMs;

        const reportedSha1 = res.headers.get("X-Bz-Content-Sha1");
        const comparable = comparableSha1(reportedSha1);
        let sha1Verified: boolean | null = null;
        if (verifySha1 && comparable !== null) {
          sha1Verified = (await sha1Hex(bytes)) === comparable;
        }

        if (args.destinationPath) {
          try {
            await Deno.writeFile(args.destinationPath, bytes);
          } catch (e) {
            throw new Error(
              `Downloaded ${bytes.byteLength} bytes but could not write ` +
                `destinationPath "${args.destinationPath}": ${
                  e instanceof Error ? e.message : String(e)
                }. The extension needs Deno write permission for that path.`,
            );
          }
        }

        const fileName = res.headers.get("X-Bz-File-Name") ?? args.fileName ??
          "";
        const file: B2File = {
          fileId: res.headers.get("X-Bz-File-Id") ?? args.fileId ?? null,
          fileName: decodeURIComponent(fileName),
          contentType: res.headers.get("Content-Type"),
          contentSha1: reportedSha1,
          bucketId: bucketId ?? undefined,
        };
        const resource = toTransferResource(file, {
          direction: "download",
          mode: "small",
          bucketName,
          bucketId,
          fileName: decodeURIComponent(fileName),
          bytes: bytes.byteLength,
          sha1Verified,
          partCount: null,
          durationMs,
          observedAt: new Date().toISOString(),
        });

        if (sha1Verified === false) {
          logger.warn(
            "Downloaded {fileName} but its SHA-1 does NOT match what B2 " +
              "reports — the bytes that arrived are not the bytes B2 holds",
            { fileName: decodeURIComponent(fileName) },
          );
        } else {
          logger.info(
            "Downloaded {fileName} ({bytes} bytes, sha1 {verdict})",
            {
              fileName: decodeURIComponent(fileName),
              bytes: bytes.byteLength,
              verdict: sha1Verified === null ? "not comparable" : "verified",
            },
          );
        }

        const name = transferInstanceName(
          "download",
          bucketName || "by-id",
          decodeURIComponent(fileName),
        );
        return {
          dataHandles: [
            await context.writeResource("transfer", name, resource),
          ],
        };
      },
    },
    "authorize_download": {
      description:
        "Mint a b2_get_download_authorization token for a file-name prefix " +
        "and, by default, prove it actually works. The token itself is NEVER " +
        "written to a snapshot or a log — unlike an application key's " +
        "one-shot secret it can be re-minted at will, so persisting it would " +
        "be all risk and no benefit. Requires shareFiles.",
      arguments: AuthorizeDownloadArgsSchema,
      execute: async (
        args: z.infer<typeof AuthorizeDownloadArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const duration = args.validDurationInSeconds ?? 3600;
        const verify = args.verify ?? true;
        const { auth, reauth } = await session(g);
        const bucket = await requireBucket(auth, g, reauth);

        const mintedMs = Date.now();
        const res = await b2Fetch<{ authorizationToken?: string }>(
          auth,
          "POST",
          "b2_get_download_authorization",
          {
            bucketId: bucket.bucketId,
            fileNamePrefix: args.fileNamePrefix,
            validDurationInSeconds: duration,
          },
          reauth,
        );
        const token = res.authorizationToken;
        if (!token) {
          throw new Error(
            "b2_get_download_authorization returned no authorizationToken, " +
              "so there is nothing to verify and nothing was granted.",
          );
        }

        // Exercise the token. A 401 means it minted but grants nothing, which
        // is precisely the failure worth catching here; a 404 means the prefix
        // holds no object yet, which says nothing about the authorization.
        let verified: boolean | null = null;
        if (verify) {
          const probeUrl = `${auth.downloadUrl}/file/${
            encodeURIComponent(bucket.bucketName)
          }/${encodeFileName(args.fileNamePrefix)}`;
          const probe = await fetch(probeUrl, {
            method: "HEAD",
            headers: { Authorization: token },
          });
          verified = probe.status !== 401 && probe.status !== 403;
          if (!verified) {
            logger.warn(
              "Download authorization for prefix {prefix} minted but was " +
                "REJECTED when used ({status}) — the token grants nothing",
              { prefix: args.fileNamePrefix, status: probe.status },
            );
          }
        }

        const resource = {
          bucketName: bucket.bucketName,
          bucketId: bucket.bucketId,
          fileNamePrefix: args.fileNamePrefix,
          validDurationInSeconds: duration,
          expiresAt: new Date(mintedMs + duration * 1000).toISOString(),
          verified,
          tokenPersisted: false as const,
          observedAt: new Date().toISOString(),
        };
        logger.info(
          "Minted a {duration}s download authorization for {bucketName} " +
            "prefix {prefix} (token not persisted)",
          {
            duration,
            bucketName: bucket.bucketName,
            prefix: args.fileNamePrefix,
          },
        );
        const name = downloadAuthInstanceName(
          bucket.bucketName,
          args.fileNamePrefix,
        );
        return {
          dataHandles: [
            await context.writeResource("download-auth", name, resource),
          ],
        };
      },
    },
    "list_parts": {
      description:
        "Size one interrupted large upload with b2_list_parts and update its " +
        "unfinished-upload resource with partCount and partBytes. This is " +
        "what turns 'there is an abandoned upload' into 'it is costing this " +
        "much'. Read-only. Requires writeFiles (B2 scopes b2_list_parts to " +
        "the write capability, not a read one).",
      arguments: ListPartsArgsSchema,
      execute: async (
        args: z.infer<typeof ListPartsArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const maxPages = args.maxPages ?? 50;
        const nowMs = Date.now();
        const { auth, reauth } = await session(g);
        // Addressed by fileId alone — no bucket lookup, so a bucket-restricted
        // key without listBuckets can still size its own stuck uploads.
        const bucketName = g.bucketName ?? "";

        const { parts, truncated } = await listParts(
          auth,
          args.fileId,
          maxPages,
          reauth,
        );
        const partBytes = totalPartBytes(parts);
        if (truncated) {
          logger.warn(
            "Part listing for {fileId} stopped at the page cap, so " +
              "partCount and partBytes are a FLOOR, not a total",
            { fileId: args.fileId },
          );
        }

        const resource = toUnfinishedResource(
          { fileId: args.fileId, fileName: "", bucketId: g.bucketId },
          {
            bucketName,
            bucketId: g.bucketId ?? null,
            partCount: parts.length,
            partBytes,
            partsTruncated: truncated,
            nowMs,
            observedAt: new Date(nowMs).toISOString(),
          },
        );
        logger.info(
          "Large file {fileId} has {n} uploaded part(s) totalling {bytes} " +
            "bytes, all still billed",
          { fileId: args.fileId, n: parts.length, bytes: partBytes },
        );
        return {
          dataHandles: [
            await context.writeResource(
              "unfinished-upload",
              unfinishedInstanceName(args.fileId),
              resource,
            ),
          ],
        };
      },
    },
    "copy_part": {
      description:
        "Copy a byte range from an existing file into a part of an " +
        "in-progress large file (b2_copy_part), server-side — no bytes move " +
        "through this process, so maxTransferBytes does not apply. Requires " +
        "writeFiles and readFiles.",
      arguments: CopyPartArgsSchema,
      execute: async (
        args: z.infer<typeof CopyPartArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const { auth, reauth } = await session(g);
        const bucketName = g.bucketName ?? "";

        const startedMs = Date.now();
        const payload: Record<string, unknown> = {
          sourceFileId: args.sourceFileId,
          largeFileId: args.largeFileId,
          partNumber: args.partNumber,
        };
        if (args.range) payload.range = args.range;
        const part = await b2Fetch<B2Part>(
          auth,
          "POST",
          "b2_copy_part",
          payload,
          reauth,
        );
        const durationMs = Date.now() - startedMs;

        const resource = toTransferResource(
          {
            fileId: part.fileId ?? args.largeFileId,
            fileName: `part-${args.partNumber}`,
            contentSha1: part.contentSha1 ?? null,
            bucketId: g.bucketId,
          },
          {
            direction: "copy_part",
            mode: "copy_part",
            bucketName,
            bucketId: g.bucketId ?? null,
            fileName: `part-${args.partNumber}`,
            bytes: typeof part.contentLength === "number"
              ? part.contentLength
              : null,
            // Server-side copy: no local bytes exist to hash, so there is
            // nothing to verify. Null, never false.
            sha1Verified: null,
            partCount: null,
            durationMs,
            observedAt: new Date().toISOString(),
          },
        );
        logger.info(
          "Copied part {partNumber} into large file {largeFileId}",
          { partNumber: args.partNumber, largeFileId: args.largeFileId },
        );
        const name = transferInstanceName(
          "copy_part",
          bucketName || "by-id",
          `${args.largeFileId}-${args.partNumber}`,
        );
        return {
          dataHandles: [
            await context.writeResource("transfer", name, resource),
          ],
        };
      },
    },
    "delete": {
      description:
        "Cancel an interrupted large upload with b2_cancel_large_file, " +
        "discarding every part already sent and stopping the storage charge. " +
        "Idempotent: an upload that is already gone is a success. Refuses " +
        "without allowTransferDestruction. Requires writeFiles.",
      arguments: DeleteArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        // Gated before any B2 call, and before authorizing, so a refusal costs
        // nothing and cannot half-happen.
        assertDestructionAllowed(g, args);

        const nowMs = Date.now();
        const { auth, reauth } = await session(g);
        // b2_cancel_large_file takes a fileId and nothing else.
        const bucketName = g.bucketName ?? "";

        let cancelled: B2File | null = null;
        let alreadyGone = false;
        try {
          cancelled = await b2Fetch<B2File>(
            auth,
            "POST",
            "b2_cancel_large_file",
            { fileId: args.fileId },
            reauth,
          );
        } catch (e) {
          if (!isAlreadyGone(e)) throw e;
          alreadyGone = true;
          logger.info(
            "Large file {fileId} was already gone — nothing to cancel",
            { fileId: args.fileId },
          );
        }

        const resource = toUnfinishedResource(
          {
            fileId: args.fileId,
            fileName: cancelled?.fileName ?? "",
            bucketId: cancelled?.bucketId ?? g.bucketId,
          },
          {
            bucketName,
            bucketId: g.bucketId ?? null,
            // Cancelled: there are no parts any more, and that IS measured —
            // zero here is a fact, not an unmeasured default.
            partCount: 0,
            partBytes: 0,
            partsTruncated: false,
            status: "absent",
            nowMs,
            observedAt: new Date(nowMs).toISOString(),
          },
        );
        if (!alreadyGone) {
          logger.info(
            "Cancelled large file {fileId}; its uploaded parts are no longer " +
              "stored or billed",
            { fileId: args.fileId },
          );
        }
        return {
          dataHandles: [
            await context.writeResource(
              "unfinished-upload",
              unfinishedInstanceName(args.fileId),
              resource,
            ),
          ],
        };
      },
    },
  },
};

/** Internals exposed for unit tests. Not part of the public model surface. */
export const _internal = {
  GlobalArgsSchema,
  ScanArgsSchema,
  UploadArgsSchema,
  DownloadArgsSchema,
  AuthorizeDownloadArgsSchema,
  ListPartsArgsSchema,
  CopyPartArgsSchema,
  DeleteArgsSchema,
  UnfinishedUploadSchema,
  TransferSchema,
  DownloadAuthSchema,
  shortHash,
  safeFragment,
  unfinishedInstanceName,
  transferInstanceName,
  downloadAuthInstanceName,
  toIso,
  ageInDays,
  sha1Hex,
  comparableSha1,
  assertWithinTransferLimit,
  assertDestructionAllowed,
  isAlreadyGone,
  encodeFileName,
  readUploadSource,
  listAllBuckets,
  requireBucketName,
  requireBucket,
  listParts,
  totalPartBytes,
  toUnfinishedResource,
  toTransferResource,
};
