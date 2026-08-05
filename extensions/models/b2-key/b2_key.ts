/**
 * Backblaze B2 application-key management via the **B2 Native API v4**.
 *
 * One swamp model instance represents one B2 application key, keyed by its real
 * `applicationKeyId`. Exposes `sync` (locate the key via `b2_list_keys`),
 * `create` (`b2_create_key`) and an idempotent `delete` (`b2_delete_key`).
 *
 * ## The one-shot secret, and why `create` fails closed
 *
 * B2 returns the `applicationKey` **secret exactly once**, in the
 * `b2_create_key` response. It is never retrievable again — not by
 * `b2_list_keys`, not by any other call. That forces a design decision, and this
 * model makes it explicitly:
 *
 * - **The resource snapshot holds metadata only** — `applicationKeyId`,
 *   `keyName`, `capabilities`, `bucketIds`, `namePrefix`, `expirationTimestamp`.
 *   The secret is **never** written to a snapshot, because swamp resources sync
 *   to a remote S3 datastore.
 * - **The secret is emitted only** by an optional direct write to a 1Password
 *   Connect server, configured through the `connect*` global arguments. This
 *   mirrors what the homelab's Ansible `restic` role already does.
 * - **If no Connect destination is configured, `create` refuses to mint at
 *   all.** A minted key whose secret has nowhere to go is a key nobody can ever
 *   use and which must immediately be revoked. This model does not mint and
 *   discard, and it never prints the secret to a log as a fallback.
 *
 * ## Required B2 capabilities
 *
 * | Method   | Capability                 |
 * | -------- | -------------------------- |
 * | `sync`   | `listKeys`                 |
 * | `create` | `writeKeys` (+ `listKeys`) |
 * | `delete` | `deleteKeys` + `listKeys`  |
 *
 * A key can never grant capabilities its **creator** lacks. Minting a scoped key
 * from an already-scoped key is the usual cause of a confusing `401
 * unauthorized`. A `401` from a missing capability is **not** transient and is
 * never retried.
 *
 * API reference: https://www.backblaze.com/apidocs/b2-create-key
 * @module
 */
// extensions/models/b2-key/b2_key.ts
import { z } from "npm:zod@4";

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

// --- Swamp execute-context shape -------------------------------------------
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

// --- B2 capability vocabulary ----------------------------------------------
/**
 * The complete B2 capability vocabulary, verified against
 * https://www.backblaze.com/apidocs/b2-create-key.
 *
 * Used only to warn on a probable typo — B2 remains the authority and rejects
 * an unknown capability with `400 bad_request`. This list is never used to
 * *reject* a capability locally, so a capability Backblaze adds later still
 * works without a model release.
 */
export const B2_CAPABILITIES: readonly string[] = [
  "listKeys",
  "writeKeys",
  "deleteKeys",
  "listAllBucketNames",
  "listBuckets",
  "readBuckets",
  "writeBuckets",
  "deleteBuckets",
  "readBucketRetentions",
  "writeBucketRetentions",
  "readBucketEncryption",
  "writeBucketEncryption",
  "readBucketNotifications",
  "writeBucketNotifications",
  "readBucketLogging",
  "writeBucketLogging",
  "listFiles",
  "readFiles",
  "shareFiles",
  "writeFiles",
  "deleteFiles",
  "readFileLegalHolds",
  "writeFileLegalHolds",
  "readFileRetentions",
  "writeFileRetentions",
  "bypassGovernance",
];

// --- Schemas ---------------------------------------------------------------
/**
 * Global arguments for the B2 key model.
 *
 * The B2 credential pair is canonical (CONVENTIONS §7). The `connect*` arguments
 * are all optional at the schema level but are **jointly required by `create`**:
 * without a complete destination for the one-shot secret, `create` refuses to
 * run at all.
 */
const GlobalArgsSchema = z.object({
  applicationKeyId: z.string().describe(
    "B2 application key ID (master or scoped) used to authenticate this model.",
  ),
  applicationKey: z.string().meta({ sensitive: true }).describe(
    "B2 application key — supply via vault.get(), never inline.",
  ),
  authHost: z.string().url().optional().describe(
    "Override the B2 authorize host (testing only).",
  ),
  accountId: z.string().optional().describe(
    "B2 account ID. Optional — defaults to the accountId returned by " +
      "b2_authorize_account, which is correct for every normal setup.",
  ),
  managedKeyId: z.string().optional().describe(
    "applicationKeyId of the B2 key this model manages. Optional — `create` " +
      "mints a key and learns its ID; `sync` and `delete` require it.",
  ),
  maxKeyCount: z.number().int().min(1).max(10000).optional().describe(
    "Page size for b2_list_keys (B2 default 100, max 10000). Every list call " +
      "is a class C transaction, so prefer a large page over many pages.",
  ),
  connectHost: z.string().url().optional().describe(
    "1Password Connect base URL, e.g. http://connect.example.com:8080. " +
      "Required by `create` — it is the only outlet for the one-shot secret.",
  ),
  connectToken: z.string().meta({ sensitive: true }).optional().describe(
    "1Password Connect API token — supply via vault.get(), never inline. " +
      "Required by `create`.",
  ),
  connectVaultId: z.string().optional().describe(
    "UUID of the Connect-readable 1Password vault that receives the secret. " +
      "Either this or connectVaultTitle is required by `create`.",
  ),
  connectVaultTitle: z.string().optional().describe(
    "Title of the 1Password vault, resolved to a UUID when connectVaultId is " +
      "unset. Connect cannot read the built-in Private/Personal/Employee or " +
      "default Shared vaults.",
  ),
  connectItemTitle: z.string().optional().describe(
    "Title of the 1Password item that receives the key. Created if absent. " +
      "Required by `create` unless overridden per run with the itemTitle input.",
  ),
  connectItemCategory: z.string().default("API_CREDENTIAL").describe(
    "1Password category used when this model has to create the item.",
  ),
  connectKeyIdFieldLabel: z.string().default("applicationKeyId").describe(
    "Label of the item field that receives the non-secret applicationKeyId.",
  ),
  connectKeyFieldLabel: z.string().default("applicationKey").describe(
    "Label of the item field that receives the one-shot secret. Written as a " +
      "CONCEALED field.",
  ),
  connectTimeoutMs: z.number().int().positive().default(10000).describe(
    "Abort any single 1Password Connect call after this long.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Arguments for minting a new B2 application key (`b2_create_key`). */
const CreateArgsSchema = z.object({
  keyName: z.string().min(1).max(100).describe(
    "Name for the new key. B2 allows only letters, numbers and '-', max 100 " +
      "characters. Not unique and not an identifier — purely a label.",
  ),
  capabilities: z.array(z.string()).min(1).describe(
    "Capabilities granted to the new key, e.g. " +
      '["listBuckets","listFiles","readFiles","writeFiles","deleteFiles"]. ' +
      "A key can never be granted a capability its creator lacks.",
  ),
  bucketIds: z.array(z.string()).optional().describe(
    "v4 multi-bucket restriction: the new key may access only these buckets. " +
      "Plural — v4 removed the v2/v3 singular `bucketId`.",
  ),
  namePrefix: z.string().optional().describe(
    "Restrict the key to files whose names start with this prefix. Applies " +
      "across all buckets unless bucketIds is also given.",
  ),
  validDurationInSeconds: z.number().int().min(1).max(86400000).optional()
    .describe(
      "Expire the key after this many seconds (B2 max 86400000, ~1000 days). " +
        "Omit for a key that never expires.",
    ),
  itemTitle: z.string().optional().describe(
    "Override globalArgs.connectItemTitle for this run — the 1Password item " +
      "that receives the secret.",
  ),
  allowDuplicateName: z.boolean().default(false).describe(
    "Mint even when a key with this keyName already exists. B2 key names are " +
      "not unique, so re-running create otherwise silently orphans the " +
      "previous key: it stays live and billable while its secret is " +
      "overwritten in 1Password.",
  ),
});

/**
 * Snapshot schema for a B2 application key.
 *
 * Deliberately has **no** `applicationKey` field. B2 returns the secret exactly
 * once and swamp resources sync to a remote S3 datastore, so the secret must
 * never reach a snapshot. `secretDestination` records *where* the secret was
 * delivered, never the secret itself.
 */
const KeySchema = z.object({
  applicationKeyId: z.string().describe(
    "The key's ID — the real B2 identifier this resource is named after.",
  ),
  keyName: z.string().nullable().describe("Name assigned to the key."),
  capabilities: z.array(z.string()).nullable().describe(
    "Capabilities granted to the key.",
  ),
  bucketIds: z.array(z.string()).describe(
    "Buckets the key is restricted to (v4 plural). EMPTY means account-wide, " +
      "not unknown — b2_list_keys omits the field for an unrestricted key.",
  ),
  namePrefix: z.string().nullable().describe(
    "File-name prefix the key is restricted to, or null.",
  ),
  expirationTimestamp: z.number().nullable().describe(
    "Expiry in milliseconds since the epoch, or null when the key never " +
      "expires.",
  ),
  options: z.array(z.string()).nullable().describe(
    'B2-reserved option strings, e.g. "s3" when the key works with the ' +
      "S3-compatible API.",
  ),
  accountId: z.string().nullable().describe(
    "B2 account that owns the key.",
  ),
  status: z.string().describe(
    'Lifecycle status: "present" or "absent" (set after delete, or when ' +
      "sync cannot find the key).",
  ),
  secretDelivered: z.boolean().describe(
    "True when this key's one-shot secret was delivered to 1Password Connect. " +
      "A property of the KEY, not of the run: sync and delete carry the value " +
      "forward rather than resetting it, because neither observes delivery.",
  ),
  secretDestination: z.string().nullable().describe(
    "Where the secret was delivered (vault/item/field). Never contains the " +
      "secret itself. Carried forward by sync and delete — it is the only " +
      "durable pointer to the stored credential, and it stays after a revoke " +
      "so the orphaned item can still be found and cleaned up.",
  ),
  truncated: z.boolean().describe(
    'True when the b2_list_keys drain hit its page cap, so "not found" may ' +
      'mean "not found within the pages read" rather than "does not exist".',
  ),
  observedAt: z.string().describe(
    "Timestamp when this snapshot was taken (ISO 8601).",
  ),
});

// --- 1Password Connect client ----------------------------------------------
/** A fully-resolved destination for the one-shot secret. */
export type ConnectDestination = {
  host: string;
  token: string;
  vaultId?: string;
  vaultTitle?: string;
  itemTitle: string;
  itemCategory: string;
  keyIdFieldLabel: string;
  keyFieldLabel: string;
  timeoutMs: number;
};

/** A single field on a 1Password Connect item. */
export type ConnectField = {
  id: string;
  label?: string;
  value?: string;
  type?: string;
  purpose?: string;
  section?: { id: string };
};

/** A 1Password Connect item record. */
export type ConnectItem = {
  id: string;
  title: string;
  vault: { id: string };
  category: string;
  fields?: ConnectField[];
};

/**
 * Call 1Password Connect, surfacing its JSON error body rather than a bare
 * status.
 *
 * The bearer token is a secret: it goes in the header and never into a message.
 */
export async function connectFetch(
  d: ConnectDestination,
  path: string,
  init: RequestInit = {},
): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(`${d.host.replace(/\/+$/, "")}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${d.token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(init.headers ?? {}),
      },
      signal: AbortSignal.timeout(d.timeoutMs),
    });
  } catch (cause) {
    const reason = cause instanceof Error && cause.name === "TimeoutError"
      ? `timed out after ${d.timeoutMs}ms`
      : String(cause);
    throw new Error(
      `1Password Connect ${init.method ?? "GET"} ${path} failed: ${reason}`,
    );
  }
  const body = await res.text();
  if (!res.ok) {
    throw new Error(
      `1Password Connect ${
        init.method ?? "GET"
      } ${path} failed: ${res.status} ${body}`,
    );
  }
  return body ? JSON.parse(body) : null;
}

/**
 * Resolve the destination vault to a UUID.
 *
 * A `connectVaultId` is used as-is; otherwise `connectVaultTitle` is resolved
 * through Connect's SCIM-ish `title eq "..."` filter.
 */
export async function resolveConnectVaultId(
  d: ConnectDestination,
  logger: Logger,
): Promise<string> {
  if (d.vaultId) return d.vaultId;
  const filter = encodeURIComponent(`title eq "${d.vaultTitle}"`);
  const vaults = await connectFetch(d, `/v1/vaults?filter=${filter}`) as Array<
    { id: string }
  >;
  if (!Array.isArray(vaults) || vaults.length === 0) {
    throw new Error(
      `1Password vault "${d.vaultTitle}" not found, or the Connect token has ` +
        `no access to it. Connect cannot read the built-in ` +
        `Private/Personal/Employee or default Shared vaults.`,
    );
  }
  if (vaults.length > 1) {
    logger.warn("Multiple vaults titled {vault}; using the first", {
      vault: d.vaultTitle,
    });
  }
  return vaults[0].id;
}

/**
 * Fetch the destination item in full, or `null` when it does not exist yet.
 *
 * The list endpoint omits field values, so the matching item is re-fetched by
 * ID. The full field set matters: Connect's item update is a destructive
 * replace.
 */
export async function findConnectItem(
  d: ConnectDestination,
  vaultId: string,
  itemTitle: string,
): Promise<ConnectItem | null> {
  const filter = encodeURIComponent(`title eq "${itemTitle}"`);
  const items = await connectFetch(
    d,
    `/v1/vaults/${vaultId}/items?filter=${filter}`,
  ) as Array<{ id: string }>;
  if (!Array.isArray(items) || items.length === 0) return null;
  return await connectFetch(
    d,
    `/v1/vaults/${vaultId}/items/${items[0].id}`,
  ) as ConnectItem;
}

/**
 * Merge the key id and secret into an item's field set **without dropping any
 * existing field**.
 *
 * This is the whole point of the function. Connect's `PUT /v1/vaults/{vaultId}/
 * items/{itemId}` is a **destructive replace**: whatever field array is sent
 * becomes the item's entire field set, and every field omitted from the payload
 * is silently deleted. The Ansible `restic` role documents this exact trap. So
 * the caller must GET the item first and pass its complete `fields` array here;
 * this function returns that array with the two target labels updated in place
 * (preserving each field's `id`, `type`, `purpose` and `section`) and appends
 * only the labels that were genuinely absent.
 */
export function mergeSecretFields(
  existing: ConnectField[],
  keyIdLabel: string,
  keyIdValue: string,
  keyLabel: string,
  keyValue: string,
): ConnectField[] {
  const wanted = new Map<string, { value: string; type: string }>([
    [keyIdLabel, { value: keyIdValue, type: "STRING" }],
    [keyLabel, { value: keyValue, type: "CONCEALED" }],
  ]);
  // Every pre-existing field is carried through by spreading it, so unrelated
  // fields survive the replace untouched.
  const merged: ConnectField[] = existing.map((f) => {
    const hit = f.label !== undefined ? wanted.get(f.label) : undefined;
    if (!hit) return { ...f };
    wanted.delete(f.label as string);
    return { ...f, value: hit.value };
  });
  for (const [label, hit] of wanted) {
    merged.push({
      id: crypto.randomUUID(),
      label,
      type: hit.type,
      value: hit.value,
    });
  }
  return merged;
}

/**
 * Deliver the one-shot secret to 1Password Connect.
 *
 * Updates the item when it exists (full-field replace, see
 * {@link mergeSecretFields}) and creates it when it does not. Returns a
 * human-readable destination string that never contains the secret.
 */
export async function deliverSecret(
  d: ConnectDestination,
  vaultId: string,
  itemTitle: string,
  applicationKeyId: string,
  applicationKey: string,
): Promise<string> {
  const existing = await findConnectItem(d, vaultId, itemTitle);
  if (existing) {
    const updated = {
      ...existing,
      fields: mergeSecretFields(
        existing.fields ?? [],
        d.keyIdFieldLabel,
        applicationKeyId,
        d.keyFieldLabel,
        applicationKey,
      ),
    };
    await connectFetch(d, `/v1/vaults/${vaultId}/items/${existing.id}`, {
      method: "PUT",
      body: JSON.stringify(updated),
    });
    return `op://${vaultId}/${existing.id}/${d.keyFieldLabel}`;
  }
  const created = await connectFetch(d, `/v1/vaults/${vaultId}/items`, {
    method: "POST",
    body: JSON.stringify({
      title: itemTitle,
      category: d.itemCategory,
      vault: { id: vaultId },
      fields: mergeSecretFields(
        [],
        d.keyIdFieldLabel,
        applicationKeyId,
        d.keyFieldLabel,
        applicationKey,
      ),
    }),
  }) as { id?: string };
  return `op://${vaultId}/${created?.id ?? itemTitle}/${d.keyFieldLabel}`;
}

/**
 * Resolve a complete Connect destination, or throw.
 *
 * This is the **fail-closed gate**. `create` calls it before touching B2, so an
 * incomplete configuration costs nothing but an error message — as opposed to
 * minting a key whose secret is then unrecoverable.
 */
export function requireConnectDestination(
  g: GlobalArgs,
  itemTitleOverride?: string,
): ConnectDestination {
  const itemTitle = itemTitleOverride ?? g.connectItemTitle;
  const missing: string[] = [];
  if (!g.connectHost) missing.push("connectHost");
  if (!g.connectToken) missing.push("connectToken");
  if (!g.connectVaultId && !g.connectVaultTitle) {
    missing.push("connectVaultId (or connectVaultTitle)");
  }
  if (!itemTitle) missing.push("connectItemTitle (or the itemTitle input)");
  if (missing.length > 0) {
    throw new Error(
      `Refusing to mint a B2 application key: no destination is configured ` +
        `for the one-shot secret (missing ${missing.join(", ")}). ` +
        `B2 returns the applicationKey exactly once, in the b2_create_key ` +
        `response, and it can never be retrieved again — so a key minted with ` +
        `nowhere to put the secret is a key nobody can ever use and which must ` +
        `immediately be revoked. This model will not mint and discard, and it ` +
        `will not print the secret to a log. Configure the 1Password Connect ` +
        `global arguments and re-run.`,
    );
  }
  return {
    host: g.connectHost as string,
    token: g.connectToken as string,
    vaultId: g.connectVaultId,
    vaultTitle: g.connectVaultTitle,
    itemTitle: itemTitle as string,
    itemCategory: g.connectItemCategory,
    keyIdFieldLabel: g.connectKeyIdFieldLabel,
    keyFieldLabel: g.connectKeyFieldLabel,
    timeoutMs: g.connectTimeoutMs,
  };
}

// --- B2 key helpers ---------------------------------------------------------
/** A raw key record as returned by b2_list_keys / b2_create_key. */
type RawKey = Record<string, unknown>;

/**
 * Map a raw B2 key record to a snapshot.
 *
 * SECRET HYGIENE: `applicationKey` is never read from `k`, so even a response
 * that carries the secret (which `b2_create_key` does) cannot leak it into a
 * snapshot. The mapper is the single choke point for this guarantee.
 */
/**
 * Normalize a raw key's bucket restriction to an array.
 *
 * Mirrors `b2-account`, so both models describe the same key identically.
 * B2 omits `bucketIds` entirely for an unrestricted key, and `b2_list_keys` has
 * no "unknown" case — absent means account-wide. Encoding that as `null` forced
 * every consumer to handle two shapes for one fact, and made
 * `bucketIds.length === 0` (the natural test for account-wide) throw.
 *
 * v4 removed the scalar `bucketId`, but a stale or proxied response carrying it
 * is degraded to a one-element array rather than dropped: silently reporting a
 * bucket-scoped key as account-wide would misstate its blast radius.
 */
export function normalizeBucketIds(k: RawKey): string[] {
  const plural = (k as Record<string, unknown>).bucketIds;
  if (Array.isArray(plural)) return plural as string[];
  const legacySingular = (k as Record<string, unknown>).bucketId;
  if (typeof legacySingular === "string" && legacySingular !== "") {
    return [legacySingular];
  }
  return [];
}

/**
 * Read what a previous run recorded about this key's secret delivery.
 *
 * `sync` and `delete` observe nothing about delivery — B2 cannot tell you where
 * a secret was filed — so they must not assert anything about it. Writing
 * `secretDestination: null` from a read-only sync destroyed the only durable
 * pointer to the stored credential, and since `data.latest()` returns the most
 * recent snapshot, a routine sync made a delivered key look undelivered.
 *
 * Same rule as everywhere else in this suite: never encode "I did not look" as
 * "it is not there". Returns the not-delivered defaults when there is no prior
 * snapshot, which is the honest answer for a key this repo has never minted.
 */
export async function loadPriorDelivery(
  context: {
    readResource?: (
      instanceName: string,
      version?: number,
    ) => Promise<Record<string, unknown> | null>;
  },
  keyId: string,
): Promise<{ secretDelivered: boolean; secretDestination: string | null }> {
  const none = { secretDelivered: false, secretDestination: null };
  if (!context.readResource) return none;
  try {
    const prior = await context.readResource(keyId);
    if (!prior) return none;
    return {
      secretDelivered: prior.secretDelivered === true,
      secretDestination: typeof prior.secretDestination === "string"
        ? prior.secretDestination
        : null,
    };
  } catch {
    // An unreadable prior snapshot is not evidence of anything either way.
    return none;
  }
}

export function toKeyResource(
  k: RawKey,
  extra: {
    status: string;
    secretDelivered: boolean;
    secretDestination: string | null;
    truncated: boolean;
    observedAt: string;
    fallbackKeyId?: string;
  },
): Record<string, unknown> {
  return {
    applicationKeyId: (k.applicationKeyId as string) ?? extra.fallbackKeyId ??
      "",
    keyName: (k.keyName as string) ?? null,
    capabilities: (k.capabilities as string[]) ?? null,
    bucketIds: normalizeBucketIds(k),
    namePrefix: (k.namePrefix as string) ?? null,
    expirationTimestamp: (k.expirationTimestamp as number) ?? null,
    options: (k.options as string[]) ?? null,
    accountId: (k.accountId as string) ?? null,
    status: extra.status,
    secretDelivered: extra.secretDelivered,
    secretDestination: extra.secretDestination,
    truncated: extra.truncated,
    observedAt: extra.observedAt,
  };
}

/**
 * Decide whether a `b2_delete_key` failure means the key was already gone.
 *
 * B2 documents no `404` and no dedicated "key not found" code for
 * `b2_delete_key` — a missing key surfaces as a generic `400 bad_request`.
 * Treating every `400 bad_request` as success would swallow genuinely
 * malformed requests, so this only accepts codes that unambiguously name a
 * missing key. Real idempotency comes from `delete` verifying existence with
 * `b2_list_keys` first; this handles only the narrow race where the key
 * disappears between that check and the delete.
 */
export function isAlreadyGone(e: unknown): boolean {
  const err = e as { status?: number; b2Code?: string };
  if (err?.status === 404) return true;
  const gone = ["key_not_found", "no_such_key", "bad_key_id"];
  return err?.status === 400 && gone.includes(err?.b2Code ?? "");
}

/** Fetch every application key on the account (class C — one call per page). */
async function listKeys(
  auth: B2Auth,
  g: GlobalArgs,
  reauth: () => Promise<B2Auth>,
): Promise<{ items: RawKey[]; truncated: boolean }> {
  // b2_list_keys is documented as GET in v4 but still accepts an equivalent
  // POST with a JSON body, which is what the canonical b2ListAll drain sends.
  // Its cursor is `nextApplicationKeyId` -> `startApplicationKeyId`, exactly the
  // next*/start* convention b2ListAll relies on.
  const payload: Record<string, unknown> = {
    accountId: g.accountId ?? auth.accountId,
  };
  if (g.maxKeyCount !== undefined) payload.maxKeyCount = g.maxKeyCount;
  return await b2ListAll<RawKey>(
    auth,
    "b2_list_keys",
    payload,
    "keys",
    50,
    reauth,
  );
}

/** Resolve the managed key ID for methods that act on an existing key. */
function requireManagedKeyId(g: GlobalArgs, method: string): string {
  if (!g.managedKeyId) {
    throw new Error(
      `The "${method}" method requires globalArgs.managedKeyId — the ` +
        `applicationKeyId of an existing B2 application key. Set managedKeyId ` +
        `on the model, or run "create" first to mint one.`,
    );
  }
  return g.managedKeyId;
}

/** Build a credential bundle plus a matching reauthorize closure. */
function authorizer(
  g: GlobalArgs,
): { authorize: () => Promise<B2Auth> } {
  const creds: B2Credentials = {
    applicationKeyId: g.applicationKeyId,
    applicationKey: g.applicationKey,
    authHost: g.authHost,
  };
  return { authorize: () => b2Authorize(creds) };
}

// --- Model -----------------------------------------------------------------
/**
 * Model type `@sntxrr/b2/key`.
 *
 * Manages one Backblaze B2 application key, keyed by its real
 * `applicationKeyId`. `create` mints a key and delivers the one-shot secret to
 * 1Password Connect, or refuses to mint at all.
 *
 * @example
 * ```bash
 * swamp model create @sntxrr/b2/key restic-backups \
 *   --global-arg 'applicationKeyId=${{ vault.get(b2, B2_APPLICATION_KEY_ID) }}' \
 *   --global-arg 'applicationKey=${{ vault.get(b2, B2_APPLICATION_KEY) }}'
 * swamp model @sntxrr/b2/key method run sync restic-backups
 * ```
 */
export const model = {
  type: "@sntxrr/b2/key",
  description:
    "Manage a Backblaze B2 application key via the Native API v4 — sync, create (with the one-shot secret delivered to 1Password Connect), and idempotent delete",
  version: "2026.08.05.3",
  globalArguments: GlobalArgsSchema,
  resources: {
    "key": {
      description:
        "Metadata snapshot of a B2 application key. Never contains the applicationKey secret",
      schema: KeySchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  checks: {
    "secret-destination-configured": {
      description:
        "A B2 key mint must have somewhere to put its one-shot secret: the 1Password Connect global arguments must be complete.",
      labels: ["policy"],
      appliesTo: ["create"],
      execute: (
        context: { globalArgs: GlobalArgs },
      ): { pass: boolean; errors?: string[] } => {
        try {
          // The per-run itemTitle input is invisible to checks, so accept
          // either source here; `create` re-validates authoritatively.
          requireConnectDestination(
            context.globalArgs,
            context.globalArgs.connectItemTitle ?? "__from-input__",
          );
          return { pass: true };
        } catch (e) {
          return { pass: false, errors: [(e as Error).message] };
        }
      },
    },
    "connect-reachable": {
      description:
        "The 1Password Connect server must answer and expose the destination vault before a key is minted.",
      labels: ["live"],
      appliesTo: ["create"],
      execute: async (
        context: { globalArgs: GlobalArgs; logger: Logger },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const g = context.globalArgs;
        if (!g.connectHost || !g.connectToken) {
          // Nothing to reach; secret-destination-configured already fails.
          return { pass: true };
        }
        try {
          const d = requireConnectDestination(
            g,
            g.connectItemTitle ?? "__from-input__",
          );
          await resolveConnectVaultId(d, context.logger);
          return { pass: true };
        } catch (e) {
          return { pass: false, errors: [(e as Error).message] };
        }
      },
    },
  },
  methods: {
    sync: {
      description:
        "Locate the managed key with b2_list_keys and snapshot its metadata.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const keyId = requireManagedKeyId(g, "sync");
        const { authorize } = authorizer(g);
        const auth = await authorize();
        logger.info("Syncing B2 application key {keyId}", { keyId });
        const { items, truncated } = await listKeys(auth, g, authorize);
        const found = items.find((k) => k.applicationKeyId === keyId);
        const observedAt = new Date().toISOString();
        if (!found && truncated) {
          // A truncated drain that did not find the key cannot distinguish
          // "absent" from "beyond the page cap" — say so rather than lie.
          logger.warn(
            'b2_list_keys hit the page cap without finding {keyId}; "absent" is not proven',
            { keyId },
          );
        }
        const priorDelivery = await loadPriorDelivery(context, keyId);
        const handle = await context.writeResource(
          "key",
          keyId,
          toKeyResource(found ?? {}, {
            status: found ? "present" : "absent",
            secretDelivered: priorDelivery.secretDelivered,
            secretDestination: priorDelivery.secretDestination,
            truncated,
            observedAt,
            fallbackKeyId: keyId,
          }),
        );
        logger.info("Synced B2 application key {keyId} (present={present})", {
          keyId,
          present: Boolean(found),
        });
        return { dataHandles: [handle] };
      },
    },
    create: {
      description:
        "Mint a B2 application key (b2_create_key) and deliver its one-shot secret to 1Password Connect. Refuses to mint when no destination is configured.",
      arguments: CreateArgsSchema,
      execute: async (
        args: z.infer<typeof CreateArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;

        // 1. Fail closed BEFORE any B2 call. Checks can be bypassed with
        //    --skip-checks, so this guard — not the check — is authoritative.
        const destination = requireConnectDestination(g, args.itemTitle);

        if (!/^[A-Za-z0-9-]+$/.test(args.keyName)) {
          throw new Error(
            `Invalid keyName "${args.keyName}": B2 allows only letters, ` +
              `numbers and "-" (max 100 characters).`,
          );
        }
        const unknown = args.capabilities.filter((c) =>
          !B2_CAPABILITIES.includes(c)
        );
        if (unknown.length > 0) {
          logger.warn(
            "Capabilities not in the known B2 vocabulary: {unknown}. B2 will reject a typo with 400 bad_request.",
            { unknown: unknown.join(", ") },
          );
        }

        // 2. Prove the secret's destination is reachable before minting. If
        //    Connect is down, the run fails here having created nothing.
        const vaultId = await resolveConnectVaultId(destination, logger);

        const { authorize } = authorizer(g);
        const auth = await authorize();

        // B2 key names are NOT unique and NOT identifiers. Minting a second key
        // with the same name overwrites the 1Password field, leaving the first
        // key live, billable and unreachable. Refuse unless asked explicitly.
        let clashScanTruncated = false;
        if (!args.allowDuplicateName) {
          const { items, truncated } = await listKeys(auth, g, authorize);
          clashScanTruncated = truncated;
          if (truncated) {
            // A capped drain cannot prove the absence of a clash. Say so and
            // carry it into the snapshot rather than implying a clean check.
            logger.warn(
              "b2_list_keys hit its page cap during the name-clash check; a duplicate {keyName} may exist beyond it",
              { keyName: args.keyName },
            );
          }
          const clashes = items
            .filter((k) => k.keyName === args.keyName)
            .map((k) => k.applicationKeyId as string);
          if (clashes.length > 0) {
            throw new Error(
              `A B2 application key named "${args.keyName}" already exists ` +
                `(${clashes.join(", ")}). B2 key names are not unique, so ` +
                `minting another would overwrite the secret in 1Password and ` +
                `leave the existing key live and unreachable. Revoke the old ` +
                `key first, or pass allowDuplicateName=true if two keys are ` +
                `genuinely intended.`,
            );
          }
        }

        const payload: Record<string, unknown> = {
          accountId: g.accountId ?? auth.accountId,
          keyName: args.keyName,
          capabilities: args.capabilities,
        };
        // v4 takes `bucketIds` (plural array). The singular `bucketId` of
        // v2/v3 was removed and is silently ignored if sent.
        if (args.bucketIds !== undefined) payload.bucketIds = args.bucketIds;
        if (args.namePrefix !== undefined) payload.namePrefix = args.namePrefix;
        if (args.validDurationInSeconds !== undefined) {
          payload.validDurationInSeconds = args.validDurationInSeconds;
        }

        logger.info("Minting B2 application key {keyName}", {
          keyName: args.keyName,
        });
        // A 401 here is a missing `writeKeys` capability, or an attempt to
        // grant a capability the creating key lacks. b2Fetch never retries a
        // 401 that is not `expired_auth_token`, which is correct: it is a
        // permanent authorization failure, not a transient one.
        const created = await b2Fetch<RawKey>(
          auth,
          "POST",
          "b2_create_key",
          payload,
          authorize,
        );

        const newKeyId = created.applicationKeyId as string | undefined;
        const secret = created.applicationKey as string | undefined;
        if (!newKeyId || !secret) {
          throw new Error(
            "b2_create_key returned no applicationKeyId/applicationKey. The " +
              "key may exist without its secret having been captured — list " +
              "your keys and revoke any unexpected key immediately.",
          );
        }

        // 3. Deliver the secret. Never logged, never snapshotted.
        let destinationRef: string;
        try {
          destinationRef = await deliverSecret(
            destination,
            vaultId,
            destination.itemTitle,
            newKeyId,
            secret,
          );
        } catch (e) {
          // The key now exists in B2 with an unrecoverable secret. Record it
          // before failing: an orphaned credential that only ever appeared in
          // an error string is one nobody finds again. The snapshot is honest
          // about the delivery having failed, and the run still fails.
          await context.writeResource(
            "key",
            newKeyId,
            toKeyResource(created, {
              status: "present",
              secretDelivered: false,
              secretDestination: null,
              truncated: clashScanTruncated,
              observedAt: new Date().toISOString(),
            }),
          );
          throw new Error(
            `B2 key ${newKeyId} was minted but its one-shot secret could NOT ` +
              `be written to 1Password Connect: ${(e as Error).message}. The ` +
              `secret is now unrecoverable — revoke this key immediately ` +
              `("delete" with managedKeyId=${newKeyId}) and re-run. The key ` +
              `has been recorded with secretDelivered=false so it is not lost.`,
          );
        }

        const handle = await context.writeResource(
          "key",
          newKeyId,
          toKeyResource(created, {
            status: "present",
            secretDelivered: true,
            secretDestination: destinationRef,
            truncated: clashScanTruncated,
            observedAt: new Date().toISOString(),
          }),
        );
        logger.info(
          "Minted B2 application key {keyId}; secret delivered to 1Password",
          { keyId: newKeyId },
        );
        return { dataHandles: [handle] };
      },
    },
    delete: {
      description:
        "Revoke the managed B2 application key (b2_delete_key). Idempotent — an already-absent key is success.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs: g, logger } = context;
        const keyId = requireManagedKeyId(g, "delete");
        const { authorize } = authorizer(g);
        const auth = await authorize();

        // Verify the ID first (CONVENTIONS §3). This is also what makes delete
        // genuinely idempotent: B2 documents no "key not found" error code for
        // b2_delete_key, so existence cannot be inferred reliably from the
        // failure alone.
        const { items, truncated } = await listKeys(auth, g, authorize);
        const found = items.find((k) => k.applicationKeyId === keyId);

        let deleted: RawKey = found ?? {};
        // Whether THIS run performed the revocation. The end state is "absent"
        // either way, so an `absent` flag would convey nothing; what an
        // operator needs from the completion log is whether the key was still
        // live a moment ago.
        let revoked = false;
        if (!found) {
          if (truncated) {
            throw new Error(
              `b2_list_keys hit its page cap before finding ${keyId}, so the ` +
                `key cannot be confirmed absent. Raise maxKeyCount and re-run ` +
                `rather than assume it is already gone.`,
            );
          }
          logger.info("B2 application key {keyId} is already absent", {
            keyId,
          });
        } else {
          logger.info("Revoking B2 application key {keyId}", { keyId });
          try {
            deleted = await b2Fetch<RawKey>(
              auth,
              "POST",
              "b2_delete_key",
              { applicationKeyId: keyId },
              authorize,
            );
            revoked = true;
          } catch (e) {
            // Narrow race: the key vanished between the list and the delete.
            if (!isAlreadyGone(e)) throw e;
            logger.info(
              "B2 application key {keyId} disappeared before the delete landed",
              { keyId },
            );
            deleted = found;
          }
        }

        const priorDelivery = await loadPriorDelivery(context, keyId);
        const handle = await context.writeResource(
          "key",
          keyId,
          toKeyResource(deleted, {
            status: "absent",
            secretDelivered: priorDelivery.secretDelivered,
            secretDestination: priorDelivery.secretDestination,
            truncated,
            observedAt: new Date().toISOString(),
            fallbackKeyId: keyId,
          }),
        );
        logger.info(
          "B2 application key {keyId} is absent (revoked={revoked})",
          {
            keyId,
            revoked,
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};

/** Internal helpers exported only for unit testing. */
export const _internal = {
  authorizer,
  listKeys,
  requireManagedKeyId,
};
