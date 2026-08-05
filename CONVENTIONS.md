# CONVENTIONS — Backblaze B2 Extension Suite

**Lead-owned. Builders read this, copy from it, and propose changes via the lead
— never edit it directly.** Single source of truth for the shared technical
contract in [`PRD.md`](./PRD.md). If the PRD and this file disagree, this file
wins for _implementation_ detail; the PRD wins for _scope_.

Derived from the working precedent `../scaleway/CONVENTIONS.md` and
`../scaleway/extensions/models/scaleway-instance/` (single service wrapped with
an inline authed HTTP client, no SDK). Study those alongside this doc.

---

## 1. How a builder uses this doc

1. Pick one model row from [`PRD.md`](./PRD.md) §4.
2. Create your extension's **own directory**:
   `extensions/models/b2-<domain>/`.
3. Copy the **canonical B2 client (§5) byte-identical** — do not "improve" it
   per-model; a change is a lead-driven sweep across all models. The §5 block is
   kept `deno fmt`-clean so that copying it byte-identical and passing
   `swamp extension fmt --check` are compatible. If `fmt` ever wants to reformat
   it, that is a lead bug — report it, do not silently reformat your copy, or
   the models drift apart.
4. Fill in schemas, operation names (from §4 + the live B2 docs), and methods
   (§3 taxonomy).
5. Copy the test template to `b2_<domain>_test.ts` in the same dir; mock
   `fetch`.
6. Copy the manifest / README / LICENSE templates (§8) into the same dir.
7. Run the verification + publish sequence (§9), including the Adversarial
   Review Gate.

**Layout — one isolated directory per extension (mandatory):**

```
extensions/models/b2-<domain>/
  b2_<domain>.ts        # export const model  (discovered via extensions/models/**/*.ts)
  b2_<domain>_test.ts   # unit tests (excluded from loading)
  manifest.yaml         # paths.base: manifest  → paths resolve to THIS dir
  README.md             # per-extension docs (additionalFiles)
  LICENSE.md            # MIT (additionalFiles)
```

**File ownership:** a builder touches **only files inside its own
`extensions/models/b2-<domain>/` directory.** No builder edits another's files,
`CONVENTIONS.md`, `PRD.md`, or the root `README.md` (all lead-owned). This makes
all builders fully parallel with zero merge contention.

---

## 2. Hard rules (non-negotiable)

- `import { z } from "npm:zod@4";` — **never** bare `"zod"`. The swamp-club
  scorer runs in a hermetic sandbox with no imports map.
- Static imports only; **no** dynamic `import()` (rejected at push).
- Deno-native only: `fetch` + Web Crypto. **No npm deps** beyond zod.
- **Never hardcode a secret.** `applicationKey` is `.meta({ sensitive: true })`
  and wired from a vault. **Never write a secret, an `authorizationToken`, or a
  `Basic` header into a resource snapshot or a log line.** B2 auth tokens are
  bearer credentials valid for 24h — they are secrets.
- Explicit return types on `execute` and every exported function.
- JSDoc on the module, every exported symbol, and each schema field via
  `.describe(...)` (drives the ≥80% JSDoc quality factor).
- Type string: `@sntxrr/b2/<domain>`. `swamp`/`si` collectives are reserved.
- **Never key a resource as the literal `"latest"`** — it is a reserved data
  name and fails at run time only, not at validation. Key by the object's real
  B2 identifier (`bucketName`, `applicationKeyId`, `fileId`).
- **Instance names must be unique across ALL specs, not just within one.**
  Instance names map onto storage paths, so two specs writing the same instance
  name silently clobber each other on disk. This bit the `b2-bucket` build:
  `sync` and `get_notification_rules` both keyed on the bare `bucketName`, so
  the notification snapshot overwrote the bucket snapshot. **When a model has
  more than one spec, prefix the instance name with the spec** — e.g.
  `notification-rules-<bucketName>`. Confirmed in the swamp model API reference;
  the adversarial review's Mechanical Verification catches it if you don't.

---

## 3. Method taxonomy

Name methods from this fixed vocabulary so every B2 model feels identical:

| Method   | Semantics                                                                                                                  |
| -------- | -------------------------------------------------------------------------------------------------------------------------- |
| `scan`   | **Factory** discovery: one method fans out and writes many snapshots. Never loop `run` N times (per-model lock contention). |
| `sync`   | Read current state of the one resource this model manages. Idempotent.                                                     |
| `create` | Provision; write a snapshot including the new ID.                                                                          |
| `update` | Mutate mutable fields.                                                                                                     |
| `delete` | Deprovision. Verify the ID first.                                                                                          |

**Pre-flight `checks`** auto-run only before methods **named**
`create`/`update`/`delete`/`action`. Name any mutating method with one of those
verbs or its pre-flight will not fire. Add at least one labeled
(`["policy"]` / `["live"]`) check. Checks receive `globalArgs` but **no**
`writeResource`.

**Idempotent `delete`:** `b2Fetch` throws an `Error & { status, b2Code }`.
Treat a `404`, or a `400` with `b2Code` in `{ bad_bucket_id, file_not_present,
no_such_file }`, as success (already gone), then write a snapshot marking the
resource absent.

---

## 4. Auth & the v4 response shape (READ THIS — v2/v3 examples online are wrong)

**Authorize:** `GET https://api.backblazeb2.com/b2api/v4/b2_authorize_account`
with header `Authorization: Basic base64(applicationKeyId:applicationKey)`.

**The v4 response nests everything under `apiInfo.storageApi`:**

```jsonc
{
  "accountId": "...",
  "authorizationToken": "...",            // bearer token, 24h, SECRET
  "applicationKeyExpirationTimestamp": null,
  "apiInfo": {
    "storageApi": {
      "apiUrl": "https://apiNNN.backblazeb2.com",   // cluster-specific — NEVER hardcode
      "downloadUrl": "https://fNNN.backblazeb2.com",
      "s3ApiUrl": "https://s3.us-west-002.backblazeb2.com",
      "recommendedPartSize": 100000000,
      "absoluteMinimumPartSize": 5000000,
      "allowed": {
        "buckets": [{ "id": "...", "name": "..." }],  // ARRAY in v4
        "capabilities": ["listBuckets", "readFiles", ...],
        "namePrefix": null
      }
    },
    "groupsApi": { "groupsApiUrl": "...", "capabilities": [...] }
  }
}
```

Two traps that will bite you if you follow older examples:

1. **`apiUrl` is cluster-specific and lives under `apiInfo.storageApi`.** All
   subsequent calls go to `${apiUrl}/b2api/v4/<op>`, never to
   `api.backblazeb2.com`. Only `b2_authorize_account` uses the well-known host.
2. **`allowed.buckets` is an array.** v2 had scalar `bucketId` / `bucketName`
   for single-bucket keys; v4 removed them. Code reading `allowed.bucketId`
   silently gets `undefined`. A bucket-scoped key appears as a one-element
   array — which is exactly what our per-host restic keys look like.

**Calling convention:** most operations are `POST` with a JSON body. A few are
`GET` with query parameters (`b2_authorize_account`,
`b2_get_bucket_notification_rules`, the download operations). `b2Fetch` handles
both — pass the method explicitly.

**Response-shape corrections verified against live docs during the wave-1 build.
Trust these over the prose above and over any older example:**

1. **`bucketIds` is plural** on `b2_list_keys` / `b2_create_key`. Confirmed.
2. **`b2_list_buckets` returns `bucketInfo`** — arbitrary user metadata, easy to
   overlook. Capture it, but **warn in your README that it lands verbatim in a
   synced resource snapshot**, so it must never hold credentials.
3. **THREE fields are wrapped**, not two — `fileLockConfiguration`,
   `defaultServerSideEncryption`, **and `replicationConfiguration`**. Confirmed
   against a live account 2026-08-05. Each arrives as
   `{ isClientAuthorizedToRead: boolean, value: object | null }`, and `value` is
   nulled out when the calling key lacks the capability to read it. Model the
   wrapper, and never treat a `null` `value` as "feature disabled" — it may mean
   "not authorized to see it", which is a different fact entirely.
4. **`bucketId` (singular) is REMOVED in v4**, not merely deprecated — on
   `b2_create_key` and `b2_list_keys` it is `bucketIds` (plural) in both request
   and response. Relatedly, **`namePrefix` no longer requires a bucket
   restriction** in v4; unrestricted, it applies across all buckets. B2's own
   prose is internally inconsistent here and still references the removed
   `bucketId` — trust the v4 changelog, not the field description.
5. **`b2_list_keys` is documented as GET in v4** (query params), but POST with a
   JSON body **is still accepted — verified live 2026-08-05**, when a real
   `account.scan` drained all 23 keys of a production account through the
   POST-only `b2ListAll`. This was the suite's one unverified external contract;
   it is now closed. Re-check it if B2 ever announces a v4 breaking change,
   because `b2-account scan` and `b2-key sync`/`create`/`delete` would all fail
   together.
6. **`defaultRetention` is an object, not a string:**
   `{ mode: "governance" | "compliance" | null, period: { duration, unit } }`.
   Backblaze's own API-docs summary renders it as `string`, which is wrong.
7. **There is no documented "key not found" error for `b2_delete_key`** — the
   error table lists only `bad_bucket_id`, `bad_request`, and three 401s. So the
   already-gone code list above does **not** cover keys, and treating a generic
   `400 bad_request` as "already gone" would swallow real request bugs. Verify
   the key exists via `b2_list_keys` first (which means `delete` needs `listKeys`
   as well as `deleteKeys`) and use narrow code matching only as a race fallback.
8. **B2 key names are neither unique nor identifiers.** Re-running a create with
   the same `keyName` mints a *second* live key rather than updating the first —
   and if the secret destination is overwritten, the original stays live and
   becomes unreachable. Refuse a name clash by default; require an explicit
   override to proceed.
9. **The four nested config blobs — `lifecycleRules`, `corsRules`,
   `fileLockConfiguration`, `defaultServerSideEncryption` — are typed
   `z.unknown()` in wave 1.** The live docs contradict themselves on
   array-vs-object for `lifecycleRules`, and a wrong structural type fails
   `writeResource` on a live scan whereas `z.unknown()` cannot. Cost: CEL cannot
   introspect inside them.

   **Live-scan update (2026-08-05):** a real `scan` over 24 buckets confirms
   `lifecycleRules` and `corsRules` serialize as **arrays**, so the
   array-vs-object ambiguity is settled. But every bucket in that account
   returned `[]`, so the **element** shape is still unobserved — do not
   structurally type the elements until a bucket that actually has a rule has
   been scanned. Typing the container as an array is now safe.

**Transaction cost classes** (this is real money, design against it):

| Class | Operations                                                    | Note                          |
| ----- | ------------------------------------------------------------- | ----------------------------- |
| A     | uploads, `b2_delete_file_version`, `b2_cancel_large_file`      | free                          |
| B     | `b2_download_*`, `b2_get_file_info`                            | cheap                         |
| C     | **all `b2_list_*`**, `b2_create_*`, `b2_authorize_account`     | billed per 1000 — the tier that hurts |

Every `list` is class C. A nightly full scan across 14 restic buckets is a
recurring bill. Prefer aggregate results over per-object enumeration, cap page
counts, and never enumerate a restic bucket's pack files by default.

---

## 5. Canonical B2 client (copy byte-identical)

```typescript
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
```

**Notes on the client**

- `b2_list_buckets` returns every bucket in one response with **no** cursor —
  call `b2Fetch` directly, not `b2ListAll`.
- `truncated: true` means `maxPages` was hit. **Always surface this in the
  resource snapshot**; a silently truncated inventory reads as "nothing else
  exists", which is the failure mode that makes an audit lie.
- Pass `reauth` whenever a run may exceed 24h or reuse a cached auth.

---

## 6. Shared context types (copy byte-identical)

```typescript
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
```

Method `execute` signature is always
`(args, context): Promise<{ dataHandles: Array<{ name: string }> }>`.

---

## 7. Credentials & global arguments

Every model takes the same credential pair, wired from a vault — never inline:

```typescript
const GlobalArgsSchema = z.object({
  applicationKeyId: z.string().describe(
    "B2 application key ID (master or scoped)",
  ),
  applicationKey: z.string().meta({ sensitive: true }).describe(
    "B2 application key — supply via vault.get(), never inline",
  ),
  authHost: z.string().url().optional().describe(
    "Override the B2 authorize host (testing only)",
  ),
});
```

Sourced from `@sntxrr/1password-connect` (built in parallel, see
`../1password-connect/`), which reads 1Password Connect over plain HTTP and so
works headless — in cron, in containers, under `swamp serve`. Until it lands,
smoke-test with `${{ env.B2_APPLICATION_KEY }}`.

**Capability requirements differ per model.** State the required B2 capabilities
in your README — e.g. `listBuckets` for `scan`, `writeKeys` for `key.create`,
`readBucketNotifications` for notification rules. A scoped key that lacks a
capability fails with `401 unauthorized`, which is *not* transient; do not
retry it.

---

## 8. Manifest / README / LICENSE templates

```yaml
manifestVersion: 1

name: "@sntxrr/b2-<domain>"
version: "2026.08.05.1" # use: swamp extension version --manifest <file> --json
description: "<one sentence: what it manages, which API, which methods>."
repository: "https://github.com/sntxrr/swamp-backblaze"

paths:
  base: manifest

models:
  - b2_<domain>.ts

additionalFiles:
  - README.md
  - LICENSE.md

labels:
  - backblaze
  - b2
  - storage
  - <keywords>
```

- **README.md** (per extension, `additionalFiles`): purpose, method table,
  required B2 capabilities, the `swamp vault` + `swamp model create`
  quick-start, development commands, license line.
- **LICENSE.md**: MIT. Copy `../../../LICENSE.md`.
- **Published-surface hygiene:** in READMEs and test fixtures use `example.com`
  and RFC 5737 IPs (`192.0.2.x` / `198.51.100.x` / `203.0.113.x`). Never a real
  bucket name, account ID, key ID, or hostname from the homelab. Fake B2 IDs
  should look like `4a48fe8875c6214145260818` but must not be real.

---

## 9. Verify → review → publish sequence

```bash
DENO=~/.swamp/deno/deno   # or: swamp doctor extensions --json | jq -r .denoPath
DIR=extensions/models/b2-<domain>

# 1. Type-check + test
$DENO check "$DIR/b2_<domain>.ts"
$DENO test  "$DIR/b2_<domain>_test.ts"

# 2. Confirm it registers
swamp model type search b2 --json

# 3. Smoke test (read-only scan/sync first) — see the swamp skill:
#    references/model/smoke_testing.md

# 4. Format + quality (target >= 14/15)
swamp extension fmt     "$DIR/manifest.yaml" --check
swamp extension quality "$DIR/manifest.yaml" --json

# 5. Adversarial Review Gate (REQUIRED before push)
swamp extension push "$DIR/manifest.yaml" --dry-run

# 6. Publish — lead runs this, not builders.
```

Never `--yes` past the review gate. Editing source or bumping the version
invalidates the report — regenerate it.

**Keep review reports in the repo, not in system temp.** The report path is
bound to a content hash, and by default it lands under the OS temp directory,
where it is one cleanup away from vanishing — which is precisely how b2-bucket's
report went missing after its fixes landed. Point the base directory at
`backblaze/reviews/` instead, and the reports survive:

```bash
export SWAMP_EXTENSION_REVIEW_DIR="$PWD/reviews"
swamp extension push "$DIR/manifest.yaml" --dry-run
```

Note the tool appends its own `swamp-extension-review/` subdirectory to that
base, so the file lands at `reviews/swamp-extension-review/<hash>.json`. Write
the report to the exact path the warning prints — do not guess it.

Run the four mechanical checks by **execution**, not by reading: import the
model, run every method against a mocked `fetch`, and diff each spec's schema
keys against the keys actually written. Judgment-based review has missed this
class of defect in this suite every time.

**Builders stop after step 5** and report back. The lead publishes.

---

## 10. Testing

Mock `fetch` — no live B2 calls in unit tests. Cover at minimum:

1. `b2Authorize` parses the **nested v4 shape** and an `allowed.buckets` array
   (including the `null` → `[]` case).
2. Cursor pagination: a two-page response drains and concatenates, and
   `next*` → `start*` renaming is correct.
3. `maxPages` exhaustion sets `truncated: true`.
4. `401 expired_auth_token` triggers exactly one re-authorization.
5. `429` with `Retry-After` retries; a non-transient `400` throws with
   `b2Code` populated.
6. `delete` treats "already gone" as success.
7. **No secret leaks:** assert that no resource snapshot your model writes
   contains `applicationKey` or `authorizationToken`.

### 10.1 The `writeResource` stub MUST validate (non-negotiable)

A stub that only records what it was handed proves nothing about it. Every bug
mechanical review has found in this suite lived in a **derived** field — the raw
B2 data was correct in every single case — and a recording-only stub is blind to
exactly that class of bug. This is not hypothetical: reverting a genuine
`corsRules` mapper fix in `b2-bucket` left all 47 tests green.

So the harness must parse each write against the real spec schema, the way swamp
does at run time:

```ts
writeResource: (spec, name, data) => {
  const resourceSpec =
    (model.resources as Record<string, { schema: z.ZodType }>)[spec];
  if (!resourceSpec) {
    throw new Error(`writeResource called with unknown spec "${spec}"`);
  }
  const parsed = resourceSpec.schema.safeParse(data);
  if (!parsed.success) {
    throw new Error(
      `writeResource("${spec}", "${name}") wrote data that the spec schema ` +
        `rejects — swamp would fail this at run time: ` +
        JSON.stringify(parsed.error.issues),
    );
  }
  written.push({ spec, name, data });
  return Promise.resolve({ name });
},
```

Build the context's `globalArgs` with `model.globalArguments.parse(...)` too, not
the raw literal — schema defaults and coercions are part of what a real run
applies, and passing the object through untouched skips them.

**Prove the harness bites before you trust it.** Green tests after adding
validation are not evidence the validation works; they are equally consistent
with a no-op. Mutate one derived field to a wrong type (`bucketIds` → joined
string, a boolean → `String(...)`), confirm tests fail *with the schema-rejection
message*, then revert. A harness that has never failed has never been tested.
