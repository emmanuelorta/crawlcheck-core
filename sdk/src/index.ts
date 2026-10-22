// @crawlcheck/sdk — typed client for the CrawlCheck API, plus the offline verifier.
// Every request and response type below is GENERATED from https://crawlcheck.io/openapi.json (src/gen/openapi.ts,
// openapi-typescript); nothing about the API is hand-typed here. Operations whose responses the contract does not
// type come back as `unknown`-free plain JSON objects (JsonObject) rather than an invented shape.
import type { paths, components } from "./gen/openapi.js";
import * as V from "./verify.js";
import * as L from "./log.js";
import * as S from "./staple.js";
import * as M from "./mcp.js";
import * as R from "./revocations.js";

export type { paths, components };
/** One verifier check. ok: true passed, false FAILED, null could not run (why says why) - never a pass. */
export interface VerifyCheck { id: string; ok: boolean | null; why: string; [k: string]: unknown }
/**
 * Three separate answers. integrity_valid: hashes and the signature agree with the document. issuer_trusted: the
 * signing key is one CrawlCheck publishes (null offline: not decided). accepted: both - the only field to act on.
 * A document someone else signed with their own key is verified: true offline and accepted: false.
 */
export interface Trust { integrity_valid: boolean; issuer_trusted: boolean | null; accepted: boolean; /** conf2: the signing policy accepts this key for this object at its signing time (purpose, retired, compromised). null: not decided. */ key_policy_valid?: boolean | null; /** conf2: stable reason: ok, ok_bound, key_wrong_purpose, key_not_yet_active, key_retired, key_compromised, key_unknown, no_signing_time, or related_<code> for a key the document leans on. */ key_policy_code?: string | null }
/** conf2: the key directory and rotation record as the signing policy reads them (keyPolicyFrom / publishedKeyPolicy). */
export interface KeyPolicyInput { v: 2; kids: string[]; keys: Record<string, { purpose: string; start: number | null }>; retired: Record<string, { purpose: string; stopped: number | null }>; compromised: Record<string, number>; rotation: boolean; read_at?: string; source?: string }
export interface KeyPolicyResult { ok: boolean | null; code: string; known: boolean; purpose: string | null; expected: string | null; why: string }
/** The signing policy as data (https://crawlcheck.io/keys#policy): object purposes, purpose chains, start times. */
export const KEY_POLICY = (V as any).KEY_POLICY as { v: 2; object_purpose: Record<string, string>; chains: Record<string, string[]>; starts: Record<string, string | null>; bound: Record<string, string>; purpose_aliases: Record<string, string> };
/** Build the policy input from a key directory you hold and, optionally, the rotation record saved with it. */
export const keyPolicyFrom = V.keyPolicyFrom as (directory: unknown, rotation?: unknown) => Promise<KeyPolicyInput>;
/** Does the signing policy accept this document's signing key for this object at its signing time? */
export const keyPolicyCheck = V.keyPolicyCheck as (doc: unknown, kp: KeyPolicyInput) => KeyPolicyResult;
/** Apply the signing policy to a verification: key_published (retired keys included), key_purpose, and the trust fields. */
export const applyKeyPolicy = V.applyKeyPolicy as <T>(res: T, doc: unknown, kp: KeyPolicyInput) => T & Trust;
function withTrust<T extends { verified: boolean; summary: string; checks: VerifyCheck[] }>(v: T, kid: string | undefined, published: string[] | null, related: string[] = []): T & Trust {
  let checks = v.checks;
  let issuer: boolean | null = null;
  if (published) {
    // kp3: keys are separated by purpose, so a decision's resolve answer or an answer's log head can carry another key; every one must be published
    const miss = related.filter((k) => k !== kid && !published.includes(k));
    issuer = !!kid && published.includes(kid) && miss.length === 0;
    const kc: VerifyCheck = { id: "key_published", ok: issuer, why: issuer ? "key id " + kid + " is in the published key directory" + (related.length ? ", and so is every key it leans on" : "") : miss.length && kid && published.includes(kid) ? "the document leans on key " + miss.join(", ") + ", which is NOT published - reject this document" : "key id " + (kid || "?") + " is NOT in the published key directory - reject this document" };
    checks = checks.some((c) => c.id === "key_published") ? checks.map((c) => c.id === "key_published" ? kc : c) : checks.concat([kc]);
  }
  const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
  const verified = ran.length > 0 && failed.length === 0;
  const integrity_valid = checks.filter((c) => c.id !== "key_published").every((c) => c.ok !== false);
  return Object.assign({}, v, { checks, verified, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed",
    integrity_valid, issuer_trusted: issuer, accepted: verified && issuer === true });
}
export interface BundleVerification extends Partial<Trust> { verified: boolean; summary: string; report: { id?: string; domain?: string; scanned_at?: string }; checks: VerifyCheck[]; experiences: number | null; note: string }
export interface ReceiptVerification extends Partial<Trust> { verified: boolean; summary: string; receipt: { id: string; domain: string; verdict: string; before: string; after: string }; checks: VerifyCheck[]; note: string }
/** Verify an evidence bundle with no call to CrawlCheck (the same code as /crawlcheck-verify.mjs). */
export const verifyBundle = V.verifyBundle as (b: unknown) => Promise<BundleVerification>;
/** Verify a remediation receipt with no call to CrawlCheck. */
export const verifyReceipt = V.verifyReceipt as (rc: unknown) => Promise<ReceiptVerification>;
export interface DocumentVerification extends Partial<Trust> { verified: boolean; summary: string; document: { kind: string; domain?: string; sha256: string }; checks: VerifyCheck[] }
/** Verify a signed resolve answer, preflight decision receipt, data inventory, export part or deletion record offline. */
export const verifyDocument = async (doc: unknown): Promise<DocumentVerification & Trust> => withTrust(await (V.verifyDataDoc as (d: unknown) => Promise<DocumentVerification>)(doc), (doc as any)?.signature?.kid, null);
/** Verify a signed evidence export (and every bundle and receipt inside it) offline. */
export const verifyExport = V.verifyExport as (x: unknown) => Promise<{ verified: boolean; summary: string; checks: VerifyCheck[]; [k: string]: unknown }>;
/** Verify a signed dispute resolution offline (re-runs the published decision table over the recorded readings). */
export const verifyResolution = V.verifyResolution as (x: unknown) => Promise<{ verified: boolean; summary: string; checks: VerifyCheck[]; [k: string]: unknown }>;
export const canon = V.canon as (v: unknown) => string;
export const merkleRootHex = V.merkleRootHex as (hexLeaves: string[]) => Promise<string>;
export const otsInspect = V.otsInspect as (u8: Uint8Array) => Promise<{ digest: string; attestations: Array<{ kind: string; [k: string]: unknown }> }>;

type S = components["schemas"];
export type MachineRecordV1 = S["MachineRecordV1"];
export type PublicReportV1 = S["PublicReportV1"];
export type EvidenceBundleV1 = S["EvidenceBundleV1"];
export type RemediationReceiptV1 = S["RemediationReceiptV1"];
export type ErrorV1 = S["ErrorV1"];
export type JsonObject = { [k: string]: unknown };

type Op<P extends keyof paths, M extends "get" | "post"> = paths[P] extends { [K in M]: infer O } ? O : never;
export type QueryOf<P extends keyof paths, M extends "get" | "post" = "get"> = Op<P, M> extends { parameters: { query?: infer Q } } ? NonNullable<Q> : Record<string, never>;
export type ResponseOf<P extends keyof paths, M extends "get" | "post" = "get"> =
  Op<P, M> extends { responses: { 200: { content: { "application/json": infer J } } } } ? (unknown extends J ? JsonObject : J) : JsonObject;
export type BodyOf<P extends keyof paths> = Op<P, "post"> extends { requestBody?: { content: { "application/json": infer B } } } ? B : JsonObject;

export type Action = "read" | "cite" | "connect" | "transact" | "administer";
/** The header an agent sends with its request so the site can see it checked CrawlCheck first. */
export const RECEIPT_HEADER = "CrawlCheck-Receipt";
/** The domain the way CrawlCheck hashes and stores it: lowercased, no scheme, no leading www., no path or port. "" when not a domain. */
export function normalizeDomain(v: string): string {
  const d = String(v ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[\/?#].*$/, "").replace(/:\d+$/, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : "";
}
/** { "CrawlCheck-Receipt": "v=1; sha256=..." } for a decision receipt. Send it only to the domain the receipt names, before expires_at. */
export function receiptHeader(receipt: { sha256: string }): Record<string, string> { return { [RECEIPT_HEADER]: "v=1; sha256=" + receipt.sha256 }; }
function randomNonce(): string { const b = new Uint8Array(16); (globalThis as any).crypto.getRandomValues(b); return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
async function sha256Hex(s: string): Promise<string> {
  const b = await (globalThis as any).crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
}
/** MCP tool lockfile (https://crawlcheck.io/spec/mcp-lockfile). A tool's hash is sha256 of the canonical JSON of {name, description, inputSchema, annotations}. */
export interface McpTool { name?: string; description?: string; inputSchema?: unknown; input_schema?: unknown; annotations?: unknown; [k: string]: unknown }
export interface McpLock { tools_sha256: string; tools: { name: string; sha256: string }[]; descriptions?: Record<string, string>; server?: { url?: string | null } | null; approved_at?: string; [k: string]: unknown }
export interface McpLockCheck { verdict: "unchanged" | "changed"; decision: "connect" | "block"; approved_tools_sha256: string; current_tools_sha256: string; added: string[]; removed: string[]; modified: string[] }
export async function lockToolHash(t: McpTool): Promise<string> {
  return sha256Hex(V.canon({ name: t?.name ?? null, description: t?.description ?? null, inputSchema: t?.inputSchema ?? t?.input_schema ?? null, annotations: t?.annotations ?? null }));
}
/** Hash a tools/list result the way a lockfile does: per tool, and the sorted per-tool hashes joined by \n. No network, no key. */
export async function lockFromTools(tools: McpTool[]): Promise<{ tools: { name: string; sha256: string }[]; tools_sha256: string; count: number }> {
  const rows: { name: string; sha256: string }[] = [];
  for (const t of (tools ?? []).slice(0, 300)) rows.push({ name: String(t?.name ?? "").slice(0, 120), sha256: await lockToolHash(t) });
  rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.sha256 < b.sha256 ? -1 : 1));
  return { tools: rows, tools_sha256: await sha256Hex(rows.map((r) => r.sha256).sort().join("\n")), count: rows.length };
}
/** Compare a lockfile with the tools a server lists now. Anything added, removed or changed means "block" until a person re-approves. Offline. */
export async function checkLock(lock: McpLock, tools: McpTool[]): Promise<McpLockCheck> {
  const now = await lockFromTools(tools);
  const was: Record<string, string> = {}; (lock?.tools ?? []).forEach((r) => { was[r.name] = r.sha256; });
  const cur: Record<string, string> = {}; now.tools.forEach((r) => { cur[r.name] = r.sha256; });
  const added = Object.keys(cur).filter((n) => !(n in was)), removed = Object.keys(was).filter((n) => !(n in cur)), modified = Object.keys(cur).filter((n) => n in was && was[n] !== cur[n]);
  const same = lock?.tools_sha256 === now.tools_sha256 && !added.length && !removed.length && !modified.length;
  return { verdict: same ? "unchanged" : "changed", decision: same ? "connect" : "block", approved_tools_sha256: lock?.tools_sha256 ?? "", current_tools_sha256: now.tools_sha256, added, removed, modified };
}
export interface PrivateLookup { found: boolean; ready: boolean; in_bucket: number | null; answer: JsonObject | null; verification: (DocumentVerification & Trust) | null; accepted: boolean; why?: string }
export interface ReceiptCheck { accept: boolean; why: string; check: JsonObject | null; verification: (DocumentVerification & Trust) | null }
export type Decision = "allow" | "warn" | "require_confirmation" | "block" | "unsupported";
export interface PreflightPolicy {
  max_age_hours?: number; on_warn?: "warn" | "require_confirmation" | "block"; require_entity?: boolean;
  human_approval?: Action[]; allow?: Action[]; deny?: Action[]; [k: string]: unknown;
}
export interface PreflightOptions { agent?: string; template?: string; policy?: PreflightPolicy; /** 8-128 characters of A-Z a-z 0-9 . _ : - signed into the receipt (replay binding). guard() sends a fresh one when you give none. */ nonce?: string; /** The exact operation this decision is for (method + url, or an MCP tool); signed into the receipt. */ operation?: Operation; /** An MCP server on this domain and the tool-list hash you approved (mcp-lockfile tools_sha256). The decision then reads the live tools, blocks when they differ, and its signed `assessed` block names exactly what it covered. https://crawlcheck.io/spec/mcp-lockfile */ mcp?: { url: string; tools_sha256?: string } }
/** What a receipt can be scoped to. Send only the keys that apply; CrawlCheck signs them back exactly as sent. https://crawlcheck.io/spec/guard#operation */
export interface Operation { method?: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"; url?: string; tool?: string; tool_schema_sha256?: string; scopes?: string[] }
/** The operation for calling an MCP tool: its name, the sha256 of its definition (as in the lockfile) and the scopes you will use. */
export async function toolOperation(tool: McpTool, scopes?: string[]): Promise<Operation> { const o: Operation = { tool: String(tool?.name ?? ""), tool_schema_sha256: await lockToolHash(tool) }; if (scopes && scopes.length) o.scopes = scopes.slice(); return o; }
/** A signed crawlcheck-decision receipt. Verify it with verifyDocument (or let guard() do it). */
export interface DecisionReceipt { kind: "crawlcheck-decision"; domain: string; action: Action; decision: Decision; sha256: string; signature: { kid: string; [k: string]: unknown }; resolve?: { sha256: string; kid: string }; alternatives?: JsonObject[]; [k: string]: unknown }
export interface GuardOptions extends PreflightOptions {
  /** Proceed on "warn" too. Default false: warn does not proceed. */
  allowWarn?: boolean;
  /** Called on "require_confirmation"; proceed only if it resolves true. Without it, require_confirmation does not proceed. */
  confirm?: (receipt: DecisionReceipt) => boolean | Promise<boolean>;
  /** Read the published key directory (default true). With false, pass publishedKids: a guard never accepts a receipt without checking who signed it. */
  onlineKeys?: boolean;
  /** Pinned CrawlCheck key ids, for offline use with onlineKeys: false. */
  publishedKids?: string[];
  /** conf2: a pinned key policy (keyPolicyFrom(savedDirectory, savedRotation)), for offline use with onlineKeys: false. Checks key purpose too. */
  keyPolicy?: KeyPolicyInput;
  /** Testing clock (ms since epoch). Default Date.now(). */
  now?: number;
}
/** The longest a receipt may stay valid, per action (seconds). A receipt that claims longer is refused. Published at https://crawlcheck.io/spec/guard */
export const ACTION_MAX_LIFETIME_S: Record<string, number> = { read: 86400, cite: 86400, connect: 3600, transact: 300, administer: 300 };
/** The most clock skew a receipt may claim (seconds). */
export const MAX_CLOCK_SKEW_S = 300;
const DECISIONS = ["allow", "warn", "require_confirmation", "block", "unsupported"];
export interface DecisionWant { domain: string; action: Action | string; nonce?: string | null; now?: number; operation?: Operation | null }
/**
 * Is this receipt about the operation you are about to perform? Checks the scope only (kind, domain, action, nonce,
 * time window, per-action lifetime, known decision, resolve binding); the signature and issuer are checked by
 * verifyDocument. guard() runs both. https://crawlcheck.io/spec/guard
 */
export function checkDecision(receipt: unknown, want: DecisionWant): { ok: boolean; why: string[] } {
  const why: string[] = [], r: any = receipt;
  if (!r || typeof r !== "object" || Array.isArray(r)) return { ok: false, why: ["no receipt: CrawlCheck sent " + (r === null || r === undefined ? "nothing" : typeof r)] };
  if (r.kind !== "crawlcheck-decision" || r.v !== 1) why.push("not a v1 decision receipt (kind " + r.kind + ", v " + r.v + ")");
  const wd = normalizeDomain(want.domain);
  if (!wd || normalizeDomain(r.domain) !== wd) why.push("the receipt is for " + r.domain + ", not " + want.domain);
  if (String(r.action) !== String(want.action)) why.push("the receipt is for action " + r.action + ", not " + want.action);
  if (want.operation && canon(r.operation ?? null) !== canon(want.operation)) why.push(r.operation ? "the receipt is for another operation (" + canon(r.operation).slice(0, 120) + ")" : "the receipt is not scoped to an operation, and this request named one");
  if (want.nonce && r.nonce !== want.nonce) why.push(r.nonce ? "the receipt carries another request's nonce (replayed)" : "the receipt does not carry the nonce this request sent");
  const now = want.now ?? Date.now(), skew = Math.min(Math.max(Number(r.clock_skew_s) || 0, 0), MAX_CLOCK_SKEW_S) * 1000;
  const at = Date.parse(r.decided_at), exp = Date.parse(r.expires_at);
  if (!isFinite(at) || !isFinite(exp)) why.push("decided_at or expires_at missing");
  else {
    if (now > exp + skew) why.push("expired at " + r.expires_at);
    if (at > now + skew) why.push("decided in the future (" + r.decided_at + "): check the clock");
    const max = ACTION_MAX_LIFETIME_S[String(want.action)];
    if (max === undefined) why.push("unknown action " + want.action);
    else if (exp - at > max * 1000 + 1000) why.push("valid for " + Math.round((exp - at) / 1000) + " s; a " + want.action + " receipt may last at most " + max + " s");
  }
  if (DECISIONS.indexOf(r.decision) < 0) why.push("unknown decision " + r.decision);
  if (!r.resolve || !/^[0-9a-f]{64}$/.test(String(r.resolve.sha256 || ""))) why.push("the receipt names no resolve answer");
  return { ok: why.length === 0, why };
}
export interface GuardResult { proceed: boolean; receipt: DecisionReceipt | null; verification: (DocumentVerification & Trust) | null; header: Record<string, string> | null; why: string[]; split_view?: LogFork[]; /** Set when the domain was refused from the held revocation list, with no network call. */ revoked?: RevokedEntry }
export interface GuardedFetchOptions extends GuardOptions { action?: Action; init?: RequestInit; maxHops?: number; fetch?: typeof fetch }
export interface GuardedHop { url: string; domain: string; proceed: boolean; decision: string | null; why: string[]; status?: number }
export interface GuardedFetchResult { proceed: boolean; response: Response | null; url: string; hops: GuardedHop[]; why: string[] }

// ── split-view detection (the Resolve transparency log) ──
export interface LogHead { kind: "crawlcheck-log-sth"; log_id: string; batch: number; first_index: number; batch_size: number; tree_size: number; batch_root: string; prev_sth_sha256: string | null; created_at: string; sha256: string; signature: JsonObject; [k: string]: unknown }
export interface LogFork { kind: "two_heads_for_one_batch" | "chain_break" | "size_mismatch" | "inconsistent_head"; batch: number; why: string; a: LogHead; b: LogHead; detected_at: string; proof: string }
export interface LogStore { v: 1; log_id: string; heads: Record<string, { batch: number; sha256: string; first_index: number; batch_size: number; tree_size: number; prev_sth_sha256: string | null; created_at: string | null; sth: LogHead }>; forks: LogFork[]; witnessed: { batch: number; sha256: string; at: string | null; run_id: string | null } | null }
export interface LogObservation { state: "new" | "known" | "fork" | "invalid" | "none"; why?: string; fork?: LogFork }
export interface LogCheckResult { consistent: boolean; forks: LogFork[]; all_forks: number; witnessed: { batch: number; sha256: string; at: string | null; run_id: string | null; token: boolean | null; why: string; observed: string; warning?: string } | null; unwitnessed: { batch: number; sha256: string; created_at: string | null }[]; stale_unwitnessed: { batch: number; sha256: string; created_at: string | null }[]; summary: string }
export const LOG_ID = L.LOG_ID as string;
/** A new, empty transparency-log store (plain JSON: persist it between runs). */
export const newLogStore = L.newLogStore as () => LogStore;
/** Check one signed tree head against the store and keep it. A fork carries both contradicting signed heads. */
export const logObserve = L.logObserve as (store: LogStore, sth: unknown, opts?: { publishedKids?: string[]; maxHeads?: number }) => Promise<LogObservation>;
/** Check the head inside a Resolve answer (transparency.sth), if it carries one. */
export const logObserveAnswer = L.logObserveAnswer as (store: LogStore, answer: unknown, opts?: { publishedKids?: string[] }) => Promise<LogObservation>;
/** The signed heads a store holds, newest first: what a client sends its peers. */
export const logHeads = L.logHeads as (store: LogStore, limit?: number) => LogHead[];
/** Gossip: check another client's heads against this store. */
export const logGossip = L.logGossip as (store: LogStore, sths: unknown[], opts?: { publishedKids?: string[] }) => Promise<{ forks: LogFork[]; results: (LogObservation & { batch: number; sha256: string })[] }>;
/** Verify the outside witness's co-signature: a GitHub OIDC JWT (RS256) whose audience is crawlcheck-sth:<head sha256>. */
export const verifyWitnessToken = L.verifyWitnessToken as (token: string, sthSha256: string, jwks: unknown) => Promise<{ ok: boolean | null; why: string; claims?: JsonObject }>;
export const GITHUB_OIDC_JWKS = "https://token.actions.githubusercontent.com/.well-known/jwks";
// ── stapled Resolve / Resolve over DNS (ccr1 records) ──
export type StapleDecisions = { read: string | null; cite: string | null; connect: string | null; transact: string | null };
export interface StapleCheck { valid: boolean; reason: string | null; expired: boolean; record: Record<string, string> | null; decisions: StapleDecisions | null }
/** Parse a ccr1 record (CrawlCheck-Staple header value or <domain>._v.crawlcheck.io TXT). */
export const parseStaple = S.parseStaple as (record: string) => { fields: Record<string, string>; body: string; sig: string };
/** The CrawlCheck-Staple header of a response (fetch Response, Headers or a plain header map), or null. */
export const stapleFromResponse = S.stapleFromResponse as (res: unknown) => string | null;
/** Verify a staple offline: published key, signature, the record names opts.host (or a parent), fresh_until in the future. Expired or foreign staples are never valid. */
export const stapleCheck = S.stapleCheck as (record: string, opts: { host: string; publishedKids: string[]; now?: number }) => Promise<StapleCheck>;

// ── offline revocations (https://crawlcheck.io/docs/api#revocations) ──
export interface RevokedEntry { domain?: string; actions: string[]; causes: string[]; state: string | null; since: string | null; updated_at: string | null }
/** The signed revocation list held locally (plain JSON: persist it between runs). */
export interface RevocationStore { v: 1; generated_at: string | null; seq: string | null; synced_at: string | null; revoked: Record<string, RevokedEntry> }
export interface RevocationSync { applied: boolean; full: boolean; added: number; removed: number; reason: string | null; total: number; generated_at: string | null; verification?: DocumentVerification & Trust }
/** A new, empty revocation store. */
export const newRevocationStore = R.newRevocationStore as () => RevocationStore;
/** Apply a VERIFIED crawlcheck-revocations document (full list or ?since= delta) to a store. */
export const applyRevocations = R.applyRevocations as (store: RevocationStore, doc: unknown, now?: number) => { applied: boolean; full: boolean; added: number; removed: number; reason: string | null };
/** The entry that revokes this domain (or a parent domain) for this action, or null. Offline. */
export const revokedFor = R.revokedFor as (store: RevocationStore, domain: string, action?: string) => (RevokedEntry & { domain: string }) | null;

// ── preflight as an MCP client extension (https://crawlcheck.io/spec/mcp-preflight) ──
export interface McpPreflightOptions extends PreflightOptions {
  /** Proceed on warn too (default false). */
  allowWarn?: boolean;
  /** Called on require_confirmation (and, with confirmDestructive, before a destructive tool call); the connect or call proceeds only if it resolves true. */
  confirm?: (receipt: DecisionReceipt & { tool?: string; annotations?: unknown }) => boolean | Promise<boolean>;
  /** An approved lockfile (mcpLock / lockFromTools): the tools the server lists after connecting must match it, and only tools in it may be called. */
  lock?: McpLock;
  /** Ask confirm() before a tool annotated destructive (destructiveHint true, or readOnlyHint false with openWorldHint true). */
  confirmDestructive?: boolean;
  /** Re-decide the host when the cached connect receipt is older than this (default: until its expires_at). */
  maxAgeMs?: number;
  /** A local (stdio) server has no host to resolve: "allow" (default) or "refuse". */
  local?: "allow" | "refuse";
  /** The server URL when the transport does not expose it. */
  serverUrl?: string;
  onlineKeys?: boolean;
}
export interface McpPreflightState { url: string | null; host: string | null; receipt: DecisionReceipt | null; verification: (DocumentVerification & Trust) | null; decidedAt: number; lockCheck: McpLockCheck | null; approved: Set<string> | null }
export interface McpPreflightHooks {
  state: McpPreflightState;
  beforeConnect(url: string | null | undefined): Promise<{ local: boolean; host?: string; receipt: DecisionReceipt | null; verification?: DocumentVerification & Trust }>;
  afterConnect(tools: McpTool[]): Promise<McpLockCheck | null>;
  beforeToolCall(name: string, annotations?: unknown): Promise<{ receipt: DecisionReceipt | null }>;
}
/** Thrown by the hooks when a connect or tools/call is refused; the request was never sent. */
export const McpPreflightRefused = M.McpPreflightRefused as unknown as new (stage: "connect" | "tools/call", why: string, detail?: { receipt?: DecisionReceipt | null; lock?: McpLockCheck | null; verification?: unknown }) => Error & { stage: "connect" | "tools/call"; why: string; receipt: DecisionReceipt | null; lock: McpLockCheck | null; verification: unknown };
/** The two hooks (beforeConnect, beforeToolCall) plus afterConnect for lockfiles, for any MCP client stack. */
export const mcpPreflight = M.mcpPreflight as (cc: CrawlCheck, opts?: McpPreflightOptions) => McpPreflightHooks;
/** Wrap an MCP client (the official @modelcontextprotocol/sdk Client, or anything with connect(transport) and callTool(params)) so both run the preflight first. Returns the same client with client.preflight set. */
export const withPreflight = M.withPreflight as <C extends { connect: (...a: any[]) => Promise<any>; callTool: (...a: any[]) => Promise<any> }>(client: C, cc: CrawlCheck, opts?: McpPreflightOptions) => C & { preflight: McpPreflightHooks };
/** The server URL a transport will talk to, if it exposes one (Streamable HTTP and SSE transports do). */
export const transportUrl = M.transportUrl as (transport: unknown) => string | null;

export interface ClientOptions {
  /** Licence key (cc_ + 32 hex). Without one, licence-gated fields come back withheld, exactly as on the website. */
  key?: string;
  /** API origin. Default https://crawlcheck.io */
  base?: string;
  /** A fetch implementation (default: globalThis.fetch). */
  fetch?: typeof fetch;
  /** Extra headers for every request. */
  headers?: Record<string, string>;
  /** Transparency-log store (newLogStore()). Every Resolve answer's signed tree head is checked against it; keep it across runs to catch a split view. Default: a fresh in-memory store. */
  logStore?: LogStore;
  /** Revocation store (newRevocationStore()). syncRevocations() fills it; guard() refuses a listed domain for a listed action without a network call. Default: a fresh, empty store. */
  revocationStore?: RevocationStore;
  /** Private mode: resolve() and resolveFor() send only a 2-hex prefix of sha256(domain) (resolvePrivate), never the domain. A domain with no public measurement then raises a 404 CrawlCheckError instead of a just-in-time answer, which would name it. preflight() and guard() still name the domain: a receipt is bound to it. */
  privateLookups?: boolean;
}

export class CrawlCheckError extends Error {
  readonly status: number; readonly body: unknown; readonly path: string;
  constructor(status: number, path: string, body: unknown) {
    const m = body && typeof body === "object" ? ((body as any).error?.message ?? (body as any).error ?? (body as any).message) : null;
    super("CrawlCheck " + path + " answered " + status + (m ? ": " + (typeof m === "string" ? m : JSON.stringify(m)) : ""));
    this.name = "CrawlCheckError"; this.status = status; this.body = body; this.path = path;
  }
  /** true when the answer was "this needs a licence for the domain (or the owner's session)". */
  get locked(): boolean { return this.status === 403; }
}

export interface ConformanceResult { name: string; group: string; ok: boolean; diffs: string[]; must_reject: string | null }

export class CrawlCheck {
  readonly base: string;
  private readonly key?: string;
  private readonly f: typeof fetch;
  private readonly extra: Record<string, string>;
  /** The transparency-log store this client checks every signed tree head against. Persist it (JSON) between runs. */
  readonly log: LogStore;
  /** The signed revocation list this client holds. Persist it (JSON) between runs; syncRevocations() keeps it current. */
  readonly revocations: RevocationStore;
  /** Private mode (ClientOptions.privateLookups). */
  readonly privateLookups: boolean;
  constructor(opts: ClientOptions = {}) {
    this.base = (opts.base ?? "https://crawlcheck.io").replace(/\/+$/, "");
    this.key = opts.key; this.extra = opts.headers ?? {}; this.log = opts.logStore ?? newLogStore(); this.revocations = opts.revocationStore ?? newRevocationStore(); this.privateLookups = !!opts.privateLookups;
    const f = opts.fetch ?? (globalThis as any).fetch;
    if (typeof f !== "function") throw new Error("no fetch available: pass { fetch } (Node 18+ and every browser have one)");
    this.f = f.bind(globalThis);
  }

  /** Any documented GET, typed from the OpenAPI document: client.get("/api/explain", { domain: "example.com" }). */
  async get<P extends keyof paths>(path: P, query?: QueryOf<P, "get">): Promise<ResponseOf<P, "get">> {
    return this.req("GET", path as string, query as Record<string, unknown> | undefined) as Promise<ResponseOf<P, "get">>;
  }
  /** Any documented POST, typed from the OpenAPI document. */
  async post<P extends keyof paths>(path: P, body: BodyOf<P> | JsonObject, query?: QueryOf<P, "post">): Promise<ResponseOf<P, "post">> {
    return this.req("POST", path as string, query as Record<string, unknown> | undefined, body) as Promise<ResponseOf<P, "post">>;
  }

  // ── read before acting ──
  /** The signed ResolveV1 answer: crawl policy, delivery, machine files, capabilities, entity, findings, freshness and a decision per action. */
  async resolve(domain: string): Promise<ResponseOf<"/api/v1/resolve", "get">> {
    if (this.privateLookups) {   // pfx2: only the hash prefix leaves this process
      const p = await this.resolvePrivate(domain);
      if (!p.ready) throw new CrawlCheckError(503, "/api/v1/resolve-prefix", { error: p.why || "the prefix index is not built yet" });
      if (!p.found) throw new CrawlCheckError(404, "/api/v1/resolve-prefix", { error: "CrawlCheck holds no public measurement of " + domain + "; in private mode the domain is never sent, so no just-in-time answer is made" });
      if (!p.accepted) throw new CrawlCheckError(502, "/api/v1/resolve-prefix", { error: "the answer in the bucket did not verify: " + (p.verification ? p.verification.summary : "no verification") });
      await logObserveAnswer(this.log, p.answer).catch(() => null);
      return p.answer as unknown as ResponseOf<"/api/v1/resolve", "get">;
    }
    const a = await this.get("/api/v1/resolve", { domain } as QueryOf<"/api/v1/resolve">);
    await logObserveAnswer(this.log, a).catch(() => null);   // a head that contradicts one this client already holds is recorded in this.log.forks
    return a;
  }
  private kidCache: { at: number; kids: string[] } | null = null;
  /** The key ids CrawlCheck publishes (/.well-known/http-message-signatures-directory), cached for an hour. */
  async publishedKids(): Promise<string[]> {
    if (this.kidCache && Date.now() - this.kidCache.at < 3600e3) return this.kidCache.kids;
    const r = await this.f(this.base + "/.well-known/http-message-signatures-directory", { headers: { accept: "application/json" } });
    const j: any = await r.json();
    const kids = ((j && j.keys) || []).map((k: any) => k.kid).filter(Boolean);
    this.kidCache = { at: Date.now(), kids }; return kids;
  }
  /**
   * The verdict for a domain, preferring a valid staple the site sent (opts.staple, or opts.response's CrawlCheck-Staple
   * header): no request to CrawlCheck is made when the staple verifies. An expired, foreign or invalid staple is ignored
   * and the signed answer is fetched instead; source says which was used and staple says why.
   */
  async resolveFor(domain: string, opts: { staple?: string | null; response?: unknown } = {}): Promise<{ source: "staple" | "network"; decisions: StapleDecisions; staple: StapleCheck | null; answer?: unknown }> {
    const rec = opts.staple || (opts.response ? stapleFromResponse(opts.response) : null);
    let chk: StapleCheck | null = null;
    if (rec) { let kids: string[] = []; try { kids = await this.publishedKids(); } catch { kids = []; } chk = await stapleCheck(rec, { host: normalizeDomain(domain), publishedKids: kids }); if (chk.valid && chk.decisions) return { source: "staple", decisions: chk.decisions, staple: chk }; }
    const a: any = await this.resolve(domain);
    const act = (k: string) => (a && a.actions && a.actions[k] && a.actions[k].decision) || null;
    return { source: "network", decisions: { read: act("read"), cite: act("cite"), connect: act("connect"), transact: act("transact") }, staple: chk, answer: a };
  }
  /** Up to 100 domains in one call; each answer is a full signed ResolveV1 document. */
  async resolveBatch(domains: string[]) {
    const r: any = await this.post("/api/v1/resolve", { domains } as JsonObject);
    for (const a of (r && r.answers) || []) await logObserveAnswer(this.log, a).catch(() => null);
    return r;
  }
  /** Split-view check: the current head, GitHub's witness co-signature on the last witnessed head, and the chain from it down to every head this client holds. Reports the heads it holds to /api/v1/log/gossip unless report is false. */
  async logCheck(opts: { report?: boolean; maxWalk?: number; maxUnwitnessedMinutes?: number } = {}): Promise<LogCheckResult> {
    const kids = await this.publishedKeyIds();
    return L.logCheck(this.log, (p: string) => this.req("GET", p), { publishedKids: kids, maxWalk: opts.maxWalk, maxUnwitnessedMinutes: opts.maxUnwitnessedMinutes,
      fetchJwks: async () => { const r = await this.f(GITHUB_OIDC_JWKS); return r.ok ? r.json() : null; },
      post: opts.report === false ? undefined : (p: string, b: unknown) => this.req("POST", p, undefined, b) }) as Promise<LogCheckResult>;
  }
  /** Check heads another client sent (logHeads on their side) against this client's store. */
  logGossip(sths: unknown[]) { return logGossip(this.log, sths); }
  /**
   * Fetch the signed revocation list (a ?since= delta when the store already holds one), verify it (integrity and a
   * published signing key) and apply it. A delta that no longer reaches back is replaced by the full list. Nothing is
   * applied from a document that does not verify. Call it on a timer (poll_seconds, 60) and before going offline.
   */
  async syncRevocations(opts: { full?: boolean } = {}): Promise<RevocationSync> {
    const st = this.revocations;
    const get = async (since: string | null) => (await this.req("GET", "/api/v1/revocations", since ? { since } : undefined)) as any;
    let doc = await get(opts.full || !st.generated_at ? null : st.generated_at);
    const verify = async (d: unknown) => this.verifyDocument(d, true);
    let v = await verify(doc);
    if (!v.accepted) return { applied: false, full: false, added: 0, removed: 0, reason: "the revocation list did not verify: " + v.summary, total: Object.keys(st.revoked).length, generated_at: st.generated_at, verification: v };
    let r = applyRevocations(st, doc);
    if (!r.applied && doc && doc.since) { doc = await get(null); v = await verify(doc); if (!v.accepted) return { applied: false, full: true, added: 0, removed: 0, reason: "the full revocation list did not verify: " + v.summary, total: Object.keys(st.revoked).length, generated_at: st.generated_at, verification: v }; r = applyRevocations(st, doc); }
    return Object.assign({}, r, { total: Object.keys(st.revoked).length, generated_at: st.generated_at, verification: v });
  }
  /** The policy engine: a signed decision receipt (allow | warn | require_confirmation | block | unsupported). A policy can only make the decision stricter. */
  async preflight(domain: string, action: Action = "read", opts: PreflightOptions = {}): Promise<DecisionReceipt> {
    const b: JsonObject = { domain, action };
    if (opts.agent) b.agent = opts.agent; if (opts.template) b.template = opts.template; if (opts.policy) b.policy = opts.policy; if (opts.nonce) b.nonce = opts.nonce; if (opts.operation) b.operation = opts.operation as unknown as JsonObject;
    if (opts.mcp && opts.mcp.url) b.mcp = (opts.mcp.tools_sha256 ? { url: opts.mcp.url, tools_sha256: opts.mcp.tools_sha256 } : { url: opts.mcp.url }) as unknown as JsonObject;
    return this.post("/api/v1/preflight", b) as unknown as Promise<DecisionReceipt>;
  }
  private kpCache: { at: number; kp: KeyPolicyInput } | null = null;
  /** conf2: the key directory and rotation record, read now (cached 10 minutes), as the signing policy reads them. */
  async publishedKeyPolicy(): Promise<KeyPolicyInput> {
    if (this.kpCache && Date.now() - this.kpCache.at < 600e3) return this.kpCache.kp;
    const d: any = await this.req("GET", "/.well-known/http-message-signatures-directory");
    let rot: unknown = null;
    try { const r = await this.f(this.base + "/.well-known/security-key-rotation.json", { headers: { accept: "application/json" } }); if (r.ok) rot = await r.json(); } catch { rot = null; }
    const kp = Object.assign(await keyPolicyFrom(d, rot), { read_at: new Date().toISOString(), source: "online" });
    this.kpCache = { at: Date.now(), kp }; return kp;
  }
  /** Verify a signed document here. With onlineKeys (default), its signing key must also be in the published directory and the signing policy must accept it. */
  async verifyDocument(doc: unknown, onlineKeys = true): Promise<DocumentVerification & Trust> {
    const kp = onlineKeys ? await this.publishedKeyPolicy() : null;
    const v = withTrust(await (V.verifyDataDoc as (d: unknown) => Promise<DocumentVerification>)(doc), (doc as any)?.signature?.kid, kp ? kp.kids : null, (V as any).relatedKids(doc));
    return kp && (doc as any)?.signature ? applyKeyPolicy(v, doc, kp) : v;
  }
  /**
   * Preflight, verify the receipt, check it is for THIS operation, and decide. Proceeds on allow; warn only with allowWarn;
   * require_confirmation only if confirm() says yes; block, unsupported and every failure never (fail closed: an error,
   * an unreachable CrawlCheck, a malformed, foreign, expired, replayed or out-of-scope receipt all return proceed false
   * with why[]). Passes the acceptance suite at https://crawlcheck.io/spec/guard
   */
  async guard(domain: string, action: Action = "read", opts: GuardOptions = {}): Promise<GuardResult> {
    const nonce = opts.nonce || randomNonce();
    const no = (why: string[], receipt: any = null, verification: any = null): GuardResult => ({ proceed: false, receipt, verification, header: null, why });
    const rv = revokedFor(this.revocations, normalizeDomain(domain) || domain, action);   // rvd1: refused offline, before any request
    if (rv) return Object.assign(no([rv.domain + " is on CrawlCheck's signed revocation list for " + action + " (" + (rv.causes.join(", ") || rv.state || "revoked") + (rv.since ? ", since " + rv.since : "") + "; list of " + this.revocations.generated_at + ")"]), { revoked: rv });
    let receipt: any;
    try { receipt = await this.preflight(domain, action, Object.assign({}, opts, { nonce })); }
    catch (e) { return no(["CrawlCheck did not give a decision: " + ((e as any)?.message || e)]); }
    if (this.log.forks.length) return Object.assign(no(["the transparency log has shown this client two histories (split view)"], receipt), { split_view: this.log.forks.slice() });
    const scope = checkDecision(receipt, { domain, action, nonce, now: opts.now, operation: opts.operation });
    if (!receipt || typeof receipt !== "object") return no(scope.why);
    const online = opts.onlineKeys ?? true;
    if (!online && !opts.keyPolicy && !(Array.isArray(opts.publishedKids) && opts.publishedKids.length)) return no(["onlineKeys is false and no keyPolicy or publishedKids were pinned: the signer cannot be checked"], receipt);
    let verification: DocumentVerification & Trust;
    try {
      const kp = online ? await this.publishedKeyPolicy() : opts.keyPolicy || null;   // conf2: purpose, retired and compromised keys, not only "published"
      verification = withTrust(await (V.verifyDataDoc as (d: unknown) => Promise<DocumentVerification>)(receipt), receipt?.signature?.kid, kp ? kp.kids : opts.publishedKids!, (V as any).relatedKids(receipt));
      if (kp) verification = applyKeyPolicy(verification, receipt, kp);
    }
    catch (e) { return no(["the receipt could not be verified: " + ((e as any)?.message || e)].concat(scope.why), receipt); }
    const why = scope.why.slice();
    if (!verification.integrity_valid) why.push("integrity failed: " + verification.checks.filter((c) => c.ok === false).map((c) => c.id).join(", "));
    if (verification.issuer_trusted !== true) why.push("signed by a key that is not in CrawlCheck's published key directory");
    else if (verification.key_policy_valid === false) why.push("the signing policy rejects this key for a decision receipt: " + ((verification.checks.find((c) => c.id === "key_purpose") || {}) as VerifyCheck).why);
    if (why.length) return no(why, receipt, verification);
    const d = receipt.decision;
    let proceed = d === "allow" || (d === "warn" && !!opts.allowWarn);
    if (d === "require_confirmation") { if (opts.confirm) { try { proceed = (await opts.confirm(receipt)) === true; } catch { proceed = false; } } }
    if (!proceed) why.push(d === "warn" ? "decision is warn and allowWarn is not set" : d === "require_confirmation" ? (opts.confirm ? "a human did not confirm" : "decision is require_confirmation and no confirm() was given") : "decision is " + d);
    return { proceed, receipt, verification, header: proceed ? receiptHeader(receipt) : null, why };
  }
  /**
   * fetch() with the check where the action runs: guard() before the first request, and again before every redirect hop
   * to a new domain. The site is contacted only after its domain proceeds; a refused hop is never requested. Redirects
   * are followed by hand (GET/HEAD only), to http(s) only, at most maxHops (10). The receipt header is sent only to the
   * domain it names. In a browser a cross-origin redirect hides its target, so it is refused rather than followed blind.
   */
  async guardedFetch(url: string, opts: GuardedFetchOptions = {}): Promise<GuardedFetchResult> {
    const action = opts.action ?? "read", max = opts.maxHops ?? 10, f = opts.fetch ? opts.fetch.bind(globalThis) : this.f;
    const init: RequestInit = Object.assign({}, opts.init || {}), method = String(init.method || "GET").toUpperCase();
    const hops: GuardedHop[] = [], seen = new Map<string, GuardResult>();
    let cur = url;
    for (let n = 0; n <= max; n++) {
      let u: URL; try { u = new URL(cur); } catch { return { proceed: false, response: null, url: cur, hops, why: ["not a URL: " + cur] }; }
      if (u.protocol !== "https:" && u.protocol !== "http:") return { proceed: false, response: null, url: cur, hops, why: ["refused a " + u.protocol + " URL"] };
      const dom = normalizeDomain(u.hostname);
      if (!dom) return { proceed: false, response: null, url: cur, hops, why: ["not a public domain name: " + u.hostname] };
      const op: Operation = { method: method as Operation["method"], url: cur };   // op1: each hop's receipt names that exact request
      let g = seen.get(method + " " + cur);
      if (!g) { g = await this.guard(dom, action, Object.assign({}, opts, { operation: op })); seen.set(method + " " + cur, g); }
      const hop: GuardedHop = { url: cur, domain: dom, proceed: g.proceed, decision: g.receipt ? String(g.receipt.decision) : null, why: g.why };
      hops.push(hop);
      if (!g.proceed) return { proceed: false, response: null, url: cur, hops, why: [dom + ": " + (g.why.join("; ") || "refused")] };
      const h = new Headers(init.headers || {}); if (g.header) for (const [k, v] of Object.entries(g.header)) h.set(k, v);
      const res = await f(cur, Object.assign({}, init, { headers: h, redirect: "manual" as RequestRedirect }));
      hop.status = res.status;
      if ((res as any).type === "opaqueredirect") return { proceed: false, response: null, url: cur, hops, why: ["the runtime hid the redirect target, so it cannot be checked"] };
      const loc = res.headers.get("location");
      if (![301, 302, 303, 307, 308].includes(res.status) || !loc) return { proceed: true, response: res, url: cur, hops, why: [] };
      if (method !== "GET" && method !== "HEAD") return { proceed: true, response: res, url: cur, hops, why: ["redirect not followed for " + method] };
      try { cur = new URL(loc, cur).toString(); } catch { return { proceed: false, response: null, url: cur, hops, why: ["unreadable redirect target " + loc] }; }
    }
    return { proceed: false, response: null, url: cur, hops, why: ["more than " + max + " redirects"] };
  }
  /** Look a domain up without sending it: only the first prefixLen hex characters of sha256(domain) leave this process (one more character per 413, up to 8). found false with ready true means no public measurement. */
  /** Make a signed lockfile for an MCP server (CrawlCheck reads tools/list; no tool is called). Save it; check with checkLock before every connect. */
  /** One signed verdict on a business fact (phone, address, hours, service_area) against what the business publishes: GET /api/v1/field-check. */
  async fieldCheck(domain: string, field: FactField, value: string): Promise<JsonObject> { return this.req("GET", "/api/v1/field-check", { domain: normalizeDomain(domain), field, value }) as Promise<JsonObject>; }
  async mcpLock(url: string): Promise<McpLock & JsonObject> { return this.req("GET", "/api/v1/mcp/lock", { url }) as Promise<McpLock & JsonObject>; }
  /** Read the server's tools now (through CrawlCheck) and compare with a lockfile; the answer is signed. For a fully offline check, list the tools yourself and call checkLock. */
  async mcpLockCheck(lock: McpLock, url?: string): Promise<McpLockCheck & JsonObject> { return this.req("POST", "/api/v1/mcp/lock/check", undefined, { lock, url: url ?? lock?.server?.url ?? undefined }) as Promise<McpLockCheck & JsonObject>; }
  /** Tool-poisoning scan of a server URL or a tool list. */
  async mcpScan(target: string | McpTool[]): Promise<JsonObject> { return (typeof target === "string" ? this.req("GET", "/api/v1/mcp/scan", { url: target }) : this.req("POST", "/api/v1/mcp/scan", undefined, { tools: target })) as Promise<JsonObject>; }
  async resolvePrivate(domain: string, prefixLen = 2): Promise<PrivateLookup> {
    const d = normalizeDomain(domain); if (!d) throw new Error("not a domain name: " + domain);
    if (prefixLen < 2 || prefixLen > 8) throw new Error("prefixLen must be 2 to 8");
    const h = await sha256Hex(d);
    let r: any;
    // pfx3: a 413 means more than 100 measured domains share the prefix (the corpus grows); send one more hex character and
    // try again, up to 8. Each extra character halves the bucket twice and still never names the domain.
    for (let n = prefixLen; ; n++) {
      try { r = await this.req("GET", "/api/v1/resolve-prefix/" + h.slice(0, n)); break; }
      catch (e) {
        if (e instanceof CrawlCheckError && e.status === 503) return { found: false, ready: false, in_bucket: null, answer: null, verification: null, accepted: false, why: "the prefix index is not built yet" };
        if (e instanceof CrawlCheckError && e.status === 413 && n < 8) continue;
        throw e;
      }
    }
    const hit = (r.answers || []).find((a: any) => a.domain_sha256 === h);
    if (!hit) return { found: false, ready: true, in_bucket: r.in_bucket ?? null, answer: null, verification: null, accepted: false };
    const verification = await this.verifyDocument(hit.answer);
    return { found: true, ready: true, in_bucket: r.in_bucket ?? null, answer: hit.answer, verification, accepted: !!verification.accepted && normalizeDomain(hit.answer.domain) === d };
  }
  /** For sites: check a CrawlCheck-Receipt header received with a request to host. accept only when the receipt is held, names host, has not expired, decided allow or warn, and verifies with a published key. */
  async checkReceiptHeader(headerValue: string, host: string): Promise<ReceiptCheck> {
    const m = String(headerValue || "").match(/sha256=([0-9a-fA-F]{64})/) || String(headerValue || "").trim().match(/^([0-9a-fA-F]{64})$/);
    if (!m) return { accept: false, why: "no receipt digest in the header", check: null, verification: null };
    const sha = m[1].toLowerCase(), h = normalizeDomain(host);
    let r: any;
    try { r = await this.req("GET", "/api/v1/decisions/" + sha, { host: h }); }
    catch (e) { if (e instanceof CrawlCheckError && e.status === 404) return { accept: false, why: "CrawlCheck holds no receipt with that digest", check: e.body as JsonObject, verification: null }; throw e; }
    const rc = r.receipt || {}, verification = await this.verifyDocument(rc);
    return { accept: !!r.accept && !!verification.accepted && rc.sha256 === sha && normalizeDomain(rc.domain) === h, why: r.reason, check: r, verification };
  }
  /** Signed change feed (what changed since a time, optionally for one domain). */
  changes(q: QueryOf<"/api/v1/changes"> = {} as QueryOf<"/api/v1/changes">) { return this.get("/api/v1/changes", q); }
  /** Report what happened after acting. Outcomes are kept apart from the signed record and never rewrite it. */
  outcome(body: JsonObject & { domain: string; action: Action }) { return this.post("/api/v1/outcome", body); }
  /** The registry record (RDAP) and lifecycle of a domain. */
  domain(domain: string) { return this.get("/api/v1/domain", { domain } as QueryOf<"/api/v1/domain">); }

  // ── the records ──
  /** The whole observation in one shape: findings (gated like the site), trust, freshness, score ledger, evidence links. */
  machineRecord(q: QueryOf<"/api/v1/machine-record">): Promise<MachineRecordV1> { return this.get("/api/v1/machine-record", q) as Promise<MachineRecordV1>; }
  /** Scan a domain now (free lane without a key; the licensed lane with one). */
  scan(domain: string): Promise<PublicReportV1> { return this.post("/api/v1/scan", { domain }) as Promise<PublicReportV1>; }
  /** A stored report by id, in the public v1 shape. */
  async report(id: string): Promise<PublicReportV1> { return this.req("GET", "/r/" + encodeURIComponent(id) + ".json") as Promise<PublicReportV1>; }

  // ── why ──
  explain(q: QueryOf<"/api/explain">) { return this.get("/api/explain", q); }
  impact(q: QueryOf<"/api/impact">) { return this.get("/api/impact", q); }
  whatIf(q: QueryOf<"/api/whatif">) { return this.get("/api/whatif", q); }
  locate(q: QueryOf<"/api/locate">) { return this.get("/api/locate", q); }

  // ── proof ──
  /** Every server-side verifier on one record. */
  verify(id: string) { return this.get("/api/verify", { id } as QueryOf<"/api/verify">); }
  /** The evidence bundle (anonymous: subject and leaves withheld; with a licence for the domain: complete). */
  bundle(id: string): Promise<EvidenceBundleV1> { return this.get("/api/bundle", { id, download: "0" } as QueryOf<"/api/bundle">) as Promise<EvidenceBundleV1>; }
  /** Download the bundle and verify it here, with the offline verifier: no trust in the API's own answer. */
  async verifyOffline(id: string) { const b: any = await this.bundle(id); return withTrust(await verifyBundle(b), b?.manifest?.signature?.kid, await this.publishedKeyIds()); }
  /** A signed remediation receipt by its id (rc1:…). */
  async receipt(id: string): Promise<RemediationReceiptV1> { const r: any = await this.get("/api/receipt", { id } as QueryOf<"/api/receipt">); return r.receipt as RemediationReceiptV1; }
  /** Fetch a receipt and verify its hash and signature here. key_published stays null offline: compare the key id with publishedKeyIds(). */
  async verifyReceiptOffline(id: string) { const rc: any = await this.receipt(id); return withTrust(await verifyReceipt(rc), rc?.signature?.kid, await this.publishedKeyIds()); }
  /** The observer's published Ed25519 key ids (RFC 7638 thumbprints), to close the one check a verifier cannot do offline. */
  async publishedKeyIds(): Promise<string[]> {
    const d: any = await this.req("GET", "/.well-known/http-message-signatures-directory");
    const out: string[] = [];
    for (const k of (d?.keys ?? [])) {
      if (!k?.x) continue;
      const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x }))));
      let s = ""; for (const b of h) s += String.fromCharCode(b);
      out.push(btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
    }
    return out;
  }
  receipts(domain: string) { return this.get("/api/receipts", { domain } as QueryOf<"/api/receipts">); }

  // ── the suite ──
  /** Run the published conformance fixtures through THIS package's verifier. Every result must be ok. */
  async conformance(): Promise<{ ok: boolean; results: ConformanceResult[]; built_at: string; verifier_sha256: string }> {
    const ix: any = await this.req("GET", "/conformance/index.json");
    const results: ConformanceResult[] = [];
    for (const f of ix.fixtures) {
      const doc: any = await this.req("GET", new URL(f.file).pathname + new URL(f.file).search);
      const res: any = f.kind === "receipt" ? await verifyReceipt(doc) : await verifyBundle(doc);
      const got: Record<string, unknown> = {}; for (const c of res.checks) got[c.id] = c.ok;
      const diffs = Object.keys(f.expected.checks).filter((k) => got[k] !== f.expected.checks[k]).map((k) => k + " expected " + f.expected.checks[k] + " got " + got[k]);
      if (res.verified !== f.expected.verified) diffs.push("verified expected " + f.expected.verified + " got " + res.verified);
      results.push({ name: f.name, group: f.group, ok: diffs.length === 0, diffs, must_reject: f.must_reject ?? null });
    }
    return { ok: results.every((r) => r.ok), results, built_at: ix.built_at, verifier_sha256: ix.verifier.sha256 };
  }

  private async req(method: "GET" | "POST", path: string, query?: Record<string, unknown>, body?: unknown): Promise<unknown> {
    const u = new URL(path, this.base + "/");
    if (query) for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) u.searchParams.set(k, Array.isArray(v) ? v.join(",") : String(v));
    const h: Record<string, string> = Object.assign({ accept: "application/json" }, this.extra);
    if (this.key) h["x-crawlcheck-key"] = this.key;
    if (body !== undefined) h["content-type"] = "application/json";
    const r = await this.f(u.toString(), { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const t = await r.text();
    let j: unknown; try { j = t ? JSON.parse(t) : null; } catch { j = t; }
    if (!r.ok) throw new CrawlCheckError(r.status, u.pathname, j);
    return j;
  }
}

/**
 * Agent tools (1.6.0; crawlcheck_verify_fact and decision facts 1.7.0): CrawlCheck as tools any agent framework can register, so the check happens inside the agent's
 * own tool loop. crawlcheck_check_site returns the signed, verified decision for an action on a site (with the business facts the site publishes); crawlcheck_verify_fact checks one phone, address or hours value; crawlcheck_fetch
 * fetches a page only after its domain (and every redirect hop) proceeds. Both fail closed, exactly like guard().
 * toolsFor() shapes them for OpenAI function calling, Anthropic tool use, the Vercel AI SDK or an MCP server.
 */
export type FactField = "phone" | "address" | "hours" | "service_area";
export interface AgentTool { name: string; description: string; parameters: JsonObject; execute: (args: any) => Promise<JsonObject> }
export interface AgentToolOptions extends GuardOptions { /** Characters of page text returned by crawlcheck_fetch (default 20000). */ maxChars?: number }
const AT_ACTIONS: Action[] = ["read", "cite", "connect", "transact", "administer"];
function atDomain(v: unknown): string { const s = String(v ?? "").trim(); try { return normalizeDomain(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? new URL(s).hostname : s); } catch { return ""; } }
function atAction(v: unknown): Action { return (AT_ACTIONS as string[]).includes(String(v)) ? (String(v) as Action) : "read"; }
export function agentTools(cc: CrawlCheck, opts: AgentToolOptions = {}): AgentTool[] {
  const max = opts.maxChars ?? 20000;
  return [
    { name: "crawlcheck_check_site",
      description: "Before acting on a website, get CrawlCheck's signed decision for that action: allow, warn, require_confirmation, block or unsupported, with the reasons. Use it before reading, citing, connecting to, buying from or administering a site you have not checked. proceed is false whenever the site should not be used for that action.",
      parameters: { type: "object", additionalProperties: false, required: ["site"], properties: {
        site: { type: "string", description: "The site's domain or any URL on it, e.g. example.com or https://example.com/page" },
        action: { type: "string", enum: AT_ACTIONS, description: "What you are about to do: read (default), cite, connect (an API or MCP server), transact (pay, book, submit personal data) or administer" } } },
      execute: async (a: any) => {
        const domain = atDomain(a?.site), action = atAction(a?.action);
        if (!domain) return { proceed: false, why: ["not a public domain name: " + String(a?.site ?? "")] };
        const g = await cc.guard(domain, action, opts);
        return { domain, action, proceed: g.proceed, decision: g.receipt ? String(g.receipt.decision) : null, why: g.why, reasons: Array.isArray((g.receipt as any)?.steps) ? (g.receipt as any).steps.map((x: any) => String(x?.why ?? "")).filter(Boolean) : [], reason_codes: (g.receipt as any)?.reason_codes ?? [],
          receipt_sha256: g.receipt?.sha256 ?? null, verified: g.verification ? g.verification.accepted : false, alternatives: g.receipt?.alternatives ?? null,
          facts: (g.receipt as any)?.facts ?? null };
      } },
    { name: "crawlcheck_verify_fact",
      description: "Check one fact you hold about a business against what the business itself publishes: its phone number, street address, opening hours or a place it serves. Returns CrawlCheck's signed verdict (published now, published before, or not this business, and who does publish it). Use it before giving someone a phone number, address or hours, especially ones that came from an AI answer or a directory.",
      parameters: { type: "object", additionalProperties: false, required: ["site", "field", "value"], properties: {
        site: { type: "string", description: "The business's website domain or any URL on it" },
        field: { type: "string", enum: ["phone", "address", "hours", "service_area"], description: "Which fact the value is" },
        value: { type: "string", description: "The value you hold, e.g. (720) 555-0100, 1200 Main St, Mon 8am, or a city name" } } },
      execute: async (a: any) => {
        const domain = atDomain(a?.site), field = String(a?.field ?? ""), value = String(a?.value ?? "").trim().slice(0, 200);
        if (!domain) return { ok: false, why: ["not a public domain name: " + String(a?.site ?? "")] };
        if (!["phone", "address", "hours", "service_area"].includes(field) || !value) return { ok: false, why: ["give field (phone, address, hours or service_area) and value"] };
        let doc: any;
        try { doc = await cc.fieldCheck(domain, field as FactField, value); } catch (e: any) { return { ok: false, domain, field, value, why: [String(e?.message ?? e)] }; }
        const v = await cc.verifyDocument(doc).catch(() => null);
        return Object.assign({}, doc, { ok: true, verified: v ? ((v as any).accepted ?? v.verified) === true : false, verification: v ? v.summary : "could not verify" }) as JsonObject;
      } },
    { name: "crawlcheck_fetch",
      description: "Fetch a web page only if CrawlCheck allows reading that site; every redirect to a new domain is checked again before it is followed. Returns the page text (truncated) or, when refused, why. Prefer this over a plain fetch for sites you have not checked.",
      parameters: { type: "object", additionalProperties: false, required: ["url"], properties: {
        url: { type: "string", description: "The http(s) URL to fetch" },
        action: { type: "string", enum: ["read", "cite"], description: "read (default) or cite, if the text will be quoted back to someone" } } },
      execute: async (a: any) => {
        const r = await cc.guardedFetch(String(a?.url ?? ""), Object.assign({}, opts, { action: (a?.action === "cite" ? "cite" : "read") as Action }));
        const hops = r.hops.map((h) => ({ url: h.url, domain: h.domain, decision: h.decision, proceed: h.proceed, status: h.status ?? null }));
        if (!r.proceed || !r.response) return { proceed: false, url: r.url, why: r.why, hops };
        const text = await r.response.text();
        return { proceed: true, url: r.url, status: r.response.status, content_type: r.response.headers.get("content-type"), text: text.slice(0, max), truncated: text.length > max, chars: text.length, hops };
      } }
  ];
}
export type ToolFormat = "openai" | "anthropic" | "vercel" | "mcp";
/** Shape agentTools() for a framework. call(name, args) runs a tool by name for formats that hand you the call (OpenAI, Anthropic, MCP). For the Vercel AI SDK wrap each parameters object: tool({ description, parameters: jsonSchema(t.parameters), execute: t.execute }). */
export function toolsFor(format: ToolFormat, tools: AgentTool[]): { tools: unknown; call: (name: string, args: unknown) => Promise<JsonObject> } {
  const by = new Map(tools.map((t) => [t.name, t]));
  const call = async (name: string, args: unknown): Promise<JsonObject> => { const t = by.get(name); if (!t) return { proceed: false, why: ["no CrawlCheck tool named " + name] }; return t.execute(typeof args === "string" ? (() => { try { return JSON.parse(args); } catch { return {}; } })() : (args ?? {})); };
  if (format === "openai") return { tools: tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } })), call };
  if (format === "anthropic") return { tools: tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters })), call };
  if (format === "mcp") return { tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.parameters, annotations: { readOnlyHint: true, openWorldHint: true } })), call };
  return { tools: Object.fromEntries(tools.map((t) => [t.name, { description: t.description, parameters: t.parameters, execute: t.execute }])), call };
}
export default CrawlCheck;
