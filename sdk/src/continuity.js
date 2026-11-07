// Tool-interface continuity (https://crawlcheck.io/spec/continuity), 1.11.0.
//
// The promise, and only this one: an agent does not silently proceed with a changed tool definition when the operator's
// policy requires renewed approval. The check compares the tools a server offers now with the baseline the operator
// approved (an mcp-lockfile), classifies every difference, applies the operator's policy, and returns a record of what
// was compared, which policy decided, and what the runtime was told to do.
//
// What it does NOT establish: that a tool is harmless, that its publisher is honest, that the code behind an unchanged
// description is unchanged, that a user authorised a call, or that no prompt injection exists. It is interface
// continuity at the check point (before a session, or before a call when you call it there), not code attestation.
//
// Three modes, for the pilot ladder:
//   observe   record what the policy would do; never change execution (outcome is always proceed, enforced false)
//   review    every change goes to a person (pause); integrity failures still deny
//   enforce   the policy's effects apply as written
// Effects, weakest to strongest: proceed, proceed_recorded (an approved exception), refresh, pause_tool, pause, deny.
// A failed exact comparison is never overridden by an interpretive assessment: nothing here reads descriptions for intent.
import { canon } from "./verify.js";

const subtle = globalThis.crypto && globalThis.crypto.subtle;
const enc = new TextEncoder();
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
async function sha256Hex(s) { return hex(new Uint8Array(await subtle.digest("SHA-256", enc.encode(s)))); }

export const CONTINUITY_EFFECTS = ["proceed", "proceed_recorded", "refresh", "pause_tool", "pause", "deny"];
export const CONTINUITY_CHANGE_CLASSES = ["tool_added", "tool_removed", "description_changed", "schema_changed", "annotations_changed", "tool_changed"];
export const CONTINUITY_FAILURE_CLASSES = ["evidence_expired", "signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch", "server_unavailable", "tool_list_truncated", "response_malformed", "baseline_stale", "policy_version_mismatch", "check_timeout", "service_unavailable", "decision_refused"];
const INTEGRITY = ["signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch"];
/** The default operator policy. Every value can be overridden; the record names the policy's sha256, so what decided is attributable. */
export const CONTINUITY_DEFAULT_POLICY = Object.freeze({
  v: 1, id: "crawlcheck-continuity-default", max_baseline_age_days: 90,
  effects: Object.freeze({
    unchanged: "proceed", tool_added: "pause_tool", tool_removed: "proceed", description_changed: "pause_tool", schema_changed: "pause_tool",
    annotations_changed: "pause_tool", tool_changed: "pause_tool", evidence_expired: "refresh", signature_invalid: "deny", key_unknown: "deny",
    key_retired: "deny", server_identity_mismatch: "deny", server_unavailable: "pause", tool_list_truncated: "pause", response_malformed: "pause",
    baseline_stale: "pause", policy_version_mismatch: "pause", check_timeout: "pause", service_unavailable: "pause", decision_refused: "deny"
  })
});
const WHY = {
  tool_added: "a tool the baseline does not list is offered", tool_removed: "a tool in the baseline is no longer offered",
  description_changed: "the tool's description differs from the approved one", schema_changed: "the tool's input schema differs from the approved one",
  annotations_changed: "the tool's annotations differ from the approved ones", tool_changed: "the tool differs from the approved one (the baseline has no per-part hashes, so the part is unknown)",
  evidence_expired: "the evidence is past its validity window", signature_invalid: "a signature over the evidence does not verify",
  key_unknown: "the evidence is signed by a key that is not published", key_retired: "the signing policy rejects the key for this object at its signing time",
  server_identity_mismatch: "the server answering is not the one the baseline names", server_unavailable: "the server could not be reached, so nothing was compared",
  tool_list_truncated: "the tool list is incomplete (a further page was not read)", response_malformed: "the tool list could not be parsed",
  baseline_stale: "the approved baseline is older than the policy allows", policy_version_mismatch: "the policy in force is not the version the deployment expects",
  check_timeout: "the check did not finish in time", service_unavailable: "the verification service could not be reached; the local fallback applies",
  decision_refused: "CrawlCheck's signed decision for the server's host did not allow the connection"
};

/** Per-part hashes of one tool, so a change can be named (description, schema, annotations). */
export async function lockToolParts(t) {
  const schema = t?.inputSchema ?? t?.input_schema ?? null;
  return { description_sha256: await sha256Hex(canon(t?.description ?? null)), schema_sha256: await sha256Hex(canon(schema)), annotations_sha256: await sha256Hex(canon(t?.annotations ?? null)) };
}
/** parts for a lockfile: { [tool name]: lockToolParts(tool) }. Store it as lock.parts next to lock.tools. */
export async function lockParts(tools) { const o = {}; for (const t of (tools ?? []).slice(0, 300)) o[String(t?.name ?? "").slice(0, 120)] = await lockToolParts(t); return o; }
async function toolHash(t) { return sha256Hex(canon({ name: t?.name ?? null, description: t?.description ?? null, inputSchema: t?.inputSchema ?? t?.input_schema ?? null, annotations: t?.annotations ?? null })); }

/** The policy in force: the default with the operator's values over it, and its sha256 (what the record names). */
export async function continuityPolicy(p) {
  const base = CONTINUITY_DEFAULT_POLICY, given = p && typeof p === "object" ? p : {};
  const effects = Object.assign({}, base.effects);
  for (const [k, v] of Object.entries(given.effects || {})) { if (!(k in base.effects)) throw new Error("unknown continuity class: " + k); if (CONTINUITY_EFFECTS.indexOf(v) < 0) throw new Error("unknown effect for " + k + ": " + v); effects[k] = v; }
  for (const k of INTEGRITY) if (effects[k] !== "deny" && given.allow_integrity_override !== true) throw new Error(k + " must stay deny (set allow_integrity_override to change it, and the record will say so)");
  const pol = { v: 1, id: String(given.id || base.id), max_baseline_age_days: Number.isFinite(given.max_baseline_age_days) ? given.max_baseline_age_days : base.max_baseline_age_days, effects, allow_integrity_override: given.allow_integrity_override === true };
  return Object.assign(pol, { sha256: await sha256Hex(canon(pol)) });
}
const rank = (e) => CONTINUITY_EFFECTS.indexOf(e);
function excFor(exceptions, cls, tool, now) {
  return (exceptions || []).find((x) => x && (x.class === cls || x.class === "*") && (x.tool === tool || (!x.tool && !tool) || x.tool === "*") && (!x.until || Date.parse(x.until) > now)) || null;
}
function modeEffect(mode, cls, eff) {
  if (mode === "review" && eff !== "proceed" && eff !== "proceed_recorded") return INTEGRITY.indexOf(cls) > -1 ? "deny" : "pause";
  return eff;
}
async function finish(rec, mode) {
  const would = rec.events.reduce((m, e) => (rank(e.policy_effect) > rank(m) ? e.policy_effect : m), "proceed");
  const eff = rec.events.reduce((m, e) => (rank(e.effect) > rank(m) ? e.effect : m), "proceed");
  rec.would = would;
  rec.enforced = mode !== "observe";
  rec.outcome = mode === "observe" ? "proceed" : eff === "pause_tool" ? "proceed" : eff === "proceed_recorded" ? "proceed" : eff;
  rec.paused_tools = mode === "observe" ? [] : rec.events.filter((e) => e.effect === "pause_tool" && e.tool).map((e) => e.tool);
  rec.why = rec.events.filter((e) => e.class !== "unchanged").map((e) => (e.tool ? e.tool + ": " : "") + e.why + " -> " + e.effect + (e.exception ? " (exception by " + (e.exception.by || "?") + ")" : ""));
  if (!rec.why.length) rec.why = ["the offered tools match the approved baseline"];
  rec.record_sha256 = await sha256Hex(canon(rec));
  return rec;
}
function base(opts, pol, mode) {
  return { kind: "crawlcheck-continuity-record", v: 1, checked_at: new Date(opts.now ?? Date.now()).toISOString(), mode, server: opts.server ?? null,
    policy: { id: pol.id, sha256: pol.sha256, integrity_override: pol.allow_integrity_override },
    claims: "interface continuity at this check point: the offered tool definitions were compared with the approved baseline. Not code attestation, not a judgement that any tool is harmless, not user authorisation.",
    events: [] };
}
function ev(rec, pol, mode, cls, tool, exceptions, now, detail) {
  const pe = pol.effects[cls]; let eff = modeEffect(mode, cls, pe); const ex = INTEGRITY.indexOf(cls) < 0 ? excFor(exceptions, cls, tool, now) : null;
  if (ex && eff !== "deny") eff = "proceed_recorded";
  const e = { class: cls, tool: tool ?? null, why: WHY[cls] || cls, policy_effect: pe, effect: eff };
  if (ex) e.exception = { by: ex.by ?? null, reason: ex.reason ?? null, until: ex.until ?? null };
  if (detail) e.detail = detail;
  rec.events.push(e);
}

/**
 * Compare the offered tools with the approved baseline (an mcp-lockfile, ideally with lock.parts) and apply the policy.
 * opts: mode ("observe" | "review" | "enforce", default "enforce"), policy, exceptions [{tool, class, until, by, reason}],
 * complete (false when tools/list returned a nextCursor you did not follow), server (the URL checked), serverIdentity
 * (the URL the baseline was approved for; differs -> server_identity_mismatch), expectPolicySha256, now (ms).
 */
export async function continuityCheck(lock, tools, opts = {}) {
  const mode = opts.mode || "enforce"; if (["observe", "review", "enforce"].indexOf(mode) < 0) throw new Error("mode must be observe, review or enforce");
  const pol = await continuityPolicy(opts.policy), now = opts.now ?? Date.now(), X = opts.exceptions;
  const rec = base(opts, pol, mode);
  if (!Array.isArray(tools)) { ev(rec, pol, mode, "response_malformed", null, X, now); return finish(rec, mode); }
  const rows = []; for (const t of tools.slice(0, 300)) rows.push({ name: String(t?.name ?? "").slice(0, 120), sha256: await toolHash(t), t });
  const cur = {}; rows.forEach((r) => { cur[r.name] = r; });
  const listHash = await sha256Hex(rows.map((r) => r.sha256).sort().join("\n"));
  const was = {}; (lock?.tools ?? []).forEach((r) => { was[r.name] = r.sha256; });
  const approvedAt = Date.parse(lock?.approved_at ?? "");
  rec.baseline = { tools_sha256: lock?.tools_sha256 ?? null, approved_at: lock?.approved_at ?? null, age_days: isFinite(approvedAt) ? Math.floor((now - approvedAt) / 864e5) : null, server: lock?.server?.url ?? null, per_part: !!(lock && lock.parts) };
  rec.observed = { tools_sha256: listHash, count: rows.length, complete: opts.complete !== false };
  if (opts.expectPolicySha256 && opts.expectPolicySha256 !== pol.sha256) ev(rec, pol, mode, "policy_version_mismatch", null, X, now, "expected " + opts.expectPolicySha256 + ", in force " + pol.sha256);
  const want = opts.serverIdentity ?? lock?.server?.url ?? null;
  if (want && opts.server && String(want).replace(/\/+$/, "") !== String(opts.server).replace(/\/+$/, "")) ev(rec, pol, mode, "server_identity_mismatch", null, X, now, "baseline approved for " + want + ", checked " + opts.server);
  if (rec.baseline.age_days !== null && rec.baseline.age_days > pol.max_baseline_age_days) ev(rec, pol, mode, "baseline_stale", null, X, now, rec.baseline.age_days + " days old; the policy allows " + pol.max_baseline_age_days);
  if (opts.complete === false) ev(rec, pol, mode, "tool_list_truncated", null, X, now);
  for (const n of Object.keys(cur).filter((n) => !(n in was)).sort()) ev(rec, pol, mode, "tool_added", n, X, now);
  if (opts.complete !== false) for (const n of Object.keys(was).filter((n) => !(n in cur)).sort()) ev(rec, pol, mode, "tool_removed", n, X, now);
  for (const n of Object.keys(cur).filter((n) => n in was && was[n] !== cur[n].sha256).sort()) {
    const P = lock && lock.parts && lock.parts[n];
    if (!P) { ev(rec, pol, mode, "tool_changed", n, X, now); continue; }
    const q = await lockToolParts(cur[n].t); let any = false;
    if (q.description_sha256 !== P.description_sha256) { ev(rec, pol, mode, "description_changed", n, X, now); any = true; }
    if (q.schema_sha256 !== P.schema_sha256) { ev(rec, pol, mode, "schema_changed", n, X, now); any = true; }
    if (q.annotations_sha256 !== P.annotations_sha256) { ev(rec, pol, mode, "annotations_changed", n, X, now); any = true; }
    if (!any) ev(rec, pol, mode, "tool_changed", n, X, now, "the name or a field outside description, schema and annotations changed");
  }
  if (!rec.events.length) rec.events.push({ class: "unchanged", tool: null, why: "the offered tools match the approved baseline", policy_effect: pol.effects.unchanged, effect: modeEffect(mode, "unchanged", pol.effects.unchanged) });
  return finish(rec, mode);
}

/** A record for a check that could not compare anything (the server, the evidence or the service failed). cls: one of CONTINUITY_FAILURE_CLASSES. */
export async function continuityFailure(cls, opts = {}) {
  if (CONTINUITY_FAILURE_CLASSES.indexOf(cls) < 0) throw new Error("unknown failure class: " + cls);
  const mode = opts.mode || "enforce", pol = await continuityPolicy(opts.policy), now = opts.now ?? Date.now();
  const rec = base(opts, pol, mode); rec.baseline = null; rec.observed = null;
  ev(rec, pol, mode, cls, null, opts.exceptions, now, opts.detail);
  return finish(rec, mode);
}

/**
 * Acceptance, split: the separate questions a single "verified: true" used to answer at once, for one decision receipt.
 * receipt: the crawlcheck-decision. verification: verifyDocument()'s result (integrity_valid, issuer_trusted, key_policy_valid,
 * unavailable). scope: checkDecision()'s result (its fields). opts: allowWarn, confirmed (true when a person approved a
 * require_confirmation), lock (a continuity record or checkLock result for the same server).
 * policy_result: proceed | pause | deny. accepted is policy_result === "proceed". Never act on integrity_valid alone.
 */
export function acceptanceOf(receipt, verification, scope, opts = {}) {
  const r = receipt && typeof receipt === "object" ? receipt : {}, v = verification || {}, f = (scope && scope.fields) || {}, why = [];
  const out = {
    integrity_valid: v.integrity_valid === true, issuer_trusted: v.issuer_trusted === undefined ? null : v.issuer_trusted, key_policy_valid: v.key_policy_valid === undefined ? null : v.key_policy_valid,
    freshness_valid: f.times_present === true && f.not_expired === true && f.not_future === true && f.lifetime_ok === true,
    subject_matches: f.kind_ok === true && f.domain_matches === true && f.action_matches === true && f.decision_known === true && f.resolve_bound === true,
    operation_matches: f.operation_matches === undefined ? null : f.operation_matches, replay_safe: f.nonce_matches === undefined ? null : f.nonce_matches,
    baseline_matches: null, assessment_complete: Array.isArray(v.unavailable) && v.unavailable.length === 0 && !!r.resolve && r.resolve.status === "measured",
    decision: typeof r.decision === "string" ? r.decision : null, policy_source: (r.authority && r.authority.policy_source) || null,
    evidence_level: (r.evidence_assurance && r.evidence_assurance.level) || null, policy_result: "deny", accepted: false, why
  };
  const L = opts.lock;
  if (L && L.kind === "crawlcheck-continuity-record") out.baseline_matches = L.events.every((e) => e.class === "unchanged");
  else if (L && L.verdict) out.baseline_matches = L.verdict === "unchanged";
  else if (r.assessed && r.assessed.expected_tools_sha256) out.baseline_matches = r.assessed.matches === undefined ? null : r.assessed.matches;
  if (!out.integrity_valid) why.push("integrity: a check over the receipt's bytes failed or none ran");
  if (out.issuer_trusted !== true) why.push(out.issuer_trusted === null ? "issuer: not checked (no published key ids)" : "issuer: the signing key is not published");
  if (out.key_policy_valid === false) why.push("key policy: the key may not sign this object at its signing time");
  if (!out.freshness_valid) why.push("freshness: expired, dated in the future, missing times, or longer-lived than the action allows");
  if (!out.subject_matches) why.push("subject: the receipt is for another domain, action or answer, or its decision is unknown");
  if (out.operation_matches === false) why.push("operation: the receipt is scoped to another operation");
  if (out.replay_safe === false) why.push("replay: the receipt does not carry this request's nonce");
  const hard = why.length > 0;
  if (hard) out.policy_result = "deny";
  else if (out.baseline_matches === false) { out.policy_result = "pause"; why.push("baseline: the tools differ from the approved baseline; re-approve before proceeding"); }
  else if (out.decision === "allow") out.policy_result = "proceed";
  else if (out.decision === "warn") { out.policy_result = opts.allowWarn ? "proceed" : "pause"; if (!opts.allowWarn) why.push("decision is warn and warn is not allowed"); }
  else if (out.decision === "require_confirmation") { out.policy_result = opts.confirmed === true ? "proceed" : "pause"; if (opts.confirmed !== true) why.push("a person must confirm"); }
  else { out.policy_result = "deny"; why.push("decision is " + out.decision); }
  out.accepted = out.policy_result === "proceed";
  return out;
}

/** Which failure class a refused guard() result is (for continuityFailure). */
export function continuityClassOf(g) {
  if (!g) return "service_unavailable";
  const why = (g.why || []).join("; "), A = g.acceptance;
  if (!g.receipt) return /timed? ?out|abort/i.test(why) ? "check_timeout" : "service_unavailable";
  if (A) { if (!A.integrity_valid) return "signature_invalid"; if (A.issuer_trusted !== true) return "key_unknown"; if (A.key_policy_valid === false) return "key_retired"; if (!A.freshness_valid) return "evidence_expired"; if (!A.subject_matches) return "server_identity_mismatch"; if (A.operation_matches === false || A.replay_safe === false) return "server_identity_mismatch"; }
  else if (g.verification === null) return "response_malformed";
  return "decision_refused";
}
