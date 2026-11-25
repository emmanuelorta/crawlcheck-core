import { CrawlCheck, type MachineRecordV1, type EvidenceBundleV1 } from "../dist/index.js";
const c = new CrawlCheck();
async function main() {
  const mr: MachineRecordV1 = await c.machineRecord({ domain: "example.com" });
  const k: "crawlcheck-machine-record" = mr.kind;            // literal from the schema's const
  const b: EvidenceBundleV1 = await c.bundle("abc");
  const st: "sealed" | "pending" | "unsealed" | "unverifiable" | "unknown" = b.seal ? b.seal.state : "unknown";
  const g = await c.guard("example.com", "read", { allowWarn: false });
  const d: "allow" | "warn" | "require_confirmation" | "block" | "unsupported" = g.receipt!.decision;
  // @ts-expect-error  not an action
  await c.preflight("example.com", "delete");
  await c.get("/api/explain", { domain: "example.com", code: "NO_LLMS_TXT" });
  // @ts-expect-error  a parameter the operation does not have
  await c.get("/api/explain", { website: "example.com" });
  // @ts-expect-error  a path that is not in the contract
  await c.get("/api/nope", {});
  // @ts-expect-error  machine-record has no "code" parameter
  await c.machineRecord({ code: "X" });
  return [k, st, d];
}
void main;
// 1.12.0: continuity at the framework's tool-list fetch
import { withContinuity, continuityGate, ContinuityRefused, type McpLock } from "../dist/index.js";
async function frameworks(lock: McpLock, server: { listTools: () => Promise<any[]>; callTool: (n: string, a: unknown) => Promise<any>; name: string }) {
  const g = withContinuity(server, lock, { mode: "observe", onRecord: (r) => r.would });
  const n: string = g.name;
  const recs = g.continuity.records.map((r) => r.outcome);
  const gate = continuityGate(lock, { mode: "enforce", confirm: async (q) => q.tool === "search" });
  // @ts-expect-error  not a mode
  continuityGate(lock, { mode: "block" });
  const e = new ContinuityRefused("why");
  return [n, recs, gate.paused, e.why];
}
void frameworks;
// failure_class on guard results, and observe mode for guard() / guardedFetch()
import { GUARD_FAILURE_CLASSES, guardFailureClassOf, type GuardFailureClass, type GuardMode, type GuardResult } from "../dist/index.js";
async function guardClasses() {
  const kept: GuardResult[] = [];
  const g = await c.guard("example.com", "read", { mode: "observe", onRecord: (r) => { kept.push(r); } });
  const cls: GuardFailureClass | null | undefined = g.failure_class;
  const would: boolean | undefined = g.would_proceed, m: GuardMode | undefined = g.mode;
  const same: GuardFailureClass = guardFailureClassOf(g), all: GuardFailureClass[] = GUARD_FAILURE_CLASSES;
  const f = await c.guardedFetch("https://example.com/", { mode: "enforce" });
  const hop: GuardFailureClass | null | undefined = f.hops[0]?.failure_class, fc: GuardFailureClass | null | undefined = f.failure_class;
  // @ts-expect-error  not a guard mode (review is the MCP gate's)
  await c.guard("example.com", "read", { mode: "review" });
  // @ts-expect-error  not a failure class
  const bad: GuardFailureClass = "operation_mismatched";
  return [cls, would, m, same, all, hop, fc, bad, kept];
}
void guardClasses;
