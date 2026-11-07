"""The shared core of the framework adapters (1.13.0): tool-interface continuity at the point where an agent framework
fetches an MCP server's tool list (https://crawlcheck.io/spec/continuity).

    gate = ContinuityGate(lock, mode="observe")       # observe | review | enforce
    rec = await gate.acheck(tools)                     # one crawlcheck-continuity-record, kept in gate.records
    tools = gate.allowed(tools)                        # what the agent may see

observe: every difference is recorded (gate.records, on_record, the "crawlcheck.continuity" logger, log_path as JSON
lines) and the tools pass through unchanged. Nothing is blocked.
review:  any difference pauses the whole server until confirm() says yes; integrity failures are denied.
enforce: the policy applies. By default a changed or new tool is withheld from the agent (pause_tool) until confirm()
re-approves it; a whole-server pause or refresh asks confirm() once; deny raises ContinuityRefused.

confirm(request) may be sync or async. request is {"continuity": record} for the server, or {"tool": name,
"continuity": record} for one tool. A yes is remembered for that exact tool definition (or tool list), so a framework
that lists tools on every turn does not ask twice. No network, no key: the comparison is local.

1.14.0 signed baseline: the constructor checks the lockfile's signature (verify_lock_baseline) before trusting it:
operator_keys, key_policy, published_kids, trusted_kids, require_signed_baseline (default: on when operator_keys are
given). A bad or forged signature, or an unsigned lockfile when one is required, is recorded as baseline_untrusted; in
review and enforce the constructor raises ContinuityRefused (a startup failure), in observe it records and goes on.
gate.baseline is the result; every record names it in baseline.trust."""
import asyncio
import inspect
import json
import logging
import threading

from .continuity import continuity_check, continuity_failure, _tool_hash, verify_lock_baseline, baseline_refusal

log = logging.getLogger("crawlcheck.continuity")


class ContinuityRefused(Exception):
    """Raised in review/enforce when the record's outcome is pause, refresh or deny and nobody re-approved."""

    def __init__(self, why, record=None, tool=None):
        Exception.__init__(self, "CrawlCheck continuity refused%s: %s" % ((" tool " + tool) if tool else "", why))
        self.why, self.record, self.tool = why, record, tool


def tool_dict(t):
    """{name, description, inputSchema, annotations} from an MCP tool as any client library hands it over (a dict, an
    mcp.types.Tool, or an object with those attributes). Pydantic models are dumped without unset/None keys, so the
    hash matches the server's raw JSON (a ToolAnnotations dumped with None keys would hash differently)."""
    if isinstance(t, dict):
        return t
    out = {}
    for k, alt in (("name", None), ("description", None), ("inputSchema", "input_schema"), ("annotations", None)):
        v = getattr(t, k, None)
        if v is None and alt:
            v = getattr(t, alt, None)
        if v is not None and hasattr(v, "model_dump"):
            v = v.model_dump(mode="json", by_alias=True, exclude_none=True)
        elif v is not None and not isinstance(v, (str, int, float, bool, list, dict)):
            try:
                v = dict(v)
            except (TypeError, ValueError):
                v = str(v)
        out[k] = v
    return out


def _run_sync(coro):
    """Run a coroutine from sync code, also when this thread already has a running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box = {}

    def go():
        try:
            box["v"] = asyncio.run(coro)
        except BaseException as e:  # pragma: no cover - re-raised below
            box["e"] = e
    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join()
    if "e" in box:
        raise box["e"]
    return box.get("v")


async def _maybe(v):
    return await v if inspect.isawaitable(v) else v


class ContinuityGate:
    def __init__(self, lock, mode="observe", policy=None, exceptions=None, server=None, server_identity=None,
                 expect_policy_sha256=None, confirm=None, on_record=None, log_path=None, keep=50, operator_keys=None,
                 key_policy=None, published_kids=None, trusted_kids=None, require_signed_baseline=None):
        if mode not in ("observe", "review", "enforce"):
            raise ValueError("mode must be observe, review or enforce")
        if not isinstance(lock, dict) or not isinstance(lock.get("tools"), list):
            raise ValueError("lock must be an approved mcp-lockfile (a dict with a tools list); see https://crawlcheck.io/spec/mcp-lockfile")
        self.lock, self.mode, self.policy, self.exceptions = lock, mode, policy, exceptions
        self.server, self.server_identity, self.expect_policy_sha256 = server, server_identity, expect_policy_sha256
        self.confirm, self.on_record, self.log_path, self.keep = confirm, on_record, log_path, keep
        self.records, self.record, self.paused = [], None, set()
        self._ok_tools, self._ok_lists, self._last = set(), set(), None
        # startup: the baseline is checked once, before anything is compared against it
        try:
            b = verify_lock_baseline(lock, operator_keys=operator_keys, key_policy=key_policy, published_kids=published_kids, trusted_kids=trusted_kids)
        except Exception as e:  # noqa: BLE001
            b = {"trust": "invalid", "signer": None, "kid": None, "why": "the baseline could not be checked: %s" % e, "parts_used": False, "lock": lock}
        self._base = b.get("lock") or lock
        self.baseline = {k: b[k] for k in ("trust", "signer", "kid", "why", "parts_used")}
        req = require_signed_baseline if require_signed_baseline is not None else bool(operator_keys)
        bad = baseline_refusal(b, req)
        self.refused = None
        if bad:
            rec = continuity_failure("baseline_untrusted", mode=self.mode, policy=self.policy, exceptions=self.exceptions, server=self.server, detail=str(bad)[:300])
            _run_sync(self._keep(rec))
            if self.mode != "observe" and rec["outcome"] != "proceed":
                self.refused = ContinuityRefused("; ".join(rec["why"]) + ": " + bad, rec)
                raise self.refused

    # -- records ---------------------------------------------------------------------------------------------------
    async def _keep(self, rec):
        self.record = rec
        self.records = (self.records + [rec])[-self.keep:]
        changed = any(e["class"] != "unchanged" for e in rec["events"])
        (log.warning if changed else log.info)("continuity %s %s: would %s, outcome %s: %s", rec["mode"], rec.get("server") or "-",
                                               rec["would"], rec["outcome"], "; ".join(rec["why"]))
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
            except OSError as e:  # recording must never break the agent
                log.warning("continuity: could not append to %s: %s", self.log_path, e)
        if self.on_record:
            try:
                await _maybe(self.on_record(rec))
            except Exception as e:  # pragma: no cover
                log.warning("continuity: on_record raised %r", e)
        return rec

    async def _ask(self, req):
        if not self.confirm:
            return False
        try:
            return bool(await _maybe(self.confirm(req)))
        except Exception as e:
            log.warning("continuity: confirm raised %r; treated as no", e)
            return False

    # -- the check ---------------------------------------------------------------------------------------------------
    async def acheck(self, tools, complete=True):
        """Compare the offered tools with the lock and apply the mode. Returns the record; raises ContinuityRefused."""
        rows = [tool_dict(t) for t in (tools or [])] if isinstance(tools, list) else tools
        rec = continuity_check(self._base, rows, baseline_trust=self.baseline["trust"], mode=self.mode, policy=self.policy, exceptions=self.exceptions, complete=complete,
                               server=self.server, server_identity=self.server_identity, expect_policy_sha256=self.expect_policy_sha256)
        key = ((rec.get("observed") or {}).get("tools_sha256"), complete is not False)
        if self._last and self._last[0] == key and self.record:   # same list as last time: no new record, same verdict
            rec = self.record
        else:
            self._last = (key,)
            await self._keep(rec)
        if self.mode == "observe":
            self.paused = set()
            return rec
        if rec["outcome"] == "deny":
            raise ContinuityRefused("; ".join(rec["why"]), rec)
        if rec["outcome"] in ("pause", "refresh"):
            if key not in self._ok_lists:
                if not await self._ask({"continuity": rec}):
                    raise ContinuityRefused("; ".join(rec["why"]), rec)
                self._ok_lists.add(key)
            self.paused = set()
            return rec
        cur = {str(r.get("name") or "")[:120]: _tool_hash(r) for r in rows} if isinstance(rows, list) else {}
        paused = set()
        for n in rec["paused_tools"]:
            k = (n, cur.get(n))
            if k in self._ok_tools or await self._ask({"tool": n, "continuity": rec}):
                self._ok_tools.add(k)
            else:
                paused.add(n)
        self.paused = paused
        return rec

    def check(self, tools, complete=True):
        """acheck() for sync frameworks."""
        return _run_sync(self.acheck(tools, complete=complete))

    async def afail(self, cls, detail=None):
        """Record a check that could not compare anything (the list could not be read). Raises ContinuityRefused unless
        the mode is observe (then the caller re-raises its own error: there are no tools to pass through)."""
        rec = continuity_failure(cls, mode=self.mode, policy=self.policy, exceptions=self.exceptions, server=self.server,
                                 detail=(str(detail)[:300] if detail else None))
        self._last = None
        await self._keep(rec)
        if self.mode != "observe" and rec["outcome"] != "proceed":
            raise ContinuityRefused("; ".join(rec["why"]), rec)
        return rec

    def fail(self, cls, detail=None):
        return _run_sync(self.afail(cls, detail))

    def allowed(self, tools, name=lambda t: getattr(t, "name", None) if not isinstance(t, dict) else t.get("name")):
        """The tools the agent may see: all of them in observe mode, else without the paused ones."""
        if self.mode == "observe" or not self.paused:
            return list(tools)
        return [t for t in tools if name(t) not in self.paused]

    def call_ok(self, tool_name):
        """Refuse a call to a paused tool (a framework that cached an earlier list could still try it)."""
        if self.mode != "observe" and tool_name in self.paused:
            raise ContinuityRefused("tool %s changed since it was approved (or is new) and no person re-approved it" % tool_name, self.record, tool_name)
        return True


__all__ = ["ContinuityGate", "ContinuityRefused", "tool_dict"]
