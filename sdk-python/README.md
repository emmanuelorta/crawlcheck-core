# crawlcheck (Python)

Before your agent reads, cites, connects to or transacts with a domain, ask CrawlCheck. No dependencies; Python 3.8+.

```
pip install https://crawlcheck.io/sdk/crawlcheck-1.0.1-py3-none-any.whl
```

```python
from crawlcheck import CrawlCheck

cc = CrawlCheck()                      # CrawlCheck(key="cc_...") for licensed detail
answer = cc.resolve("example.com")     # signed ResolveV1: policy, delivery, files, capabilities, entity, freshness, actions
print(answer["actions"]["read"]["decision"])

receipt = cc.preflight("example.com", action="cite", agent="GPTBot", template="safe_citation")
print(receipt["decision"], [s["why"] for s in receipt["steps"]])
assert cc.verify(receipt)["verified"]  # Ed25519, checked locally; the key must be in the published directory

ok, receipt = cc.guard("shop.example", action="transact", confirm=lambda r: input(r["meaning"] + " y/n? ") == "y")
```

Command line: `python -m crawlcheck preflight example.com cite GPTBot`, `python -m crawlcheck verify receipt.json`.

Decisions: `allow`, `warn`, `require_confirmation`, `block`, `unsupported`. A policy (`max_age_hours`, `on_warn`, `require_entity`, `human_approval`, `allow`, `deny`) can only make a decision stricter.


## LangChain, LlamaIndex, CrewAI and the OpenAI Agents SDK (CrewAI and OpenAI Agents 1.11.0)

```python
from crawlcheck import CrawlCheck
from crawlcheck.langchain import crawlcheck_tools        # needs langchain-core
# from crawlcheck.llama_index import crawlcheck_tools   # needs llama-index-core
# from crawlcheck.crewai import crawlcheck_tools        # needs crewai: Agent(..., tools=tools)
# from crawlcheck.openai_agents import crawlcheck_tools # needs openai-agents: Agent(..., tools=tools)

tools = crawlcheck_tools(CrawlCheck(key="cc_..."))       # or CrawlCheck() with no key
```

Three tools, the same in every framework: `crawlcheck_check_site` (a signed allow / warn / block decision before an agent
reads, cites, connects to, pays or administers a site), `crawlcheck_verify_fact` (one phone, address, hours or service area
checked against what the business publishes) and `crawlcheck_fetch` (fetches a page only after its domain and every
redirect hop proceed). They fail closed. The package itself still has no dependencies; each adapter imports its framework
only when called.

A free key of your own: `curl -s -X POST -H "content-type: application/json" -d '{"email":"you@example.com"}' https://crawlcheck.io/api/v1/keys/free`

## Trust

`verify_document(doc)` and `CrawlCheck.verify(doc)` return `verified`, `integrity_valid`, `issuer_trusted` and `accepted`. Act on `accepted`: offline, `issuer_trusted` is `None` and `accepted` is `False`, because a document signed with someone else's key can be self-consistent. `CrawlCheck.verify` and `guard` check the published key directory, so `accepted` is decided there.

Since 1.9.1 a key the rotation record lists as retired still counts for its own signing window when the expected purpose is worked out: after a decision-key rotation, receipts the old decision key signed inside its window verify, and no other key may sign a decision made while that key was live (key-policy suite cases retired-decision-key-*).

Since 1.9.0 `log_check` reads the chain of signed heads 200 per request (`/api/v1/log/sths`) instead of one per batch, so a first check on a client holding no heads takes one or two requests; an older server is still walked one head per request.

Since 1.8.0 an MCP connect decision names the server and, with a lockfile, its approved `tools_sha256` (`preflight(domain, "connect", mcp={"url": ..., "tools_sha256": ...})`; `with_preflight` sends it for you). CrawlCheck reads the live tools from its own network: a changed tool list comes back as `block`, and the signed receipt's `assessed` block says exactly which endpoint and tool state it covered.

Since 1.8.0 they also apply the signing policy (https://crawlcheck.io/keys#policy): which key purpose may sign which object at which time (decision receipts move to the decision key at 2026-11-09 17:00 UTC), retired keys (valid only for documents signed before they stopped) and compromised keys (never valid on their signature alone). The result carries `key_policy_valid`, and `accepted` needs it. Offline, build the same input from copies you saved: `kp = key_policy_from(saved_directory, saved_rotation_record)`, then `apply_key_policy(result, doc, kp)` or `client.verify(doc, key_policy=kp)`. A saved copy cannot know a key retired or compromised after you saved it.

`accepted` says who signed a document. It is not permission to act: a valid receipt can say `block`, `warn` or `require_confirmation`. `guard()` decides that part.

Since 1.12.0 `guard()` leaves the split in `client.last_guard["acceptance"]`: `integrity_valid`, `issuer_trusted`, `key_policy_valid`, `freshness_valid`, `subject_matches`, `operation_matches`, `replay_safe`, `baseline_matches`, `assessment_complete`, `policy_source` (which policy produced the decision), `evidence_level` (A record integrity, B reproducible decision, C corroborated reading) and `policy_result` (`proceed`, `pause` or `deny`). `acceptance_of(receipt, verification, decision_scope(receipt, domain, action))` computes it for a receipt you hold. It is the same contract as the JS SDK's `acceptanceOf`, pinned by the shared golden file `tests/fixtures/continuity.json`. A receipt is evidence and a recommendation; your deployment's policy decides whether the agent acts. `POST https://crawlcheck.io/api/v1/preflight/replay` re-runs a receipt's decision from the archived answer and the inputs it carries.

## Give your agent the check as a tool

`agent_tools(cc)` returns three tools: `crawlcheck_check_site` (the signed, verified decision for an action on a site, including the business facts the site publishes and which AI engines get them wrong), `crawlcheck_verify_fact` (one signed verdict on a phone number, address, hours or service area you hold) and `crawlcheck_fetch` (fetches a page only after its domain and every redirect hop are allowed). All fail closed.

```python
from crawlcheck import CrawlCheck, agent_tools, tools_for
tools = agent_tools(CrawlCheck(), agent="MyAgentBot")
defs, call = tools_for("anthropic", tools)   # or "openai", "mcp"; on a tool call: call(name, args)
print(call("crawlcheck_verify_fact", {"site": "example.com", "field": "phone", "value": "(720) 555-0100"})["verdict"])
```

## Preflight inside your MCP client

Wrap an MCP `ClientSession` so `initialize` and `call_tool` are decided before anything is sent ([proposal](https://crawlcheck.io/spec/mcp-preflight)):

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from crawlcheck import CrawlCheck
from crawlcheck.mcp import McpPreflight, with_preflight, McpPreflightRefused

cc = CrawlCheck()
pf = McpPreflight(cc, confirm=ask_the_user)
await pf.before_connect(url)              # McpPreflightRefused before any transport opens: block / unsupported / no confirmation
async with streamable_http_client(url) as (read, write):
    async with with_preflight(ClientSession(read, write), cc, server_url=url, preflight=pf) as s:
        await s.initialize()
        await s.call_tool("search", {"q": "x"})
```

A refusal raised inside the transport's context arrives in an ExceptionGroup (`except* McpPreflightRefused`); deciding first, as above, keeps it a plain exception.
Options: `lock=` (an approved lockfile: changed tools refuse, tools outside it refuse), `confirm_destructive=True`, `allow_warn=True`, `local="refuse"` for stdio servers. Other stacks use `McpPreflight(cc).before_connect(url)` / `before_tool_call(name, annotations)`.

### Tool-interface continuity (1.12.0)

The promise, and only this one: your agent does not silently proceed with a changed tool definition when your policy requires renewed approval ([spec](https://crawlcheck.io/spec/continuity)). Keep per-part hashes in the lockfile (`lock["parts"] = lock_parts(tools)`), then `McpPreflight(cc, lock=lock, confirm=ask, continuity={"mode": "observe", "on_record": log.write})`, moving to `"review"` and then `"enforce"`. observe never blocks and records what the policy would do; review sends every change to a person (integrity failures still deny); enforce pauses a changed or new tool on its own while the rest stay usable, and denies on an invalid signature, an unpublished or retired key, or a different server. Every check leaves a `crawlcheck-continuity-record` in `pf.records` with the baseline, what was observed, each event, the policy's sha256, the outcome and its own `record_sha256`. `continuity_check(lock, tools, mode=...)` and `continuity_failure(cls, mode=...)` run the same logic without a session and match the JS SDK byte for byte. A record states interface continuity at the check point: not code attestation, not a judgement that a tool is harmless, not user authorisation.

### Continuity in your agent framework (1.13.0)

The same check where the framework fetches an MCP server's tool list, against your approved lockfile. Nothing here calls CrawlCheck, needs a key, or adds a dependency: each adapter imports its framework only when you call it.

```python
# OpenAI Agents SDK
from crawlcheck.openai_agents import with_continuity
async with MCPServerStreamableHttp(params={"url": url}) as server:
    agent = Agent(name="a", instructions="...", mcp_servers=[with_continuity(server, lock, mode="observe")])

# LangChain (langchain-mcp-adapters)
from crawlcheck.langchain import load_mcp_tools_with_continuity
tools = await load_mcp_tools_with_continuity(MultiServerMCPClient({"shop": conn}), lock, server_name="shop", mode="observe")

# CrewAI (crewai-tools MCPServerAdapter)
from crawlcheck.crewai import with_continuity
with with_continuity(MCPServerAdapter(server_params), lock, mode="observe") as tools:
    agent = Agent(role="...", goal="...", backstory="...", tools=tools)
```

`observe` records every difference (the `crawlcheck.continuity` logger, `on_record=`, `log_path=` as JSON lines, `.gate.records`) and passes the tools through. `review` pauses the whole server on any change until `confirm=` says yes. `enforce` applies the policy: a changed or new tool is withheld from the agent, and a call to it is refused, until `confirm({"tool": name, "continuity": record})` re-approves it; the rest stay usable. A refusal raises `ContinuityRefused` (with `.record`). A yes is remembered for that exact definition, so a framework that lists tools every turn does not ask twice. The LangChain and CrewAI adapters build the agent's tools from exactly the definitions that were compared.

1.13.0 also fixes `with_preflight` continuity with the MCP Python SDK: a real `mcp.types.Tool` was hashed with its annotations' unset keys, so every annotated tool read as changed against a lockfile built from the server's JSON.

### Check the baseline before trusting it (1.14.0)

Whoever can edit your approved lockfile can approve their own tools. So every gate (`McpPreflight` / `with_preflight` with `lock=`, `ContinuityGate` and the three framework adapters) checks the lockfile's signature once, when it is constructed, before it compares anything against it:

| `baseline["trust"]` | meaning |
|---|---|
| `verified` | signed by CrawlCheck (`cc.mcp_lock(url)` / `GET /api/v1/mcp/lock`) with a CrawlCheck key. The package ships the published key ids (`CRAWLCHECK_LOCK_KIDS`); pass `key_policy=key_policy_from(directory)` to follow a key rotation. These lockfiles carry `parts` inside the signature; `parts` added afterwards are not used. |
| `operator_signed` | you signed it with `sign_lock` and passed your public key in `operator_keys`. Use this when you edit a lockfile yourself, for example to drop a tool. |
| `unsigned` | no signature. Accepted unless `require_signed_baseline=True` (on by default once you pass `operator_keys`). |
| `invalid` | the signature does not verify, the file was changed after signing, or the key is neither CrawlCheck's nor one of yours. |

`invalid`, or `unsigned` when a signed one is required, is the failure class `baseline_untrusted`: in `enforce` and `review` the constructor raises (`ContinuityRefused` / `McpPreflightRefused`), so the agent fails at startup; `observe` records it and goes on. Every record names the result in `baseline.trust`. Nothing is verified per call. The adapters take the options as `baseline={"operator_keys": [...], "require_signed_baseline": True}`; `McpPreflight` takes them in `continuity={...}` or as keyword arguments.

Sign your own lockfile, with no command line:

```python
from crawlcheck import new_operator_key, sign_lock
from crawlcheck.continuity_gate import ContinuityGate

key = new_operator_key()                       # once; store key["private_key"] where the agent cannot read it
signed = sign_lock(lock, key["private_key"])   # after you review (or edit) the lockfile; save signed
# at startup, with only the public key:
gate = ContinuityGate(signed, mode="enforce", operator_keys=[key["public_key"]])
```

`verify_lock_baseline(lock, ...)` runs the same check on its own. The signature is Ed25519 over `"crawlcheck-lock-operator-v1\n" + sha256(canonical JSON of the lockfile without operator_signature)`, the same bytes the JS SDK signs; signing is pure Python and not constant-time, so sign on a machine you control.

### Compare on jcs-v1 (1.15.0)

Every lockfile from `GET /api/v1/mcp/lock` since 2026-11-07 carries `jcs_v1`: RFC 8785 digests of each tool's contract (`name`, `description`, `inputSchema`, `outputSchema`) and of everything else it carries (`title`, `annotations`, `icons`, `_meta`, vendor members). The package now computes the same digests offline, byte for byte with the JS SDK and the endpoint:

```python
from crawlcheck import jcs_v1
d = jcs_v1(tools)   # {"tools_sha256": "sha256-...", "extras_sha256": "sha256-...", "count": ..., "tools": [{"name", "contract", "extras"}]}
```

When the approved lockfile carries `jcs_v1`, `continuity_check` and every gate compare on it, over every tool: a moved contract is named `description_changed` or `schema_changed` (from `parts`), a moved extras digest `annotations_changed`, and any other change (a new `title`, `outputSchema`, `_meta`) `tool_changed` with a `detail`. Records say `baseline["alg"] == "jcs-v1"`. Pass `digest="lk-v1"` to compare on the v1 hashes instead. A missing `description` and `""` are the same contract under jcs-v1.

Nothing is cut silently. `with_preflight` follows `nextCursor` to the last page; a list whose pages could not all be read is `tool_list_truncated` (and a v1 lockfile refuses it). A v1 lockfile hashes at most `LOCK_V1_MAX_TOOLS` (300) tools: past that, `lock_from_tools` returns `complete: False` with `offered`, `check_lock` answers `verdict "incomplete"`, `decision "block"`, and a v1 continuity check raises `tool_list_truncated`. jcs-v1 has no cap.

## Catch a split view

Every Resolve answer carries its place in CrawlCheck's transparency log. The client keeps every signed tree head it sees in `client.log` (plain JSON; persist it and pass it back as `log_store=`) and treats two heads for one batch, or a head that does not chain to the one before, as a fork with both signed heads as proof. `guard()` returns `False` while the client holds one.

```python
import json, os
from crawlcheck import CrawlCheck, new_log_store
store = json.load(open("cc-log.json")) if os.path.exists("cc-log.json") else new_log_store()
client = CrawlCheck(log_store=store)
client.resolve("example.com")
r = client.log_check()          # current head, GitHub's witness co-signature (RS256, checked here), the chain down to your heads
print(r["summary"])
json.dump(client.log, open("cc-log.json", "w"))
```

## Use the site's staple

```python
v = client.resolve_for("shop.example.com", headers=response_headers)   # or staple="v=ccr1;..."
v["source"]                 # "staple" (no request made) or "network"
v["decisions"]["transact"]
```

An expired, foreign or tampered staple is ignored and the signed answer is fetched instead. `staple_check(record, host, published_kids)` does the offline check on its own. Spec: https://crawlcheck.io/spec/staple


## Hold the revocation list offline

```python
import json, os
from crawlcheck import CrawlCheck, new_revocation_store
store = json.load(open("cc-revocations.json")) if os.path.exists("cc-revocations.json") else new_revocation_store()
client = CrawlCheck(revocation_store=store)
client.sync_revocations()                       # signed, verified, a ?since= delta after the first sync
json.dump(client.revocations, open("cc-revocations.json", "w"))
ok, _ = client.guard("pay.example.com", "transact")
client.last_guard.get("revoked")                # set when the held list refused it - no request was made
```

Owner incidents, suspected impersonations and unconfirmed high-risk field changes are listed. `revoked_for(store, domain, action)` is the same check on its own; reading and citing are never revoked by this list.

## Look up without naming the domain

`CrawlCheck(private_lookups=True)` makes `resolve()` and `resolve_for()` send only the first 2 hex characters of sha256(domain) and verify the matching answer locally. A domain with no public measurement raises `CrawlCheckError` (404) instead of a just-in-time answer. `preflight()` and `guard()` still send the domain: a receipt is bound to it.
