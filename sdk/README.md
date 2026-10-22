# @crawlcheck/sdk

A typed client for the CrawlCheck API and the offline verifier for its evidence, in one package with no dependencies.

```sh
npm i @crawlcheck/sdk
```

## Check before acting

```js
import { CrawlCheck } from "@crawlcheck/sdk";
const cc = new CrawlCheck();
const { proceed, receipt } = await cc.guard("example.com", "read", { agent: "MyAgentBot" });
// proceed is true on allow; warn proceeds only with { allowWarn: true }; require_confirmation only if confirm(receipt) resolves true.
// The receipt is a signed crawlcheck-decision; guard() verified it here and checked its key against the published directory.
```

Every verification returns `integrity_valid`, `issuer_trusted` and `accepted`. Act on `accepted`: it needs the signing key to be one CrawlCheck publishes, so a document someone signed with their own key is `verified` offline but never `accepted`. The client methods (`verifyDocument`, `verifyOffline`, `verifyReceiptOffline`, `guard`) check the published key directory for you.

Since 1.8.0 an MCP connect decision names the server and, with a lockfile, its approved `tools_sha256` (`preflight(domain, "connect", { mcp: { url, tools_sha256 } })`; `withPreflight` sends it for you). CrawlCheck reads the live tools from its own network: a changed tool list comes back as `block`, and the signed receipt's `assessed` block says exactly which endpoint and tool state it covered.

Since 1.8.0 they also apply the signing policy (https://crawlcheck.io/keys#policy): which key purpose may sign which object at which time (decision receipts move to the decision key at 2026-11-09 17:00 UTC), retired keys (valid only for documents signed before they stopped) and compromised keys (never valid on their signature alone). The result carries `key_policy_valid`, and `accepted` needs it. Offline, build the same input from copies you saved: `keyPolicyFrom(savedDirectory, savedRotationRecord)`, then `applyKeyPolicy(result, doc, kp)` or `guard(domain, action, { onlineKeys: false, keyPolicy })`. A saved copy cannot know a key retired or compromised after you saved it.

`accepted` says who signed a document. It is not permission to act: a valid receipt can say `block`, `warn` or `require_confirmation`. `guard()` decides that part.

`preflight(domain, action, { agent, template, policy })` returns the signed receipt without deciding for you; `verifyDocument(doc)` verifies any signed resolve answer or decision receipt offline. `resolve(domain)` returns the full signed ResolveV1 answer.

## Give your agent the check as a tool

Three tools your agent can call itself: `crawlcheck_check_site` (the signed, verified decision for an action on a site, including the business facts the site publishes and which AI engines get them wrong), `crawlcheck_verify_fact` (one signed verdict on a phone number, address, hours or service area you hold: does the business publish it, did it once, or whose is it) and `crawlcheck_fetch` (fetches a page only after its domain, and every redirect hop, is allowed). All fail closed.

```js
import { CrawlCheck, agentTools, toolsFor } from "@crawlcheck/sdk";
const tools = agentTools(new CrawlCheck(), { agent: "MyAgentBot" });

// OpenAI function calling
const oa = toolsFor("openai", tools);          // oa.tools → tools: [...]; on a tool call: await oa.call(name, argumentsJson)
// Anthropic tool use
const an = toolsFor("anthropic", tools);       // an.tools → tools: [...]; on tool_use: await an.call(block.name, block.input)
// Vercel AI SDK
import { tool, jsonSchema } from "ai";
const vt = Object.fromEntries(tools.map((t) => [t.name, tool({ description: t.description, parameters: jsonSchema(t.parameters), execute: t.execute })]));
// An MCP server you run
const mc = toolsFor("mcp", tools);             // list mc.tools; answer tools/call with mc.call(name, args)
```

## Read a record

```js
import { CrawlCheck } from "@crawlcheck/sdk";
const cc = new CrawlCheck();                       // { key: "cc_…" } for licence-gated fields
const mr = await cc.machineRecord({ domain: "example.com" });
mr.findings;            // gated exactly like the website: the top finding without a licence
mr.score_ledger;        // what each row and finding does to the grade
```

Every request and response type is generated from https://crawlcheck.io/openapi.json. Any documented route is callable with types checked against the contract:

```ts
await cc.get("/api/explain", { domain: "example.com", code: "NO_LLMS_TXT" });
await cc.get("/api/explain", { website: "x" });   // compile error: not a parameter of this operation
```

## Use the site's staple

A site can serve its own signed verdict in the `CrawlCheck-Staple` header (and at `/.well-known/crawlcheck-staple.json`). `resolveFor` uses it when it verifies, with no request to CrawlCheck, and falls back to a signed lookup when it is missing, expired, for another domain or tampered:

```js
const res = await fetch("https://shop.example.com/");
const v = await client.resolveFor("shop.example.com", { response: res });
v.source;              // "staple" or "network"
v.decisions.transact;  // allow | warn | require_confirmation | block | unsupported
```

`stapleCheck(record, { host, publishedKids })` does the offline check on its own. Spec: https://crawlcheck.io/spec/staple

## Hold the revocation list offline

CrawlCheck signs a list of domains whose connect or transact decision is block now: an owner-declared incident, a suspected impersonation of a top-10,000 brand, or an unconfirmed change to a payment, checkout, wallet, login, mail or MCP field. `syncRevocations()` fetches it (a `?since=` delta after the first sync), checks the signature and the published key, and applies it. From then on `guard()` refuses a listed domain for a listed action with no request at all, so it keeps working with the network cut:

```js
import fs from "node:fs";
import { CrawlCheck, newRevocationStore } from "@crawlcheck/sdk";
const store = fs.existsSync("cc-revocations.json") ? JSON.parse(fs.readFileSync("cc-revocations.json", "utf8")) : newRevocationStore();
const client = new CrawlCheck({ revocationStore: store });
await client.syncRevocations();                 // every poll_seconds (60), and before going offline
fs.writeFileSync("cc-revocations.json", JSON.stringify(client.revocations));
const g = await client.guard("pay.example.com", "transact");
g.revoked;                                      // set when the held list refused it: { domain, actions, causes, since }
```

`revokedFor(store, domain, action)` is the same check on its own. Reading and citing are never revoked by this list.

## Look up without naming the domain

`new CrawlCheck({ privateLookups: true })` makes `resolve()` and `resolveFor()` send only the first 2 hex characters of sha256(domain); the signed answer is picked out of the bucket and verified locally. A domain CrawlCheck has never measured raises a 404 instead of a just-in-time answer, because making one would name it. `preflight()` and `guard()` still send the domain: a receipt is bound to it.

## Preflight inside your MCP client

Wrap the official MCP client so `connect` and `callTool` are decided before anything is sent ([proposal](https://crawlcheck.io/spec/mcp-preflight)):

```js
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CrawlCheck, withPreflight, McpPreflightRefused } from "@crawlcheck/sdk";

const client = withPreflight(new Client({ name: "my-agent", version: "1.0.0" }), new CrawlCheck(), {
  confirm: async (receipt) => askTheUser(receipt),   // require_confirmation, and destructive tools with confirmDestructive
  lock: approvedLock,                                 // optional: refuse a server whose tools changed, and any tool outside the lock
});
try { await client.connect(new StreamableHTTPClientTransport(new URL(url))); }
catch (e) { if (e instanceof McpPreflightRefused) console.log(e.stage, e.why, e.receipt.decision); else throw e; }
```

`block`, `unsupported`, an unverifiable receipt, or `require_confirmation` with no yes refuse the connect before `initialize`. Other client stacks use the bare hooks: `mcpPreflight(cc, opts)` returns `beforeConnect`, `afterConnect` and `beforeToolCall`. A runnable demo is in `examples/mcp-preflight-demo.mjs`.

## Do not trust the API: check the evidence yourself

```js
const v = await cc.verifyOffline(mr.subject.report_id);   // downloads the bundle, verifies it HERE
v.checks;   // manifest hash, Ed25519 signature, key id, record digest, Merkle path to the day's root,
            // OpenTimestamps proof (Bitcoin), sealed roots over fetches, decisions and facts
```

`ok: true` passed, `ok: false` failed, `ok: null` could not run and `why` says why. A null is never a pass.

Remediation receipts (before, declared fix, deployment, after, verdict, signed):

```js
import { verifyReceipt } from "@crawlcheck/sdk";
const rc = await cc.receipt("rc1:…");
const r = await verifyReceipt(rc);                                  // hash, key id, signature, order
const ours = (await cc.publishedKeyIds()).includes(rc.signature.kid);  // the one check offline cannot do
const accept = r.verified && ours;
```

## Prove the verifier

```js
const suite = await cc.conformance();   // 19 real bundles and receipts, valid and tampered, with expected outputs
suite.ok;                              // every fixture gave exactly its expected checks and verdict
```

`npm test` in the installed package runs the conformance suite and live checks against crawlcheck.io.

## Catch a split view

Every Resolve answer names its leaf in CrawlCheck's transparency log and, once merged, carries the signed tree head of its batch. The client keeps every head it sees in `client.log` (plain JSON) and checks each new one against its neighbours: two heads for one batch, or a head that does not chain to the one before, is a **fork**, kept with both signed heads as proof. `guard()` refuses to proceed while the client holds one.

```js
import fs from "node:fs";
import { CrawlCheck, newLogStore } from "@crawlcheck/sdk";
const store = fs.existsSync("cc-log.json") ? JSON.parse(fs.readFileSync("cc-log.json", "utf8")) : newLogStore();
const client = new CrawlCheck({ logStore: store });
await client.resolve("example.com");                 // the answer's head is checked against the store
const r = await client.logCheck();                   // current head + GitHub's witness co-signature + the chain down to your heads
console.log(r.summary);                              // "consistent: ..." or "SPLIT VIEW: ..."
fs.writeFileSync("cc-log.json", JSON.stringify(client.log));
```

`logCheck` verifies the outside witness: a GitHub Actions run re-checks the chain and co-signs the newest head with a GitHub OIDC token (RS256, GitHub's key) whose audience is the head's digest. A head the witness's chain does not contain shows up as a fork. Heads newer than the witnessed one are listed as `unwitnessed`. Clients can also swap heads directly: `logHeads(store)` on one side, `client.logGossip(heads)` on the other. Forks are reported to `/api/v1/log/gossip` (pass `{ report: false }` to skip).

## Errors

A refused request throws `CrawlCheckError` with `status`, `body` and `locked` (true for "this needs a licence for the domain").

Requires Node 20+ or any current browser (WebCrypto Ed25519).
