// Agent tools (1.6.0): shapes offline, decisions against the live API. npm test
import test from "node:test"; import assert from "node:assert/strict";
import { CrawlCheck, agentTools, toolsFor } from "../dist/index.js";
const cc = new CrawlCheck();
const tools = agentTools(cc);

test("agent tools: two tools, each with a JSON-schema object and an execute()", () => {
  assert.deepEqual(tools.map((t) => t.name), ["crawlcheck_check_site", "crawlcheck_fetch"]);
  for (const t of tools) { assert.equal(t.parameters.type, "object"); assert.equal(typeof t.execute, "function"); assert.ok(t.description.length > 40); }
});

test("toolsFor: OpenAI, Anthropic, MCP and Vercel shapes carry the same schema", () => {
  const o = toolsFor("openai", tools).tools, a = toolsFor("anthropic", tools).tools, m = toolsFor("mcp", tools).tools, v = toolsFor("vercel", tools).tools;
  assert.equal(o[0].type, "function"); assert.equal(o[0].function.parameters, tools[0].parameters);
  assert.equal(a[1].input_schema, tools[1].parameters); assert.equal(m[0].inputSchema, tools[0].parameters);
  assert.equal(typeof v.crawlcheck_fetch.execute, "function");
});

test("check_site fails closed on a non-domain without calling the API", async () => {
  const r = await toolsFor("openai", tools).call("crawlcheck_check_site", JSON.stringify({ site: "not a domain" }));
  assert.equal(r.proceed, false);
  assert.equal((await toolsFor("openai", tools).call("no_such_tool", {})).proceed, false);
});

test("live: check_site returns a verified, signed decision for crawlcheck.io", async () => {
  const r = await tools[0].execute({ site: "https://crawlcheck.io/pricing", action: "read" });
  assert.equal(r.domain, "crawlcheck.io");
  assert.ok(["allow", "warn", "require_confirmation", "block", "unsupported"].includes(r.decision), JSON.stringify(r));
  assert.match(String(r.receipt_sha256), /^[0-9a-f]{64}$/);
  assert.equal(r.verified, true);
});

test("live: fetch returns page text only after the check proceeds", async () => {
  const r = await tools[1].execute({ url: "https://crawlcheck.io/llms.txt" });
  if (r.proceed) { assert.equal(r.status, 200); assert.ok(r.text.length > 100); assert.ok(r.hops.length >= 1 && r.hops[0].proceed); }
  else assert.ok(r.why.length, "a refusal names why");
});
