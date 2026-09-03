import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { agentSurfaces, agentSurfaceRows, surfaceApplicability, skillMd, agentsMd, grab, looksHtml, UA, CRAWLER_ACCEPT, SURFACE_PATHS, TIMEOUT_MS } from "../src/surfaces.js";

const fxj = (n) => JSON.parse(readFileSync(new URL("./fixtures/" + n, import.meta.url), "utf8"));

// Record every request, answer from a table. The global fetch is what these
// functions call, so this is the whole seam — no injection, nothing rewritten.
function stub(routes) {
  const sent = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, opt) => {
    const u = String(url);
    sent.push({ url: u, headers: Object.assign({}, (opt || {}).headers) });
    const r = routes[u.replace(/^https?:\/\/[^/]+/, "")] || routes[u] || { status: 404, body: "<!doctype html><title>404</title>", type: "text/html" };
    if (r.throw) throw new Error(r.throw);
    return new Response(r.body === undefined ? "" : r.body, { status: r.status, headers: r.type ? { "content-type": r.type } : {} });
  };
  return { sent, restore: () => { globalThis.fetch = real; } };
}

const HTML404 = { status: 200, body: "<!doctype html><html><body>Page not found</body></html>", type: "text/html; charset=utf-8" };

test("the fetcher sends a browser-shaped Accept — the trap this module documents", async () => {
  const s = stub({ "/": { status: 200, body: "<!doctype html><html></html>", type: "text/html" } });
  try {
    await grab("https://example.test/");
    assert.equal(s.sent[0].headers["User-Agent"], UA);
    assert.equal(s.sent[0].headers.Accept, CRAWLER_ACCEPT);
    assert.match(CRAWLER_ACCEPT, /^text\/html/, "leading with text/html is what makes a markdown answer a deliberate finding rather than an accident");
    assert.equal(CRAWLER_ACCEPT.includes("*/*;q=0.8"), true, "*/* stays, but at a lower q than html");
    assert.equal(TIMEOUT_MS, 10000);
  } finally { s.restore(); }
});

test("markdown negotiation is one request of its own, with Accept: text/markdown", async () => {
  const s = stub({
    "/": { status: 200, body: "# Acme", type: "text/markdown; charset=utf-8" },
    "/agents.md": { status: 200, body: "# agents", type: "text/markdown" },
    "/.well-known/agent-skills/index.json": HTML404,
    "/.well-known/mcp/server-card.json": { status: 404 },
    "/.well-known/api-catalog": { status: 200, body: '{"linkset":[]}', type: "application/linkset+json" },
  });
  try {
    const out = await agentSurfaces("https://example.test", { headers: { link: '<https://example.test/>; rel="canonical"' } });
    assert.equal(out.found.markdown, true);
    assert.equal(out.evidence.markdown.content_type, "text/markdown; charset=utf-8");

    const md = s.sent.filter((r) => r.headers.Accept === "text/markdown");
    assert.equal(md.length, 1, "exactly one request negotiates markdown");
    assert.equal(md[0].url, "https://example.test/", "and it is the root, not one of the probes");
    assert.equal(s.sent.length, SURFACE_PATHS.length + 1, "four probes plus the negotiation request; the Link header costs nothing");
    for (const r of s.sent) if (r.headers.Accept !== "text/markdown") assert.equal(r.headers.Accept, CRAWLER_ACCEPT);

    assert.equal(out.found.agents_md, true);
    assert.equal(out.found.agent_skills, false, "200 with an HTML body is a soft 404, not a surface");
    assert.equal(out.found.mcp_card, false);
    assert.equal(out.found.api_catalog, true);
    assert.equal(out.found.link_header, true);
    assert.equal(out.evidence.link_header.value, '<https://example.test/>; rel="canonical"');
    assert.ok(Date.parse(out.checked_at) > 0);
  } finally { s.restore(); }
});

test("an HTML answer to Accept: text/markdown is not markdown, and a failure is null", async () => {
  let s = stub({ "/": { status: 200, body: "<!doctype html>", type: "text/html; charset=utf-8" } });
  try {
    const out = await agentSurfaces("https://example.test", null);
    assert.equal(out.found.markdown, false);
    assert.equal(out.evidence.markdown.content_type, "text/html; charset=utf-8");
    assert.equal(out.found.link_header, false, "no root response held: absent, not invented");
  } finally { s.restore(); }

  s = stub({ "/": { throw: "network down" } });
  try {
    const out = await agentSurfaces("https://example.test", null);
    assert.equal(out.found.markdown, null, "a probe that could not run is null — never false");
  } finally { s.restore(); }
});

test("looksHtml reads the body first and the content-type second", () => {
  assert.equal(looksHtml("<!DOCTYPE html><p>x", "text/plain"), true, "a doctype is html whatever the header claims");
  assert.equal(looksHtml("<html>", ""), true);
  assert.equal(looksHtml("User-agent: *", "text/html; charset=utf-8"), true, "the header alone is enough");
  assert.equal(looksHtml("User-agent: *\nDisallow:", "text/plain"), false);
  assert.equal(looksHtml("\n\n  <html>", ""), true, "leading whitespace does not hide it");
});

test("SKILL.md: a 200 carrying HTML is absent, and frontmatter names the skill", async () => {
  let s = stub({ "/SKILL.md": { status: 200, body: "---\nname: acme-fencing\n---\n\n# What an agent can do here\n", type: "text/markdown" } });
  try {
    const r = await skillMd("example.test");
    assert.equal(r.present, true);
    assert.equal(r.markdown, true);
    assert.equal(r.frontmatter, true);
    assert.equal(r.name, "acme-fencing");
  } finally { s.restore(); }

  s = stub({ "/SKILL.md": HTML404 });
  try {
    const r = await skillMd("example.test");
    assert.equal(r.status, 200);
    assert.equal(r.present, false, "the naive check calls this present; it is a soft 404");
  } finally { s.restore(); }

  s = stub({ "/agents.md": HTML404 });
  try {
    const r = await agentsMd("example.test");
    assert.equal(r.html, true);
    assert.equal(r.text, "", "an SPA shell is not an instruction file");
  } finally { s.restore(); }
});

test("surface rows are informational, and say NOT APPLICABLE rather than failing a brochure site", () => {
  const rows = agentSurfaceRows({});
  assert.equal(rows.length, 10);
  assert.equal(rows.every((r) => r.ok === null), true, "nothing here is scored: adoption is early and absence is not a defect");
  const pay = rows.find((r) => r.k === "Agent payment protocols");
  assert.equal(pay.cur, "not applicable");
  assert.match(pay.why, /measuring the wrong site/);
  assert.equal(surfaceApplicability({}).commerce, false);
  assert.equal(surfaceApplicability({ schema_types: ["Product"] }).commerce, true);
  assert.equal(surfaceApplicability({ commerce: { detected: true } }).commerce, true);
  assert.equal(surfaceApplicability({ agent_surfaces: { found: { api_catalog: true } } }).api, true);

  const withCommerce = agentSurfaceRows({ schema_types: ["Offer"], agent_surfaces: { found: { markdown: true }, evidence: { markdown: { content_type: "text/markdown" } } } });
  assert.equal(withCommerce.find((r) => r.k === "Agent payment protocols").cur, "no profile published");
  assert.equal(withCommerce.find((r) => r.k === "Markdown for agents").cur, "present (text/markdown)");
  assert.equal(agentSurfaceRows({ agent_surfaces: { found: {} } }).find((r) => r.k === "Markdown for agents").cur, "not checked");
});

// Opt in with CC_LIVE=1 to re-run the probes against the two sites the fixtures
// were captured from. Off by default so the suite needs no network.
const live = process.env.CC_LIVE === "1";
for (const domain of ["treeservicedenverllc.com", "emmanuelorta.com"]) {
  test("live: the probes still answer what the production scan recorded for " + domain, { skip: live ? false : "set CC_LIVE=1" }, async () => {
    const expected = fxj(domain + ".quotable.json");
    const base = "https://" + domain;
    const out = await agentSurfaces(base, await grab(base + "/"));
    for (const k of Object.keys(expected.agent_surfaces_found)) {
      assert.equal(out.found[k], expected.agent_surfaces_found[k], k);
    }
    assert.equal(out.evidence.markdown.content_type, expected.agent_surfaces_markdown_content_type);
  });
}
