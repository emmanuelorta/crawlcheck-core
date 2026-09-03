// crawlcheck-core / surfaces.js
// The agent-surface probes from CrawlCheck (crawlcheck.io), extracted verbatim
// from the production scanner. ESM, no dependencies. These are the only fetching
// functions in the package; they use the global fetch (Node 20+, Workers, Deno).
//
// THE ACCEPT TRAP, which is why this module exists.
// A scanner's Accept header is part of its identity, and getting it wrong makes
// the whole grade a measurement of the wrong document. This fetcher sent
// `Accept: */*` until 2026-09-01. vercel.com answered that with 3,025 bytes of
// text/markdown, while every named-crawler row (which sends text/html) received
// the 521 KB page. The scan then scored mobile 0 — there is no viewport meta in
// a markdown file — entity-map parity 0, and graded the site F: a grade about a
// document no crawler is ever handed. Googlebot, GPTBot and ClaudeBot all send a
// browser-shaped Accept, so CRAWLER_ACCEPT does too.
//
// Markdown negotiation is therefore measured ON PURPOSE, ONCE, in agentSurfaces,
// with its own request that turns on `Accept: text/markdown` — never as a side
// effect of how the page was fetched. Anything else conflates "this site offers
// markdown to agents" with "our scanner asked for the wrong thing".
//
// The four .well-known probes are fired together, not in series: three of them
// are 404s on most sites and ship the full 404 HTML, so serial cost 3.2s of a
// 22s scan while measuring nothing that depends on order. A 200 that hands back
// HTML is a SOFT 404 and counts as absent — the check every naive scanner fails.

export const BOT_URL = "https://crawlcheck.io/bot";
export const UA = `Mozilla/5.0 (compatible; CrawlCheck/1.0; +${BOT_URL})`;

export const TIMEOUT_MS = 10000;

export function abortable(ms) {
  const c = new AbortController();
  setTimeout(() => c.abort(), ms);
  return c.signal;
}

// ACCEPT IS PART OF THE IDENTITY. This fetcher sent Accept: */* until
// 2026-09-01, and vercel.com answered it with 3,025 bytes of text/markdown
// while every named crawler row (which sends text/html) received the 521 KB
// page. The scan then scored mobile 0 (no viewport in a markdown file),
// entity-map parity 0 and graded the site F - a grade about a document no
// crawler is ever handed. Googlebot, GPTBot and ClaudeBot all send a
// browser-shaped Accept; so does this fetcher now. Markdown negotiation is
// measured on purpose, once, in agentSurfaces, with Accept: text/markdown.
export const CRAWLER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
export async function grab(url) {
  const t0 = Date.now();
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": UA, Accept: CRAWLER_ACCEPT },
      redirect: "follow",
      signal: abortable(TIMEOUT_MS),
    });
    const buf = await res.arrayBuffer();
    const bytes = buf.byteLength;
    const body = new TextDecoder("utf-8", { fatal: false }).decode(
      buf.slice(0, 60000)
    );
    const headers = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    return {
      status: res.status,
      headers,
      body,
      bytes,
      finalUrl: res.url || url,
      ms: Date.now() - t0,
      error: null,
    };
  } catch (e) {
    return {
      status: null,
      headers: {},
      body: "",
      bytes: 0,
      finalUrl: url,
      ms: Date.now() - t0,
      error: String(e && e.message ? e.message : e),
    };
  }
}

export const looksHtml = (body, ctype) => {
  const head = body.slice(0, 2000).trimStart().toLowerCase();
  return (
    head.startsWith("<!doctype html") ||
    head.startsWith("<html") ||
    (ctype || "").includes("text/html")
  );
};

// ── agent surfaces ────────────────────────────────────────────────────────
// Five extra requests, capped and non-fatal. Deliberately NOT a probe per
// standard: DNS-AID needs a DNSSEC-signed SVCB lookup a Worker cannot make,
// and the OAuth/commerce documents are only meaningful once something on the
// site indicates there is an API or a checkout to protect. Guessing at those
// costs requests and buys nothing.
export const SURFACE_PATHS = [
  ["agents_md", "/agents.md"],
  ["agent_skills", "/.well-known/agent-skills/index.json"],
  ["mcp_card", "/.well-known/mcp/server-card.json"],
  ["api_catalog", "/.well-known/api-catalog"]
];
export async function agentSurfaces(base, root) {
  const out = { checked_at: new Date().toISOString(), found: {}, evidence: {} };
  // Four probes fired together, not one after another. Three of the four are
  // 404s on most sites and ship the full 404 HTML, so serial cost 3.2s of a
  // 22s scan while measuring nothing that depends on order.
  await Promise.all(SURFACE_PATHS.map(function (pair) {
    return grab(base + pair[1]).then(function (g) {
      out.found[pair[0]] = g.status === 200 && !looksHtml(g.body, (g.headers || {})["content-type"] || "");
      out.evidence[pair[0]] = { status: g.status, bytes: g.bytes || 0 };
    }).catch(function () { out.found[pair[0]] = null; });
  }));
  // Link headers come free off the response we already hold - no extra request.
  const lh = ((root && root.headers) || {})["link"] || "";
  out.found.link_header = !!lh;
  out.evidence.link_header = { value: lh.slice(0, 180) };
  // Markdown negotiation needs its own request because it turns on Accept.
  try {
    const res = await fetch(base + "/", {
      headers: { "User-Agent": UA, Accept: "text/markdown" },
      redirect: "follow", signal: abortable(TIMEOUT_MS)
    });
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    out.found.markdown = ct.indexOf("text/markdown") !== -1;
    out.evidence.markdown = { content_type: ct.slice(0, 60) };
  } catch (e) { out.found.markdown = null; }
  return out;
}

// agents.md — the INSTRUCTION file for agents, as distinct from llms.txt which
// is the content map. Found the convention empirically: gymshark's robots.txt
// names it in a comment ("# Agent instructions: .../agents.md"), and every
// Shopify store ships one from the same ~4.3KB template. Vercel ships 1.5MB.
// Reported, NOT scored on its own: adoption is early and absence is not a
// defect. What IS scored is its CONTENT - it goes through the same
// instruction-pattern scan as hidden text, because it is the one file on a
// site written to be obeyed by a machine.
// SKILL.md — the agent-skill document. Shopify points every merchant's agents.md
// at shop.app/SKILL.md rather than each store serving its own, so PRESENCE here
// means the operator authored one. Unscored: adoption is early and absence is
// not a defect. A 200 that hands back HTML is a soft 404 (vercel.com serves
// 1.5 MB of SPA shell at this path) — same rule as agentsMd.
export async function skillMd(host) {
  const out = { url: "https://" + host + "/SKILL.md", status: null, bytes: 0, markdown: false, frontmatter: false, name: "", present: false };
  try {
    const r = await fetch(out.url, { headers: { "user-agent": UA, accept: "text/markdown, text/plain" }, redirect: "follow" });
    out.status = r.status;
    if (r.status !== 200) return out;
    const ct = String(r.headers.get("content-type") || "").toLowerCase();
    const b = (await r.text()).slice(0, 60000);
    out.bytes = b.length;
    if (/^\s*<(!doctype|html)/i.test(b)) return out;      // soft 404
    if (/html/.test(ct) && !/markdown|plain/.test(ct)) return out;
    out.markdown = /markdown|plain/.test(ct);
    const fm = /^---\r?\n([\s\S]{0,2000}?)\r?\n---/.exec(b);
    if (fm) {
      out.frontmatter = true;
      const n = /(^|\n)name:\s*(.+)/.exec(fm[1]);
      if (n) out.name = String(n[2]).trim().replace(/^["']|["']$/g, "").slice(0, 60);
    }
    out.present = true;
  } catch (e) { }
  return out;
}
export async function agentsMd(host) {
  const out = { url: "https://" + host + "/agents.md", status: null, bytes: 0, text: "" };
  try {
    const r = await fetch(out.url, { redirect: "follow", signal: abortable(8000),
      headers: { "user-agent": UA, accept: "text/markdown,text/plain" } });
    out.status = r.status;
    if (r.status !== 200) return out;
    const b = (await r.text()).slice(0, 300000);
    // A 200 that hands back HTML is a soft 404, not a policy file.
    if (/^\s*<(!doctype|html)/i.test(b)) { out.status = 200; out.bytes = b.length; out.text = ""; out.html = true; return out; }
    out.bytes = b.length;
    out.text = b;
  } catch (e) { /* absent is the common case; never invent a verdict */ }
  return out;
}

export function surfaceApplicability(r) {
  const t = new Set((r.schema_types || []).map(String));
  const commerce = t.has("Product") || t.has("Offer") || t.has("OnlineStore") ||
    t.has("AggregateOffer") || !!(r.commerce && r.commerce.detected);
  const api = !!((r.agent_surfaces || {}).found || {}).api_catalog;
  return { commerce: commerce, api: api };
}

export function agentSurfaceRows(r) {
  const f = ((r.agent_surfaces || {}).found) || {};
  const ev = ((r.agent_surfaces || {}).evidence) || {};
  const app = surfaceApplicability(r);
  const state = function (k) { return f[k] === null || f[k] === undefined ? "not checked" : (f[k] ? "present" : "absent"); };
  const rows = [];
  rows.push({ k: "agents.md", ok: null, cur: state("agents_md"),
    opt: "An authored file at /agents.md: what the business does, the area it serves, what an agent must collect before acting, and what it must not promise",
    why: "The one surface here that pays off for an ordinary business today. Almost every agents.md on the web is a platform default its owner never wrote" });
  // SKILL.md was fetched on every scan since 2026-08-23 and rendered nowhere.
  const __sk = r.skillmd;
  rows.push({ k: "SKILL.md", ok: null,
    cur: !__sk ? "not checked" : __sk.present ? "present" + (__sk.name ? " (name: " + __sk.name + ")" : "") + (__sk.frontmatter ? "" : ", no frontmatter")
      : (__sk.status === 200 && !__sk.markdown ? "absent (200 with HTML - a soft 404)" : "absent" + (__sk.status ? " (" + __sk.status + ")" : "")),
    opt: "A markdown file at /SKILL.md with YAML frontmatter naming the skill, then what an agent can do here and how",
    why: "The agent-skills convention. A 200 that carries HTML is a soft 404 and counts as absent - a naive check would call it present" });
  rows.push({ k: "Markdown for agents", ok: null, cur: state("markdown") + (ev.markdown && ev.markdown.content_type ? " (" + ev.markdown.content_type + ")" : ""),
    opt: "Accept: text/markdown returns a markdown body; HTML stays the default for browsers",
    why: "Cuts what an agent must parse. A toggle on some edges rather than a build" });
  rows.push({ k: "Link response headers", ok: null, cur: state("link_header") + (ev.link_header && ev.link_header.value ? ": " + ev.link_header.value : ""),
    opt: "Registered relations only - canonical, alternate, describedby. Never an invented rel to satisfy a checker",
    why: "Useful where a relation is real. Inventing one to score a point is the cargo-culting these lists encourage" });
  rows.push({ k: "Agent skills index", ok: null, cur: state("agent_skills"),
    opt: "/.well-known/agent-skills/index.json listing each skill with a name, description, url and sha256",
    why: "For sites that expose actions an agent can perform. A brochure site has no skills to declare" });
  rows.push({ k: "API catalog", ok: null, cur: state("api_catalog"),
    opt: app.api ? "application/linkset+json with service-desc, service-doc and status links per API"
      : "Nothing to publish - no API was discoverable on this site",
    why: app.api ? "An API is discoverable here, so a catalog is worth publishing" : "NOT APPLICABLE: no public API found. A catalog of nothing is not an improvement" });
  rows.push({ k: "MCP server card", ok: null, cur: state("mcp_card"),
    opt: "/.well-known/mcp/server-card.json with serverInfo, transport endpoint and capabilities",
    why: "Applies once you run an MCP server. Publishing a card without one advertises an endpoint that does not answer" });
  rows.push({ k: "Agent payment protocols", ok: null, cur: app.commerce ? "no profile published" : "not applicable",
    opt: app.commerce ? "x402, MPP, UCP or ACP - pick the one your processor actually supports rather than all four"
      : "Nothing to publish - no commerce signals on this site",
    why: app.commerce ? "Commerce markup is present, so agent-native payment is a real question" : "NOT APPLICABLE: no Product, Offer or checkout found. A scanner that docks a service business for this is measuring the wrong site" });
  rows.push({ k: "OAuth / protected-resource metadata", ok: null, cur: app.api ? "no metadata published" : "not applicable",
    opt: app.api ? "/.well-known/oauth-protected-resource naming the resource, its authorization servers and scopes"
      : "Nothing to publish - no protected API on this site",
    why: app.api ? "There is an API here worth describing" : "NOT APPLICABLE: nothing to authenticate against" });
  rows.push({ k: "Web Bot Auth", ok: null, cur: "informational",
    opt: "A JWKS at /.well-known/http-message-signatures-directory - only if THIS site sends signed agent requests to others",
    why: "Identifies you as a caller, not as a destination. Irrelevant to a site that only receives traffic" });
  return rows;
}
