// Measures agent-surface adoption across a ranked sample of real sites,
// using the same module the scanner uses. Nothing here is estimated: every
// row is one HTTP response, and a 200 that answers with HTML is recorded as
// absent (a soft 404), not as present.
import { readFileSync, writeFileSync } from "node:fs";
import { grab, looksHtml, UA, TIMEOUT_MS, abortable } from "../src/surfaces.js";

const N = Number(process.argv[2] || 500);
const CONC = Number(process.argv[3] || 25);
const rows = readFileSync("/tmp/tranco.csv", "utf8").trim().split("\n").slice(0, N)
  .map((l) => { const [rank, domain] = l.split(","); return { rank: Number(rank), domain: domain.trim() }; });

const PATHS = [
  ["llms_txt", "/llms.txt"],
  ["agents_md", "/agents.md"],
  ["skill_md", "/SKILL.md"],
  ["agent_skills", "/.well-known/agent-skills/index.json"],
  ["mcp_card", "/.well-known/mcp/server-card.json"],
  ["api_catalog", "/.well-known/api-catalog"],
];

async function markdownNegotiation(base) {
  try {
    const res = await fetch(base + "/", {
      headers: { "User-Agent": UA, Accept: "text/markdown" },
      redirect: "follow", signal: abortable(TIMEOUT_MS),
    });
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    return { ok: true, status: res.status, content_type: ct.slice(0, 60), markdown: ct.indexOf("text/markdown") !== -1 };
  } catch (e) { return { ok: false, status: null, content_type: "", markdown: null }; }
}

async function probe(site) {
  const base = "https://" + site.domain;
  const out = { rank: site.rank, domain: site.domain, reachable: false, found: {}, soft404: {}, status: {} };
  const root = await grab(base + "/");
  out.reachable = root.status !== null;
  out.root_status = root.status;
  if (!out.reachable) return out;
  out.link_header = !!(root.headers || {})["link"];
  const md = await markdownNegotiation(base);
  out.found.markdown = md.markdown;
  out.markdown_content_type = md.content_type;
  await Promise.all(PATHS.map(async ([key, path]) => {
    const g = await grab(base + path);
    const html = looksHtml(g.body || "", (g.headers || {})["content-type"] || "");
    out.status[key] = g.status;
    out.found[key] = g.status === 200 && !html;
    out.soft404[key] = g.status === 200 && html;   // the trap a naive checker falls into
  }));
  return out;
}

const results = [];
let done = 0;
const queue = rows.slice();
await Promise.all(Array.from({ length: CONC }, async () => {
  while (queue.length) {
    const site = queue.shift();
    try { results.push(await probe(site)); } catch (e) { results.push({ rank: site.rank, domain: site.domain, error: String(e.message || e) }); }
    if (++done % 50 === 0) process.stderr.write(`  ${done}/${rows.length}\n`);
  }
}));

results.sort((a, b) => a.rank - b.rank);
writeFileSync("/home/claude/tranco-surfaces.json", JSON.stringify({
  list: "Tranco ZJQ6G", sampled: rows.length, measured_at: new Date().toISOString(),
  method: "One HTTPS request per path with the CrawlCheck user-agent and a browser-shaped Accept, except the markdown probe which sends Accept: text/markdown. A 200 whose body is HTML is recorded as absent (soft 404).",
  results,
}, null, 1));

const reach = results.filter((r) => r.reachable);
const pct = (n) => (100 * n / reach.length).toFixed(1) + "%";
const count = (k, obj = "found") => reach.filter((r) => r[obj] && r[obj][k]).length;
console.log("\nsampled:", rows.length, "| reachable:", reach.length);
console.log("\nsurface                 present        soft-404 (200 with HTML)");
for (const k of ["markdown", "llms_txt", "agents_md", "skill_md", "agent_skills", "mcp_card", "api_catalog"]) {
  const p = count(k), s = k === "markdown" ? 0 : count(k, "soft404");
  console.log(`${k.padEnd(22)} ${String(p).padStart(4)} ${pct(p).padStart(7)}   ${k === "markdown" ? "" : String(s).padStart(4) + " " + pct(s).padStart(7)}`);
}
console.log("link header           ", reach.filter((r) => r.link_header).length, pct(reach.filter((r) => r.link_header).length));
console.log("\nsites negotiating markdown:", reach.filter((r) => r.found.markdown).map((r) => r.rank + " " + r.domain).join(", ") || "none");
console.log("\nsites serving llms.txt:", reach.filter((r) => r.found.llms_txt).map((r) => r.rank + " " + r.domain).slice(0, 40).join(", ") || "none");
console.log("\nsites serving agents.md:", reach.filter((r) => r.found.agents_md).map((r) => r.rank + " " + r.domain).slice(0, 40).join(", ") || "none");
