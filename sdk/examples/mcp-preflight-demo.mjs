// Preflight as an MCP client extension: the official MCP TypeScript client, wrapped so `connect` and `callTool` are
// decided before anything is sent. Run: node mcp-preflight-demo.mjs (needs @modelcontextprotocol/sdk and @crawlcheck/sdk).
//
//   1. A server on a domain nothing vouches for -> the connect is refused; no packet leaves the client.
//   2. CrawlCheck's own MCP server (connect = require_confirmation) -> refused when nobody confirms, connected when a
//      person says yes; the signed receipt is shown and verifies offline.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CrawlCheck, withPreflight, McpPreflightRefused } from "@crawlcheck/sdk";

const cc = new CrawlCheck();
const sent = [];
const watchedFetch = async (u, init) => { sent.push((init && init.method || "GET") + " " + String(u)); return fetch(u, init); };   // every request the transport makes

async function attempt(label, url, opts) {
  const client = withPreflight(new Client({ name: "preflight-demo", version: "1.0.0" }), cc, opts);
  const before = sent.length;
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(url), { fetch: watchedFetch }));
    const tools = await client.listTools();
    console.log(label + ": CONNECTED, " + tools.tools.length + " tools listed; receipt " + client.preflight.state.receipt.decision + " sha256 " + client.preflight.state.receipt.sha256.slice(0, 16));
    await client.close();
  } catch (e) {
    if (!(e instanceof McpPreflightRefused)) throw e;
    console.log(label + ": REFUSED at " + e.stage + " - " + e.why);
    console.log("   decision " + (e.receipt && e.receipt.decision) + ", receipt sha256 " + (e.receipt && e.receipt.sha256 && e.receipt.sha256.slice(0, 16)) + ", verifies offline: " + (e.verification && e.verification.verified));
  }
  console.log("   requests the MCP transport sent: " + (sent.length - before));
}

await attempt("1. mcp.example.com (no record)", "https://mcp.example.com/mcp", {});
await attempt("2a. crawlcheck.io/mcp, nobody to confirm", "https://crawlcheck.io/mcp", {});
await attempt("2b. crawlcheck.io/mcp, a person confirms", "https://crawlcheck.io/mcp", { confirm: async (r) => { console.log("   confirm? " + r.decision + ": " + ((r.steps || [])[0] || {}).why); return true; } });
