import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs";
import { stapleCheck, stapleFromResponse, CrawlCheck } from "../dist/index.js";
const F = JSON.parse(fs.readFileSync(new URL("./fixtures/staple.json", import.meta.url), "utf8"));
const kids = [F.kid];
test("valid staple verifies offline", async () => { const c = await stapleCheck(F.valid, { host: "example.com", publishedKids: kids }); assert.equal(c.valid, true); assert.equal(c.decisions.transact, "block"); });
test("subdomain of the stapled domain is covered", async () => { assert.equal((await stapleCheck(F.valid, { host: "shop.example.com", publishedKids: kids })).valid, true); });
test("expired staple is ignored", async () => { const c = await stapleCheck(F.expired, { host: "example.com", publishedKids: kids }); assert.equal(c.valid, false); assert.equal(c.expired, true); });
test("staple for another domain is refused", async () => { assert.equal((await stapleCheck(F.foreign, { host: "example.com", publishedKids: kids })).valid, false); });
test("tampered staple fails the signature", async () => { const c = await stapleCheck(F.tampered, { host: "example.com", publishedKids: kids }); assert.equal(c.valid, false); assert.match(c.reason, /signature/); });
test("unpublished key is refused", async () => { assert.equal((await stapleCheck(F.valid, { host: "example.com", publishedKids: ["someone-else"] })).valid, false); });
test("header is read from a response", () => { assert.equal(stapleFromResponse({ headers: new Headers({ "CrawlCheck-Staple": F.valid }) }), F.valid); assert.equal(stapleFromResponse({ "crawlcheck-staple": "x" }), "x"); });
function mockClient(calls) { return new CrawlCheck({ fetch: async (u) => { calls.push(String(u)); if (String(u).includes("signatures-directory")) return new Response(JSON.stringify({ keys: [{ kid: F.kid }] })); return new Response(JSON.stringify({ kind: "crawlcheck-resolve", actions: { read: { decision: "warn" }, cite: { decision: "warn" }, connect: { decision: "unsupported" }, transact: { decision: "require_confirmation" } } })); } }); }
test("resolveFor prefers a valid staple and makes no resolve request", async () => { const calls = []; const r = await mockClient(calls).resolveFor("example.com", { staple: F.valid }); assert.equal(r.source, "staple"); assert.equal(calls.some((u) => u.includes("/api/v1/resolve")), false); });
test("resolveFor ignores an expired staple and asks CrawlCheck", async () => { const calls = []; const r = await mockClient(calls).resolveFor("example.com", { staple: F.expired }); assert.equal(r.source, "network"); assert.equal(r.decisions.read, "warn"); assert.equal(r.staple.expired, true); assert.equal(calls.some((u) => u.includes("/api/v1/resolve")), true); });
