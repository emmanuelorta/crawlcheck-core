import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { identifyBot, ipInCidr, ip4ToInt, ip6ToBig, verifyBotIP, verifyLines, BOT_TOKENS, BOT_FEED_OF, BOT_IP_FEEDS, CRAWLERS } from "../src/agents.js";

const fx = (n) => JSON.parse(readFileSync(new URL("./fixtures/" + n, import.meta.url), "utf8"));
const ranges = fx("ranges.json");

test("identifyBot: longest matching token wins, case-insensitive", () => {
  assert.equal(identifyBot("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"), "GPTBot");
  assert.equal(identifyBot("mozilla/5.0 (compatible; oai-searchbot/1.0)"), "OAI-SearchBot");
  assert.equal(identifyBot("Applebot-Extended/0.1"), "Applebot-Extended", "the longer token beats its prefix");
  assert.equal(identifyBot("Mozilla/5.0 (Windows NT 10.0) Chrome/128"), null);
  assert.equal(identifyBot(""), null);
});

test("every feed family named in BOT_FEED_OF has a feed URL", () => {
  for (const fam of new Set(Object.values(BOT_FEED_OF))) assert.ok(BOT_IP_FEEDS[fam], fam);
  // Production carries "Meta-ExternalAgent" and "meta-externalagent" — a case
  // variant, harmless because matching is case-insensitive. Kept verbatim for parity.
  assert.equal(new Set(BOT_TOKENS.map((t) => t.toLowerCase())).size, BOT_TOKENS.length - 1);
  assert.equal(identifyBot("meta-externalagent/1.1"), "Meta-ExternalAgent");
  assert.equal(CRAWLERS.length, 18);
});

test("ip4ToInt / ip6ToBig reject malformed input", () => {
  assert.equal(ip4ToInt("1.2.3"), null);
  assert.equal(ip4ToInt("1.2.3.256"), null);
  assert.equal(ip4ToInt("10.0.0.1"), 167772161);
  assert.equal(ip6ToBig("2001:db8::1"), (0x20010db8n << 96n) | 1n);
  assert.equal(ip6ToBig("::ffff:1.2.3.4"), 0xffff01020304n, "IPv4-mapped");
  assert.equal(ip6ToBig("1:2:3:4:5:6:7:8:9"), null);
});

test("ipInCidr: v4 and v6, family mismatch is false, /0 is everything", () => {
  assert.equal(ipInCidr("10.1.2.3", "10.0.0.0/8"), true);
  assert.equal(ipInCidr("11.1.2.3", "10.0.0.0/8"), false);
  assert.equal(ipInCidr("107.20.236.151", "107.20.236.150/32"), false, "a /32 is one address");
  assert.equal(ipInCidr("2001:db8:1::1", "2001:db8::/32"), true);
  assert.equal(ipInCidr("2001:db9::1", "2001:db8::/32"), false);
  assert.equal(ipInCidr("10.0.0.1", "2001:db8::/32"), false);
  assert.equal(ipInCidr("10.0.0.1", "0.0.0.0/0"), true);
});

test("verifyBotIP: three states, and an absent feed is null not false", () => {
  assert.equal(verifyBotIP("CCBot", "1.2.3.4", ranges), null, "no feed for the operator");
  assert.equal(verifyBotIP("GPTBot", "1.2.3.4", ranges), false);
  assert.equal(verifyBotIP("GPTBot", "1.2.3.4", { feeds: {} }), null, "feed unreadable is not forgery");
  assert.equal(verifyBotIP("GPTBot", "", ranges), null);
});

test("parity with the production verifier (/api/tool/verify) on 11 real lines", () => {
  const lines = fx("verify.lines.json");
  const expected = fx("verify.expected.json");
  const got = verifyLines(lines, ranges);
  assert.equal(got.counted, expected.counted);
  assert.deepEqual(got.tally, expected.tally);
  assert.equal(got.forged_rate_pct, expected.forged_rate_pct);
  assert.deepEqual(got.rows.map((r) => [r.bot, r.ip, r.verdict]), expected.rows.map((r) => [r.bot, r.ip, r.verdict]));
});

test("forged rate divides by verified + spoofed only; null when nothing is checkable", () => {
  const r = verifyLines(["1.2.3.4 - CCBot/2.0", "5.6.7.8 - Bytespider"], ranges);
  assert.equal(r.forged_rate_pct, null);
  assert.deepEqual(r.tally, { verified: 0, spoofed: 0, unverifiable: 2, no_bot: 0 });
});
