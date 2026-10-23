import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { crawlerPolicy, parseGroups, shadowedGroups, groupFor, pathAllowed, rootAllowed, starGroup, ruleMatches, decide, AGENTS } from "../src/robots.js";

const fx = (n) => readFileSync(new URL("./fixtures/" + n, import.meta.url), "utf8");

test("parses consecutive user-agent lines into one group (RFC 9309)", () => {
  const g = parseGroups("User-agent: a\nUser-agent: b\nDisallow: /x\n\nUser-agent: c\nAllow: /");
  assert.equal(g.length, 2);
  assert.deepEqual(g[0].uas, ["a", "b"]);
  assert.deepEqual(g[0].rules, [{ allow: false, path: "/x" }]);
});

test("most specific matching group wins; * is the fallback", () => {
  const g = parseGroups("User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nAllow: /");
  assert.equal(groupFor(g, "GPTBot").named, true);
  assert.equal(groupFor(g, "Bingbot").named, false);
  assert.equal(pathAllowed(groupFor(g, "GPTBot").group, "/anything"), true);
  assert.equal(pathAllowed(groupFor(g, "Bingbot").group, "/anything"), false);
});

test("longest rule wins; Allow beats Disallow at equal length", () => {
  const g = parseGroups("User-agent: *\nDisallow: /a\nAllow: /a/b\n");
  const grp = groupFor(g, "x").group;
  assert.equal(pathAllowed(grp, "/a/c"), false);
  assert.equal(pathAllowed(grp, "/a/b/c"), true);
  const g2 = parseGroups("User-agent: *\nDisallow: /a\nAllow: /a\n");
  assert.equal(pathAllowed(groupFor(g2, "x").group, "/a"), true);
});

test("naming an agent in its own group SHADOWS every * rule for it", () => {
  const t = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /feed/\n\nUser-agent: GPTBot\nAllow: /\n";
  const p = crawlerPolicy(t, false, "/wp-admin/");
  assert.equal(p.shadowed_groups, 1);
  assert.deepEqual(p.shadowed[0], { uas: ["gptbot"], missing: ["/wp-admin/", "/feed/"], missing_count: 2, declares_own_rules: false });
  const gpt = p.agents.find((a) => a.ua === "GPTBot");
  assert.equal(gpt.allowed, true, "GPTBot reaches /wp-admin/ because its own group has no Disallow");
  assert.equal(gpt.rules_shadowed, true);
  const oai = p.agents.find((a) => a.ua === "OAI-SearchBot");
  assert.equal(oai.allowed, false, "an unnamed agent still falls under *");
});

test("a named group that repeats the * disallows is not shadowed", () => {
  const t = "User-agent: *\nDisallow: /wp-admin/\n\nUser-agent: GPTBot\nDisallow: /wp-admin/\nAllow: /\n";
  assert.equal(shadowedGroups(parseGroups(t)).length, 0);
});

test("no file / unreadable file is reported as unmeasured, never as a policy", () => {
  assert.equal(crawlerPolicy("", false).measured, false);
  assert.equal(crawlerPolicy("<html>challenge</html>", true).measured, false);
});

test("the agent table has 114 entries and no duplicates", () => {
  assert.equal(AGENTS.length, 114);
  assert.equal(new Set(AGENTS.map((a) => a[0].toLowerCase())).size, 114);
});

for (const d of ["crawlcheck.io", "terrariumstation.com"]) {
  test("parity with the production scanner: " + d, () => {
    const expected = JSON.parse(fx(d + ".expected.json"));
    const got = crawlerPolicy(fx(d + ".robots.txt"), false, expected.path);
    assert.equal(got.groups, expected.groups);
    assert.equal(got.shadowed_groups, expected.shadowed_groups);
    assert.equal(got.agents.length, expected.agents.length);
    for (let i = 0; i < got.agents.length; i++) {
      const a = got.agents[i], b = expected.agents[i];
      assert.deepEqual({ ua: a.ua, allowed: a.allowed, allowed_root: a.allowed_root, named: a.named, rules_shadowed: a.rules_shadowed },
        { ua: b.ua, allowed: b.allowed, allowed_root: b.allowed_root, named: b.named, rules_shadowed: b.rules_shadowed }, "agent " + a.ua);
    }
  });
}

// build 0.3.1 — the documented call pathAllowed(groupFor(groups, ua), path)
// threw "g.rules is not iterable" because groupFor returns an envelope.
test("pathAllowed/rootAllowed accept the groupFor envelope", () => {
  const groups = parseGroups("User-agent: GPTBot\nDisallow: /wp-admin/\nUser-agent: *\nAllow: /");
  const env = groupFor(groups, "GPTBot");
  assert.equal(pathAllowed(env, "/wp-admin/"), false);
  assert.equal(pathAllowed(env, "/"), true);
  assert.equal(rootAllowed(env), true);
  assert.equal(pathAllowed(env.group, "/wp-admin/"), false, "bare group still works");
});
test("no matching group and no * must not throw", () => {
  const env = groupFor(parseGroups("User-agent: Bingbot\nDisallow: /"), "GPTBot");
  assert.equal(env.group, null);
  assert.equal(pathAllowed(env, "/"), true);
  assert.equal(rootAllowed(env), true);
  assert.equal(pathAllowed(null, "/"), true);
  assert.equal(rootAllowed(undefined), true);
});
test("crawlerPolicy is unchanged by the unwrap", () => {
  const txt = "User-agent: GPTBot\nDisallow: /wp-admin/\nUser-agent: *\nAllow: /";
  const groups = parseGroups(txt);
  const pol = crawlerPolicy(txt, false, "/wp-admin/");
  for (const a of pol.agents) assert.equal(a.allowed, pathAllowed(groupFor(groups, a.ua), "/wp-admin/"), a.ua);
});

// 0.6.0 — RFC 9309 matching, as production has done since 2026-09-30.
test("`Disallow: /` + `Allow: /$` opens the homepage and nothing else", () => {
  const g = starGroup(parseGroups("User-agent: *\nDisallow: /\nAllow: /$\n"));
  assert.equal(rootAllowed(g), true, "the 0.5 reader stripped nothing from /$ and read the whole site closed");
  assert.equal(pathAllowed(g, "/"), true);
  assert.equal(pathAllowed(g, "/about"), false);
});

test("`*` matches anywhere in the rule, not only at the end", () => {
  const g = starGroup(parseGroups("User-agent: *\nDisallow: /*?add-to-cart=\nDisallow: /*/private/\n"));
  assert.equal(pathAllowed(g, "/shop/?add-to-cart=12"), false);
  assert.equal(pathAllowed(g, "/shop/"), true);
  assert.equal(pathAllowed(g, "/a/private/x"), false);
  assert.equal(pathAllowed(g, "/private/x"), true, "the 0.5 reader read /*/private/ as the prefix //private/");
});

test("a trailing `$` anchors the end; elsewhere `$` and `.` are literal", () => {
  assert.equal(ruleMatches("/*.pdf$", "/files/a.pdf"), true);
  assert.equal(ruleMatches("/*.pdf$", "/files/a.pdf?dl=1"), false);
  assert.equal(ruleMatches("/a.b", "/aXb"), false);
  assert.equal(ruleMatches("/$x", "/$x/y"), true);
});

test("longest match wins, and an equal-length tie goes to Allow", () => {
  assert.deepEqual(decide([{ path: "/a", allow: false }, { path: "/a/b", allow: true }], "/a/b/c"), { allowed: true, rule: "/a/b" });
  assert.deepEqual(decide([{ path: "/p", allow: false }, { path: "/p", allow: true }], "/p"), { allowed: true, rule: "/p" });
  assert.deepEqual(decide([], "/x"), { allowed: true, rule: null });
});
