import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { quoteSignals, quoteRows, quoteBlock, quotable, pctScore, SCORE_VERSION, QUOTABLE_WEIGHT } from "../src/quotable.js";
import { ldGraphNodes } from "../src/jsonld.js";

const fx = (n) => readFileSync(new URL("./fixtures/" + n, import.meta.url), "utf8");
const fxj = (n) => JSON.parse(fx(n));

const page = (body) => "<html><head><title>t</title></head><body>" + body + "</body></html>";

// ── parity with a live production scan ──────────────────────────────────────
// The fixture holds the service's own output plus the sha256 of the exact
// response body it read. The page itself is not committed: the test re-fetches
// with the scanner's user-agent and Accept, refuses to compare unless the bytes
// are identical, and only then asserts that this module reproduces the numbers.
// Opt in with CC_LIVE=1 — the offline suite needs no network.
//
// One thing is stripped before the digest is taken, and only one: the Cloudflare
// Web Analytics beacon <script> the edge injects into the response. It is not
// part of the page the site serves and it is not stable — two colos served this
// page 8 bytes apart on 2026-09-03, differing only in the beacon's build hash,
// its SRI integrity hash and an "spa" flag — so a digest over the raw bytes
// fails on the CDN's release schedule and says "the site changed" when it did
// not. The fixture names the exclusion and carries the pattern; nothing else is
// normalised. The reader never saw the element either: it is a <script>, which
// the reader excludes from content before it counts anything.
const live = process.env.CC_LIVE === "1";
const sha256 = async (buf) => Buffer.from(await crypto.subtle.digest("SHA-256", buf)).toString("hex");

test("parity with the production scanner on a live scan of treeservicedenverllc.com",
  { skip: live ? false : "set CC_LIVE=1" }, async () => {
  const expected = fxj("treeservicedenverllc.com.quotable.json");
  assert.equal(expected.reproducible, true);
  const res = await fetch(expected.page_url, {
    headers: { "user-agent": expected.fetch.user_agent, accept: expected.fetch.accept },
    redirect: "follow",
  });
  assert.equal(res.status, 200);
  const raw = Buffer.from(await res.arrayBuffer());
  const beacon = new RegExp(expected.digest_excludes_pattern, "gi");
  const buf = Buffer.from(raw.toString("latin1").replace(beacon, ""), "latin1");
  assert.ok(buf.byteLength < raw.byteLength, "the edge-injected beacon this digest excludes was not found — the exclusion pattern is stale, not the page");
  assert.equal(buf.byteLength, expected.page_bytes,
    "the page is a different length than when this fixture was captured — the site changed, not the reader");
  assert.equal(await sha256(buf), expected.page_sha256,
    "the page no longer matches the captured digest — recapture the fixture rather than loosening this check");

  const html = new TextDecoder("utf-8").decode(buf);
  const got = quoteSignals(html, ldGraphNodes(html), expected.name_hint);
  assert.equal(expected.score_version, SCORE_VERSION, "fixture captured under a different score version");
  for (const k of Object.keys(expected.quotable)) {
    assert.deepEqual(got[k], expected.quotable[k], k);
  }
  assert.equal(Object.keys(got).length, Object.keys(expected.quotable).length, "field set");
  assert.equal(pctScore(quoteRows({ quotable: got })), expected.section_score, "section score");
});

// Two recorded readings of two different sites. The second site's page carries
// live figures and cannot be re-fetched byte-identically, so it is not a parity
// target — it is here to prove the reader does not flatten one site into another.
test("the two recorded scans disagree, which is what makes them worth keeping", () => {
  const tsd = fxj("treeservicedenverllc.com.quotable.json");
  const eo = fxj("emmanuelorta.com.quotable.json");
  assert.equal(tsd.section_score, 100);
  assert.equal(eo.section_score, 67, "a page whose lead is a slogan and whose factual share is 12% loses three rows");
  assert.equal(tsd.quotable.faq_questions, 9);
  assert.equal(eo.quotable.faq_questions, 0, "no FAQPage: the parity row is not scored rather than failed");
  assert.equal(eo.quotable.lead_defines, false);
  assert.equal(tsd.agent_surfaces_found.markdown, true, "this site answers Accept: text/markdown with markdown");
  assert.equal(eo.agent_surfaces_found.markdown, false);
  assert.equal(tsd.reproducible, true);
  assert.equal(eo.reproducible, false, "a page that rewrites itself hourly cannot be a re-fetch target");
  assert.ok(eo.not_reproducible_because.length > 40, "and the fixture has to say why");
});

// ── the reader itself ───────────────────────────────────────────────────────
test("no <body> is null, not a zero", () => {
  assert.equal(quoteSignals("", [], ""), null);
  assert.equal(quoteSignals("User-agent: *", [], ""), null, "a text file is not a page with no content");
  assert.deepEqual(quotable("", "").rows, []);
});

test("navigation, header, footer, forms, script and style are not content", () => {
  const noise = "<nav><p>Home about contact services blog careers</p></nav><footer><p>Copyright 2026 all rights reserved everywhere</p></footer><form><p>Your name and your email address please</p></form><script>var p = 1;</script>";
  const real = "<p>Acme Fencing is a Denver contractor that installs cedar fence for homeowners.</p>";
  assert.equal(quoteSignals(page(noise + real), [], "").paragraphs, 1);
  assert.equal(quoteSignals(page("<p>one two three four five</p>"), [], "").paragraphs, 0, "under six words is not a paragraph");
});

test("lead: names the subject and uses a defining verb — reported separately", () => {
  const a = quoteSignals(page("<p>Acme Fencing is a Denver fence contractor serving the metro area today.</p>"), [], "Acme Fencing LLC");
  assert.equal(a.lead_names_subject, true, "the LLC suffix is stripped before matching");
  assert.equal(a.lead_defines, true);
  const b = quoteSignals(page("<p>Quality you can count on, every single day of the week, always.</p>"), [], "Acme Fencing");
  assert.equal(b.lead_names_subject, false);
  assert.equal(b.lead_defines, false, "a slogan has no defining verb in its first sentence");
});

test("a question heading counts as answered only with a 8-90 word paragraph under it", () => {
  const q = "<h2>How much does a fence cost?</h2>";
  const short = quoteSignals(page(q + "<p>It depends on the fence you want here</p>"), [], "");
  assert.equal(short.question_headings, 1);
  assert.equal(short.question_headings_answered, 1);
  const tooShort = quoteSignals(page(q + "<p>Depends on the fence</p>"), [], "");
  assert.equal(tooShort.question_headings_answered, 0, "four words is not an answer");
  const noQ = quoteSignals(page("<h2>Our fences</h2><p>We build fences for people in the Denver metro area.</p>"), [], "");
  assert.equal(noQ.question_headings, 0);
  const bare = quoteSignals(page("<h2>What we do</h2><p>We build fences for people in the Denver metro area.</p>"), [], "");
  assert.equal(bare.question_headings, 1, "an interrogative opener counts even without a question mark");
});

test("FAQ parity is checked against the whole visible page, footer and form included", () => {
  const ld = '<script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{"@type":"Question","name":"Do you offer free estimates?","acceptedAnswer":{"@type":"Answer","text":"Yes"}},{"@type":"Question","name":"What areas do you serve?","acceptedAnswer":{"@type":"Answer","text":"Denver"}}]}</script>';
  const visible = "<footer><p>Do you offer free estimates? Yes, every quote is free.</p></footer>";
  const html = page("<p>Acme Fencing is a Denver fence contractor for homeowners.</p>" + visible + ld);
  const s = quoteSignals(html, ldGraphNodes(html), "");
  assert.equal(s.faq_questions, 2);
  assert.equal(s.faq_visible, 1, "the second question is declared and nowhere on the page");
  const rows = quoteRows({ quotable: Object.assign({}, s, { paragraphs: 5 }) });
  assert.equal(rows.find((r) => r.k === "FAQ markup matches the visible text").ok, false);
});

test("a fact means a number, a year or a proper noun; first person is excluded", () => {
  const s = quoteSignals(page(
    "<p>Acme Fencing installs cedar privacy fence across the Denver metro area today.</p>" +
    "<p>A cedar privacy fence runs 45 to 70 dollars per linear foot installed.</p>" +
    "<p>We have been building fences for a very long time and we love it.</p>"), [], "");
  assert.equal(s.first_person, 1);
  assert.ok(s.quotable >= 2);
  assert.ok(!s.samples.some((x) => /^we\b/i.test(x)), "a first-person sentence is never offered as a quotable sample");
});

// ── the rows ────────────────────────────────────────────────────────────────
test("under five paragraphs nothing is scored — a JS shell is not a thin page", () => {
  const s = quoteSignals(page("<p>Acme Fencing is a Denver fence contractor for homeowners here.</p>"), [], "");
  const rows = quoteRows({ quotable: s });
  assert.equal(rows.length, 10);
  assert.equal(rows.filter((r) => r.ok !== null).length, 0);
  assert.equal(pctScore(rows), null, "an unscored section is null, never zero");
});

test("ten rows, three of them never scored at any input", () => {
  const q = fxj("treeservicedenverllc.com.quotable.json").quotable;
  const rows = quoteRows({ quotable: q });
  assert.equal(rows.length, 10);
  const unscored = rows.filter((r) => r.ok === null).map((r) => r.k);
  assert.deepEqual(unscored, ["Headings carry an id", "Tables with a header row and at least two data rows", "A visible updated or published date"],
    "too rare in the corpus to score fairly — measured and shown, deliberately not counted");
  assert.equal(quoteRows({ quotable: null }).length, 0);
  assert.equal(QUOTABLE_WEIGHT, 0.8);
});

test("quoteBlock renders the samples, the lead and the caveat", () => {
  const q = fxj("emmanuelorta.com.quotable.json").quotable;
  const h = quoteBlock({ quotable: q });
  assert.match(h, /Sentences an engine could lift as they stand/);
  assert.match(h, /176-homepage corpus pass/);
  assert.equal(quoteBlock({ quotable: null }), "");
});

// ── jsonld ──────────────────────────────────────────────────────────────────
test("ldGraphNodes: @graph children are entities, the same @id twice is one subject", () => {
  const html = '<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@id":"#org"},{"@id":"#org","name":"Acme"},{"@id":"#org","@type":"Organization","url":"https://acme.test"}]}</script>';
  const nodes = ldGraphNodes(html);
  assert.equal(nodes.length, 1, "a bare @id stub is a reference, not a subject; the rest merge");
  assert.equal(nodes[0].name, "Acme");
  assert.equal(nodes[0]["@type"], "Organization", "a typeless stub declared first must not read as an untyped business");
  assert.deepEqual(ldGraphNodes("<script type=\"application/ld+json\">{ not json </script>"), [], "unparseable JSON-LD is skipped, not thrown");
});
