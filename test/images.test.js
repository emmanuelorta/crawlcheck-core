// images: what an engine can learn from the pictures.
//
// The offline tests pin the three distinctions the module exists to make, each
// of which has produced a false accusation somewhere before: alt="" is not a
// missing alt, a page with no images is not a page that fails, and format and
// hero priority are reported without being scored.
//
// The last test is a parity test against the live service and is skipped unless
// CC_LIVE=1, so the offline suite needs no network. It refuses to compare unless
// the page still hashes to what the recorded scan read - if the site changed,
// the test says the site changed rather than blaming the reader.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { imageSignals, imageRows } from "../src/images.js";
import { pctScore } from "../src/rows.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fxj = (n) => JSON.parse(fs.readFileSync(path.join(here, "fixtures", n), "utf8"));
const live = process.env.CC_LIVE === "1";
const sha256 = async (buf) => Buffer.from(await crypto.subtle.digest("SHA-256", buf)).toString("hex");

const page = (body) => `<!doctype html><html><head><title>t</title></head><body>${body}</body></html>`;

test("a missing alt attribute and alt=\"\" are counted separately", () => {
  const s = imageSignals(page(
    `<img src="/a.jpg" alt="a cedar fence">` +
    `<img src="/b.jpg" alt="">` +
    `<img src="/c.jpg">`
  ));
  assert.equal(s.total, 3);
  assert.equal(s.no_alt, 1, "only the image with no alt attribute at all");
  assert.equal(s.empty_alt, 1, "alt=\"\" is decorative, counted apart");
});

test("empty alt is never scored, so a decorative-heavy page is not failed", () => {
  const s = imageSignals(page(new Array(12).fill(`<img src="/x.svg" alt="" width="16" height="16">`).join("")));
  assert.equal(s.no_alt, 0);
  assert.equal(s.empty_alt, 12);
  const rows = imageRows({ images: s });
  const alt = rows.find((r) => /alt/i.test(r.k));
  assert.equal(alt.ok, true, "no image is missing an alt attribute, so the row passes");
});

test("a page with no images returns one unscored row, never a zero", () => {
  const s = imageSignals(page("<p>no pictures here at all</p>"));
  assert.equal(s.total, 0);
  const rows = imageRows({ images: s });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].ok, null, "measured, deliberately not scored");
  assert.equal(pctScore(rows), null, "a section with no scored rows scores null, not 0");
});

test("declared dimensions and above-the-fold lazy loading are read", () => {
  const withDims = imageSignals(page(`<img src="/a.jpg" alt="x" width="800" height="600">`));
  assert.equal(withDims.no_dimensions, 0);
  const without = imageSignals(page(`<img src="/a.jpg" alt="x">`));
  assert.equal(without.no_dimensions, 1);
  const lazyTop = imageSignals(page(`<img src="/hero.jpg" alt="hero" loading="lazy">`));
  assert.ok(lazyTop.lazy >= 1);
  assert.ok(lazyTop.lazy_above_fold >= 1, "a lazy image in the first quarter of the body is the finding");
});

test("format and hero priority are reported and never scored", () => {
  const s = imageSignals(page(
    `<img src="/a.webp" alt="x" width="1" height="1">` +
    `<img src="/b.jpg" alt="y" width="1" height="1" fetchpriority="high">`
  ));
  assert.equal(s.modern_format, 1);
  assert.equal(s.fetchpriority_high, 1);
  const rows = imageRows({ images: s });
  const unscored = rows.filter((r) => r.ok === null).map((r) => r.k).join(" | ").toLowerCase();
  assert.ok(/format/.test(unscored), "file format is reported, not scored");
});

test("an entity image and an og:image are both read from the document", () => {
  const s = imageSignals(page(
    `<img src="/a.jpg" alt="x">` +
    `<meta property="og:image" content="https://example.com/og.png">` +
    `<script type="application/ld+json">{"@type":"LocalBusiness","image":"https://example.com/e.png"}</script>`
  ));
  assert.equal(s.og_image, true);
  assert.equal(s.ld_image, true);
});

test("the reader never throws on absent or malformed input", () => {
  for (const bad of [null, undefined, "", 0, "<img", "<html><img src=", "not html at all"]) {
    assert.doesNotThrow(() => imageSignals(bad));
  }
  assert.deepEqual(imageRows({}), []);
  assert.deepEqual(imageRows(null), []);
  assert.deepEqual(imageRows({ images: { measured: false } }), []);
});

test("rows carry the row contract and the three-state verdict", () => {
  const s = imageSignals(page(`<img src="/a.jpg" alt="a cedar fence" width="8" height="6">`));
  const rows = imageRows({ images: s });
  assert.ok(rows.length > 1);
  for (const r of rows) {
    assert.deepEqual(Object.keys(r).sort(), ["cur", "k", "ok", "opt", "why"]);
    assert.ok(r.ok === true || r.ok === false || r.ok === null);
    assert.equal(typeof r.cur, "string");
  }
  assert.ok(rows.some((r) => r.ok === null), "at least one row is measured but not scored");
  assert.ok(rows.some((r) => r.ok !== null), "and at least one is scored");
});

test("parity with the production scanner on a live page (treeservicedenverllc.com)",
  { skip: live ? false : "set CC_LIVE=1" }, async () => {
  const expected = fxj("treeservicedenverllc.com.images.json");
  assert.equal(expected.reproducible, true);
  const res = await fetch(expected.page_url, {
    headers: { "user-agent": expected.fetch.user_agent, accept: expected.fetch.accept },
    redirect: "follow",
  });
  assert.equal(res.status, 200);
  const raw = Buffer.from(await res.arrayBuffer()).toString("utf8");
  const stripped = raw.replace(new RegExp(expected.digest_excludes_pattern, "gi"), "");
  const bytes = Buffer.byteLength(stripped);
  const digest = await sha256(Buffer.from(stripped, "utf8"));
  assert.equal(
    digest, expected.page_sha256,
    `the page is ${bytes} bytes and was ${expected.page_bytes} when this fixture was captured — ` +
    `the site changed, not the reader. Re-capture the fixture rather than relaxing this check.`
  );
  assert.deepEqual(imageSignals(stripped), expected.images,
    "every field the production scanner recorded, reproduced from the same bytes");
});
