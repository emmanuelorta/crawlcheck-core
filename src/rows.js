// crawlcheck-core / rows.js
// The two row helpers every CrawlCheck report section is built out of, extracted
// verbatim from the production scanner. ESM, no dependencies.
//
// A row is { k, cur, opt, ok, why }: the check, what this site currently does,
// what it should do, the verdict, and why it matters. `ok === null` is the third
// state and it is load-bearing: it means MEASURED BUT NOT SCORED — the row is
// shown and deliberately left out of the section score, because the signal is
// too rare, not applicable to this kind of site, or informational. pctScore()
// therefore divides by the scored rows only, and returns null when a section has
// none — an unscored section is never reported as zero.

export function tgt(k, cur, optimal, ok, why) {
  return { k: k, cur: String(cur), opt: optimal, ok: ok === null ? null : !!ok, why: why || "" };
}

export function pctScore(rows) {
  const scored = rows.filter(function (x) { return x.ok !== null; });
  if (!scored.length) return null;
  return Math.round((scored.filter(function (x) { return x.ok; }).length / scored.length) * 100);
}
