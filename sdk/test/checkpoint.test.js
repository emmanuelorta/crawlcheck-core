// Outside-witness verification: a checkpoint, its cosignatures against a pinned list and a quorum, an answer's place in the
// tree, and that the tree only grew. The fixture comes from the service's own log and witness code over real batches of the
// answer log (tools/cum/harness5.mjs); "live" is the real checkpoint and verifies with the key this SDK pins.
import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs";
import { LOG_VKEY, WITNESS_VKEYS, parseVkey, parseCheckpoint, verifyCheckpoint, verifyInclusion, verifyConsistency, verifyAnswerInLog } from "../src/checkpoint.js";
const F = JSON.parse(fs.readFileSync(new URL("./fixtures/checkpoint.json", import.meta.url), "utf8")), t = F.test;

test("the live checkpoint verifies with the pinned log key; no witness is pinned, so it is not witnessed", async () => {
  const r = await verifyCheckpoint(F.live.note);
  assert.equal(r.ok, true); assert.equal(r.log_signed, true); assert.equal(r.origin, "crawlcheck.io/log"); assert.equal(r.size, F.live.size);
  assert.equal(r.witnessed, false); assert.equal(WITNESS_VKEYS.length, 0); assert.equal(r.witnesses_pinned, 0);
  const q = await verifyCheckpoint(F.live.note, { quorum: 1 }); assert.equal(q.ok, false); assert.equal(q.log_signed, true); assert.equal(q.quorum_met, false);
});
test("a checkpoint signed by another key than the pinned log key is refused", async () => {
  const r = await verifyCheckpoint(t.note); assert.equal(r.ok, false); assert.equal(r.log_signed, false);   // throwaway log key, default pin
  assert.equal((await verifyCheckpoint(t.note, { logVkey: t.log_vkey })).ok, true);
  assert.equal((await verifyCheckpoint(F.live.note, { logVkey: t.log_vkey })).log_signed, false);
});
test("cosignatures count only from pinned witnesses, once each, and the quorum decides", async () => {
  const o = { logVkey: t.log_vkey };
  let r = await verifyCheckpoint(t.note_w1, { ...o, witnesses: [t.w1_vkey], quorum: 1 }); assert.equal(r.ok, true); assert.equal(r.witnessed, true); assert.deepEqual(r.cosigned_by.map((x) => x.name), ["crawlcheck.io/witness"]);
  r = await verifyCheckpoint(t.note_w1, { ...o, witnesses: [t.w1_vkey, t.w2_vkey], quorum: 2 }); assert.equal(r.ok, false); assert.equal(r.cosigned_by.length, 1); assert.equal(r.witnesses_pinned, 2);
  r = await verifyCheckpoint(t.note_w1_w2, { ...o, witnesses: [t.w1_vkey, t.w2_vkey], quorum: 2 }); assert.equal(r.ok, true); assert.equal(r.cosigned_by.length, 2);
  r = await verifyCheckpoint(t.note_w1_w2, { ...o, witnesses: [t.w1_vkey, t.w1_vkey], quorum: 2 }); assert.equal(r.ok, false, "one witness listed twice is one witness"); assert.equal(r.witnesses_pinned, 1);
  r = await verifyCheckpoint(t.note_w1_stranger, { ...o, witnesses: [t.w1_vkey], quorum: 2 }); assert.equal(r.ok, false, "a cosignature from an unpinned key counts for nothing"); assert.equal(r.cosigned_by.length, 1);
  r = await verifyCheckpoint(t.note_w1, { ...o, witnesses: [t.w2_vkey], quorum: 1 }); assert.equal(r.ok, false);
  r = await verifyCheckpoint(t.note, { ...o, witnesses: [t.w1_vkey], quorum: 1 }); assert.equal(r.ok, false); assert.equal(r.log_signed, true);
  r = await verifyCheckpoint(t.note_w1, { ...o, witnesses: [t.log_vkey], quorum: 1 }); assert.equal(r.witnesses_pinned, 0, "a log key is not a witness key");
});
test("a changed checkpoint or a moved cosignature fails", async () => {
  const o = { logVkey: t.log_vkey, witnesses: [t.w1_vkey], quorum: 1 }, size = String(parseCheckpoint(t.note_w1).size);
  assert.equal((await verifyCheckpoint(t.note_w1.replace(size, String(Number(size) + 1)), o)).log_signed, false);
  const otherBody = F.live.note.slice(0, F.live.note.lastIndexOf("\n\n") + 2), w1line = t.note_w1.slice(t.note.length);
  const moved = await verifyCheckpoint(F.live.note + w1line, { witnesses: [t.w1_vkey], quorum: 1 }); assert.equal(moved.log_signed, true); assert.equal(moved.witnessed, false, "a cosignature made for another checkpoint does not carry over"); assert.ok(otherBody);
  for (const bad of ["", "x", t.note.replace("\n\n", "\n"), t.note.slice(0, -1), null, 7]) assert.equal((await verifyCheckpoint(bad, o)).ok, false);
  assert.equal(await parseVkey(t.w1_vkey.replace(/\+[0-9a-f]{8}\+/, "+00000000+")), null, "a verifier key whose id does not match is refused");
  assert.equal((await parseVkey(LOG_VKEY)).type, 1);
});
test("an answer's leaf is in the tree the verified checkpoint commits to", async () => {
  const o = { logVkey: t.log_vkey, witnesses: [t.w1_vkey], quorum: 1 };
  for (const d of t.inclusion) {
    const r = await verifyAnswerInLog(d, d.leaf_hash, o); assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(r.included, true); assert.equal(r.checkpoint.witnessed, true);
    assert.equal((await verifyAnswerInLog({ ...d, root: "A".repeat(43) + "=" }, d.leaf_hash, o)).ok, true, "the document's own root field is never trusted");
    assert.equal((await verifyAnswerInLog({ ...d, index: d.index + 1 }, d.leaf_hash, o)).included, false);
    assert.equal((await verifyAnswerInLog({ ...d, leaf_hash: "00".repeat(32) }, null, o)).included, false);
    assert.equal((await verifyAnswerInLog(d, "11".repeat(32), o)).ok, false, "a proof for another leaf");
    assert.equal((await verifyAnswerInLog({ ...d, path: d.path.slice(1) }, d.leaf_hash, o)).included, false);
    assert.equal((await verifyAnswerInLog({ ...d, tree_size: d.tree_size - 1 }, d.leaf_hash, o)).ok, false);
    assert.equal((await verifyAnswerInLog(d, d.leaf_hash, { ...o, quorum: 2 })).ok, false, "included but under quorum is not ok"); assert.equal((await verifyAnswerInLog(d, d.leaf_hash, { ...o, quorum: 2 })).included, true);
    assert.equal((await verifyAnswerInLog({ ...d, checkpoint: F.live.note }, d.leaf_hash)).included, false, "a real checkpoint for another tree does not vouch for this leaf");
  }
  assert.equal(await verifyInclusion(t.inclusion[0].leaf_hash, 0, 1, [], Buffer.from(t.inclusion[0].leaf_hash, "hex").toString("base64")), true, "a tree of one leaf");
});
test("a later checkpoint extends an earlier one", async () => {
  const c = t.consistency;
  assert.equal(await verifyConsistency(c.first, c.second, c.root1, c.root2, c.proof), true);
  assert.equal(await verifyConsistency(c.first, c.second, c.root2, c.root1, c.proof), false);
  assert.equal(await verifyConsistency(c.first + 1, c.second, c.root1, c.root2, c.proof), false);
  assert.equal(await verifyConsistency(c.first, c.second, c.root1, c.root2, c.proof.slice(1)), false);
  assert.equal(await verifyConsistency(c.first, c.second, c.root1, c.root2, []), false);
  assert.equal(await verifyConsistency(c.second, c.second, c.root2, c.root2, []), true);
  assert.equal(await verifyConsistency(c.second, c.second, c.root1, c.root2, []), false);
  assert.equal(await verifyConsistency(c.second, c.first, c.root2, c.root1, c.proof), false);
});
