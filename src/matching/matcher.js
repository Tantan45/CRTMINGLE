// Choose the waiting pair with the most shared interests while enforcing anonymous safety blocks.
function chooseBestPair(waiting, db, now = Date.now()) {
  const candidates = [];
  for (let i = 0; i < waiting.length; i++) for (let j = i + 1; j < waiting.length; j++) {
    const a = waiting[i], b = waiting[j];
    if (a.userId === b.userId || a.fingerprintHash === b.fingerprintHash) continue;
    const shared = a.interests.filter(tag => b.interests.some(other => other.toLowerCase() === tag.toLowerCase()));
    const fallbackExpired = now - Math.max(a.queuedAt, b.queuedAt) >= 10_000;
    if (a.interests.length && b.interests.length && !shared.length && !fallbackExpired) continue;
    const excluded = db.prepare(`
      SELECT 1 FROM anonymous_blocks
      WHERE (blocker_session_id=? AND blocked_session_id=?)
         OR (blocker_session_id=? AND blocked_session_id=?)
         OR (blocker_fingerprint_hash=? AND blocked_fingerprint_hash=?)
         OR (blocker_fingerprint_hash=? AND blocked_fingerprint_hash=?)
      UNION ALL
      SELECT 1 FROM anonymous_reports
      WHERE (reporter_session_id=? AND reported_session_id=?)
         OR (reporter_session_id=? AND reported_session_id=?)
         OR (reporter_fingerprint_hash=? AND reported_fingerprint_hash=?)
         OR (reporter_fingerprint_hash=? AND reported_fingerprint_hash=?)
      LIMIT 1
    `).get(a.userId,b.userId,b.userId,a.userId,a.fingerprintHash,b.fingerprintHash,b.fingerprintHash,a.fingerprintHash,a.userId,b.userId,b.userId,a.userId,a.fingerprintHash,b.fingerprintHash,b.fingerprintHash,a.fingerprintHash);
    if (!excluded) candidates.push({ a, b, shared });
  }
  if (!candidates.length) return null;
  const best = candidates.reduce((max, pair) => Math.max(max, pair.shared.length), 0);
  const top = candidates.filter(pair => pair.shared.length === best);
  return top[Math.floor(Math.random() * top.length)];
}

module.exports = { chooseBestPair };
