const db = require('../db/database');
const { fingerprintForRequest } = require('../security/fingerprint');

// Require a live anonymous session and deny suspended device fingerprints.
function requireStudent(req, res, next) {
  const id = req.session.user?.id;
  if (!id) return res.status(401).json({ error: 'Start a chat to create your anonymous session.' });
  const session = db.prepare('SELECT id,fingerprint_hash,banned_until FROM anonymous_sessions WHERE id=?').get(id);
  const fingerprint = fingerprintForRequest(req, req.session.user.deviceTokenHash);
  const fingerprintBan = db.prepare('SELECT banned_until FROM banned_fingerprints WHERE fingerprint_hash=?').get(fingerprint);
  if (!session || (session.banned_until && session.banned_until > Date.now()) || (fingerprintBan?.banned_until > Date.now())) {
    return res.status(403).json({ error: 'This session is suspended from CRTMINGLE.' });
  }
  if (session.fingerprint_hash !== fingerprint) db.prepare('UPDATE anonymous_sessions SET fingerprint_hash=?,last_seen_at=? WHERE id=?').run(fingerprint, Date.now(), id);
  else db.prepare('UPDATE anonymous_sessions SET last_seen_at=? WHERE id=?').run(Date.now(), id);
  req.session.user.fingerprintHash = fingerprint;
  next();
}

module.exports = { requireStudent };
