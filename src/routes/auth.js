const express = require('express');
const rateLimit = require('express-rate-limit');
const db = require('../db/database');
const { fingerprintForRequest, hashDeviceToken } = require('../security/fingerprint');
const router = express.Router();

// Reject a known banned fingerprint before creating or resuming a guest session.
function activeFingerprintBan(fingerprint) {
  const ban = db.prepare('SELECT banned_until FROM banned_fingerprints WHERE fingerprint_hash=?').get(fingerprint);
  return ban?.banned_until > Date.now() ? ban.banned_until : null;
}

// Check the anonymous browser session and refresh its hashed fingerprint activity.
router.get('/session', (req, res) => {
  const id = req.session.user?.id;
  if (!id) return res.json({ hasSession: false });
  const deviceTokenHash = String(req.session.user.deviceTokenHash || '');
  if (!/^[a-f0-9]{64}$/.test(deviceTokenHash)) { req.session.destroy(() => {}); return res.status(403).json({ error: 'This anonymous browser session is invalid. Start a new session.' }); }
  const fingerprint = fingerprintForRequest(req, deviceTokenHash);
  const banUntil = activeFingerprintBan(fingerprint);
  const sessionUser = db.prepare('SELECT id,accepted_rules,banned_until FROM anonymous_sessions WHERE id=?').get(id);
  if (banUntil || !sessionUser || (sessionUser.banned_until && sessionUser.banned_until > Date.now())) {
    req.session.destroy(() => {});
    return res.status(403).json({ error: 'This session is suspended. Contact the CRTMINGLE administrator.' });
  }
  db.prepare('UPDATE anonymous_sessions SET fingerprint_hash=?,last_seen_at=? WHERE id=?').run(fingerprint, Date.now(), id);
  req.session.user.fingerprintHash = fingerprint;
  res.set('Cache-Control', 'no-store').json({ hasSession: true, id, acceptedRules: !!sessionUser.accepted_rules });
});

// Start an anonymous session immediately, without collecting account details.
// Keep session creation usable for a school network where many students share one IP.
router.post('/anonymous-session', rateLimit({ windowMs: 15 * 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }), (req, res) => {
  const currentId = req.session.user?.id;
  if (currentId && db.prepare('SELECT 1 FROM anonymous_sessions WHERE id=?').get(currentId)) return res.json({ ok: true, id: currentId, existing: true });
  const deviceToken = String(req.body?.deviceToken || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(deviceToken)) return res.status(400).json({ error: 'Could not identify this anonymous browser. Refresh and try again.' });
  const deviceTokenHash = hashDeviceToken(deviceToken);
  const fingerprint = fingerprintForRequest(req, deviceTokenHash);
  const banUntil = activeFingerprintBan(fingerprint);
  if (banUntil) return res.status(403).json({ error: 'This device is suspended from CRTMINGLE.' });
  const now = Date.now();
  req.session.regenerate(error => {
    if (error) return res.status(500).json({ error: 'Could not start a chat session.' });
    const id = req.sessionID;
    db.prepare('INSERT INTO anonymous_sessions(id,fingerprint_hash,accepted_rules,created_at,last_seen_at) VALUES(?,?,0,?,?)').run(id, fingerprint, now, now);
    req.session.user = { id, fingerprintHash: fingerprint, deviceTokenHash };
    req.session.save(saveError => {
      if (saveError) { db.prepare('DELETE FROM anonymous_sessions WHERE id=?').run(id); return res.status(500).json({ error: 'Could not start a chat session.' }); }
      res.json({ ok: true, id });
    });
  });
});

// Destroy the anonymous browser session without collecting account details.
router.post('/logout', (req, res) => {
  const id = req.session.user?.id;
  if (id) db.prepare('DELETE FROM anonymous_sessions WHERE id=? AND banned_until IS NULL').run(id);
  req.session.destroy(() => res.json({ ok: true }));
});

module.exports = router;
