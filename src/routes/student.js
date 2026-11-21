const express = require('express');
const sanitizeHtml = require('sanitize-html');
const db = require('../db/database');
const { requireStudent } = require('../middleware/auth');
const router = express.Router();
router.use(requireStudent);

// Save the anonymous student's agreement before allowing a chat connection.
router.post('/rules', (req, res) => {
  if (req.body?.accepted !== true) return res.status(400).json({ error: 'Accept the rules before continuing.' });
  db.prepare('UPDATE anonymous_sessions SET accepted_rules=1 WHERE id=?').run(req.session.user.id);
  res.json({ ok: true });
});

// Return always-open chat availability and support contacts.
router.get('/config', (req, res) => res.json({
  open: 0,
  close: 24,
  timezone: process.env.CHAT_TIMEZONE || 'Asia/Manila',
  counselor: process.env.COUNSELOR_CONTACT || 'Ask your school counselor for help',
  crisis: process.env.CRISIS_RESOURCE || 'Contact local emergency services',
  acceptedRules: !!db.prepare('SELECT accepted_rules FROM anonymous_sessions WHERE id=?').get(req.session.user.id)?.accepted_rules
}));

// Report a chat partner and make the last 20 logged messages available to moderators.
router.post('/report', (req, res) => {
  const reporterId = req.session.user.id;
  const targetId = String(req.body?.reportedId || '').slice(0, 100);
  const roomId = String(req.body?.roomId || '').slice(0, 100);
  const reason = sanitizeHtml(String(req.body?.reason || 'Safety concern').slice(0, 300), { allowedTags: [], allowedAttributes: {} });
  if (!targetId || targetId === reporterId || !roomId) return res.status(400).json({ error: 'No active stranger to report.' });
  const target = db.prepare('SELECT id,fingerprint_hash FROM anonymous_sessions WHERE id=?').get(targetId);
  if (!target) return res.status(404).json({ error: 'Chat session not found.' });
  const participated = db.prepare('SELECT 1 FROM chat_rooms WHERE id=? AND ((user_a=? AND user_b=?) OR (user_a=? AND user_b=?))').get(roomId, reporterId, targetId, targetId, reporterId);
  if (!participated) return res.status(403).json({ error: 'A report needs a chat between these two sessions.' });
  if (db.prepare('SELECT 1 FROM anonymous_reports WHERE reporter_fingerprint_hash=? AND reported_fingerprint_hash=? AND room_id=?').get(req.session.user.fingerprintHash, target.fingerprint_hash, roomId)) return res.status(409).json({ error: 'You already reported this conversation.' });
  const now = Date.now();
  db.prepare('INSERT INTO anonymous_reports(reporter_session_id,reporter_fingerprint_hash,reported_session_id,reported_fingerprint_hash,room_id,reason,created_at) VALUES(?,?,?,?,?,?,?)').run(reporterId, req.session.user.fingerprintHash, targetId, target.fingerprint_hash, roomId, reason, now);
  db.prepare('INSERT OR IGNORE INTO anonymous_blocks(blocker_session_id,blocked_session_id,blocker_fingerprint_hash,blocked_fingerprint_hash,created_at) VALUES(?,?,?,?,?)').run(reporterId, targetId, req.session.user.fingerprintHash, target.fingerprint_hash, now);
  const rows = db.prepare('SELECT sender_id,body,created_at FROM chat_messages WHERE room_id=? ORDER BY id DESC LIMIT 20').all(roomId).reverse();
  const threshold = Number(db.prepare("SELECT value FROM settings WHERE key='report_limit'").get()?.value ?? process.env.REPORT_LIMIT ?? 3);
  const windowHours = Number(db.prepare("SELECT value FROM settings WHERE key='report_window_hours'").get()?.value ?? process.env.REPORT_WINDOW_HOURS ?? 24);
  const recentReports = db.prepare('SELECT COUNT(DISTINCT reporter_fingerprint_hash) AS count FROM anonymous_reports WHERE reported_fingerprint_hash=? AND created_at>?').get(target.fingerprint_hash, now - windowHours * 60 * 60_000).count;
  if (recentReports >= threshold) {
    const until = now + 24 * 60 * 60_000;
    db.prepare('UPDATE anonymous_sessions SET banned_until=? WHERE id=?').run(until, targetId);
    db.prepare('INSERT INTO banned_fingerprints(fingerprint_hash,banned_until,reason,created_at) VALUES(?,?,?,?) ON CONFLICT(fingerprint_hash) DO UPDATE SET banned_until=excluded.banned_until,reason=excluded.reason').run(target.fingerprint_hash, until, 'Automatic suspension after repeated reports', now);
    for (const client of req.app.get('io')?.sockets.sockets.values() || []) if (client.userId === targetId) { client.emit('notice', 'This session has been temporarily suspended.'); client.disconnect(true); }
  }
  res.json({ savedMessages: rows.length });
});

// Keep the selected session and device fingerprint out of future matches.
router.post('/block', (req, res) => {
  const blockerId = req.session.user.id;
  const targetId = String(req.body?.blockedId || '').slice(0, 100);
  const roomId = String(req.body?.roomId || '').slice(0, 100);
  if (!targetId || targetId === blockerId || !roomId) return res.status(400).json({ error: 'Choose an active chat partner to block.' });
  const participated = db.prepare('SELECT 1 FROM chat_rooms WHERE id=? AND ((user_a=? AND user_b=?) OR (user_a=? AND user_b=?))').get(roomId, blockerId, targetId, targetId, blockerId);
  if (!participated) return res.status(403).json({ error: 'You can only block someone you have chatted with.' });
  const target = db.prepare('SELECT fingerprint_hash FROM anonymous_sessions WHERE id=?').get(targetId);
  if (!target) return res.status(404).json({ error: 'Chat session not found.' });
  db.prepare('INSERT OR IGNORE INTO anonymous_blocks(blocker_session_id,blocked_session_id,blocker_fingerprint_hash,blocked_fingerprint_hash,created_at) VALUES(?,?,?,?,?)').run(blockerId, targetId, req.session.user.fingerprintHash, target.fingerprint_hash, Date.now());
  res.json({ ok: true });
});

// Return only the random session ID and any unread moderator notices.
router.get('/me', (req, res) => {
  const warnings = db.prepare('SELECT id,message,created_at FROM anonymous_warnings WHERE session_id=? AND seen_at IS NULL ORDER BY id').all(req.session.user.id);
  if (warnings.length) db.prepare('UPDATE anonymous_warnings SET seen_at=? WHERE session_id=? AND seen_at IS NULL').run(Date.now(), req.session.user.id);
  res.json({ id: req.session.user.id, nickname: 'Anonymous', warnings });
});

module.exports = router;
