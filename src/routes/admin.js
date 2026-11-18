const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('../db/database');
const { hashSecret } = require('../security/fingerprint');
const router = express.Router();
const requireAdmin = (req, res, next) => req.session.admin ? next() : res.status(401).json({ error: 'Staff access code required.' });
router.use('/login', rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false }));
const setting = (key, fallback) => db.prepare('SELECT value FROM settings WHERE key=?').get(key)?.value ?? fallback;
const writeSetting = db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');

// Calculate today's start in the school's configured timezone.
function localMidnight(timeZone) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date()).map(part => [part.type, part.value]));
  const base = Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day));
  const atBase = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(base)).map(part => [part.type, part.value]));
  const localAsUtc = Date.UTC(Number(atBase.year), Number(atBase.month) - 1, Number(atBase.day), Number(atBase.hour), Number(atBase.minute));
  return base - (localAsUtc - base);
}

// Record each staff action without collecting a personal admin email.
function audit(action, targetId = '', details = '') {
  db.prepare('INSERT INTO admin_audit(admin,action,target_id,details,created_at) VALUES(?,?,?,?,?)').run('school-admin', action, targetId, String(details).slice(0, 1000), Date.now());
}

// Compare staff codes without returning timing information about the stored hash.
function validAdminCode(code) {
  const expected = Buffer.from(process.env.ADMIN_ACCESS_CODE_HASH || '', 'hex');
  const actual = Buffer.from(hashSecret(code), 'hex');
  return expected.length === actual.length && expected.length === 32 && crypto.timingSafeEqual(expected, actual);
}

// Verify the separate staff access code and start a protected admin session.
router.post('/login', (req, res) => {
  if (!validAdminCode(String(req.body?.accessCode || ''))) return res.status(401).json({ error: 'Invalid staff access code.' });
  req.session.regenerate(error => {
    if (error) return res.status(500).json({ error: 'Could not start the staff session.' });
    req.session.admin = true;
    req.session.save(saveError => {
      if (saveError) return res.status(500).json({ error: 'Could not start the staff session.' });
      audit('staff portal opened');
      res.json({ ok: true });
    });
  });
});

// Return safety reports with chat context and anonymous session/fingerprint details.
router.get('/data', requireAdmin, (req, res) => {
  const reports = db.prepare("SELECT id,reporter_session_id,reported_session_id,reported_fingerprint_hash,room_id,reason,status,created_at FROM anonymous_reports WHERE status='open' ORDER BY created_at DESC LIMIT 100")
    .all().map(report => ({ ...report, messages: db.prepare('SELECT sender_id,body,created_at FROM chat_messages WHERE room_id=? ORDER BY id DESC LIMIT 20').all(report.room_id).reverse() }));
  const timezone = process.env.CHAT_TIMEZONE || 'Asia/Manila';
  const midnight = localMidnight(timezone);
  const onlineSockets = [...(req.app.get('io')?.sockets.sockets.values() || [])];
  const stats = {
    onlineUsers: new Set(onlineSockets.map(client => client.userId)).size,
    sessionsToday: db.prepare('SELECT COUNT(*) AS n FROM anonymous_sessions WHERE created_at>=?').get(midnight).n,
    reports: db.prepare('SELECT COUNT(*) AS n FROM anonymous_reports').get().n,
    reportsToday: db.prepare('SELECT COUNT(*) AS n FROM anonymous_reports WHERE created_at>=?').get(midnight).n,
    messages: db.prepare('SELECT COUNT(*) AS n FROM chat_messages').get().n,
    activeBans: db.prepare('SELECT COUNT(*) AS n FROM banned_fingerprints WHERE banned_until>?').get(Date.now()).n,
    chatsToday: db.prepare('SELECT COUNT(*) AS n FROM chat_rooms WHERE created_at>=?').get(midnight).n
  };
  const auditLog = db.prepare('SELECT admin,action,target_id,details,created_at FROM admin_audit ORDER BY id DESC LIMIT 50').all();
  res.json({ reports, stats, auditLog, timezone, openHour: Number(setting('open_hour', process.env.CHAT_OPEN_HOUR || 15)), closeHour: Number(setting('close_hour', process.env.CHAT_CLOSE_HOUR || 21)), reportLimit: Number(setting('report_limit', process.env.REPORT_LIMIT || 3)), reportWindowHours: Number(setting('report_window_hours', process.env.REPORT_WINDOW_HOURS || 24)), blockedTerms: setting('blocked_terms', process.env.BLOCKED_TERMS || 'fuck,shit,bitch,asshole') });
});

// Ban or unban by session, fingerprint, or report; edit chat safety settings.
router.post('/action', requireAdmin, (req, res) => {
  const { action, reportId, sessionId, fingerprintHash, openHour, closeHour, reportLimit, reportWindowHours, blockedTerms } = req.body || {};
  let targetSession = typeof sessionId === 'string' ? sessionId.trim().slice(0, 128) : '';
  let targetFingerprint = typeof fingerprintHash === 'string' ? fingerprintHash.trim().toLowerCase() : '';
  let report = null;
  if (Number.isInteger(reportId)) report = db.prepare('SELECT * FROM anonymous_reports WHERE id=?').get(reportId);
  if (report) {
    targetSession ||= report.reported_session_id;
    targetFingerprint ||= report.reported_fingerprint_hash;
  }
  if (['ban', 'suspend', 'unban', 'warn'].includes(action)) {
    if (targetFingerprint && !/^[a-f0-9]{64}$/.test(targetFingerprint)) return res.status(400).json({ error: 'Fingerprint must be a 64-character hexadecimal hash.' });
    const row = targetSession ? db.prepare('SELECT fingerprint_hash FROM anonymous_sessions WHERE id=?').get(targetSession) : null;
    if (!targetFingerprint && row) targetFingerprint = row.fingerprint_hash;
    if (!targetSession && !targetFingerprint) return res.status(400).json({ error: 'Choose a session ID, report, or fingerprint.' });
    const now = Date.now(), until = action === 'suspend' ? now + 24 * 60 * 60_000 : now + 10 * 365 * 24 * 60 * 60_000;
    if (action === 'unban') {
      if (targetSession) db.prepare('UPDATE anonymous_sessions SET banned_until=NULL WHERE id=?').run(targetSession);
      if (targetFingerprint) db.prepare('DELETE FROM banned_fingerprints WHERE fingerprint_hash=?').run(targetFingerprint);
    } else if (action === 'warn') {
      if (!targetSession) return res.status(400).json({ error: 'A warning needs a session ID or report.' });
      db.prepare('INSERT INTO anonymous_warnings(session_id,message,created_at) VALUES(?,?,?)').run(targetSession, String(req.body?.message || 'A moderator has sent a safety warning.').slice(0, 500), now);
    } else {
      if (targetSession) db.prepare('UPDATE anonymous_sessions SET banned_until=? WHERE id=?').run(until, targetSession);
      if (targetFingerprint) db.prepare('INSERT INTO banned_fingerprints(fingerprint_hash,banned_until,reason,created_at) VALUES(?,?,?,?) ON CONFLICT(fingerprint_hash) DO UPDATE SET banned_until=excluded.banned_until,reason=excluded.reason').run(targetFingerprint, until, `Staff ${action}`, now);
      for (const client of req.app.get('io')?.sockets.sockets.values() || []) if ((targetSession && client.userId === targetSession) || (targetFingerprint && client.fingerprintHash === targetFingerprint)) { client.emit('notice', 'This session has been suspended by a moderator.'); client.disconnect(true); }
    }
    audit(action, targetSession || targetFingerprint, reportId ? `report ${reportId}` : '');
  }
  if (action === 'dismiss' && Number.isInteger(reportId)) { db.prepare("UPDATE anonymous_reports SET status='dismissed' WHERE id=?").run(reportId); audit('dismiss report', String(reportId)); }
  if (Number.isInteger(openHour) && Number.isInteger(closeHour) && openHour >= 0 && openHour <= 23 && closeHour >= 1 && closeHour <= 24 && openHour < closeHour) { writeSetting.run('open_hour', String(openHour)); writeSetting.run('close_hour', String(closeHour)); audit('change operating hours', '', `${openHour}:00-${closeHour}:00`); }
  if (Number.isInteger(reportLimit) && reportLimit >= 1 && reportLimit <= 20 && Number.isInteger(reportWindowHours) && reportWindowHours >= 1 && reportWindowHours <= 168) { writeSetting.run('report_limit', String(reportLimit)); writeSetting.run('report_window_hours', String(reportWindowHours)); audit('change report threshold', '', `${reportLimit} reports/${reportWindowHours} hours`); }
  if (typeof blockedTerms === 'string' && blockedTerms.length <= 5000) { const words = blockedTerms.split(',').map(word => word.trim()).filter(Boolean); if (words.length > 200 || words.some(word => word.length > 40 || !/^[\p{L}\p{N} _'-]+$/u.test(word))) return res.status(400).json({ error: 'Use up to 200 comma-separated words, max 40 letters/numbers each.' }); writeSetting.run('blocked_terms', words.join(',')); audit('edit blocked words', '', `${words.length} terms saved`); }
  res.json({ ok: true });
});

// Close the staff portal session.
router.post('/logout', (req, res) => { audit('staff portal closed'); req.session.admin = false; res.json({ ok: true }); });
module.exports = router;
