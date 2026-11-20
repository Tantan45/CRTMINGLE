const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

// Open the local SQLite database and create the tables the app needs.
const file = path.resolve(process.env.DATABASE_PATH || (process.env.VERCEL ? '/tmp/crtmingle.sqlite' : './data/crtmingle.sqlite'));
fs.mkdirSync(path.dirname(file), { recursive: true });
const db = new Database(file);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('secure_delete = ON');
// Remove the old account-based prototype tables; the current app stores anonymous sessions only.
db.pragma('foreign_keys = OFF');
db.exec('DROP TABLE IF EXISTS user_warnings; DROP TABLE IF EXISTS password_resets; DROP TABLE IF EXISTS guest_verifications; DROP TABLE IF EXISTS reports; DROP TABLE IF EXISTS blocks; DROP TABLE IF EXISTS users;');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY, room_id TEXT NOT NULL, sender_id TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS chat_rooms (id TEXT PRIMARY KEY, user_a TEXT NOT NULL, user_b TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_room_time ON chat_messages(room_id, created_at);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_audit (id INTEGER PRIMARY KEY, admin TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT, details TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS anonymous_sessions (id TEXT PRIMARY KEY, fingerprint_hash TEXT NOT NULL, accepted_rules INTEGER NOT NULL DEFAULT 0, banned_until INTEGER, created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS anonymous_sessions_fingerprint ON anonymous_sessions(fingerprint_hash);
CREATE TABLE IF NOT EXISTS anonymous_reports (id INTEGER PRIMARY KEY, reporter_session_id TEXT NOT NULL, reporter_fingerprint_hash TEXT NOT NULL, reported_session_id TEXT NOT NULL, reported_fingerprint_hash TEXT NOT NULL, room_id TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS anonymous_reports_target_time ON anonymous_reports(reported_fingerprint_hash, created_at);
CREATE TABLE IF NOT EXISTS anonymous_blocks (blocker_session_id TEXT NOT NULL, blocked_session_id TEXT NOT NULL, blocker_fingerprint_hash TEXT NOT NULL, blocked_fingerprint_hash TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(blocker_session_id, blocked_session_id));
CREATE TABLE IF NOT EXISTS banned_fingerprints (fingerprint_hash TEXT PRIMARY KEY, banned_until INTEGER NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS anonymous_warnings (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL, seen_at INTEGER);
`);
// Add the reporter fingerprint when migrating an earlier anonymous-session database.
try { db.exec("ALTER TABLE anonymous_reports ADD COLUMN reporter_fingerprint_hash TEXT NOT NULL DEFAULT ''"); } catch {}
// Add the report status field to databases created by earlier versions.
try { db.exec("ALTER TABLE reports ADD COLUMN status TEXT NOT NULL DEFAULT 'open'"); } catch {}
// Remove chat and moderation records after the published retention period.
function cleanupExpiredData(){const cutoff=Date.now()-30*24*60*60_000;const run=db.transaction(()=>{db.prepare('DELETE FROM chat_messages WHERE created_at<?').run(cutoff);db.prepare('DELETE FROM anonymous_reports WHERE created_at<?').run(cutoff);db.prepare('DELETE FROM chat_rooms WHERE created_at<?').run(cutoff);db.prepare('DELETE FROM admin_audit WHERE created_at<?').run(cutoff);db.prepare('DELETE FROM anonymous_warnings WHERE created_at<?').run(cutoff);db.prepare('DELETE FROM banned_fingerprints WHERE banned_until<?').run(Date.now());db.prepare('DELETE FROM anonymous_sessions WHERE last_seen_at<? AND (banned_until IS NULL OR banned_until<?)').run(cutoff,Date.now())});run()}
db.cleanupExpiredData=cleanupExpiredData;
module.exports=db;
