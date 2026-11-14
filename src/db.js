const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function passwordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function passwordMatches(password, stored) {
  const [salt, expected] = String(stored).split(':');
  if (!salt || !expected) return false;
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}

function createDatabase(filename, adminUsername, adminPassword) {
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  const db = new DatabaseSync(filename);
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      audience_label TEXT NOT NULL,
      subject TEXT NOT NULL,
      sender_label TEXT NOT NULL,
      lure_text TEXT NOT NULL,
      landing_message TEXT NOT NULL,
      public_token TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'archived')),
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER NOT NULL,
      participant_code TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('clicked', 'submitted')),
      risk_score INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
    );
    CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_events_participant ON events(campaign_id, participant_code);
  `);
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(adminUsername);
  if (!existing) {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(adminUsername, passwordHash(adminPassword));
  }
  return db;
}

function metrics(db, campaignId = null) {
  const where = campaignId === null ? '' : 'WHERE campaign_id = @campaignId';
  const params = campaignId === null ? {} : { campaignId };
  const row = db.prepare(`SELECT
    COUNT(DISTINCT CASE WHEN event_type = 'clicked' THEN participant_code END) AS clicks,
    COUNT(DISTINCT CASE WHEN event_type = 'submitted' THEN participant_code END) AS submissions,
    COUNT(DISTINCT participant_code) AS participants
    FROM events ${where}`).get(params);
  const clicks = row.clicks || 0;
  const submissions = row.submissions || 0;
  return { clicks, submissions, participants: row.participants || 0, awareness: clicks ? Math.round(((clicks - submissions) / clicks) * 100) : 0 };
}

function participants(db, campaignId) {
  const rows = db.prepare(`SELECT participant_code,
    SUM(event_type = 'clicked') AS clicks,
    SUM(event_type = 'submitted') AS submissions,
    MAX(created_at) AS last_seen
    FROM events WHERE campaign_id = ? GROUP BY participant_code ORDER BY last_seen DESC`).all(campaignId);
  return rows.map((row) => {
    const riskScore = Math.min(100, (row.clicks ? 40 : 0) + (row.submissions ? 60 : 0));
    return { ...row, risk_score: riskScore, risk_label: riskScore >= 70 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low' };
  });
}

module.exports = { createDatabase, metrics, participants, passwordMatches };
