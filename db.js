const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'commerceworld.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS articles (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    cat TEXT NOT NULL,
    date TEXT NOT NULL,
    excerpt TEXT,
    img TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT,
    tagline TEXT,
    copyright TEXT,
    nlTitle TEXT,
    nlSub TEXT
  );

  CREATE TABLE IF NOT EXISTS footer_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    section TEXT NOT NULL,
    label TEXT NOT NULL,
    url TEXT NOT NULL,
    sort_order INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL
  );
`);

const configRow = db.prepare('SELECT * FROM config WHERE id = 1').get();
if (!configRow) {
  db.prepare(`
    INSERT INTO config (id, name, tagline, copyright, nlTitle, nlSub)
    VALUES (1, ?, ?, ?, ?, ?)
  `).run(
    'CommerceWorld',
    'The premium digital commerce news platform.\nNavigating trade, technology, and Web3.',
    '© 2026 CommerceWorld. All rights reserved. Built for the future of digital commerce.',
    'STAY AHEAD OF THE CURVE',
    'Get the latest commerce intelligence delivered to your inbox.'
  );
}

const adminRow = db.prepare('SELECT * FROM admin WHERE id = 1').get();
if (!adminRow) {
  const initialPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const hash = bcrypt.hashSync(initialPassword, 10);
  db.prepare('INSERT INTO admin (id, password_hash) VALUES (1, ?)').run(hash);
  console.log('Seeded default admin password. Set ADMIN_PASSWORD env var to customize, or change it later in the admin panel.');
}

module.exports = db;
