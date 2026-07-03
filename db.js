const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// DATABASE_URL comes from Neon (set as an environment variable on Render).
// Neon requires SSL connections.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS articles (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      cat TEXT NOT NULL,
      date TEXT NOT NULL,
      excerpt TEXT,
      img TEXT,
      created_at BIGINT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS config (
      id INTEGER PRIMARY KEY,
      name TEXT,
      tagline TEXT,
      copyright TEXT,
      nl_title TEXT,
      nl_sub TEXT,
      categories TEXT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS footer_links (
      id SERIAL PRIMARY KEY,
      section TEXT NOT NULL,
      label TEXT NOT NULL,
      url TEXT NOT NULL,
      sort_order INTEGER NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin (
      id INTEGER PRIMARY KEY,
      password_hash TEXT NOT NULL
    );
  `);

  // Seed default config if empty
  const configRes = await pool.query('SELECT id FROM config WHERE id = 1');
  // Add categories column if it doesn't exist yet (for existing databases)
  await pool.query(`ALTER TABLE config ADD COLUMN IF NOT EXISTS categories TEXT`).catch(() => {});

  if (configRes.rows.length === 0) {
    await pool.query(
      `INSERT INTO config (id, name, tagline, copyright, nl_title, nl_sub, categories)
       VALUES (1, $1, $2, $3, $4, $5, $6)`,
      [
        'OwlEconomics',
        'Sharp-eyed insight on trade, technology, and Web3.',
        '© 2026 OwlEconomics. All rights reserved. Built for the future of digital commerce.',
        'STAY AHEAD OF THE CURVE',
        'Get the latest commerce intelligence delivered to your inbox.',
        JSON.stringify(['LATEST','TREND','TRADE','TECH','CURRENCY','STARTUPS','WEB3']),
      ]
    );
  }

  // Seed default admin password if empty.
  // Default password is "admin123" unless ADMIN_PASSWORD env var is set
  // before the very first run. Change it later via the admin panel.
  const adminRes = await pool.query('SELECT id FROM admin WHERE id = 1');
  if (adminRes.rows.length === 0) {
    const initialPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const hash = bcrypt.hashSync(initialPassword, 10);
    await pool.query('INSERT INTO admin (id, password_hash) VALUES (1, $1)', [hash]);
    console.log('Seeded default admin password. Set ADMIN_PASSWORD env var to customize, or change it later in the admin panel.');
  }
}

module.exports = { pool, initDb };
