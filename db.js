const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

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
        'EconomicPulse',
        'Sharp-eyed insight on trade, technology, and Web3.',
        '© 2026 EconomicPulse. All rights reserved. Built for the future of digital commerce.',
        'STAY AHEAD OF THE CURVE',
        'Get the latest commerce intelligence delivered to your inbox.',
        JSON.stringify(['LATEST','TREND','TRADE','TECH','CURRENCY','STARTUPS','WEB3']),
      ]
    );
  }

  // Seed the admin password on first run only.
  // No hardcoded fallback password — that would be sitting in a public
  // GitHub repo for anyone to read and log in with. Instead:
  //  - If ADMIN_PASSWORD env var is set, use that as the initial password.
  //  - Otherwise, generate a random one and print it ONCE to the server
  //    logs so you can grab it from Render's log viewer, then change it
  //    immediately via the admin panel.
  const adminRes = await pool.query('SELECT id FROM admin WHERE id = 1');
  if (adminRes.rows.length === 0) {
    let initialPassword = process.env.ADMIN_PASSWORD;
    let generated = false;
    if (!initialPassword) {
      initialPassword = crypto.randomBytes(9).toString('base64url'); // 12-char random string
      generated = true;
    }
    const hash = bcrypt.hashSync(initialPassword, 10);
    await pool.query('INSERT INTO admin (id, password_hash) VALUES (1, $1)', [hash]);
    if (generated) {
      console.log('════════════════════════════════════════════════');
      console.log('No ADMIN_PASSWORD env var was set, so a random');
      console.log('initial admin password was generated:');
      console.log('  ' + initialPassword);
      console.log('Log in with it now and change it via the admin');
      console.log('panel immediately. This will not be shown again.');
      console.log('════════════════════════════════════════════════');
    } else {
      console.log('Seeded admin password from ADMIN_PASSWORD env var.');
    }
  }
}

module.exports = { pool, initDb };
