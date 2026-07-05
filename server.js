require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start with an insecure default. Set JWT_SECRET on Render (Settings > Environment) to a long random string before deploying.');
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: '15mb' }));

/* ──────────────────────────────────────────────
   BASIC LOGIN RATE LIMITING (in-memory)
   Blocks brute-force password guessing on /api/login.
   Resets on server restart — fine for a single-admin blog.
   ────────────────────────────────────────────── */
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const LOGIN_MAX_ATTEMPTS = 8;

function loginRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
    return next();
  }
  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    const waitMin = Math.ceil((LOGIN_WINDOW_MS - (now - entry.firstAttempt)) / 60000);
    return res.status(429).json({ error: `Too many login attempts. Try again in ${waitMin} minute(s).` });
  }
  entry.count++;
  next();
}
// Periodic cleanup so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now - entry.firstAttempt > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  }
}, LOGIN_WINDOW_MS).unref();

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ──────────────────────────────────────────────
   AUTH ROUTES
   ────────────────────────────────────────────── */
app.post('/api/login', loginRateLimit, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'Password required' });

    const result = await pool.query('SELECT * FROM admin WHERE id = 1');
    const admin = result.rows[0];
    if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    loginAttempts.delete(ip);
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }
    if (newPassword.length < 4) {
      return res.status(400).json({ error: 'New password must be at least 4 characters' });
    }
    const result = await pool.query('SELECT * FROM admin WHERE id = 1');
    const admin = result.rows[0];
    if (!bcrypt.compareSync(currentPassword, admin.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const newHash = bcrypt.hashSync(newPassword, 10);
    await pool.query('UPDATE admin SET password_hash = $1 WHERE id = 1', [newHash]);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────────────────────────────────────────────
   CONFIG ROUTES
   ────────────────────────────────────────────── */
app.get('/api/config', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM config WHERE id = 1');
    const c = result.rows[0];
    let categories = ['LATEST','TREND','TRADE','TECH','CURRENCY','STARTUPS','WEB3'];
    try { if (c.categories) categories = JSON.parse(c.categories); } catch(e) {}
    res.json({
      name: c.name,
      tagline: c.tagline,
      copyright: c.copyright,
      nlTitle: c.nl_title,
      nlSub: c.nl_sub,
      categories,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/config', requireAuth, async (req, res) => {
  try {
    const { name, tagline, copyright, nlTitle, nlSub, categories } = req.body || {};
    await pool.query(
      `UPDATE config SET name = $1, tagline = $2, copyright = $3, nl_title = $4, nl_sub = $5, categories = $6 WHERE id = 1`,
      [name, tagline, copyright, nlTitle, nlSub, JSON.stringify(categories || ['LATEST'])]
    );
    const result = await pool.query('SELECT * FROM config WHERE id = 1');
    const c = result.rows[0];
    let cats = ['LATEST','TREND','TRADE','TECH','CURRENCY','STARTUPS','WEB3'];
    try { if (c.categories) cats = JSON.parse(c.categories); } catch(e) {}
    res.json({
      name: c.name,
      tagline: c.tagline,
      copyright: c.copyright,
      nlTitle: c.nl_title,
      nlSub: c.nl_sub,
      categories: cats,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────────────────────────────────────────────
   ARTICLE ROUTES
   ────────────────────────────────────────────── */
app.get('/api/articles', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM articles ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/articles', requireAuth, async (req, res) => {
  try {
    const { title, content, cat, date, excerpt, img } = req.body || {};
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO articles (id, title, content, cat, date, excerpt, img, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, title, content, cat || 'LATEST', date || new Date().toLocaleDateString(), excerpt || '', img || '', Date.now()]
    );
    res.json({ id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/articles/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existingRes = await pool.query('SELECT * FROM articles WHERE id = $1', [id]);
    const existing = existingRes.rows[0];
    if (!existing) return res.status(404).json({ error: 'Article not found' });

    const { title, content, cat, excerpt, img } = req.body || {};
    await pool.query(
      `UPDATE articles SET title = $1, content = $2, cat = $3, excerpt = $4, img = $5 WHERE id = $6`,
      [
        title ?? existing.title,
        content ?? existing.content,
        cat ?? existing.cat,
        excerpt ?? existing.excerpt,
        img ?? existing.img,
        id,
      ]
    );
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/articles/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM articles WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Article not found' });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────────────────────────────────────────────
   FOOTER LINKS ROUTES
   ────────────────────────────────────────────── */
app.get('/api/footer-links', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM footer_links ORDER BY section, sort_order');
    const out = { company: [], resources: [], social: [] };
    for (const row of result.rows) {
      if (out[row.section]) out[row.section].push({ label: row.label, url: row.url });
    }
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/footer-links', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const links = req.body || {};
    const sections = ['company', 'resources', 'social'];

    await client.query('BEGIN');
    for (const section of sections) {
      await client.query('DELETE FROM footer_links WHERE section = $1', [section]);
      const items = Array.isArray(links[section]) ? links[section] : [];
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        await client.query(
          'INSERT INTO footer_links (section, label, url, sort_order) VALUES ($1, $2, $3, $4)',
          [section, item.label || '', item.url || '#', i]
        );
      }
    }
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

/* ──────────────────────────────────────────────
   HEALTH CHECK
   ────────────────────────────────────────────── */
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'economicpulse-backend' });
});

/* ──────────────────────────────────────────────
   STARTUP
   ────────────────────────────────────────────── */
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`EconomicPulse backend running on port ${PORT}`);
    });
  })
  .catch((e) => {
    console.error('Failed to initialize database:', e);
    process.exit(1);
  });
