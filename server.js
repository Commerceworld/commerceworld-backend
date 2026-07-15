require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const webpush = require('web-push');
const { pool, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start with an insecure default. Set JWT_SECRET on Render (Settings > Environment) to a long random string before deploying.');
  process.exit(1);
}

/* ──────────────────────────────────────────────
   WEB PUSH (VAPID) SETUP
   VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY must be set on Render
   (Settings > Environment). Generate a pair with:
     npx web-push generate-vapid-keys
   ────────────────────────────────────────────── */
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';

if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.warn('VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY not set — push notifications are disabled until these are configured on Render.');
} else {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

// Sends a push payload to every stored subscription, pruning any that
// are no longer valid (410 Gone / 404 Not Found from the push service).
async function broadcastPush(payload) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
  const result = await pool.query('SELECT * FROM push_subscriptions');
  const json = JSON.stringify(payload);
  await Promise.all(result.rows.map(async (row) => {
    const subscription = {
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.auth },
    };
    try {
      await webpush.sendNotification(subscription, json);
    } catch (err) {
      if (err.statusCode === 410 || err.statusCode === 404) {
        await pool.query('DELETE FROM push_subscriptions WHERE endpoint = $1', [row.endpoint]);
      } else {
        console.error('Push send error:', err.statusCode, err.body);
      }
    }
  }));
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

// Auth guard for logged-in READERS (separate from the single-admin
// requireAuth above). Verifies the JWT was issued for a user account
// (role === 'user') and attaches the user id to the request.
function requireUserAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'user' || !decoded.uid) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.userId = decoded.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Same basic in-memory rate limiting, reused for reader register/login.
const readerAuthAttempts = new Map();
function readerAuthRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const now = Date.now();
  const entry = readerAuthAttempts.get(ip);
  if (!entry || now - entry.firstAttempt > LOGIN_WINDOW_MS) {
    readerAuthAttempts.set(ip, { count: 1, firstAttempt: now });
    return next();
  }
  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    const waitMin = Math.ceil((LOGIN_WINDOW_MS - (now - entry.firstAttempt)) / 60000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${waitMin} minute(s).` });
  }
  entry.count++;
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of readerAuthAttempts) {
    if (now - entry.firstAttempt > LOGIN_WINDOW_MS) readerAuthAttempts.delete(ip);
  }
}, LOGIN_WINDOW_MS).unref();

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
   READER ACCOUNT ROUTES (register / login / me)
   Separate from the single-admin routes above — these are for
   regular visitors so their Saved + History follow their account.
   ────────────────────────────────────────────── */
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post('/api/auth/register', readerAuthRateLimit, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Enter a valid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with that email already exists' });
    }

    const id = crypto.randomUUID();
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(
      'INSERT INTO users (id, name, email, password_hash, created_at) VALUES ($1, $2, $3, $4, $5)',
      [id, name.trim(), normalizedEmail, hash, Date.now()]
    );

    const token = jwt.sign({ role: 'user', uid: id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, name: name.trim(), email: normalizedEmail } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', readerAuthRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const normalizedEmail = email.trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Incorrect email or password' });
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    readerAuthAttempts.delete(ip);
    const token = jwt.sign({ role: 'user', uid: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', requireUserAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [req.userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ──────────────────────────────────────────────
   SAVED ARTICLES + READING HISTORY ROUTES
   All scoped to the logged-in reader (requireUserAuth).
   ────────────────────────────────────────────── */
app.get('/api/saved', requireUserAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT article_id FROM user_saved WHERE user_id = $1 ORDER BY created_at DESC',
      [req.userId]
    );
    res.json({ savedIds: result.rows.map(r => r.article_id) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/saved/:articleId', requireUserAuth, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO user_saved (user_id, article_id, created_at) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, article_id) DO NOTHING`,
      [req.userId, req.params.articleId, Date.now()]
    );
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/saved/:articleId', requireUserAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_saved WHERE user_id = $1 AND article_id = $2', [req.userId, req.params.articleId]);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/saved', requireUserAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_saved WHERE user_id = $1', [req.userId]);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/history', requireUserAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT article_id, viewed_at FROM user_history WHERE user_id = $1 ORDER BY viewed_at DESC LIMIT 50',
      [req.userId]
    );
    res.json({ history: result.rows.map(r => ({ articleId: r.article_id, viewedAt: Number(r.viewed_at) })) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/history/:articleId', requireUserAuth, async (req, res) => {
  try {
    const now = Date.now();
    await pool.query(
      `INSERT INTO user_history (user_id, article_id, viewed_at) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, article_id) DO UPDATE SET viewed_at = $3`,
      [req.userId, req.params.articleId, now]
    );
    // Keep only the 50 most recent entries per user
    await pool.query(
      `DELETE FROM user_history WHERE user_id = $1 AND article_id NOT IN (
         SELECT article_id FROM user_history WHERE user_id = $1 ORDER BY viewed_at DESC LIMIT 50
       )`,
      [req.userId]
    );
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/history', requireUserAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM user_history WHERE user_id = $1', [req.userId]);
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
   PUSH NOTIFICATION ROUTES
   ────────────────────────────────────────────── */
app.get('/api/push/vapid-public-key', (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push not configured' });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { subscription } = req.body || {};
    if (!subscription || !subscription.endpoint || !subscription.keys) {
      return res.status(400).json({ error: 'Invalid subscription' });
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO push_subscriptions (id, endpoint, p256dh, auth, created_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (endpoint) DO UPDATE SET p256dh = $3, auth = $4`,
      [id, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth, Date.now()]
    );
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/push/unsubscribe', async (req, res) => {
  try {
    const { endpoint } = req.body || {};
    if (!endpoint) return res.status(400).json({ error: 'Endpoint required' });
    await pool.query('DELETE FROM push_subscriptions WHERE endpoint = $1', [endpoint]);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Lets the admin send a one-off manual push (e.g. "New issue is live!")
app.post('/api/push/send', requireAuth, async (req, res) => {
  try {
    const { title, body, url } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Title is required' });
    await broadcastPush({ title, body: body || '', url: url || '/' });
    res.json({ success: true });
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

    // Fire-and-forget: notify subscribers a new article is up.
    // Doesn't block or fail the response if push errors out.
    broadcastPush({
      title: 'New article published',
      body: excerpt || title,
      url: `/?article=${id}`,
    }).catch((e) => console.error('broadcastPush failed:', e));
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
