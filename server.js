require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

app.use(cors());
app.use(express.json({ limit: '15mb' }));

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

app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });

  const admin = db.prepare('SELECT * FROM admin WHERE id = 1').get();
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters' });
  }
  const admin = db.prepare('SELECT * FROM admin WHERE id = 1').get();
  if (!bcrypt.compareSync(currentPassword, admin.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const newHash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE admin SET password_hash = ? WHERE id = 1').run(newHash);
  res.json({ success: true });
});

app.get('/api/config', (req, res) => {
  const config = db.prepare('SELECT * FROM config WHERE id = 1').get();
  delete config.id;
  res.json(config);
});

app.put('/api/config', requireAuth, (req, res) => {
  const { name, tagline, copyright, nlTitle, nlSub } = req.body || {};
  db.prepare(`
    UPDATE config SET name = ?, tagline = ?, copyright = ?, nlTitle = ?, nlSub = ?
    WHERE id = 1
  `).run(name, tagline, copyright, nlTitle, nlSub);
  const updated = db.prepare('SELECT * FROM config WHERE id = 1').get();
  delete updated.id;
  res.json(updated);
});

app.get('/api/articles', (req, res) => {
  const articles = db.prepare('SELECT * FROM articles ORDER BY created_at DESC').all();
  res.json(articles);
});

app.post('/api/articles', requireAuth, (req, res) => {
  const { title, content, cat, date, excerpt, img } = req.body || {};
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }
  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO articles (id, title, content, cat, date, excerpt, img, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, title, content, cat || 'LATEST', date || new Date().toLocaleDateString(), excerpt || '', img || '', Date.now());
  res.json({ id });
});

app.put('/api/articles/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM articles WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Article not found' });

  const { title, content, cat, excerpt, img } = req.body || {};
  db.prepare(`
    UPDATE articles SET title = ?, content = ?, cat = ?, excerpt = ?, img = ?
    WHERE id = ?
  `).run(
    title ?? existing.title,
    content ?? existing.content,
    cat ?? existing.cat,
    excerpt ?? existing.excerpt,
    img ?? existing.img,
    id
  );
  res.json({ success: true });
});

app.delete('/api/articles/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const result = db.prepare('DELETE FROM articles WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Article not found' });
  res.json({ success: true });
});

app.get('/api/footer-links', (req, res) => {
  const rows = db.prepare('SELECT * FROM footer_links ORDER BY section, sort_order').all();
  const result = { company: [], resources: [], social: [] };
  for (const row of rows) {
    if (result[row.section]) {
      result[row.section].push({ label: row.label, url: row.url });
    }
  }
  res.json(result);
});

app.put('/api/footer-links', requireAuth, (req, res) => {
  const links = req.body || {};
  const sections = ['company', 'resources', 'social'];

  const deleteStmt = db.prepare('DELETE FROM footer_links WHERE section = ?');
  const insertStmt = db.prepare(`
    INSERT INTO footer_links (section, label, url, sort_order) VALUES (?, ?, ?, ?)
  `);

  const tx = db.transaction(() => {
    for (const section of sections) {
      deleteStmt.run(section);
      const items = Array.isArray(links[section]) ? links[section] : [];
      items.forEach((item, i) => {
        insertStmt.run(section, item.label || '', item.url || '#', i);
      });
    }
  });
  tx();

  res.json({ success: true });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'commerceworld-backend' });
});

app.listen(PORT, () => {
  console.log(`CommerceWorld backend running on port ${PORT}`);
});
