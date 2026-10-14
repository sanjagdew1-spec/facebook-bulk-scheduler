import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'better-sqlite3-session-store';
import Database from 'better-sqlite3';
import cron from 'node-cron';
import crypto from 'node:crypto';

const app = express();
const PORT = process.env.PORT || 3000;
const APP_BASE_URL = (process.env.APP_BASE_URL || '').replace(/\/$/, '');
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://sanjagdew1-spec.github.io';
const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;
const GRAPH_VERSION = process.env.META_GRAPH_VERSION || 'v23.0';
const DB_PATH = process.env.DB_PATH || './scheduler.sqlite';

if (!META_APP_ID || !META_APP_SECRET || !APP_BASE_URL || !process.env.SESSION_SECRET) {
  console.warn('Missing one or more required environment variables: META_APP_ID, META_APP_SECRET, APP_BASE_URL, SESSION_SECRET');
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS pages (
  user_id TEXT NOT NULL, page_id TEXT NOT NULL, name TEXT NOT NULL,
  access_token TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, page_id)
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, page_id TEXT NOT NULL,
  page_name TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', image_url TEXT NOT NULL,
  scheduled_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'scheduled',
  post_id TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_due_idx ON jobs(status, scheduled_at);
`);

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(session({
  name: 'fb_scheduler_sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: new (SQLiteStoreFactory(session))( { client: db, expired: { clear: true, intervalMs: 15 * 60 * 1000 } } ),
  cookie: { httpOnly: true, secure: 'auto', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const graph = (path) => `https://graph.facebook.com/${GRAPH_VERSION}/${path}`;
const now = () => new Date().toISOString();
const scopes = ['public_profile'];
app.get('/health', (_req, res) => res.json({ ok: true, service: 'Facebook Bulk Scheduler Pro', timestamp: now() }));
app.get('/config/status', (_req, res) => res.json({
  configured: Boolean(META_APP_ID && META_APP_SECRET && APP_BASE_URL && process.env.SESSION_SECRET),
  appIdPresent: Boolean(META_APP_ID), appSecretPresent: Boolean(META_APP_SECRET),
  callbackUrl: `${APP_BASE_URL}/auth/facebook/callback`, graphVersion: GRAPH_VERSION,
  note: 'Page publishing requires Meta app access and approval for requested permissions.'
}));

app.get('/auth/facebook', (req, res) => {
  if (!META_APP_ID || !APP_BASE_URL) return res.status(500).json({ error: 'Facebook login is not configured on the server.' });
  const state = crypto.randomBytes(24).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({ client_id: META_APP_ID, redirect_uri: `${APP_BASE_URL}/auth/facebook/callback`, state, response_type: 'code', scope: scopes.join(',') });
  res.redirect(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth?${params.toString()}`);
});

app.get('/auth/facebook/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;
  if (error) return res.status(400).send(`Facebook login failed: ${String(errorDescription || error)}. You can close this tab and return to the app.`);
  if (!code || !state || state !== req.session.oauthState) return res.status(400).send('Login could not be verified. Please return to the app and try Connect with Facebook again.');
  delete req.session.oauthState;
  try {
    const tokenUrl = new URL(graph('oauth/access_token'));
    tokenUrl.search = new URLSearchParams({ client_id: META_APP_ID, client_secret: META_APP_SECRET, redirect_uri: `${APP_BASE_URL}/auth/facebook/callback`, code: String(code) }).toString();
    const tokenResponse = await fetch(tokenUrl);
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) throw new Error(tokenData.error?.message || 'Could not exchange the login code for an access token.');
    const meResponse = await fetch(`${graph('me')}?${new URLSearchParams({ fields: 'id,name', access_token: tokenData.access_token })}`);
    const me = await meResponse.json();
    if (!meResponse.ok || !me.id) throw new Error(me.error?.message || 'Could not read the Facebook account.');
    req.session.fbUser = { id: String(me.id), name: me.name || 'Facebook user', accessToken: tokenData.access_token };
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
    res.redirect(`${FRONTEND_ORIGIN}/?facebook_connected=1`);
  } catch (e) {
    res.status(400).send(`Facebook connection failed: ${String(e.message || e)}. Check Meta app status, OAuth redirect URI, and permission access.`);
  }
});

app.get('/auth/status', (req, res) => res.json({ connected: Boolean(req.session.fbUser), user: req.session.fbUser ? { id: req.session.fbUser.id, name: req.session.fbUser.name } : null }));
app.post('/auth/logout', (req, res) => req.session.destroy(err => err ? res.status(500).json({ error: 'Could not log out.' }) : res.json({ ok: true })));

function requireAuth(req, res, next) {
  if (!req.session.fbUser) return res.status(401).json({ error: 'Connect with Facebook first.' });
  next();
}

app.get('/api/pages', requireAuth, async (req, res) => {
  try {
    const u = req.session.fbUser;
    const url = `${graph('me/accounts')}?${new URLSearchParams({ fields: 'id,name,access_token,tasks', limit: '100', access_token: u.accessToken })}`;
    const response = await fetch(url);
    const data = await response.json();
    if (!response.ok || data.error) return res.status(502).json({ error: data.error?.message || 'Meta did not return Pages. Check pages_show_list access and your Page role.' });
    const pages = (data.data || []).map(p => ({ id: String(p.id), name: p.name, tasks: p.tasks || [] }));
    const save = db.prepare('INSERT INTO pages(user_id,page_id,name,access_token,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(user_id,page_id) DO UPDATE SET name=excluded.name, access_token=excluded.access_token, updated_at=excluded.updated_at');
    const tx = db.transaction(() => { for (const p of data.data || []) save.run(u.id, String(p.id), p.name || 'Facebook Page', p.access_token, now()); });
    tx();
    res.json({ pages });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/api/jobs', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id,page_id,page_name,message,image_url,scheduled_at,status,post_id,error,created_at,updated_at FROM jobs WHERE user_id=? ORDER BY scheduled_at DESC LIMIT 500').all(req.session.fbUser.id);
  res.json({ jobs: rows });
});

app.post('/api/schedule', requireAuth, (req, res) => {
  const { pageIds, imageUrl, message = '', scheduledAt } = req.body || {};
  if (!Array.isArray(pageIds) || !pageIds.length || pageIds.some(id => typeof id !== 'string' && typeof id !== 'number')) return res.status(400).json({ error: 'Select at least one Facebook Page.' });
  if (typeof imageUrl !== 'string' || !/^https:\/\//i.test(imageUrl)) return res.status(400).json({ error: 'imageUrl must be a publicly reachable HTTPS image URL.' });
  const date = new Date(scheduledAt);
  if (!scheduledAt || Number.isNaN(date.getTime()) || date.getTime() < Date.now() + 15_000) return res.status(400).json({ error: 'Choose a future schedule time at least 15 seconds from now.' });
  const insert = db.prepare("INSERT INTO jobs(id,user_id,page_id,page_name,message,image_url,scheduled_at,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'scheduled',?,?)");
  const created = [];
  const tx = db.transaction(() => {
    for (const rawId of pageIds) {
      const page = db.prepare('SELECT page_id,name FROM pages WHERE user_id=? AND page_id=?').get(req.session.fbUser.id, String(rawId));
      if (!page) throw new Error(`Page ${rawId} was not found. Refresh the Page list and try again.`);
      const id = crypto.randomUUID();
      insert.run(id, req.session.fbUser.id, page.page_id, page.name, String(message), imageUrl, date.toISOString(), now(), now());
      created.push({ id, pageId: page.page_id, pageName: page.name, scheduledAt: date.toISOString(), status: 'scheduled' });
    }
  });
  try { tx(); res.status(201).json({ jobs: created }); } catch (e) { res.status(400).json({ error: String(e.message || e) }); }
});

app.delete('/api/schedule/:id', requireAuth, (req, res) => {
  const result = db.prepare("DELETE FROM jobs WHERE id=? AND user_id=? AND status='scheduled'").run(req.params.id, req.session.fbUser.id);
  if (!result.changes) return res.status(404).json({ error: 'Scheduled job not found or already started.' });
  res.json({ ok: true });
});

async function publishDueJobs() {
  const due = db.prepare("SELECT * FROM jobs WHERE status='scheduled' AND scheduled_at<=? ORDER BY scheduled_at LIMIT 10").all(now());
  for (const job of due) {
    const claimed = db.prepare("UPDATE jobs SET status='publishing',updated_at=? WHERE id=? AND status='scheduled'").run(now(), job.id);
    if (!claimed.changes) continue;
    try {
      const page = db.prepare('SELECT access_token FROM pages WHERE user_id=? AND page_id=?').get(job.user_id, job.page_id);
      if (!page?.access_token) throw new Error('Page token missing. Reconnect Facebook and refresh Pages.');
      const body = new URLSearchParams({ url: job.image_url, caption: job.message, access_token: page.access_token });
      const response = await fetch(graph(`${job.page_id}/photos`), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
      const data = await response.json();
      if (!response.ok || data.error) throw new Error(data.error?.message || 'Meta rejected the photo post.');
      db.prepare("UPDATE jobs SET status='published',post_id=?,error=NULL,updated_at=? WHERE id=?").run(String(data.post_id || data.id || ''), now(), job.id);
    } catch (e) {
      db.prepare("UPDATE jobs SET status='failed',error=?,updated_at=? WHERE id=?").run(String(e.message || e).slice(0, 1500), now(), job.id);
      console.error('Scheduled publish failed', job.id, e.message || e);
    }
  }
}
cron.schedule('* * * * *', () => publishDueJobs().catch(err => console.error('Scheduler loop failed:', err)));

app.get('/', (_req, res) => res.type('text').send('Facebook Bulk Scheduler Pro backend is running.'));
app.listen(PORT, () => console.log(`Facebook Bulk Scheduler Pro listening on ${PORT}`));
