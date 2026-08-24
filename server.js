/* ============================================================
 *  Sprue portal — Node.js / Express API + Supabase backend
 * ============================================================ */
'use strict';
require('dotenv').config();

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

/* ---------- config ---------- */
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ADMIN_PASSCODE,
  SESSION_SECRET,
  PORT = 3000,
  STORAGE_BUCKET = 'attachments',
} = process.env;

for (const [k, v] of Object.entries({ SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ADMIN_PASSCODE, SESSION_SECRET })) {
  if (!v) { console.error(`\n[FATAL] Missing required env var: ${k}\n`); process.exit(1); }
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024, files: 12 },
});

/* ---------- helpers ---------- */
const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => {
  console.error(e);
  res.status(500).json({ error: 'server_error', message: e.message });
});

function signToken() {
  return jwt.sign({ role: 'admin' }, SESSION_SECRET, { expiresIn: '12h' });
}
function requireAdmin(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  try {
    const p = jwt.verify(token, SESSION_SECRET);
    if (p.role !== 'admin') throw new Error('bad role');
    next();
  } catch (_) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

const SAFE_STATUSES = new Set([
  'submitted','under_review','classified','info_needed','quoted','approved',
  'design','manufacturing','trial','shipped','aftersales','closed','declined',
]);
const rid = () => Math.random().toString(36).slice(2, 10);
const now = () => Date.now();
const evt = (kind, by, role, text, extra) => ({ id: rid(), at: now(), kind, by, role, text, ...(extra || {}) });

/* Attach fresh signed URLs to every stored attachment path so the
 * browser can preview private files without exposing the bucket. */
async function signAttachments(list) {
  if (!Array.isArray(list) || !list.length) return list || [];
  const paths = list.map((a) => a.path).filter(Boolean);
  if (!paths.length) return list;
  const { data } = await supabase.storage.from(STORAGE_BUCKET).createSignedUrls(paths, 3600);
  const byPath = {};
  (data || []).forEach((d) => { if (d.path) byPath[d.path] = d.signedUrl; });
  return list.map((a) => ({ ...a, url: byPath[a.path] || null }));
}
async function signRequest(r) {
  if (!r) return r;
  r.attachments = await signAttachments(r.attachments);
  if (Array.isArray(r.events)) {
    for (const e of r.events) if (e && Array.isArray(e.atts) && e.atts.length) e.atts = await signAttachments(e.atts);
  }
  return r;
}
/* What the customer is allowed to see: hide internal notes. */
function clientView(r) {
  const copy = { ...r };
  copy.events = (r.events || []).filter((e) => e.kind !== 'internal');
  return copy;
}

async function getById(id) {
  const { data, error } = await supabase.from('requests').select('*').eq('id', id).single();
  if (error) throw error;
  return data;
}
async function getByRef(ref) {
  const { data, error } = await supabase.from('requests').select('*').ilike('ref', ref).limit(1);
  if (error) throw error;
  return data && data[0];
}

/* ============================================================
 *  PUBLIC (customer) endpoints
 * ============================================================ */
const publicLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });

/* Upload files -> Supabase Storage. Returns attachment descriptors. */
app.post('/api/uploads', uploadLimiter, upload.array('files', 12), wrap(async (req, res) => {
  const out = [];
  for (const f of req.files || []) {
    const ext = (f.originalname.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 6);
    const id = rid();
    const p = `att/${new Date().getFullYear()}/${id}.${ext}`;
    const { error } = await supabase.storage.from(STORAGE_BUCKET)
      .upload(p, f.buffer, { contentType: f.mimetype || 'application/octet-stream', upsert: false });
    if (error) throw error;
    out.push({ id, name: f.originalname, size: f.size, type: f.mimetype || '', path: p });
  }
  res.json({ attachments: out });
}));

/* Create a new request. */
app.post('/api/requests', publicLimiter, wrap(async (req, res) => {
  const b = req.body || {};
  const client = b.client || {};
  if (!client.name || !client.email) return res.status(400).json({ error: 'name_email_required' });
  if (!b.category) return res.status(400).json({ error: 'category_required' });

  const row = {
    client: {
      name: String(client.name).slice(0, 200),
      email: String(client.email).slice(0, 200),
      company: String(client.company || '').slice(0, 200),
      phone: String(client.phone || '').slice(0, 60),
    },
    category: String(b.category).slice(0, 60),
    category_label: String(b.categoryLabel || b.category).slice(0, 120),
    title: String(b.title || b.category).slice(0, 200),
    fields: b.fields || {},
    moulds: Array.isArray(b.moulds) ? b.moulds : [],
    description: String(b.description || '').slice(0, 8000),
    attachments: Array.isArray(b.attachments) ? b.attachments : [],
    group: '', priority: 'Standard', status: 'submitted', quotes: [],
    events: [evt('status', client.name, 'client', 'Request submitted', { status: 'submitted' })],
  };
  const { data, error } = await supabase.from('requests').insert(row).select('ref,id').single();
  if (error) throw error;
  res.json({ ok: true, ref: data.ref, id: data.id });
}));

/* Customer track — requires ref + matching email. */
app.post('/api/track', publicLimiter, wrap(async (req, res) => {
  const { ref, email } = req.body || {};
  if (!ref || !email) return res.status(400).json({ error: 'ref_email_required' });
  const r = await getByRef(String(ref).trim());
  if (!r || (r.client.email || '').toLowerCase() !== String(email).trim().toLowerCase()) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json({ request: await signRequest(clientView(r)) });
}));

/* Customer posts a message (optionally with attachments). */
app.post('/api/track/message', publicLimiter, wrap(async (req, res) => {
  const { ref, email, text, atts } = req.body || {};
  const r = await getByRef(String(ref || '').trim());
  if (!r || (r.client.email || '').toLowerCase() !== String(email || '').trim().toLowerCase()) {
    return res.status(404).json({ error: 'not_found' });
  }
  const e = evt('message', r.client.name, 'client', String(text || '').slice(0, 5000) || '(attachments)', { atts: Array.isArray(atts) ? atts : [] });
  await supabase.rpc('append_event', { p_id: r.id, p_event: e });
  const fresh = await getById(r.id);
  res.json({ request: await signRequest(clientView(fresh)) });
}));

/* Customer accepts / declines a quotation. */
app.post('/api/track/quote-response', publicLimiter, wrap(async (req, res) => {
  const { ref, email, quoteId, decision } = req.body || {};
  if (!['accepted', 'declined'].includes(decision)) return res.status(400).json({ error: 'bad_decision' });
  const r = await getByRef(String(ref || '').trim());
  if (!r || (r.client.email || '').toLowerCase() !== String(email || '').trim().toLowerCase()) {
    return res.status(404).json({ error: 'not_found' });
  }
  const e = evt('message', r.client.name, 'client', `Quotation ${decision} by customer.`, {});
  await supabase.rpc('respond_quote', { p_id: r.id, p_quote_id: String(quoteId), p_decision: decision, p_event: e });
  const fresh = await getById(r.id);
  res.json({ request: await signRequest(clientView(fresh)) });
}));

/* ============================================================
 *  ADMIN endpoints
 * ============================================================ */
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

app.post('/api/admin/login', loginLimiter, wrap(async (req, res) => {
  const { passcode } = req.body || {};
  if (!passcode || String(passcode) !== String(ADMIN_PASSCODE)) {
    return res.status(401).json({ error: 'bad_passcode' });
  }
  res.json({ token: signToken() });
}));

app.get('/api/admin/requests', requireAdmin, wrap(async (req, res) => {
  const { data, error } = await supabase.from('requests')
    .select('id,ref,created_at,client,category,category_label,title,group,priority,status,quotes,events')
    .order('created_at', { ascending: false });
  if (error) throw error;
  // lightweight list: strip heavy fields, keep counts
  const list = (data || []).map((r) => ({
    id: r.id, ref: r.ref, createdAt: new Date(r.created_at).getTime(),
    client: r.client, category: r.category, categoryLabel: r.category_label, title: r.title,
    group: r.group, priority: r.priority, status: r.status,
    quoteCount: (r.quotes || []).length,
    clientMsgCount: (r.events || []).filter((e) => e.kind === 'message' && e.role === 'client').length,
  }));
  res.json({ requests: list });
}));

app.get('/api/admin/requests/:id', requireAdmin, wrap(async (req, res) => {
  const r = await getById(req.params.id);
  res.json({ request: await signRequest(r) });
}));

app.post('/api/admin/requests/:id/status', requireAdmin, wrap(async (req, res) => {
  const { status, note } = req.body || {};
  if (!SAFE_STATUSES.has(status)) return res.status(400).json({ error: 'bad_status' });
  const e = evt('status', 'Team', 'admin', note ? `${status} — ${note}` : status, { status });
  await supabase.rpc('set_request_status', { p_id: req.params.id, p_status: status, p_event: e });
  res.json({ request: await signRequest(await getById(req.params.id)) });
}));

app.post('/api/admin/requests/:id/classify', requireAdmin, wrap(async (req, res) => {
  const { group, priority, note, status } = req.body || {};
  const e = evt('classify', 'Team', 'admin', `Classified: ${group} · ${priority}${note ? ' — ' + note : ''}`, {});
  const newStatus = SAFE_STATUSES.has(status) ? status : null;
  await supabase.rpc('classify_request', {
    p_id: req.params.id, p_group: String(group || ''), p_priority: String(priority || 'Standard'),
    p_status: newStatus, p_event: e,
  });
  res.json({ request: await signRequest(await getById(req.params.id)) });
}));

app.post('/api/admin/requests/:id/message', requireAdmin, wrap(async (req, res) => {
  const { text, internal, atts } = req.body || {};
  if (!text && !(atts && atts.length)) return res.status(400).json({ error: 'empty' });
  const e = evt(internal ? 'internal' : 'message', 'Team', 'admin', String(text || '').slice(0, 5000), { atts: Array.isArray(atts) ? atts : [] });
  await supabase.rpc('append_event', { p_id: req.params.id, p_event: e });
  res.json({ request: await signRequest(await getById(req.params.id)) });
}));

app.post('/api/admin/requests/:id/quote', requireAdmin, wrap(async (req, res) => {
  const b = req.body || {};
  if (!b.amount) return res.status(400).json({ error: 'amount_required' });
  const quote = {
    id: rid(), at: now(),
    amount: String(b.amount).slice(0, 40), currency: String(b.currency || 'USD').slice(0, 8),
    leadTime: String(b.leadTime || '').slice(0, 120), validity: String(b.validity || '').slice(0, 120),
    incoterm: String(b.incoterm || '').slice(0, 60), notes: String(b.notes || '').slice(0, 4000),
    status: 'pending',
  };
  const e = evt('quote', 'Team', 'admin', `Quotation ${quote.currency} ${quote.amount}${quote.leadTime ? ' · ' + quote.leadTime : ''}`, { quoteId: quote.id });
  await supabase.rpc('add_quote', { p_id: req.params.id, p_quote: quote, p_event: e });
  res.json({ request: await signRequest(await getById(req.params.id)) });
}));

/* health check for Railway */
app.get('/api/health', (req, res) => res.json({ ok: true }));

/* SPA fallback */
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not_found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ---------- boot ---------- */
async function ensureBucket() {
  try {
    const { data } = await supabase.storage.getBucket(STORAGE_BUCKET);
    if (!data) {
      const { error } = await supabase.storage.createBucket(STORAGE_BUCKET, { public: false });
      if (error && !/already exists/i.test(error.message)) console.warn('[storage] createBucket:', error.message);
      else console.log(`[storage] bucket "${STORAGE_BUCKET}" ready`);
    }
  } catch (e) { console.warn('[storage] bucket check skipped:', e.message); }
}

// Start listening IMMEDIATELY so Railway's health check passes, then set up
// the storage bucket in the background (a slow/failed Supabase call must never
// delay the port from opening).
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sprue portal listening on :${PORT}`);
  ensureBucket();
});
