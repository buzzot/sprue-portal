/* ============================================================
 *  Sprue portal — Node.js / Express API + Supabase backend
 * ============================================================ */
'use strict';
require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
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

function signAdminToken() {
  return jwt.sign({ role: 'admin' }, SESSION_SECRET, { expiresIn: '12h' });
}
function signCustomerToken(c) {
  return jwt.sign({ role: 'customer', sub: c.id, email: c.email, name: c.name }, SESSION_SECRET, { expiresIn: '30d' });
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}
function requireAdmin(req, res, next) {
  try {
    const p = jwt.verify(bearer(req), SESSION_SECRET);
    if (p.role !== 'admin') throw new Error('bad role');
    next();
  } catch (_) { res.status(401).json({ error: 'unauthorized' }); }
}
function requireCustomer(req, res, next) {
  try {
    const p = jwt.verify(bearer(req), SESSION_SECRET);
    if (p.role !== 'customer' || !p.sub) throw new Error('bad role');
    req.customer = p;   // {sub, email, name}
    next();
  } catch (_) { res.status(401).json({ error: 'unauthorized' }); }
}
const publicProfile = (c) => ({ id: c.id, name: c.name, email: c.email, company: c.company || '', phone: c.phone || '' });

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
 *  CUSTOMER ACCOUNTS — register / login / profile
 * ============================================================ */
const publicLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 80, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'rate_limited' }),
});
const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 });

const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function customerById(id) {
  const { data, error } = await supabase.from('customers').select('*').eq('id', id).single();
  if (error) throw error;
  return data;
}
async function customerRequests(custId) {
  const { data, error } = await supabase.from('requests')
    .select('id,ref,created_at,category,category_label,title,status,priority,quotes,events')
    .eq('customer_id', custId).order('created_at', { ascending: false });
  if (error) throw error;
  return (data || []).map((r) => ({
    id: r.id, ref: r.ref, createdAt: new Date(r.created_at).getTime(),
    category: r.category, categoryLabel: r.category_label, title: r.title,
    status: r.status, priority: r.priority,
    quoteCount: (r.quotes || []).length,
    adminMsgCount: (r.events || []).filter((e) => e.kind === 'message' && e.role === 'admin').length,
  }));
}

app.post('/api/auth/register', authLimiter, wrap(async (req, res) => {
  const b = req.body || {};
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  const name = String(b.name || '').trim();
  if (!emailRe.test(email)) return res.status(400).json({ error: 'bad_email' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (!name) return res.status(400).json({ error: 'name_required' });

  const { data: existing } = await supabase.from('customers').select('id').ilike('email', email).limit(1);
  if (existing && existing.length) return res.status(409).json({ error: 'email_taken' });

  const password_hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('customers')
    .insert({ email, password_hash, name, company: String(b.company || '').slice(0, 200), phone: String(b.phone || '').slice(0, 60), verified: false })
    .select('*').single();
  if (error) {
    if (/duplicate|unique/i.test(error.message)) return res.status(409).json({ error: 'email_taken' });
    throw error;
  }
  try { await issueVerification(data, req); } catch (_) { /* logged */ }
  // No login token yet — the account must confirm their email first.
  res.json({ ok: true, pending_verification: true, email: data.email });
}));

app.post('/api/auth/login', authLimiter, wrap(async (req, res) => {
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const password = String((req.body || {}).password || '');
  const { data, error } = await supabase.from('customers').select('*').ilike('email', email).limit(1);
  if (error) throw error;
  const c = data && data[0];
  let ok = false;
  if (c && typeof c.password_hash === 'string' && c.password_hash.length) {
    try { ok = await bcrypt.compare(password, c.password_hash); } catch (_) { ok = false; }
  }
  if (!ok) return res.status(401).json({ error: 'bad_credentials' });
  if (!c.verified) return res.status(403).json({ error: 'not_verified', email: c.email });
  res.json({ token: signCustomerToken(c), customer: publicProfile(c) });
}));

/* ---------- Email (Resend) ---------- */
async function emailSend(to, subject, html) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || 'Sprue <onboarding@resend.dev>';
  if (!key) { console.warn('[email] RESEND_API_KEY not set —', subject, 'for', to, '\n', html.match(/https?:\/\/\S+?(?=["<])/) ? html.match(/https?:\/\/\S+?(?=["<])/)[0] : ''); return; }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to, subject, html }),
  });
  if (!r.ok) { console.error('[email] Resend send failed', r.status, await r.text().catch(() => '')); throw new Error('email_failed'); }
}
function emailHtml(name, intro, button, link, footer) {
  const safe = name ? String(name).replace(/[<>&]/g, '') : 'there';
  return `
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:auto;color:#0F1720">
      <p style="font-size:15px">Hi ${safe},</p>
      <p style="font-size:15px;line-height:1.5">${intro}</p>
      <p style="text-align:center;margin:28px 0">
        <a href="${link}" style="background:#1E5F8C;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-size:15px;font-weight:600;display:inline-block">${button}</a>
      </p>
      <p style="font-size:13px;color:#6C7A8A;line-height:1.5">If the button doesn't work, copy this link into your browser:<br><a href="${link}" style="color:#1E5F8C;word-break:break-all">${link}</a></p>
      <p style="font-size:13px;color:#6C7A8A">${footer}</p>
    </div>`;
}
const appBase = (req) => (process.env.APP_URL || (req.protocol + '://' + req.get('host'))).replace(/\/+$/, '');

async function issueVerification(c, req) {
  const token = crypto.randomBytes(32).toString('hex');
  const verify_hash = crypto.createHash('sha256').update(token).digest('hex');
  const verify_expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  await supabase.from('customers').update({ verify_hash, verify_expires }).eq('id', c.id);
  const link = `${appBase(req)}/verify?token=${token}&email=${encodeURIComponent(c.email)}`;
  await emailSend(c.email, 'Confirm your Sprue account',
    emailHtml(c.name, 'Thanks for registering. Please confirm your email address to activate your account. This link expires in 24 hours.',
      'Confirm my email', link, "If you didn't create this account, you can ignore this email."));
}

/* Resend the verification email (always responds ok). */
app.post('/api/auth/resend-verification', authLimiter, wrap(async (req, res) => {
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  if (emailRe.test(email)) {
    const { data } = await supabase.from('customers').select('*').ilike('email', email).limit(1);
    const c = data && data[0];
    if (c && !c.verified) { try { await issueVerification(c, req); } catch (_) {} }
  }
  res.json({ ok: true });
}));

/* Confirm the email: verify token, mark verified, sign the customer in. */
app.post('/api/auth/verify', authLimiter, wrap(async (req, res) => {
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const token = String((req.body || {}).token || '');
  if (!token) return res.status(400).json({ error: 'verify_invalid' });
  const { data } = await supabase.from('customers').select('*').ilike('email', email).limit(1);
  const c = data && data[0];
  if (c && c.verified) return res.json({ token: signCustomerToken(c), customer: publicProfile(c), already: true });
  if (!c || !c.verify_hash || !c.verify_expires || new Date(c.verify_expires).getTime() < Date.now()) {
    return res.status(400).json({ error: 'verify_invalid' });
  }
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const a = Buffer.from(hash); const bb = Buffer.from(String(c.verify_hash));
  if (a.length !== bb.length || !crypto.timingSafeEqual(a, bb)) return res.status(400).json({ error: 'verify_invalid' });
  await supabase.from('customers').update({ verified: true, verify_hash: null, verify_expires: null }).eq('id', c.id);
  res.json({ token: signCustomerToken(c), customer: publicProfile(c) });
}));

/* Request a reset link. Always responds ok (never reveals whether the email exists). */
app.post('/api/auth/forgot', authLimiter, wrap(async (req, res) => {
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  if (emailRe.test(email)) {
    const { data } = await supabase.from('customers').select('*').ilike('email', email).limit(1);
    const c = data && data[0];
    if (c) {
      const token = crypto.randomBytes(32).toString('hex');
      const reset_hash = crypto.createHash('sha256').update(token).digest('hex');
      const reset_expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      await supabase.from('customers').update({ reset_hash, reset_expires }).eq('id', c.id);
      const link = `${appBase(req)}/reset?token=${token}&email=${encodeURIComponent(c.email)}`;
      try {
        await emailSend(c.email, 'Reset your Sprue password',
          emailHtml(c.name, 'We received a request to reset your password. Click below to choose a new one. This link expires in 1 hour.',
            'Reset password', link, "If you didn't request this, ignore this email — your password won't change."));
      } catch (_) { /* logged; don't reveal to caller */ }
    }
  }
  res.json({ ok: true });
}));

/* Complete the reset: verify token, set new password, sign the customer in. */
app.post('/api/auth/reset', authLimiter, wrap(async (req, res) => {
  const b = req.body || {};
  const email = String(b.email || '').trim().toLowerCase();
  const token = String(b.token || '');
  const password = String(b.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (!token) return res.status(400).json({ error: 'reset_invalid' });
  const { data } = await supabase.from('customers').select('*').ilike('email', email).limit(1);
  const c = data && data[0];
  if (!c || !c.reset_hash || !c.reset_expires || new Date(c.reset_expires).getTime() < Date.now()) {
    return res.status(400).json({ error: 'reset_invalid' });
  }
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const a = Buffer.from(hash);
  const bb = Buffer.from(String(c.reset_hash));
  if (a.length !== bb.length || !crypto.timingSafeEqual(a, bb)) {
    return res.status(400).json({ error: 'reset_invalid' });
  }
  const password_hash = await bcrypt.hash(password, 10);
  // completing a reset also proves email ownership → mark verified
  await supabase.from('customers').update({ password_hash, verified: true, reset_hash: null, reset_expires: null }).eq('id', c.id);
  res.json({ token: signCustomerToken(c), customer: publicProfile(c) });
}));

/* Profile + this customer's requests (the dashboard payload). */
app.get('/api/me', requireCustomer, wrap(async (req, res) => {
  const c = await customerById(req.customer.sub);
  res.json({ customer: publicProfile(c), requests: await customerRequests(c.id) });
}));

/* ============================================================
 *  CUSTOMER — files & requests (all require a customer session)
 * ============================================================ */

/* Upload files -> Supabase Storage. Returns attachment descriptors. */
app.post('/api/uploads', requireCustomer, uploadLimiter, upload.array('files', 12), wrap(async (req, res) => {
  const out = [];
  for (const f of req.files || []) {
    // multer/busboy decodes the filename as latin1 — re-decode as UTF-8 so
    // non-ASCII names (Cyrillic, Chinese, etc.) are preserved correctly.
    let original = f.originalname;
    try { original = Buffer.from(f.originalname, 'latin1').toString('utf8'); } catch (_) {}
    const ext = (original.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 6);
    const id = rid();
    const p = `att/${req.customer.sub}/${id}.${ext}`;
    const { error } = await supabase.storage.from(STORAGE_BUCKET)
      .upload(p, f.buffer, { contentType: f.mimetype || 'application/octet-stream', upsert: false });
    if (error) throw error;
    out.push({ id, name: original, size: f.size, type: f.mimetype || '', path: p });
  }
  res.json({ attachments: out });
}));

/* Create a new request tied to the signed-in customer. */
app.post('/api/requests', requireCustomer, wrap(async (req, res) => {
  const b = req.body || {};
  if (!b.category) return res.status(400).json({ error: 'category_required' });
  const c = await customerById(req.customer.sub);
  const row = {
    customer_id: c.id,
    client: { name: c.name, email: c.email, company: c.company || '', phone: c.phone || '' },
    category: String(b.category).slice(0, 60),
    category_label: String(b.categoryLabel || b.category).slice(0, 120),
    title: String(b.title || b.category).slice(0, 200),
    fields: b.fields || {},
    moulds: Array.isArray(b.moulds) ? b.moulds : [],
    description: String(b.description || '').slice(0, 8000),
    attachments: Array.isArray(b.attachments) ? b.attachments : [],
    group: '', priority: 'Standard', status: 'submitted', quotes: [],
    events: [evt('status', c.name, 'client', 'Request submitted', { status: 'submitted' })],
  };
  const { data, error } = await supabase.from('requests').insert(row).select('ref,id').single();
  if (error) throw error;
  res.json({ ok: true, ref: data.ref, id: data.id });
}));

app.get('/api/my/requests', requireCustomer, wrap(async (req, res) => {
  res.json({ requests: await customerRequests(req.customer.sub) });
}));

/* Fetch one of my requests (ownership enforced). */
async function ownedRequest(id, custId) {
  const { data, error } = await supabase.from('requests').select('*').eq('id', id).single();
  if (error) return null;
  if (!data || data.customer_id !== custId) return null;
  return data;
}
app.get('/api/my/requests/:id', requireCustomer, wrap(async (req, res) => {
  const r = await ownedRequest(req.params.id, req.customer.sub);
  if (!r) return res.status(404).json({ error: 'not_found' });
  res.json({ request: await signRequest(clientView(r)) });
}));

app.post('/api/my/requests/:id/message', requireCustomer, wrap(async (req, res) => {
  const r = await ownedRequest(req.params.id, req.customer.sub);
  if (!r) return res.status(404).json({ error: 'not_found' });
  const { text, atts } = req.body || {};
  if (!text && !(atts && atts.length)) return res.status(400).json({ error: 'empty' });
  const e = evt('message', r.client.name, 'client', String(text || '').slice(0, 5000) || '(attachments)', { atts: Array.isArray(atts) ? atts : [] });
  await supabase.rpc('append_event', { p_id: r.id, p_event: e });
  res.json({ request: await signRequest(clientView(await getById(r.id))) });
}));

app.post('/api/my/requests/:id/quote-response', requireCustomer, wrap(async (req, res) => {
  const { quoteId, decision } = req.body || {};
  if (!['accepted', 'declined'].includes(decision)) return res.status(400).json({ error: 'bad_decision' });
  const r = await ownedRequest(req.params.id, req.customer.sub);
  if (!r) return res.status(404).json({ error: 'not_found' });
  const e = evt('message', r.client.name, 'client', `Quotation ${decision} by customer.`, {});
  await supabase.rpc('respond_quote', { p_id: r.id, p_quote_id: String(quoteId), p_decision: decision, p_event: e });
  res.json({ request: await signRequest(clientView(await getById(r.id))) });
}));

/* ============================================================
 *  ADMIN endpoints
 * ============================================================ */
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

// Tolerate the two most common env-var mistakes: surrounding quotes and
// leading/trailing whitespace saved into ADMIN_PASSCODE.
function normalizePass(v) {
  let s = String(v == null ? '' : v).trim();
  if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
    s = s.slice(1, -1);
  }
  return s;
}
const EXPECTED_PASSCODE = normalizePass(ADMIN_PASSCODE);
app.post('/api/admin/login', loginLimiter, wrap(async (req, res) => {
  const submitted = normalizePass((req.body || {}).passcode);
  if (!submitted || submitted !== EXPECTED_PASSCODE) {
    return res.status(401).json({ error: 'bad_passcode' });
  }
  res.json({ token: signAdminToken() });
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

/* Registered customers, with a request count for each. */
app.get('/api/admin/customers', requireAdmin, wrap(async (req, res) => {
  const { data, error } = await supabase.from('customers')
    .select('id,name,email,company,phone,verified,created_at')
    .order('created_at', { ascending: false });
  if (error) throw error;
  const { data: reqs } = await supabase.from('requests').select('customer_id');
  const counts = {};
  (reqs || []).forEach((r) => { if (r.customer_id) counts[r.customer_id] = (counts[r.customer_id] || 0) + 1; });
  const customers = (data || []).map((c) => ({
    id: c.id, name: c.name, email: c.email, company: c.company || '', phone: c.phone || '',
    verified: !!c.verified, createdAt: new Date(c.created_at).getTime(), requests: counts[c.id] || 0,
  }));
  res.json({ customers });
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
