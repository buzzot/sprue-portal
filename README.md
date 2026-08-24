# Sprue — mould request & quotation portal

A self-hosted customer portal for a plastic‑injection mould business. Customers submit
structured enquiries (per‑category questionnaires, per‑mould tables, file attachments);
your team classifies, quotes and tracks each project from DFM through trial, shipment and
aftersales. Trilingual — **English (default), Русский, 中文** — with automatic
browser‑locale detection.

- **Frontend** — single static page (`public/index.html`), no build step.
- **Backend** — Node.js + Express (`server.js`).
- **Database & files** — Supabase (Postgres + Storage).
- **Hosting** — Railway.
- **Admin login** — one shared team passcode.

---

## What's in the repo

```
sprue/
├─ server.js            Express API + Supabase + auth + file uploads
├─ package.json
├─ railway.json         Railway build/deploy config (health check, restart policy)
├─ .env.example         Copy to .env for local dev
├─ .gitignore
├─ public/
│  └─ index.html        The whole portal UI (EN/RU/ZH), talks to /api/*
└─ supabase/
   └─ schema.sql        Run once in Supabase → creates tables + functions
```

---

## Deploy — step by step

You said you already have Supabase and Railway accounts, so this is the short path.

### 1 · Supabase — database

1. Open your Supabase project → **SQL Editor** → **New query**.
2. Paste the entire contents of `supabase/schema.sql` and click **Run**. This creates the
   `requests` table, the reference‑number sequence, and the atomic update functions.
3. Go to **Project Settings → API** and copy two values:
   - **Project URL** → this is `SUPABASE_URL`
   - **`service_role` secret** (under *Project API keys*) → this is
     `SUPABASE_SERVICE_ROLE_KEY`.
     ⚠️ The service_role key bypasses row‑level security. It lives **only** on the server
     (Railway env var). Never put it in the frontend or commit it.
4. Storage bucket: the server **auto‑creates** a private bucket named `attachments` on
   first boot. (If you'd rather do it by hand: **Storage → New bucket → name
   `attachments`, Public: OFF**.)

### 2 · Railway — deploy the app

**Option A — from GitHub (recommended)**

1. Push this folder to a new GitHub repo.
2. In Railway: **New Project → Deploy from GitHub repo →** pick the repo.
3. Railway auto‑detects Node and runs `npm install` then `node server.js`.

**Option B — Railway CLI**

```bash
npm i -g @railway/cli
railway login
railway init          # in this folder
railway up
```

### 3 · Railway — environment variables

In your Railway service → **Variables**, add:

| Variable | Value |
|---|---|
| `SUPABASE_URL` | your Project URL from step 1 |
| `SUPABASE_SERVICE_ROLE_KEY` | your service_role secret |
| `ADMIN_PASSCODE` | the passcode your team will type to open the admin console |
| `SESSION_SECRET` | any long random string (40+ chars) — signs login sessions |
| `STORAGE_BUCKET` | `attachments` (optional; this is the default) |

`PORT` is provided by Railway automatically — don't set it. After adding variables,
redeploy (Railway does this for you on save).

### 4 · Custom domain — inquiry.highsb.com

1. Railway service → **Settings → Networking → Custom Domain →** enter
   `inquiry.highsb.com`. Railway shows a target hostname.
2. At your DNS provider for `highsb.com`, add a **CNAME**:
   `inquiry` → the `xxxx.up.railway.app` target Railway gave you.
3. Wait for DNS to propagate (minutes to an hour). Railway issues the HTTPS certificate
   automatically. Done — the portal is live at `https://inquiry.highsb.com`.

---

## Run locally (optional)

```bash
cp .env.example .env      # then fill in the four required values
npm install
npm start                 # http://localhost:3000
```

---

## How it works

- **Customers** open the portal, pick their language (auto‑detected, switchable top‑right),
  and either submit a new request or track an existing one with their **reference number +
  email**. That pair is the private key to a request — a customer can only see their own.
- **Your team** clicks *Team access*, enters the shared passcode, and gets the admin
  console: filter the pipeline, open a request, read the questionnaire and per‑mould table,
  post messages (or internal‑only notes), send quotations, classify, and advance status
  through the lifecycle. Every action is logged to the request's timeline.
- **Files** are uploaded to the private Supabase Storage bucket and served to customers and
  admins through short‑lived signed URLs (1 hour), so the bucket itself stays private.

### Languages

All UI text, statuses, categories and questionnaire fields are translated in
`public/index.html` (the `UI`, `STATUSES`, `GROUPS`, `PRIORITIES` and `CATEGORIES`
objects). Each translatable string is an object like `{en:'…', ru:'…', zh:'…'}`. Stored
values (e.g. selected material, status key) are language‑neutral, so a request created in
Chinese reads correctly in English and vice‑versa.

### Adding or editing questionnaire fields

Edit the `CATEGORIES` object in `public/index.html`. Each field is
`{k, t, label:{en,ru,zh}, ...}` where `t` is `text` | `number` | `textarea` | `select` |
`multi`. For a `select`/`multi`, `options` is an array of either plain strings (kept the
same in all languages — good for steel grades, brand names) or `{v, en, ru, zh}` objects
(translated; `v` is the stored value). No backend change is needed — the server stores
whatever fields you send.

---

## Security notes

- The **shared passcode** gates the admin console and the server verifies it before issuing
  a 12‑hour signed session token. It's appropriate for a small trusted team. If you later
  want per‑person logins, the code is structured so Supabase Auth can replace the passcode
  check in `/api/admin/login` and `requireAdmin`.
- The **service_role key** and **passcode** live only in Railway env vars.
- Public endpoints (submit, track, upload) are rate‑limited.
- Row‑level security is enabled on the table with no public policies, so the Supabase anon
  key can't read anything — only your server (service_role) can.
