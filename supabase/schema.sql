-- ============================================================
--  Sprue portal — Supabase / Postgres schema
--  Run this once in your Supabase project:
--  Dashboard → SQL Editor → New query → paste → Run
-- ============================================================

-- Reference-number sequence (RFQ-YY-0001, RFQ-YY-0002, ...)
create sequence if not exists request_seq start 1;

create or replace function next_ref() returns text
  language sql as $$
    select 'RFQ-' || to_char(now(), 'YY') || '-' || lpad(nextval('request_seq')::text, 4, '0');
$$;

-- ------------------------------------------------------------
--  Customer accounts (email + password). Passwords are bcrypt
--  hashes created by the server; only the hash is stored here.
-- ------------------------------------------------------------
create table if not exists customers (
  id            uuid primary key default gen_random_uuid(),
  email         text not null,
  password_hash text not null,
  name          text not null,
  company       text default '',
  phone         text default '',
  created_at    timestamptz not null default now()
);
-- case-insensitive unique email
create unique index if not exists customers_email_uidx on customers(lower(email));
alter table customers enable row level security;

-- ------------------------------------------------------------
--  Main table. Sub-collections (events/quotes) are jsonb so the
--  app model maps 1:1; all mutations go through the atomic
--  functions below (row-level append, no lost updates).
-- ------------------------------------------------------------
create table if not exists requests (
  id             uuid primary key default gen_random_uuid(),
  ref            text unique not null default next_ref(),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  client         jsonb not null default '{}'::jsonb,   -- {name,email,company,phone}
  category       text,
  category_label text,
  title          text,
  fields         jsonb not null default '{}'::jsonb,   -- questionnaire answers by field key
  moulds         jsonb not null default '[]'::jsonb,   -- per-mould rows
  description    text  default '',
  attachments    jsonb not null default '[]'::jsonb,   -- [{id,name,size,type,path}]
  "group"        text  default '',
  priority       text  default 'Standard',
  status         text  not null default 'submitted',
  quotes         jsonb not null default '[]'::jsonb,   -- [{id,at,amount,...,status}]
  events         jsonb not null default '[]'::jsonb,   -- timeline / thread
  customer_id    uuid references customers(id)         -- owner (account)
);

-- If you deployed an earlier version, this adds the new column in place:
alter table requests add column if not exists customer_id uuid references customers(id);

create index if not exists requests_customer_idx on requests(customer_id);
create index if not exists requests_status_idx  on requests(status);
create index if not exists requests_created_idx on requests(created_at desc);
create index if not exists requests_ref_idx      on requests(lower(ref));

-- Lock the table down. The Node server uses the SERVICE ROLE key,
-- which bypasses RLS. Enabling RLS with no policies means the public
-- anon key cannot read or write directly — only your server can.
alter table requests enable row level security;

-- ------------------------------------------------------------
--  Atomic mutation helpers (called via supabase.rpc from server)
-- ------------------------------------------------------------
create or replace function append_event(p_id uuid, p_event jsonb)
  returns void language sql as $$
    update requests set events = events || p_event, updated_at = now() where id = p_id;
$$;

create or replace function add_quote(p_id uuid, p_quote jsonb, p_event jsonb)
  returns void language sql as $$
    update requests
       set quotes = quotes || p_quote,
           events = events || p_event,
           status = case
                      when status in ('approved','design','manufacturing','trial','shipped','aftersales','closed','declined')
                      then status else 'quoted' end,
           updated_at = now()
     where id = p_id;
$$;

create or replace function set_request_status(p_id uuid, p_status text, p_event jsonb)
  returns void language sql as $$
    update requests set status = p_status, events = events || p_event, updated_at = now() where id = p_id;
$$;

create or replace function classify_request(p_id uuid, p_group text, p_priority text, p_status text, p_event jsonb)
  returns void language sql as $$
    update requests
       set "group" = p_group,
           priority = p_priority,
           status = coalesce(p_status, status),
           events = events || p_event,
           updated_at = now()
     where id = p_id;
$$;

create or replace function respond_quote(p_id uuid, p_quote_id text, p_decision text, p_event jsonb)
  returns void language sql as $$
    update requests
       set quotes = (
             select coalesce(jsonb_agg(
                      case when q->>'id' = p_quote_id
                           then jsonb_set(q, '{status}', to_jsonb(p_decision))
                           else q end), '[]'::jsonb)
             from jsonb_array_elements(quotes) q),
           events = events || p_event,
           updated_at = now()
     where id = p_id;
$$;

-- ------------------------------------------------------------
--  GRANTS
--  The server connects as the "service_role". Tables created via
--  the SQL editor do not always auto-receive these grants, which
--  shows up as: 42501 "permission denied for table ...". Setting
--  them explicitly here fixes and future-proofs it. Safe to re-run.
--  (service_role bypasses RLS, so no table policies are needed.)
-- ------------------------------------------------------------
grant select, insert, update, delete on public.customers to service_role;
grant select, insert, update, delete on public.requests  to service_role;
grant usage, select on sequence request_seq to service_role;

-- Tell PostgREST to reload its schema cache immediately (avoids the
-- transient PGRST205 "could not find the table in the schema cache").
notify pgrst, 'reload schema';

-- ============================================================
--  STORAGE
--  The server auto-creates a PRIVATE bucket named "attachments"
--  on first boot. If you prefer to create it by hand:
--  Dashboard → Storage → New bucket → name: attachments, Public: OFF
--  Files are served to users through short-lived signed URLs.
-- ============================================================
