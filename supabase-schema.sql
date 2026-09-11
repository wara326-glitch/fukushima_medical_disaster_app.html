-- Fukushima Medical Disaster App secure backend schema
-- Run in Supabase SQL Editor before enabling the production frontend.

create extension if not exists pgcrypto;

create table if not exists public.medical_reports (
  id uuid primary key default gen_random_uuid(),
  report_type text not null check (report_type in ('safety','emergency','detail')),
  facility text not null,
  facility_type text not null,
  municipality text not null,
  reporter text not null,
  phone text not null,
  reported_at timestamptz,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_ip_hash text,
  user_agent_hash text
);

create index if not exists idx_medical_reports_created_at on public.medical_reports(created_at desc);
create index if not exists idx_medical_reports_type on public.medical_reports(report_type);
create index if not exists idx_medical_reports_facility on public.medical_reports(facility);
create index if not exists idx_medical_reports_municipality on public.medical_reports(municipality);

create table if not exists public.admin_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'viewer' check (role in ('viewer','editor','admin')),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor uuid references auth.users(id),
  action text not null,
  report_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.medical_reports enable row level security;
alter table public.admin_profiles enable row level security;
alter table public.audit_logs enable row level security;

-- No direct anonymous SELECT/UPDATE/DELETE access to reports.
-- Anonymous INSERT is intentionally NOT granted directly: public submissions
-- should go through the submit-report Edge Function with validation and rate limiting.

create or replace function public.is_admin_or_editor()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.admin_profiles p
    where p.user_id = auth.uid()
      and p.enabled = true
      and p.role in ('editor','admin')
  );
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.admin_profiles p
    where p.user_id = auth.uid()
      and p.enabled = true
      and p.role = 'admin'
  );
$$;

drop policy if exists reports_select_admin on public.medical_reports;
create policy reports_select_admin on public.medical_reports
for select to authenticated
using (exists (
  select 1 from public.admin_profiles p
  where p.user_id = auth.uid() and p.enabled = true
));

drop policy if exists reports_update_editor on public.medical_reports;
create policy reports_update_editor on public.medical_reports
for update to authenticated
using (public.is_admin_or_editor())
with check (public.is_admin_or_editor());

drop policy if exists reports_delete_admin on public.medical_reports;
create policy reports_delete_admin on public.medical_reports
for delete to authenticated
using (public.is_admin());

drop policy if exists profiles_self_read on public.admin_profiles;
create policy profiles_self_read on public.admin_profiles
for select to authenticated
using (user_id = auth.uid());

drop policy if exists audit_read_admin on public.audit_logs;
create policy audit_read_admin on public.audit_logs
for select to authenticated
using (public.is_admin());

-- Keep updated_at current.
create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_medical_reports_updated_at on public.medical_reports;
create trigger trg_medical_reports_updated_at
before update on public.medical_reports
for each row execute function public.touch_updated_at();

drop trigger if exists trg_admin_profiles_updated_at on public.admin_profiles;
create trigger trg_admin_profiles_updated_at
before update on public.admin_profiles
for each row execute function public.touch_updated_at();

-- Record administrator changes inside PostgreSQL so browser clients cannot
-- suppress or forge the audit trail.
create or replace function public.audit_medical_report_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.audit_logs(actor, action, report_id, details)
  values (
    auth.uid(),
    lower(TG_OP),
    coalesce(new.id, old.id),
    jsonb_build_object(
      'report_type', coalesce(new.report_type, old.report_type),
      'facility', coalesce(new.facility, old.facility)
    )
  );
  return coalesce(new, old);
end;
$$;

revoke all on function public.audit_medical_report_change() from public, anon, authenticated;

drop trigger if exists trg_medical_reports_audit on public.medical_reports;
create trigger trg_medical_reports_audit
after update or delete on public.medical_reports
for each row execute function public.audit_medical_report_change();

-- IMPORTANT production rules:
-- 1. Never expose the service_role key in GitHub Pages.
-- 2. Require MFA for administrator accounts.
-- 3. Restrict administrator email domains/addresses in Auth configuration.
-- 4. Put anonymous submissions behind an Edge Function with CAPTCHA/Turnstile,
--    body-size validation and IP-based rate limiting.
-- 5. Do not collect patient names, DOBs, chart numbers or other patient identifiers.
