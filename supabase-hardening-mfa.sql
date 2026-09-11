-- Additional production hardening: require MFA (AAL2) for administrator access.

create or replace function public.is_mfa_admin_or_editor()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select (auth.jwt()->>'aal') = 'aal2'
    and exists (
      select 1 from public.admin_profiles p
      where p.user_id = auth.uid()
        and p.enabled = true
        and p.role in ('editor','admin')
    );
$$;

create or replace function public.is_mfa_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select (auth.jwt()->>'aal') = 'aal2'
    and exists (
      select 1 from public.admin_profiles p
      where p.user_id = auth.uid()
        and p.enabled = true
        and p.role = 'admin'
    );
$$;

drop policy if exists reports_select_admin on public.medical_reports;
create policy reports_select_admin on public.medical_reports
for select to authenticated
using (
  (auth.jwt()->>'aal') = 'aal2'
  and exists (
    select 1 from public.admin_profiles p
    where p.user_id = auth.uid() and p.enabled = true
  )
);

drop policy if exists reports_update_editor on public.medical_reports;
create policy reports_update_editor on public.medical_reports
for update to authenticated
using (public.is_mfa_admin_or_editor())
with check (public.is_mfa_admin_or_editor());

drop policy if exists reports_delete_admin on public.medical_reports;
create policy reports_delete_admin on public.medical_reports
for delete to authenticated
using (public.is_mfa_admin());

drop policy if exists profiles_self_read on public.admin_profiles;
create policy profiles_self_read on public.admin_profiles
for select to authenticated
using ((auth.jwt()->>'aal') = 'aal2' and user_id = auth.uid());

drop policy if exists audit_read_admin on public.audit_logs;
create policy audit_read_admin on public.audit_logs
for select to authenticated
using (public.is_mfa_admin());

-- Direct writes to audit_logs remain unavailable to browser clients.
-- Write audit events from trusted Edge Functions/service-role code only.
