# Security policy / production design

This application is intended to collect disaster-status reports from medical institutions in Fukushima Prefecture.

## Security model

### Medical-institution side
- No administrator login required for emergency reporting.
- Browser clients cannot SELECT, UPDATE or DELETE reports.
- Reports are submitted only through the `submit-report` Edge Function.
- The Edge Function validates origin, method, body size, required fields and field lengths.
- Optional Cloudflare Turnstile human verification is supported and should be enabled in production.
- IP addresses and user agents are not stored in plaintext; salted hashes may be used only for abuse/rate-limit controls.
- Patient-identifying fields are explicitly rejected. Do not collect patient name, DOB, chart number or medical-record number.

### Administrator side
- Use Supabase Auth with individual administrator accounts.
- Require MFA/AAL2 for all report viewing, editing and deletion.
- Use `admin_profiles` roles: `viewer`, `editor`, `admin`.
- `viewer`: read only.
- `editor`: read and edit.
- `admin`: read, edit, delete and view audit logs.
- Never share administrator credentials.
- Disable accounts immediately when a user no longer needs access.

### Database
- Row Level Security (RLS) is mandatory.
- Anonymous database SELECT/UPDATE/DELETE is prohibited.
- Anonymous direct INSERT is also prohibited; public reports go through the Edge Function.
- The Supabase `service_role` key must exist only in server-side Edge Function secrets, never in GitHub Pages or committed source code.
- The public anon/publishable key may be used by the admin login client only because RLS remains the authorization boundary.

## Required production configuration

1. Create a Supabase project.
2. Apply `supabase-schema.sql`.
3. Apply `supabase-hardening-mfa.sql`.
4. Deploy `supabase/functions/submit-report/index.ts`.
5. Configure Edge Function secrets:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `REQUEST_HASH_SALT` (long random value)
   - `TURNSTILE_SECRET_KEY` (recommended)
6. Enable MFA for administrators in Supabase Auth.
7. Create each administrator account individually and add its UUID to `admin_profiles`.
8. Configure backups and retention suitable for the organization.
9. Review Supabase logs and audit logs periodically.

## Incident-safety priorities

Availability during a disaster is important. Public reporting should therefore avoid mandatory user accounts, while administrative access is intentionally strict. If a CAPTCHA/human-verification service is unavailable during a major disaster, maintain a documented emergency procedure for temporarily relaxing only that control without disabling RLS or administrator MFA.

## Secrets

Do not commit passwords, Supabase service-role keys, JWT secrets, Turnstile secret keys or administrator recovery codes to this repository.
