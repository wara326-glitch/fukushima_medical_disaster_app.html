import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const ALLOWED_ORIGINS = new Set([
  'https://wara326-glitch.github.io',
])

const MAX_BODY_BYTES = 32_000
const VALID_TYPES = new Set(['safety', 'emergency', 'detail'])

function cors(origin: string | null) {
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'https://wara326-glitch.github.io'
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, cf-turnstile-response',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin',
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  }
}

function text(v: unknown, max = 500) {
  if (typeof v !== 'string') return ''
  return v.trim().slice(0, max)
}

async function sha256(value: string) {
  const bytes = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

Deno.serve(async (req) => {
  const origin = req.headers.get('origin')
  const headers = cors(origin)

  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers })
  if (req.method !== 'POST') return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405, headers })
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return new Response(JSON.stringify({ error: 'origin_not_allowed' }), { status: 403, headers })

  const contentLength = Number(req.headers.get('content-length') || '0')
  if (contentLength > MAX_BODY_BYTES) return new Response(JSON.stringify({ error: 'payload_too_large' }), { status: 413, headers })

  let body: Record<string, unknown>
  try {
    body = await req.json()
  } catch {
    return new Response(JSON.stringify({ error: 'invalid_json' }), { status: 400, headers })
  }

  const reportType = text(body.type, 20)
  const facility = text(body.facility, 200)
  const facilityType = text(body.facilityType, 80)
  const municipality = text(body.municipality, 100)
  const reporter = text(body.reporter, 120)
  const phone = text(body.phone, 40)
  const reportedAt = text(body.reportedAt, 40)

  if (!VALID_TYPES.has(reportType) || !facility || !facilityType || !municipality || !reporter || !phone) {
    return new Response(JSON.stringify({ error: 'validation_failed' }), { status: 400, headers })
  }

  // Reject fields that look like patient-identifying data if future clients accidentally send them.
  const forbidden = ['patientName', 'patient_name', 'dob', 'dateOfBirth', 'chartNumber', 'medicalRecordNumber']
  if (forbidden.some(k => k in body)) {
    return new Response(JSON.stringify({ error: 'patient_identifiers_not_allowed' }), { status: 400, headers })
  }

  // Optional Cloudflare Turnstile. In production set TURNSTILE_SECRET_KEY and require a token.
  const turnstileSecret = Deno.env.get('TURNSTILE_SECRET_KEY')
  if (turnstileSecret) {
    const token = req.headers.get('cf-turnstile-response') || text(body.turnstileToken, 2048)
    if (!token) return new Response(JSON.stringify({ error: 'human_verification_required' }), { status: 403, headers })
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || ''
    const verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: turnstileSecret, response: token, remoteip: ip }),
    })
    const result = await verify.json()
    if (!result.success) return new Response(JSON.stringify({ error: 'human_verification_failed' }), { status: 403, headers })
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const serviceRole = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const salt = Deno.env.get('REQUEST_HASH_SALT') || crypto.randomUUID()
  const supabase = createClient(supabaseUrl, serviceRole, { auth: { persistSession: false } })

  const rawIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('cf-connecting-ip') || ''
  const ua = req.headers.get('user-agent') || ''
  const ipHash = rawIp ? await sha256(`${salt}:${rawIp}`) : null
  const uaHash = ua ? await sha256(`${salt}:${ua}`) : null

  // Rate limit: 20 submissions per hashed IP per 10 minutes.
  if (ipHash) {
    const cutoff = new Date(Date.now() - 10 * 60 * 1000).toISOString()
    const { count } = await supabase.from('medical_reports').select('id', { count: 'exact', head: true })
      .eq('created_ip_hash', ipHash).gte('created_at', cutoff)
    if ((count || 0) >= 20) return new Response(JSON.stringify({ error: 'rate_limited' }), { status: 429, headers })
  }

  const safePayload: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body)) {
    if (['type', 'facility', 'facilityType', 'municipality', 'reporter', 'phone', 'reportedAt', 'turnstileToken'].includes(key)) continue
    if (typeof value === 'string') safePayload[key] = value.slice(0, 2000)
    else if (typeof value === 'number' || typeof value === 'boolean' || value === null) safePayload[key] = value
  }

  const { error } = await supabase.from('medical_reports').insert({
    report_type: reportType,
    facility,
    facility_type: facilityType,
    municipality,
    reporter,
    phone,
    reported_at: reportedAt || null,
    payload: safePayload,
    created_ip_hash: ipHash,
    user_agent_hash: uaHash,
  })

  if (error) {
    console.error(error)
    return new Response(JSON.stringify({ error: 'server_error' }), { status: 500, headers })
  }

  return new Response(JSON.stringify({ ok: true }), { status: 201, headers })
})
