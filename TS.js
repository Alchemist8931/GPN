// supabase/functions/register-and-auth/index.ts
// POST { username?, password?, ref? }
//   - без username/password  -> регистрация: генерим логин/пароль/реф-код, ловим ref, отдаём creds + session JWT
//   - с username+password    -> автоавторизация: проверяем хэш, отдаём session JWT + состояние
//
// ENV: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_JWT_SECRET

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { create, getNumericDate } from 'https://deno.land/x/djwt@v3.0.2/mod.ts'

const supabase = createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
)
const JWT_SECRET = Deno.env.get('SESSION_JWT_SECRET')!

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, content-type, apikey',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

// ---------- crypto helpers (Web Crypto, edge-friendly) ----------
const enc = new TextEncoder()
const b64 = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b)))
const b64url = (b: Uint8Array) =>
  b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

async function hashPassword(password: string): Promise<string> {
  const iterations = 120_000
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256)
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(bits)}`
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iterStr, saltB64, hashB64] = stored.split('$')
  if (scheme !== 'pbkdf2') return false
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0))
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: parseInt(iterStr), hash: 'SHA-256' }, key, 256)
  const got = b64(bits)
  // constant-time-ish compare
  if (got.length !== hashB64.length) return false
  let r = 0
  for (let i = 0; i < got.length; i++) r |= got.charCodeAt(i) ^ hashB64.charCodeAt(i)
  return r === 0
}

async function makeSessionJWT(userId: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
  return await create(
    { alg: 'HS256', typ: 'JWT' },
    { sub: userId, exp: getNumericDate(60 * 60 * 24 * 30) }, // 30 дней
    key,
  )
}

// ---------- generators ----------
function genUsername(): string {
  const r = crypto.getRandomValues(new Uint8Array(4))
  return 'gpn-' + Array.from(r).map((x) => x.toString(16).padStart(2, '0')).join('')
}
function genPassword(): string {
  return b64url(crypto.getRandomValues(new Uint8Array(18))) // ~24 симв., высокая энтропия
}
function genReferralCode(): string {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' // без похожих 0/O/1/I
  const r = crypto.getRandomValues(new Uint8Array(7))
  return Array.from(r).map((x) => A[x % A.length]).join('')
}

function stateOf(u: any) {
  return {
    referral_code: u.referral_code,
    bonus_days_balance: u.bonus_days_balance,
    current_kind: u.current_kind,
    current_expires_at: u.current_expires_at,
    has_active: u.current_kind !== 'none' &&
      u.current_expires_at && new Date(u.current_expires_at) > new Date(),
    telegram_linked: !!u.telegram_id,
    subscription_link: u.current_kind === 'paid' ? u.subscription_link : null,
  }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS })
  if (req.method !== 'POST') return json({ error: 'method' }, 405)

  let body: any = {}
  try { body = await req.json() } catch { /* пусто = регистрация */ }
  const { username, password, ref } = body ?? {}

  // ---------- АВТОАВТОРИЗАЦИЯ ----------
  if (username && password) {
    const { data: u } = await supabase.from('pwa_users').select('*').eq('username', username).maybeSingle()
    if (!u || !(await verifyPassword(password, u.password_hash))) {
      return json({ error: 'invalid_credentials' }, 401)
    }
    await supabase.from('pwa_users').update({ last_seen: new Date().toISOString() }).eq('id', u.id)
    return json({ token: await makeSessionJWT(u.id), state: stateOf(u) })
  }

  // ---------- РЕГИСТРАЦИЯ ----------
  // валидируем реф-код (если есть и существует) — самореферал тут невозможен (юзера ещё нет)
  let referredBy: string | null = null
  if (typeof ref === 'string' && ref.length > 0) {
    const { data: r } = await supabase.from('pwa_users').select('id').eq('referral_code', ref).maybeSingle()
    if (r) referredBy = ref
  }

  const newUsername = genUsername()
  const newPassword = genPassword()
  const insert = {
    username: newUsername,
    password_hash: await hashPassword(newPassword),
    referral_code: genReferralCode(),
    referred_by: referredBy,
  }

  const { data: u, error } = await supabase.from('pwa_users').insert(insert).select('*').single()
  if (error) {
    // крайне маловероятная коллизия username/referral_code — пусть клиент повторит
    return json({ error: 'register_failed', detail: error.message }, 409)
  }

  // запись реферальной связи (награда начислится при первой оплате — отдельной функцией)
  if (referredBy) {
    const { data: referrer } = await supabase.from('pwa_users').select('id').eq('referral_code', referredBy).maybeSingle()
    if (referrer && referrer.id !== u.id) {
      await supabase.from('pwa_referrals').insert({ referrer_id: referrer.id, referred_id: u.id })
    }
  }

  return json({
    // отдаём creds ОДИН раз — PWA кладёт в localStorage и показывает «сохраните»
    credentials: { username: newUsername, password: newPassword },
    token: await makeSessionJWT(u.id),
    state: stateOf(u),
  })
})
