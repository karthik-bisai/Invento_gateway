import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify'
import { afterEach, vi } from 'vitest'
import { buildApp } from '../src/app.js'
import { type Config, loadConfig } from '../src/config.js'
import type { Mailer, MailMessage } from '../src/mail/mailer.js'
import { LocalStorage } from '../src/storage/index.js'
import { MemoryStore, type Store } from '../src/store.js'
import { Upstream } from '../src/upstream.js'

export interface FakeUser {
  id: string
  email: string
  full_name: string | null
  password: string
  verified: boolean
  active: boolean
  role: string
  avatar_url: string | null
}

export interface Call {
  method: string
  path: string
  headers: Record<string, string>
  body: unknown
}

export const ADMIN_ID = '11111111-1111-4111-8111-111111111111'
export const STAFF_ID = '22222222-2222-4222-8222-222222222222'
export const NEW_ID = '33333333-3333-4333-8333-333333333333'
const MEDIA = 'http://localhost:4000/media/'

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })

/** A stand-in for FastAPI: just enough behaviour, recording every call the gateway makes. */
export function makeHarness(env: Record<string, string> = {}, opts: { rateLimits?: boolean; store?: Store } = {}) {
  const clock = { t: 1_700_000_000_000 }
  const config: Config = loadConfig({ NODE_ENV: 'test', ...env })
  const store: Store = opts.store ?? new MemoryStore(() => clock.t)
  const sent: MailMessage[] = []
  const mailState = { fail: false }
  const mailer: Mailer = {
    async send(m) {
      if (mailState.fail) throw new Error('smtp down')
      sent.push(m)
    },
  }
  const calls: Call[] = []
  const state = { upstreamDown: false, tokenCalls: 0, throttleLogin: false, rejectAvatar: false }

  const users = new Map<string, FakeUser>([
    [ADMIN_ID, { id: ADMIN_ID, email: 'admin@acme.com', full_name: 'Ada Admin', password: 'AdminPass1', verified: true, active: true, role: 'ADMIN', avatar_url: null }],
    [STAFF_ID, { id: STAFF_ID, email: 'staff@acme.com', full_name: null, password: 'StaffPass1', verified: true, active: true, role: 'WAREHOUSE_STAFF', avatar_url: null }],
  ])
  const byEmail = (email: string) => [...users.values()].find((u) => u.email === email)
  const publicUser = (u: FakeUser) => ({ id: u.id, email: u.email, full_name: u.full_name, role: u.role, is_active: u.active, avatar_url: u.avatar_url })
  const jwtFor = (id: string) => `h.${Buffer.from(JSON.stringify({ sub: id })).toString('base64url')}.s`
  const userForBearer = (headers: Record<string, string>) => {
    const m = /^Bearer svc-(.+)$/.exec(headers.authorization ?? '')
    const u = m ? users.get(m[1] as string) : undefined
    return u?.active ? u : undefined
  }

  const upstreamFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    if (state.upstreamDown) throw new TypeError('fetch failed')
    const url = new URL(String(input))
    const p = url.pathname.replace(/^\/api\/v1/, '') + url.search
    const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]))
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    const method = String(init?.method ?? 'GET')
    calls.push({ method, path: p, headers, body })
    const internal = headers['x-internal-key'] === config.internalApiKey

    if (p.startsWith('/internal') && !internal) return json(403, { detail: 'Forbidden' })
    const key = `${method} ${p.split('?')[0]}`

    if (key === 'POST /auth/login') {
      if (state.throttleLogin) return json(429, { detail: 'Too many attempts. Try again in 42 seconds.' }, { 'retry-after': '42' })
      const u = byEmail(body.email)
      if (!u || u.password !== body.password) return json(401, { detail: 'Incorrect email or password' })
      if (!u.verified) return json(403, { detail: 'Verify your email to continue.' }, { 'x-account-status': 'email_unverified' })
      if (!u.active) return json(403, { detail: 'Your access request is waiting for an administrator.' }, { 'x-account-status': 'pending_approval' })
      return json(200, { access_token: jwtFor(u.id), token_type: 'bearer' })
    }
    if (key === 'POST /auth/register') {
      if (byEmail(body.email)) return json(409, { detail: 'Email already registered' })
      users.set(NEW_ID, { id: NEW_ID, email: body.email, full_name: body.full_name ?? null, password: body.password, verified: false, active: false, role: 'WAREHOUSE_STAFF', avatar_url: null })
      return json(201, publicUser(users.get(NEW_ID) as FakeUser))
    }
    if (method === 'POST' && /^\/internal\/users\/[^/]+\/token$/.test(p)) {
      state.tokenCalls++
      const u = users.get(p.split('/')[3] as string)
      return u?.active ? json(200, { access_token: `svc-${u.id}`, token_type: 'bearer' }) : json(404, { detail: 'No active user' })
    }
    if (key === 'POST /internal/login/lookup') {
      const u = byEmail(body.email)
      if (!u) return json(200, { status: 'unknown', id: null, full_name: null })
      const status = !u.verified ? 'email_unverified' : !u.active ? 'pending_approval' : 'ok'
      return json(200, { status, id: u.id, full_name: u.full_name })
    }
    if (method === 'POST' && /^\/internal\/users\/[^/]+\/password$/.test(p)) {
      const u = users.get(p.split('/')[3] as string)
      if (!u || !u.active) return json(404, { detail: 'No active user' })
      u.password = body.password
      return new Response(null, { status: 204 })
    }
    if (key === 'POST /internal/signup/status') {
      const u = byEmail(body.email)
      return json(200, u ? { exists: true, email_verified: u.verified, full_name: u.full_name } : { exists: false, email_verified: false, full_name: null })
    }
    if (key === 'POST /internal/signup/verified') {
      const u = byEmail(body.email)
      if (!u) return json(404, { detail: 'No account for that email' })
      u.verified = true
      return json(200, {
        user: { id: u.id, email: u.email, full_name: u.full_name },
        auto_approved: false,
        request_id: 'r1',
        admins: [
          { email: 'admin@acme.com', full_name: 'Ada Admin', wants_email: true },
          { email: 'quiet@acme.com', full_name: null, wants_email: false },
        ],
      })
    }
    if (p === '/health') return json(200, { status: 'ok' })

    // Everything below needs a signed-in (service-token) caller.
    const caller = userForBearer(headers)
    if (!caller) return json(401, { detail: 'Could not validate credentials' })
    if (key === 'GET /auth/me') return json(200, publicUser(caller))
    if (key === 'PUT /auth/me/avatar') {
      if (state.rejectAvatar) return json(422, { detail: [{ loc: ['body', 'avatar_url'], msg: 'Value error, Avatars must be uploaded through the app' }] })
      if (body.avatar_url !== null && !String(body.avatar_url).startsWith(MEDIA)) return json(422, { detail: [{ loc: ['body', 'avatar_url'], msg: 'Value error, Avatars must be uploaded through the app' }] })
      caller.avatar_url = body.avatar_url
      return json(200, publicUser(caller))
    }
    if (key === 'POST /auth/me/password') {
      if (body.current_password !== caller.password) return json(400, { detail: 'Your current password is incorrect' })
      caller.password = body.new_password
      return new Response(null, { status: 204 })
    }
    if (method === 'PATCH' && /^\/auth\/users\/[^/]+$/.test(p)) return json(200, { id: p.split('/')[3], ...body })
    if (method === 'POST' && /^\/access-requests\/[^/]+\/(approve|reject)$/.test(p)) {
      if (caller.role !== 'ADMIN') return json(403, { detail: 'Insufficient permissions' })
      const id = p.split('/')[2]
      if (id === '99999999-9999-4999-8999-999999999999') return json(409, { detail: 'This request was already approved' })
      return json(200, { id, status: p.endsWith('approve') ? 'APPROVED' : 'REJECTED', note: body?.note ?? null, user: { id: NEW_ID, email: 'new@acme.com', full_name: 'Nia New' } })
    }
    if (key === 'GET /inventory') return json(200, { items: [], total: 0, page: 1, size: 20, q: url.searchParams.get('q') })
    return json(404, { detail: 'Not Found' })
  }

  let mediaDir: string | undefined
  const build = async () => {
    mediaDir = await mkdtemp(path.join(tmpdir(), 'gw-media-'))
    const storage = new LocalStorage(mediaDir, config.storage.mediaPublicUrl)
    const app = await buildApp({
      config,
      store,
      mailer,
      storage,
      upstream: new Upstream(config, upstreamFetch as typeof fetch),
      now: () => clock.t,
      rateLimits: opts.rateLimits ?? false,
    })
    return { app, storage, mediaDir }
  }

  return { config, clock, store, sent, calls, state, users, mailState, build, byEmail }
}

export type Harness = ReturnType<typeof makeHarness>

/** Build an app and register it for cleanup. */
export async function start(env: Record<string, string> = {}, opts: { rateLimits?: boolean; store?: Store } = {}) {
  const h = makeHarness(env, opts)
  const { app, storage, mediaDir } = await h.build()
  cleanups.push(async () => {
    await app.close()
    await rm(mediaDir, { recursive: true, force: true })
  })
  return { ...h, app, storage, mediaDir }
}

const cleanups: (() => Promise<void>)[] = []
afterEach(async () => {
  vi.restoreAllMocks()
  while (cleanups.length) await cleanups.pop()?.()
})

export const API = '/api/v1'

export interface Session {
  cookie: string
  csrf: string
}

export const bodyOf = <T = Record<string, unknown>>(res: LightMyRequestResponse): T => res.json() as T

export function cookieFrom(res: LightMyRequestResponse): string | undefined {
  const raw = res.headers['set-cookie']
  const first = Array.isArray(raw) ? raw[0] : raw
  return first?.split(';')[0]
}

export async function signIn(app: FastifyInstance, email = 'admin@acme.com', password = 'AdminPass1'): Promise<Session> {
  const res = await app.inject({ method: 'POST', url: `${API}/auth/login`, payload: { email, password } })
  if (res.statusCode !== 200) throw new Error(`login failed: ${res.statusCode} ${res.body}`)
  return { cookie: cookieFrom(res) as string, csrf: res.json().csrf_token as string }
}

/** inject() with the session cookie and (for writes) the CSRF header filled in. */
export function as(app: FastifyInstance, s: Session, opts: InjectOptions): Promise<LightMyRequestResponse> {
  const headers = { cookie: s.cookie, 'x-csrf-token': s.csrf, ...(opts.headers as Record<string, string> | undefined) }
  return app.inject({ ...opts, headers })
}

export function multipart(field: string, filename: string, contentType: string, data: Buffer) {
  const boundary = '----gwtest' + Math.random().toString(16).slice(2)
  const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${field}"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`)
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`)
  return { payload: Buffer.concat([head, data, tail]), headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } }
}

export const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64, 1)])
export const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(64, 2)])
export const WEBP = Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WEBP'), Buffer.alloc(32)])

/** Emails are sent in the background; wait until `n` have arrived. */
export const mailArrived = (h: Harness, n: number) => vi.waitFor(() => { if (h.sent.length < n) throw new Error(`only ${h.sent.length} email(s)`) })

/** The newest emailed 6-digit code whose subject matches `kind` (e.g. /sign-in code/). */
export const codeFrom = (h: Harness, kind: RegExp): string => {
  const m = [...h.sent].reverse().find((e) => kind.test(e.subject))
  const code = /\b(\d{6})\b/.exec(m?.text ?? '')?.[1]
  if (!code) throw new Error(`no email matching ${kind} was sent`)
  return code
}

export const otpFrom = (h: Harness): string => {
  const m = [...h.sent].reverse().find((e) => /verification code/i.test(e.subject))
  const code = /\b(\d{6})\b/.exec(m?.text ?? '')?.[1]
  if (!code) throw new Error('no OTP email was sent')
  return code
}
