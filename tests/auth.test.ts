import { describe, expect, it } from 'vitest'
import { Sessions } from '../src/sessions.js'
import { API, as, bodyOf, cookieFrom, mailArrived, otpFrom, signIn, start } from './helpers.js'

const post = (app: Awaited<ReturnType<typeof start>>['app'], url: string, payload: unknown, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url: `${API}${url}`, payload: payload as object, headers })

const signup = { email: 'new@acme.com', password: 'Sup3rSecret', full_name: 'Nia New' }

describe('login', () => {
  it('starts a session in an HTTP-only cookie and never exposes the API token', async () => {
    const { app } = await start()
    const res = await post(app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' })
    expect(res.statusCode).toBe(200)
    const setCookie = String(res.headers['set-cookie'])
    expect(setCookie).toMatch(/inv_session=[\w-]{40,}/)
    expect(setCookie).toMatch(/HttpOnly/i)
    expect(setCookie).toMatch(/SameSite=Lax/i)
    expect(setCookie).toMatch(/Path=\//)
    expect(res.body).not.toMatch(/access_token|eyJ|h\./) // the JWT stays between the gateway and the API
    expect(bodyOf(res).csrf_token).toMatch(/^[0-9a-f]{64}$/)
    expect(res.headers['x-csrf-token']).toBe(bodyOf(res).csrf_token)
  })

  it('stores sessions under a hash, so the cookie value is not the storage key', async () => {
    const { app, store } = await start()
    const session = await signIn(app)
    const id = session.cookie.split('=')[1] as string
    expect(await store.get(`sess:${id}`)).toBeNull()
    expect(await store.get(`sess:${Sessions.handleFor(id)}`)).not.toBeNull()
  })

  it('marks the cookie Secure and host-locked in production-style config', async () => {
    const { app } = await start({ COOKIE_SECURE: 'true' })
    const res = await post(app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' })
    expect(String(res.headers['set-cookie'])).toMatch(/^__Host-inv_session=.*Secure/i)
  })

  it('answers wrong credentials with 401 and no cookie', async () => {
    const { app } = await start()
    for (const body of [{ email: 'admin@acme.com', password: 'nope' }, { email: 'ghost@acme.com', password: 'nope' }]) {
      const res = await post(app, '/auth/login', body)
      expect(res.statusCode).toBe(401)
      expect(bodyOf(res)).toEqual({ detail: 'Incorrect email or password', code: 'invalid_credentials' })
      expect(res.headers['set-cookie']).toBeUndefined()
    }
  })

  it('passes the account stage through so the app can route the user', async () => {
    const { app, users } = await start()
    users.set('44444444-4444-4444-8444-444444444444', { id: '44444444-4444-4444-8444-444444444444', email: 'pending@acme.com', full_name: null, password: 'PendingPass1', verified: true, active: false, role: 'WAREHOUSE_STAFF', avatar_url: null })
    users.set('55555555-5555-4555-8555-555555555555', { id: '55555555-5555-4555-8555-555555555555', email: 'fresh@acme.com', full_name: null, password: 'FreshPass12', verified: false, active: false, role: 'WAREHOUSE_STAFF', avatar_url: null })
    const pending = await post(app, '/auth/login', { email: 'pending@acme.com', password: 'PendingPass1' })
    expect(pending.statusCode).toBe(403)
    expect(bodyOf(pending).code).toBe('pending_approval')
    const fresh = await post(app, '/auth/login', { email: 'fresh@acme.com', password: 'FreshPass12' })
    expect(bodyOf(fresh).code).toBe('email_unverified')
    expect(pending.headers['set-cookie']).toBeUndefined()
  })

  it('validates input before calling the API', async () => {
    const { app, calls } = await start()
    expect((await post(app, '/auth/login', {})).statusCode).toBe(422)
    expect((await post(app, '/auth/login', { email: 'not-an-email', password: 'x' })).statusCode).toBe(422)
    expect((await post(app, '/auth/login', { email: 'a@b.co', password: '' })).statusCode).toBe(422)
    expect(calls).toHaveLength(0)
  })

  it('relays the API’s throttling with Retry-After', async () => {
    const { app, state } = await start()
    state.throttleLogin = true
    const res = await post(app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' })
    expect(res.statusCode).toBe(429)
    expect(res.headers['retry-after']).toBe('42')
    expect(bodyOf(res).detail).toContain('42 seconds')
    expect(res.headers['set-cookie']).toBeUndefined()
  })

  it('reports an unreachable API as 502 in the usual shape', async () => {
    const { app, state } = await start()
    state.upstreamDown = true
    const res = await post(app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' })
    expect(res.statusCode).toBe(502)
    expect(bodyOf(res).code).toBe('upstream_unavailable')
  })

  it('gives every sign-in a new session id, so a planted cookie is never adopted', async () => {
    const { app, store } = await start()
    const first = await signIn(app)
    const res = await app.inject({ method: 'POST', url: `${API}/auth/login`, headers: { cookie: first.cookie }, payload: { email: 'admin@acme.com', password: 'AdminPass1' } })
    expect(cookieFrom(res)).not.toBe(first.cookie)
    expect(await store.get(`sess:${Sessions.handleFor(first.cookie.split('=')[1] as string)}`)).toBeNull()
  })

  it('forwards the real client address to the API only when told to trust the proxy', async () => {
    const trusting = await start({ TRUST_PROXY: 'true' })
    await post(trusting.app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' }, { 'x-forwarded-for': '203.0.113.9' })
    expect(trusting.calls.find((c) => c.path === '/auth/login')?.headers['x-forwarded-for']).toBe('203.0.113.9')

    const strict = await start()
    await post(strict.app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' }, { 'x-forwarded-for': '203.0.113.9' })
    expect(strict.calls.find((c) => c.path === '/auth/login')?.headers['x-forwarded-for']).not.toBe('203.0.113.9')
  })

  it('throttles sign-in attempts per address', async () => {
    const { app } = await start({}, { rateLimits: true })
    for (let i = 0; i < 30; i++) await post(app, '/auth/login', { email: 'admin@acme.com', password: 'wrong' })
    const res = await post(app, '/auth/login', { email: 'admin@acme.com', password: 'AdminPass1' })
    expect(res.statusCode).toBe(429)
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0)
  })
})

describe('logout', () => {
  it('ends the session server-side and clears the cookie', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await as(app, s, { method: 'POST', url: `${API}/auth/logout` })
    expect(res.statusCode).toBe(204)
    expect(String(res.headers['set-cookie'])).toMatch(/inv_session=;/)
    const after = await as(app, s, { method: 'GET', url: `${API}/auth/me` })
    expect(after.statusCode).toBe(401) // the old cookie is dead even if someone kept a copy
  })

  it('needs the CSRF header while the session is live', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await app.inject({ method: 'POST', url: `${API}/auth/logout`, headers: { cookie: s.cookie } })
    expect(res.statusCode).toBe(403)
    expect((await as(app, s, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200) // still signed in
  })

  it('is harmless without a session', async () => {
    const { app } = await start()
    expect((await post(app, '/auth/logout', {})).statusCode).toBe(204)
  })
})

describe('sign-up and email verification', () => {
  it('creates the account, emails a 6-digit code, and never returns it', async () => {
    const h = await start()
    const res = await post(h.app, '/auth/signup', signup)
    expect(res.statusCode).toBe(201)
    expect(bodyOf(res)).toEqual({ status: 'verify_email', email: 'new@acme.com', email_sent: true, resend_in: 60 })
    expect(h.sent).toHaveLength(1)
    expect(h.sent[0]?.to).toBe('new@acme.com')
    expect(otpFrom(h)).toMatch(/^\d{6}$/)
    expect(res.body).not.toContain(otpFrom(h))
    expect(h.calls.find((c) => c.path === '/auth/register')?.body).toEqual({ email: 'new@acme.com', password: 'Sup3rSecret', full_name: 'Nia New' })
  })

  it('normalises the email and lets the user retry the code if mail fails', async () => {
    const h = await start()
    h.mailState.fail = true
    const res = await post(h.app, '/auth/signup', { ...signup, email: '  New@Acme.com ' })
    expect(res.statusCode).toBe(201)
    expect(bodyOf(res)).toMatchObject({ email: 'new@acme.com', email_sent: false })
  })

  it('rejects bad input before touching the API', async () => {
    const h = await start()
    const bad = [
      { ...signup, password: 'short' },
      { ...signup, password: 'é'.repeat(37) }, // 74 bytes: bcrypt would refuse it
      { ...signup, email: 'nope' },
      { ...signup, full_name: 'x'.repeat(121) },
    ]
    for (const payload of bad) expect((await post(h.app, '/auth/signup', payload)).statusCode).toBe(422)
    expect(h.calls).toHaveLength(0)
  })

  it('tells the user when the email is already registered', async () => {
    const h = await start()
    const res = await post(h.app, '/auth/signup', { ...signup, email: 'admin@acme.com' })
    expect(res.statusCode).toBe(409)
    expect(bodyOf(res).code).toBe('email_taken')
    expect(h.sent).toHaveLength(0)
  })

  it('verifies the code once, opens the request and emails the applicant and opted-in admins only', async () => {
    const h = await start()
    await post(h.app, '/auth/signup', signup)
    const code = otpFrom(h)
    const res = await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code })
    expect(res.statusCode).toBe(200)
    expect(bodyOf(res)).toEqual({ status: 'pending_approval' })

    await mailArrived(h, 3) // OTP + "request received" + one admin (the other opted out)
    const recipients = h.sent.map((m) => m.to).sort()
    expect(recipients).toEqual(['admin@acme.com', 'new@acme.com', 'new@acme.com'])
    expect(h.sent.find((m) => m.to === 'admin@acme.com')?.subject).toContain('Nia New')

    const again = await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code })
    expect(again.statusCode).toBe(400) // single use
    expect(bodyOf(again).code).toBe('otp_expired')
  })

  it('counts wrong codes and locks the code after too many', async () => {
    const h = await start()
    await post(h.app, '/auth/signup', signup)
    const right = otpFrom(h)
    const wrong = right === '000000' ? '111111' : '000000'
    const first = await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code: wrong })
    expect(first.statusCode).toBe(400)
    expect(bodyOf(first).detail).toBe("That code isn't right. 4 tries left.")
    for (let i = 0; i < 3; i++) await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code: wrong })
    const last = await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code: wrong })
    expect(bodyOf(last).code).toBe('otp_locked')
    const afterLock = await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code: right })
    expect(afterLock.statusCode).toBe(400) // the right code no longer works either
    expect(h.calls.some((c) => c.path === '/internal/signup/verified')).toBe(false)
  })

  it('expires codes after the configured time', async () => {
    const h = await start({ OTP_TTL_MINUTES: '10' })
    await post(h.app, '/auth/signup', signup)
    const code = otpFrom(h)
    h.clock.t += 11 * 60_000
    const res = await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code })
    expect(bodyOf(res).code).toBe('otp_expired')
  })

  it('validates the code shape', async () => {
    const h = await start()
    for (const code of ['12345', '1234567', 'abcdef', '']) {
      expect((await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code })).statusCode).toBe(422)
    }
  })

  it('does not store the code itself', async () => {
    const h = await start()
    await post(h.app, '/auth/signup', signup)
    const stored = (await h.store.get('otp:new@acme.com')) ?? ''
    expect(stored).not.toContain(otpFrom(h))
    expect(JSON.parse(stored).hash).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('resending the code', () => {
  it('issues a fresh code that replaces the old one, after the cooldown', async () => {
    const h = await start()
    await post(h.app, '/auth/signup', signup)
    const old = otpFrom(h)
    h.clock.t += 61_000
    const res = await post(h.app, '/auth/resend-otp', { email: 'new@acme.com' })
    expect(res.statusCode).toBe(200)
    await mailArrived(h, 2)
    const fresh = otpFrom(h)
    expect((await post(h.app, '/auth/verify-otp', { email: 'new@acme.com', code: fresh })).statusCode).toBe(200)
    if (old !== fresh) {
      // (a 1-in-a-million collision would make the assertion above the only one that matters)
      expect(h.sent.filter((m) => /verification code/.test(m.subject))).toHaveLength(2)
    }
  })

  it('enforces the cooldown between sends', async () => {
    const h = await start()
    await post(h.app, '/auth/signup', signup)
    const res = await post(h.app, '/auth/resend-otp', { email: 'new@acme.com' })
    expect(res.statusCode).toBe(429)
    expect(bodyOf(res).code).toBe('otp_cooldown')
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0)
  })

  it('caps codes per address per hour', async () => {
    const h = await start({ OTP_MAX_PER_HOUR: '3' })
    await post(h.app, '/auth/signup', signup)
    for (let i = 0; i < 2; i++) {
      h.clock.t += 61_000
      expect((await post(h.app, '/auth/resend-otp', { email: 'new@acme.com' })).statusCode).toBe(200)
    }
    h.clock.t += 61_000
    const res = await post(h.app, '/auth/resend-otp', { email: 'new@acme.com' })
    expect(res.statusCode).toBe(429)
    expect(bodyOf(res).code).toBe('otp_hourly')
  })

  it('looks the same for unknown and already-verified addresses, and sends nothing', async () => {
    const h = await start()
    const unknown = await post(h.app, '/auth/resend-otp', { email: 'ghost@acme.com' })
    h.clock.t += 61_000
    const verified = await post(h.app, '/auth/resend-otp', { email: 'admin@acme.com' })
    expect(unknown.statusCode).toBe(200)
    expect(verified.statusCode).toBe(200)
    expect(bodyOf(unknown)).toEqual(bodyOf(verified))
    expect(h.sent).toHaveLength(0)
  })
})
