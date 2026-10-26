import { describe, expect, it } from 'vitest'
import { ADMIN_ID, API, as, bodyOf, signIn, start, STAFF_ID } from './helpers.js'

describe('proxy', () => {
  it('requires a session for everything under the API', async () => {
    const { app, calls } = await start()
    const res = await app.inject({ method: 'GET', url: `${API}/inventory` })
    expect(res.statusCode).toBe(401)
    expect(bodyOf(res)).toEqual({ detail: 'Sign in to continue.', code: 'unauthenticated' })
    expect(calls).toHaveLength(0) // nothing reached the API
  })

  it('forwards as the signed-in user with a service token, keeping the query string', async () => {
    const { app, calls } = await start()
    const s = await signIn(app)
    const res = await as(app, s, { method: 'GET', url: `${API}/inventory?q=bolt&page=2` })
    expect(res.statusCode).toBe(200)
    expect(bodyOf(res).q).toBe('bolt')
    const forwarded = calls.find((c) => c.path.startsWith('/inventory'))
    expect(forwarded?.path).toBe('/inventory?q=bolt&page=2')
    expect(forwarded?.headers.authorization).toBe(`Bearer svc-${ADMIN_ID}`)
  })

  it('never passes the browser’s cookie or CSRF header on to the API', async () => {
    const { app, calls } = await start()
    const s = await signIn(app)
    await as(app, s, { method: 'GET', url: `${API}/inventory` })
    const forwarded = calls.find((c) => c.path.startsWith('/inventory'))
    expect(forwarded?.headers.cookie).toBeUndefined()
    expect(forwarded?.headers['x-csrf-token']).toBeUndefined()
  })

  it('relays the API’s status and body, including errors', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await as(app, s, { method: 'GET', url: `${API}/nothing-here` })
    expect(res.statusCode).toBe(404)
    expect(bodyOf(res)).toEqual({ detail: 'Not Found' })
  })

  it('reuses the service token instead of asking for one on every request', async () => {
    const { app, state } = await start()
    const s = await signIn(app)
    for (let i = 0; i < 5; i++) await as(app, s, { method: 'GET', url: `${API}/inventory` })
    expect(state.tokenCalls).toBe(1)
  })

  it('keeps the browser away from gateway-only and bypass routes', async () => {
    const { app, calls } = await start()
    const s = await signIn(app)
    const before = calls.length
    const blocked = [
      ['GET', '/internal/users/x/token'],
      ['POST', '/internal/signup/verified'],
      ['POST', '/auth/register'],
      ['PUT', '/auth/me/avatar'],
    ] as const
    for (const [method, path] of blocked) {
      const res = await as(app, s, { method, url: `${API}${path}`, payload: method === 'GET' ? undefined : { x: 1 } })
      expect(res.statusCode, `${method} ${path}`).toBe(404)
    }
    expect(calls.slice(before).every((c) => c.path === '/internal/users/' + ADMIN_ID + '/token')).toBe(true) // only the token lookup
  })

  it('reports an unreachable API as 502', async () => {
    const { app, state } = await start()
    const s = await signIn(app)
    state.upstreamDown = true
    const res = await as(app, s, { method: 'GET', url: `${API}/inventory` })
    expect(res.statusCode).toBe(502)
    expect(bodyOf(res).code).toBe('upstream_unavailable')
  })

  it('ends the session when the API no longer recognises the user', async () => {
    const { app, users } = await start()
    const s = await signIn(app, 'staff@acme.com', 'StaffPass1')
    const staff = users.get(STAFF_ID)
    if (staff) staff.active = false // deactivated by an admin
    const res = await as(app, s, { method: 'GET', url: `${API}/inventory` })
    expect(res.statusCode).toBe(401)
    expect(bodyOf(res).code).toBe('session_expired')
    if (staff) staff.active = true
    expect((await as(app, s, { method: 'GET', url: `${API}/inventory` })).statusCode).toBe(401) // and stays ended
  })

  it('answers unknown top-level paths with a JSON 404', async () => {
    const { app } = await start()
    const res = await app.inject({ method: 'GET', url: '/nope' })
    expect(res.statusCode).toBe(404)
    expect(bodyOf(res).code).toBe('not_found')
  })
})

describe('CSRF and origin checks', () => {
  it('lets reads through without a token', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await app.inject({ method: 'GET', url: `${API}/auth/me`, headers: { cookie: s.cookie } })
    expect(res.statusCode).toBe(200)
  })

  it('refuses writes without the token, or with someone else’s', async () => {
    const { app, calls } = await start()
    const s = await signIn(app)
    const before = calls.length
    const none = await app.inject({ method: 'PATCH', url: `${API}/auth/users/${STAFF_ID}`, headers: { cookie: s.cookie }, payload: { role: 'ADMIN' } })
    const wrong = await app.inject({ method: 'PATCH', url: `${API}/auth/users/${STAFF_ID}`, headers: { cookie: s.cookie, 'x-csrf-token': 'f'.repeat(64) }, payload: { role: 'ADMIN' } })
    expect(none.statusCode).toBe(403)
    expect(bodyOf(none).code).toBe('csrf')
    expect(wrong.statusCode).toBe(403)
    expect(calls.length).toBe(before) // the API never saw the write
  })

  it('accepts the token from the session’s own sign-in', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await as(app, s, { method: 'PATCH', url: `${API}/auth/users/${STAFF_ID}`, payload: { role: 'INVENTORY_MANAGER' } })
    expect(res.statusCode).toBe(200)
  })

  it('does not accept one session’s token on another session', async () => {
    const { app } = await start()
    const a = await signIn(app)
    const b = await signIn(app, 'staff@acme.com', 'StaffPass1')
    const res = await as(app, { cookie: b.cookie, csrf: a.csrf }, { method: 'PATCH', url: `${API}/auth/users/${STAFF_ID}`, payload: {} })
    expect(res.statusCode).toBe(403)
  })

  it('re-issues the token on every authenticated response so a reload can recover it', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await app.inject({ method: 'GET', url: `${API}/auth/me`, headers: { cookie: s.cookie } })
    expect(res.headers['x-csrf-token']).toBe(s.csrf)
  })

  it('refuses cross-site writes from an origin that is not ours, even before sign-in', async () => {
    const { app } = await start()
    const res = await app.inject({ method: 'POST', url: `${API}/auth/login`, headers: { origin: 'https://evil.example' }, payload: { email: 'admin@acme.com', password: 'AdminPass1' } })
    expect(res.statusCode).toBe(403)
    expect(bodyOf(res).code).toBe('origin_not_allowed')
    expect(res.headers['set-cookie']).toBeUndefined()
  })

  it('allows our own front end, with credentials, and exposes the token header', async () => {
    const { app } = await start()
    const res = await app.inject({ method: 'OPTIONS', url: `${API}/auth/login`, headers: { origin: 'http://localhost:5173', 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type,x-csrf-token' } })
    expect(res.statusCode).toBeLessThan(300)
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173')
    expect(res.headers['access-control-allow-credentials']).toBe('true')
    const login = await app.inject({ method: 'POST', url: `${API}/auth/login`, headers: { origin: 'http://localhost:5173' }, payload: { email: 'admin@acme.com', password: 'AdminPass1' } })
    expect(login.headers['access-control-expose-headers']).toContain('x-csrf-token')
  })

  it('does not echo other origins in CORS responses', async () => {
    const { app } = await start()
    const res = await app.inject({ method: 'OPTIONS', url: `${API}/auth/login`, headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } })
    expect(res.headers['access-control-allow-origin']).toBeUndefined()
  })
})

describe('response hardening', () => {
  it('stops browsers caching or sniffing API responses', async () => {
    const { app } = await start()
    const s = await signIn(app)
    const res = await as(app, s, { method: 'GET', url: `${API}/auth/me` })
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.headers['x-content-type-options']).toBe('nosniff')
    expect(res.headers['x-frame-options']).toBe('DENY')
  })

  it('reports health, and degrades when the API is down', async () => {
    const { app, state } = await start()
    expect((await app.inject({ url: '/healthz' })).json()).toEqual({ status: 'ok', store: 'ok', upstream: 'ok' })
    state.upstreamDown = true
    const down = await app.inject({ url: '/healthz' })
    expect(down.statusCode).toBe(503)
    expect(down.json()).toMatchObject({ status: 'degraded', upstream: 'down' })
  })
})

describe('sessions', () => {
  it('lists signed-in devices and marks the current one', async () => {
    const { app } = await start()
    const laptop = await signIn(app)
    await signIn(app) // a second device
    const res = await as(app, laptop, { method: 'GET', url: `${API}/auth/sessions` })
    const items = bodyOf<{ items: { id: string; current: boolean }[] }>(res).items
    expect(items).toHaveLength(2)
    expect(items.filter((i) => i.current)).toHaveLength(1)
    expect(items[0]?.id).toMatch(/^[0-9a-f]{64}$/)
    expect(res.body).not.toContain(laptop.cookie.split('=')[1] as string) // handles are not usable as sign-in cookies
  })

  it('revokes another device but not the current one through the same route', async () => {
    const { app } = await start()
    const a = await signIn(app)
    const b = await signIn(app)
    const list = bodyOf<{ items: { id: string; current: boolean }[] }>(await as(app, a, { method: 'GET', url: `${API}/auth/sessions` })).items
    const other = list.find((i) => !i.current)?.id as string
    const mine = list.find((i) => i.current)?.id as string

    expect((await as(app, a, { method: 'DELETE', url: `${API}/auth/sessions/${mine}` })).statusCode).toBe(400)
    expect((await as(app, a, { method: 'DELETE', url: `${API}/auth/sessions/${other}` })).statusCode).toBe(204)
    expect((await as(app, b, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401) // that device is signed out
    expect((await as(app, a, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
  })

  it('cannot revoke another user’s session', async () => {
    const { app } = await start()
    const admin = await signIn(app)
    const staff = await signIn(app, 'staff@acme.com', 'StaffPass1')
    const staffHandle = bodyOf<{ items: { id: string }[] }>(await as(app, staff, { method: 'GET', url: `${API}/auth/sessions` })).items[0]?.id as string
    const res = await as(app, admin, { method: 'DELETE', url: `${API}/auth/sessions/${staffHandle}` })
    expect(res.statusCode).toBe(404)
    expect((await as(app, staff, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
  })

  it('rejects malformed handles', async () => {
    const { app } = await start()
    const s = await signIn(app)
    expect((await as(app, s, { method: 'DELETE', url: `${API}/auth/sessions/not-a-handle` })).statusCode).toBe(422)
  })

  it('signs out every other device at once', async () => {
    const { app } = await start()
    const a = await signIn(app)
    const b = await signIn(app)
    const c = await signIn(app)
    const res = await as(app, a, { method: 'POST', url: `${API}/auth/sessions/revoke-others` })
    expect(bodyOf(res)).toEqual({ ended: 2 })
    expect((await as(app, b, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401)
    expect((await as(app, c, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401)
    expect((await as(app, a, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
  })

  it('expires after the idle window, but activity keeps it alive', async () => {
    const { app, clock } = await start({ SESSION_IDLE_HOURS: '1', SESSION_MAX_DAYS: '30' })
    const s = await signIn(app)
    for (let i = 0; i < 4; i++) {
      clock.t += 40 * 60_000 // 40 minutes between requests: never idle for a full hour
      expect((await as(app, s, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
    }
    clock.t += 61 * 60_000
    expect((await as(app, s, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401)
  })

  it('expires at the absolute limit however active the user is', async () => {
    const { app, clock } = await start({ SESSION_IDLE_HOURS: '24', SESSION_MAX_DAYS: '2' })
    const s = await signIn(app)
    for (let i = 0; i < 3; i++) {
      clock.t += 20 * 3600_000
      const res = await as(app, s, { method: 'GET', url: `${API}/auth/me` })
      if (i < 2) expect(res.statusCode).toBe(200)
      else expect(res.statusCode).toBe(401) // 60 hours in, past the 48-hour cap
    }
  })

  it('ends a user’s sessions when an admin resets their password or deactivates them', async () => {
    const { app } = await start()
    const admin = await signIn(app)
    const staff = await signIn(app, 'staff@acme.com', 'StaffPass1')
    const reset = await as(app, admin, { method: 'PATCH', url: `${API}/auth/users/${STAFF_ID}`, payload: { password: 'BrandNewPass1' } })
    expect(reset.statusCode).toBe(200)
    expect((await as(app, staff, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401)
    expect((await as(app, admin, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
  })

  it('leaves sessions alone for harmless admin edits', async () => {
    const { app } = await start()
    const admin = await signIn(app)
    const staff = await signIn(app, 'staff@acme.com', 'StaffPass1')
    await as(app, admin, { method: 'PATCH', url: `${API}/auth/users/${STAFF_ID}`, payload: { role: 'INVENTORY_MANAGER' } })
    expect((await as(app, staff, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
  })
})
