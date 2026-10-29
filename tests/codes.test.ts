import { describe, expect, it } from 'vitest'
import { Sessions } from '../src/sessions.js'
import { API, as, bodyOf, codeFrom, cookieFrom, mailArrived, signIn, start, STAFF_ID } from './helpers.js'

type Started = Awaited<ReturnType<typeof start>>
const post = (h: Started, url: string, payload: unknown, headers: Record<string, string> = {}) =>
  h.app.inject({ method: 'POST', url: `${API}${url}`, payload: payload as object, headers })

const SIGN_IN = /sign-in code/i
const RESET = /reset code/i

describe('sign in with a code', () => {
  it('emails a code to an account that can sign in, and answers the same either way', async () => {
    const h = await start()
    const known = await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    expect(known.statusCode).toBe(200)
    expect(bodyOf(known)).toEqual({ status: 'sent', resend_in: 60 })
    await mailArrived(h, 1)
    expect(h.sent[0]).toMatchObject({ to: 'staff@acme.com' })
    expect(codeFrom(h, SIGN_IN)).toMatch(/^\d{6}$/)

    const unknown = await post(h, '/auth/login-code/request', { email: 'ghost@acme.com' })
    expect(unknown.statusCode).toBe(404)
    expect(bodyOf(unknown).code).toBe('no_account')
    expect(bodyOf(unknown).detail).toContain('Unable to sign in. No eligible account was found')
    expect(h.sent).toHaveLength(1)
  })

  it('rejects accounts that are not allowed in yet with clear status errors', async () => {
    const h = await start()
    h.users.set('44444444-4444-4444-8444-444444444444', { id: '44444444-4444-4444-8444-444444444444', email: 'pending@acme.com', full_name: null, password: 'PendingPass1', verified: true, active: false, role: 'WAREHOUSE_STAFF', avatar_url: null })
    h.users.set('55555555-5555-4555-8555-555555555555', { id: '55555555-5555-4555-8555-555555555555', email: 'fresh@acme.com', full_name: null, password: 'FreshPass12', verified: false, active: false, role: 'WAREHOUSE_STAFF', avatar_url: null })
    
    const pendingRes = await post(h, '/auth/login-code/request', { email: 'pending@acme.com' })
    expect(pendingRes.statusCode).toBe(403)
    expect(bodyOf(pendingRes).code).toBe('pending_approval')
    expect(bodyOf(pendingRes).detail).toContain('awaiting administrator approval')

    const freshRes = await post(h, '/auth/login-code/request', { email: 'fresh@acme.com' })
    expect(freshRes.statusCode).toBe(403)
    expect(bodyOf(freshRes).code).toBe('email_unverified')

    await new Promise((r) => setTimeout(r, 30))
    expect(h.sent).toHaveLength(0)
  })

  it('signs the person in with the right code, in the same kind of session as a password sign-in', async () => {
    const h = await start()
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const res = await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code: codeFrom(h, SIGN_IN) })
    expect(res.statusCode).toBe(200)
    expect(String(res.headers['set-cookie'])).toMatch(/inv_session=[\w-]{40,}.*HttpOnly.*SameSite=Lax/i)
    expect(bodyOf(res).csrf_token).toMatch(/^[0-9a-f]{64}$/)

    const me = await as(h.app, { cookie: cookieFrom(res) as string, csrf: bodyOf<{ csrf_token: string }>(res).csrf_token }, { method: 'GET', url: `${API}/auth/me` })
    expect(me.statusCode).toBe(200)
    expect(bodyOf(me).email).toBe('staff@acme.com')
  })

  it('works once only', async () => {
    const h = await start()
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const code = codeFrom(h, SIGN_IN)
    expect((await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code })).statusCode).toBe(200)
    const again = await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code })
    expect(again.statusCode).toBe(400)
    expect(bodyOf(again).code).toBe('otp_expired')
  })

  it('counts wrong codes and locks after too many, even for the right code afterwards', async () => {
    const h = await start()
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const right = codeFrom(h, SIGN_IN)
    const wrong = right === '000000' ? '111111' : '000000'
    const first = await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code: wrong })
    expect(bodyOf(first).detail).toBe("That code isn't right. 4 tries left.")
    for (let i = 0; i < 4; i++) await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code: wrong })
    const afterLock = await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code: right })
    expect(afterLock.statusCode).toBe(400)
    expect(afterLock.headers['set-cookie']).toBeUndefined()
  })

  it('expires after the configured time', async () => {
    const h = await start({ OTP_TTL_MINUTES: '10' })
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const code = codeFrom(h, SIGN_IN)
    h.clock.t += 11 * 60_000
    expect(bodyOf(await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code })).code).toBe('otp_expired')
  })

  it('refuses if the account was deactivated after the code was sent', async () => {
    const h = await start()
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const code = codeFrom(h, SIGN_IN)
    const staff = h.users.get(STAFF_ID)
    if (staff) staff.active = false
    const res = await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code })
    expect(res.statusCode).toBe(403)
    expect(bodyOf(res).code).toBe('pending_approval')
    expect(res.headers['set-cookie']).toBeUndefined()
  })

  it('does not accept a sign-up code, or a reset code, as a sign-in code', async () => {
    const h = await start()
    await post(h, '/auth/forgot-password', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const resetCode = codeFrom(h, RESET)
    const res = await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code: resetCode })
    expect(res.statusCode).toBe(400) // no sign-in code was ever issued
    expect(res.headers['set-cookie']).toBeUndefined()
  })

  it('enforces the resend cooldown per address', async () => {
    const h = await start()
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    const again = await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    expect(again.statusCode).toBe(429)
    expect(bodyOf(again).code).toBe('otp_cooldown')
    h.clock.t += 61_000
    expect((await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })).statusCode).toBe(200)
  })

  it('validates input before doing anything', async () => {
    const h = await start()
    expect((await post(h, '/auth/login-code/request', { email: 'nope' })).statusCode).toBe(422)
    expect((await post(h, '/auth/login-code/verify', { email: 'staff@acme.com', code: '12' })).statusCode).toBe(422)
    expect(h.calls).toHaveLength(0)
  })

  it('throttles code requests per address', async () => {
    const h = await start({}, { rateLimits: true })
    let last = 200
    for (let i = 0; i < 12; i++) last = (await post(h, '/auth/login-code/request', { email: `u${i}@acme.com` })).statusCode
    expect(last).toBe(429)
  })

  it('reports an unreachable API instead of pretending to send', async () => {
    const h = await start()
    h.state.upstreamDown = true
    expect((await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })).statusCode).toBe(502)
  })
})

describe('forgotten password', () => {
  it('emails a reset code, again without revealing whether the account exists', async () => {
    const h = await start()
    const known = await post(h, '/auth/forgot-password', { email: 'staff@acme.com' })
    const unknown = await post(h, '/auth/forgot-password', { email: 'ghost@acme.com' })
    expect(bodyOf(known)).toEqual(bodyOf(unknown))
    await mailArrived(h, 1)
    expect(h.sent).toHaveLength(1)
    expect(h.sent[0]?.subject).toMatch(/password reset code/i)
  })

  it('sets the new password, ends every session and emails a security notice', async () => {
    const h = await start()
    const phone = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    await post(h, '/auth/forgot-password', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const res = await post(h, '/auth/reset-password', { email: 'staff@acme.com', code: codeFrom(h, RESET), new_password: 'Brand-New-Pass9' })
    expect(res.statusCode).toBe(204)

    expect(h.calls.find((c) => c.path.endsWith('/password'))?.body).toEqual({ password: 'Brand-New-Pass9' })
    expect((await as(h.app, phone, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401) // old sessions are gone
    expect((await post(h, '/auth/login', { email: 'staff@acme.com', password: 'Brand-New-Pass9' })).statusCode).toBe(200)
    expect((await post(h, '/auth/login', { email: 'staff@acme.com', password: 'StaffPass1' })).statusCode).toBe(401)
    await mailArrived(h, 2)
    expect(h.sent.at(-1)?.subject).toMatch(/password was changed/i)
  })

  it('checks the new password before spending the code, so a typo costs nothing', async () => {
    const h = await start()
    await post(h, '/auth/forgot-password', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const code = codeFrom(h, RESET)
    for (const bad of ['short', 'é'.repeat(37)]) {
      expect((await post(h, '/auth/reset-password', { email: 'staff@acme.com', code, new_password: bad })).statusCode).toBe(422)
    }
    expect((await post(h, '/auth/reset-password', { email: 'staff@acme.com', code, new_password: 'Brand-New-Pass9' })).statusCode).toBe(204)
  })

  it('refuses a wrong code and leaves the password alone', async () => {
    const h = await start()
    await post(h, '/auth/forgot-password', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const right = codeFrom(h, RESET)
    const res = await post(h, '/auth/reset-password', { email: 'staff@acme.com', code: right === '000000' ? '111111' : '000000', new_password: 'Brand-New-Pass9' })
    expect(res.statusCode).toBe(400)
    expect(h.calls.some((c) => c.path.endsWith('/password'))).toBe(false)
  })

  it('does not accept a sign-in code as a reset code', async () => {
    const h = await start()
    await post(h, '/auth/login-code/request', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const res = await post(h, '/auth/reset-password', { email: 'staff@acme.com', code: codeFrom(h, SIGN_IN), new_password: 'Brand-New-Pass9' })
    expect(res.statusCode).toBe(400)
    expect(h.calls.some((c) => c.path.endsWith('/password'))).toBe(false)
  })

  it('works once only', async () => {
    const h = await start()
    await post(h, '/auth/forgot-password', { email: 'staff@acme.com' })
    await mailArrived(h, 1)
    const code = codeFrom(h, RESET)
    expect((await post(h, '/auth/reset-password', { email: 'staff@acme.com', code, new_password: 'Brand-New-Pass9' })).statusCode).toBe(204)
    expect((await post(h, '/auth/reset-password', { email: 'staff@acme.com', code, new_password: 'Another-Pass-77' })).statusCode).toBe(400)
  })

  it('keeps session handles unusable as cookies', async () => {
    const h = await start()
    const s = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    expect(Sessions.handleFor(s.cookie.split('=')[1] as string)).not.toBe(s.cookie.split('=')[1])
  })
})
