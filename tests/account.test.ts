import { existsSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { API, as, bodyOf, JPEG, mailArrived, multipart, PNG, signIn, start, WEBP } from './helpers.js'

const upload = (app: Awaited<ReturnType<typeof start>>['app'], s: Awaited<ReturnType<typeof signIn>>, file: Parameters<typeof multipart>) => {
  const m = multipart(...file)
  return as(app, s, { method: 'POST', url: `${API}/auth/me/avatar`, payload: m.payload, headers: m.headers })
}

const filesIn = (dir: string) => {
  const avatars = path.join(dir, 'avatars')
  return existsSync(avatars) ? readdirSync(avatars) : []
}

describe('changing your password', () => {
  it('signs out every other device, keeps this one, and emails a security notice', async () => {
    const h = await start()
    const here = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    const phone = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    const res = await as(h.app, here, { method: 'POST', url: `${API}/auth/me/password`, payload: { current_password: 'StaffPass1', new_password: 'EvenBetter123' } })
    expect(res.statusCode).toBe(204)
    expect((await as(h.app, phone, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(401)
    expect((await as(h.app, here, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
    await mailArrived(h, 1)
    expect(h.sent[0]).toMatchObject({ to: 'staff@acme.com' })
    expect(h.sent[0]?.subject).toMatch(/password was changed/i)
  })

  it('changes nothing when the current password is wrong', async () => {
    const h = await start()
    const here = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    const phone = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    const res = await as(h.app, here, { method: 'POST', url: `${API}/auth/me/password`, payload: { current_password: 'wrong', new_password: 'EvenBetter123' } })
    expect(res.statusCode).toBe(400)
    expect(bodyOf(res).detail).toBe('Your current password is incorrect')
    expect((await as(h.app, phone, { method: 'GET', url: `${API}/auth/me` })).statusCode).toBe(200)
    expect(h.sent).toHaveLength(0)
  })

  it('needs a session and the CSRF token', async () => {
    const h = await start()
    expect((await h.app.inject({ method: 'POST', url: `${API}/auth/me/password`, payload: { current_password: 'a', new_password: 'b' } })).statusCode).toBe(401)
    const s = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    const noCsrf = await h.app.inject({ method: 'POST', url: `${API}/auth/me/password`, headers: { cookie: s.cookie }, payload: { current_password: 'a', new_password: 'b' } })
    expect(noCsrf.statusCode).toBe(403)
  })
})

describe('avatar upload', () => {
  it('stores a PNG, points the profile at it and returns the updated user', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const res = await upload(h.app, s, ['file', 'me.png', 'image/png', PNG])
    expect(res.statusCode).toBe(200)
    const url = bodyOf<{ avatar_url: string }>(res).avatar_url
    expect(url).toMatch(/^http:\/\/localhost:4000\/media\/avatars\/[0-9a-f-]{36}-[\w-]+\.png$/)
    expect(filesIn(h.mediaDir)).toHaveLength(1)
    expect(h.calls.find((c) => c.method === 'PUT' && c.path === '/auth/me/avatar')?.body).toEqual({ avatar_url: url })
  })

  it('accepts JPEG and WebP', async () => {
    const h = await start()
    const s = await signIn(h.app)
    for (const [name, type, data, ext] of [['a.jpg', 'image/jpeg', JPEG, 'jpg'], ['a.webp', 'image/webp', WEBP, 'webp']] as const) {
      const res = await upload(h.app, s, ['file', name, type, data])
      expect(res.statusCode).toBe(200)
      expect(bodyOf<{ avatar_url: string }>(res).avatar_url.endsWith(`.${ext}`)).toBe(true)
    }
  })

  it('replaces the old picture instead of piling up files', async () => {
    const h = await start()
    const s = await signIn(h.app)
    await upload(h.app, s, ['file', 'one.png', 'image/png', PNG])
    await upload(h.app, s, ['file', 'two.png', 'image/png', PNG])
    await upload(h.app, s, ['file', 'three.jpg', 'image/jpeg', JPEG])
    expect(await waitUntil(() => filesIn(h.mediaDir).length === 1)).toBe(true)
  })

  it('decides the type from the bytes, not the name or the claimed content type', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const fakes: Parameters<typeof multipart>[] = [
      ['file', 'cat.png', 'image/png', Buffer.from('<?php echo 1; ?>')],
      ['file', 'logo.svg', 'image/svg+xml', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')],
      ['file', 'anim.gif', 'image/gif', Buffer.from('GIF89a' + 'x'.repeat(40))],
      ['file', 'notes.txt', 'text/plain', Buffer.from('hello')],
      ['file', 'empty.png', 'image/png', Buffer.alloc(0)],
    ]
    for (const f of fakes) {
      const res = await upload(h.app, s, f)
      expect(res.statusCode, f[1]).toBe(415)
    }
    expect(filesIn(h.mediaDir)).toHaveLength(0)
    expect(h.calls.some((c) => c.method === 'PUT')).toBe(false)
  })

  it('refuses images over the size limit', async () => {
    const h = await start({ AVATAR_MAX_BYTES: '1024' })
    const s = await signIn(h.app)
    const big = Buffer.concat([PNG, Buffer.alloc(4096, 7)])
    const res = await upload(h.app, s, ['file', 'big.png', 'image/png', big])
    expect(res.statusCode).toBe(413)
    expect(bodyOf(res).code).toBe('too_large')
    expect(filesIn(h.mediaDir)).toHaveLength(0)
  })

  it('rejects a request that is not a file upload', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const res = await as(h.app, s, { method: 'POST', url: `${API}/auth/me/avatar`, payload: {} })
    expect(res.statusCode).toBe(415)
  })

  it('removes the new file if the API refuses to save it', async () => {
    const h = await start()
    h.state.rejectAvatar = true
    const s = await signIn(h.app)
    const res = await upload(h.app, s, ['file', 'a.png', 'image/png', PNG])
    expect(res.statusCode).toBe(422)
    expect(await waitUntil(() => filesIn(h.mediaDir).length === 0)).toBe(true) // no orphan left on disk
  })

  it('needs a session and the CSRF token', async () => {
    const h = await start()
    const m = multipart('file', 'a.png', 'image/png', PNG)
    expect((await h.app.inject({ method: 'POST', url: `${API}/auth/me/avatar`, payload: m.payload, headers: m.headers })).statusCode).toBe(401)
    const s = await signIn(h.app)
    const noCsrf = await h.app.inject({ method: 'POST', url: `${API}/auth/me/avatar`, payload: m.payload, headers: { ...m.headers, cookie: s.cookie } })
    expect(noCsrf.statusCode).toBe(403)
    expect(filesIn(h.mediaDir)).toHaveLength(0)
  })

  it('serves the stored picture safely to the app on another origin', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const url = bodyOf<{ avatar_url: string }>(await upload(h.app, s, ['file', 'a.png', 'image/png', PNG])).avatar_url
    const res = await h.app.inject({ method: 'GET', url: new URL(url).pathname })
    expect(res.statusCode).toBe(200)
    expect(res.headers['content-type']).toBe('image/png')
    expect(res.headers['x-content-type-options']).toBe('nosniff')
    expect(res.headers['cross-origin-resource-policy']).toBe('cross-origin')
    expect(String(res.headers['content-security-policy'])).toContain("default-src 'none'")
    expect(String(res.headers['cache-control'])).toContain('immutable')
    expect(res.rawPayload.equals(PNG)).toBe(true)
  })

  it('cannot be tricked into serving files outside the media folder', async () => {
    const h = await start()
    for (const url of ['/media/../package.json', '/media/%2e%2e/package.json', '/media/..%2fpackage.json', '/media/avatars/']) {
      const res = await h.app.inject({ method: 'GET', url })
      expect(res.statusCode, url).toBeGreaterThanOrEqual(400)
      expect(res.body).not.toContain('invento-gateway')
    }
  })

  it('removes the picture on request', async () => {
    const h = await start()
    const s = await signIn(h.app)
    await upload(h.app, s, ['file', 'a.png', 'image/png', PNG])
    const res = await as(h.app, s, { method: 'DELETE', url: `${API}/auth/me/avatar` })
    expect(res.statusCode).toBe(200)
    expect(bodyOf(res).avatar_url).toBeNull()
    expect(await waitUntil(() => filesIn(h.mediaDir).length === 0)).toBe(true)
  })
})

describe('deciding access requests', () => {
  const REQ = '66666666-6666-4666-8666-666666666666'

  it('approving emails the applicant and relays the result', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const res = await as(h.app, s, { method: 'POST', url: `${API}/access-requests/${REQ}/approve`, payload: { role: 'INVENTORY_MANAGER' } })
    expect(res.statusCode).toBe(200)
    expect(bodyOf(res).status).toBe('APPROVED')
    await mailArrived(h, 1)
    expect(h.sent[0]).toMatchObject({ to: 'new@acme.com' })
    expect(h.sent[0]?.subject).toMatch(/approved/i)
    expect(h.sent[0]?.html).toContain('http://localhost:5173/login')
    expect(h.calls.find((c) => c.path.endsWith('/approve'))?.body).toEqual({ role: 'INVENTORY_MANAGER' })
  })

  it('approving works without a body', async () => {
    const h = await start()
    const s = await signIn(h.app)
    expect((await as(h.app, s, { method: 'POST', url: `${API}/access-requests/${REQ}/approve` })).statusCode).toBe(200)
  })

  it('rejecting includes the admin’s reason, escaped, in the email', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const res = await as(h.app, s, { method: 'POST', url: `${API}/access-requests/${REQ}/reject`, payload: { note: 'Not on the <b>team</b>' } })
    expect(res.statusCode).toBe(200)
    await mailArrived(h, 1)
    expect(h.sent[0]?.subject).toMatch(/declined/i)
    expect(h.sent[0]?.text).toContain('Not on the <b>team</b>')
    expect(h.sent[0]?.html).toContain('Not on the &lt;b&gt;team&lt;/b&gt;')
    expect(h.sent[0]?.html).not.toContain('<b>team</b>')
  })

  it('sends nothing when the API refuses (not an admin, or already decided)', async () => {
    const h = await start()
    const staff = await signIn(h.app, 'staff@acme.com', 'StaffPass1')
    const denied = await as(h.app, staff, { method: 'POST', url: `${API}/access-requests/${REQ}/approve` })
    expect(denied.statusCode).toBe(403)

    const admin = await signIn(h.app)
    const decided = await as(h.app, admin, { method: 'POST', url: `${API}/access-requests/99999999-9999-4999-8999-999999999999/approve` })
    expect(decided.statusCode).toBe(409)
    await new Promise((r) => setTimeout(r, 30))
    expect(h.sent).toHaveLength(0)
  })

  it('validates ids and bodies before calling the API', async () => {
    const h = await start()
    const s = await signIn(h.app)
    const before = h.calls.length
    expect((await as(h.app, s, { method: 'POST', url: `${API}/access-requests/not-a-uuid/approve` })).statusCode).toBe(422)
    expect((await as(h.app, s, { method: 'POST', url: `${API}/access-requests/${REQ}/approve`, payload: { role: 'SUPERUSER' } })).statusCode).toBe(422)
    expect((await as(h.app, s, { method: 'POST', url: `${API}/access-requests/${REQ}/reject`, payload: { note: 'x'.repeat(501) } })).statusCode).toBe(422)
    expect(h.calls.length).toBe(before)
  })

  it('does not fail the decision if the email cannot be sent', async () => {
    const h = await start()
    h.mailState.fail = true
    const s = await signIn(h.app)
    const res = await as(h.app, s, { method: 'POST', url: `${API}/access-requests/${REQ}/approve` })
    expect(res.statusCode).toBe(200)
  })
})


async function waitUntil(check: () => boolean, ms = 500): Promise<boolean> {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (check()) return true
    await new Promise((r) => setTimeout(r, 10))
  }
  return check()
}
