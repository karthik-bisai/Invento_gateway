import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { asUser, type Ctx, parse, relay, requireSession } from '../context.js'
import { randomToken } from '../crypto.js'
import { HttpError } from '../errors.js'
import { avatarPrefix, sniffImage } from '../storage/index.js'

const passwordBody = z.object({ current_password: z.string().min(1).max(200), new_password: z.string().min(1).max(500) })

interface Me {
  email: string
  full_name?: string | null
  avatar_url?: string | null
}

export async function accountRoutes(app: FastifyInstance, ctx: Ctx) {
  const { sessions, notifier, storage, limiter, config } = ctx
  const guard = { preHandler: requireSession(ctx) }

  const publicSession = (s: Awaited<ReturnType<typeof sessions.listForUser>>[number]) => ({
    id: s.handle,
    current: s.current,
    ip: s.ip,
    user_agent: s.userAgent,
    created_at: new Date(s.createdAt).toISOString(),
    last_seen: new Date(s.lastSeen).toISOString(),
  })

  // ---- devices ------------------------------------------------------------------------------------

  app.get('/auth/sessions', guard, async (req) => {
    const auth = req.auth!
    return { items: (await sessions.listForUser(auth.userId, auth.handle)).map(publicSession) }
  })

  // Declared before "/auth/sessions/:handle" so "revoke-others" isn't read as a handle.
  app.post('/auth/sessions/revoke-others', guard, async (req) => {
    const auth = req.auth!
    return { ended: await sessions.destroyAllForUser(auth.userId, auth.handle) }
  })

  app.delete('/auth/sessions/:handle', guard, async (req, reply) => {
    const auth = req.auth!
    const { handle } = parse(z.object({ handle: z.string().regex(/^[0-9a-f]{64}$/) }), req.params)
    if (handle === auth.handle) throw new HttpError(400, 'Use Sign out to end this session.', 'current_session')
    if (!(await sessions.destroyHandle(auth.userId, handle))) throw new HttpError(404, 'That session was not found.', 'not_found')
    return reply.code(204).send()
  })

  // ---- password -----------------------------------------------------------------------------------

  app.post('/auth/me/password', guard, async (req, reply) => {
    const auth = req.auth!
    const body = parse(passwordBody, req.body)
    const res = await asUser(ctx, req, { method: 'POST', path: '/auth/me/password', body })
    if (res.status !== 204) return relay(reply, res)

    // A changed password ends every other device's session: whoever else had access loses it now.
    await sessions.destroyAllForUser(auth.userId, auth.handle)
    const me = await asUser(ctx, req, { method: 'GET', path: '/auth/me' })
    const user = me.json<Me>()
    if (user) void notifier.passwordChanged(user)
    return reply.code(204).send()
  })

  // ---- avatar -------------------------------------------------------------------------------------

  const currentAvatar = async (req: Parameters<typeof asUser>[1]) =>
    (await asUser(ctx, req, { method: 'GET', path: '/auth/me' })).json<Me>()?.avatar_url ?? null

  const dropFile = (url: string | null) => {
    if (url) storage.deleteByUrl(url).catch((err) => app.log.error({ err }, 'could not delete old avatar'))
  }

  app.post('/auth/me/avatar', guard, async (req, reply) => {
    const auth = req.auth!
    await limiter.check('avatar', auth.userId, 20, 3600, 'uploads')
    const file = await req.file()
    if (!file) throw new HttpError(400, 'Choose an image to upload.', 'no_file')
    const data = await file.toBuffer()
    if (file.file.truncated) {
      throw new HttpError(413, `That image is too large. The limit is ${Math.round(config.storage.maxBytes / 1024 / 1024)} MB.`, 'too_large')
    }
    const kind = sniffImage(data)
    if (!kind) throw new HttpError(415, 'Use a PNG, JPEG or WebP image.', 'unsupported_type')

    const previous = await currentAvatar(req)
    const url = await storage.put(`${avatarPrefix(config)}${auth.userId}-${randomToken(9)}.${kind.ext}`, data, kind.contentType)
    const res = await asUser(ctx, req, { method: 'PUT', path: '/auth/me/avatar', body: { avatar_url: url } })
    if (res.status !== 200) {
      dropFile(url) // the profile didn't take it, so don't leave an orphan behind
      return relay(reply, res)
    }
    dropFile(previous)
    return relay(reply, res)
  })

  app.delete('/auth/me/avatar', guard, async (req, reply) => {
    const previous = await currentAvatar(req)
    const res = await asUser(ctx, req, { method: 'PUT', path: '/auth/me/avatar', body: { avatar_url: null } })
    if (res.status === 200) dropFile(previous)
    return relay(reply, res)
  })
}
