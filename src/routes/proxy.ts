import type { FastifyInstance } from 'fastify'
import { API_PREFIX, asUser, type Ctx, relay, requireSession } from '../context.js'
import { HttpError } from '../errors.js'

/**
 * Paths a browser must never reach through the gateway:
 *  - /internal: gateway-only calls
 *  - /auth/register and /auth/login: the gateway owns these (OTP, sessions); going direct would skip them
 *  - /auth/me/avatar: only the gateway's upload route may set it, so profiles can't point at arbitrary files
 */
const BLOCKED = [/^\/internal(\/|$|\?)/, /^\/auth\/register(\?|$)/, /^\/auth\/login(\?|$)/, /^\/auth\/me\/avatar(\?|$)/]

const USER_PATCH = /^\/auth\/users\/([0-9a-f-]{36})(\?|$)/i

/**
 * Everything else under the API prefix: authenticate the cookie, then forward as that user.
 * Adds session side effects the API can't perform itself (it doesn't know about sessions).
 */
export async function proxyRoutes(app: FastifyInstance, ctx: Ctx) {
  const guard = { preHandler: requireSession(ctx) }

  app.all('/*', guard, async (req, reply) => {
    const path = req.url.slice(API_PREFIX.length) // keeps the query string
    if (BLOCKED.some((re) => re.test(path))) throw new HttpError(404, 'Not found', 'not_found')

    const res = await asUser(ctx, req, { method: req.method, path, body: req.body })

    // An admin changing someone's password or deactivating them must also end that person's open sessions.
    const target = req.method === 'PATCH' ? USER_PATCH.exec(path)?.[1] : undefined
    if (target && res.status === 200) {
      const body = (req.body ?? {}) as { password?: unknown; is_active?: unknown }
      if (typeof body.password === 'string' || body.is_active === false) await ctx.sessions.destroyAllForUser(target)
    }
    return relay(reply, res)
  })
}
