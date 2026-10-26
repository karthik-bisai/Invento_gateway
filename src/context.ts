import type { FastifyReply, FastifyRequest } from 'fastify'
import { z } from 'zod'
import type { Config } from './config.js'
import { hmac, safeEqual } from './crypto.js'
import { HttpError } from './errors.js'
import type { Notifier } from './notify.js'
import type { OtpService } from './otp.js'
import type { RateLimiter } from './rateLimit.js'
import type { Sessions } from './sessions.js'
import type { Storage } from './storage/index.js'
import type { Store } from './store.js'
import type { Upstream, UpstreamCall, UpstreamResponse } from './upstream.js'

export interface AuthInfo {
  userId: string
  handle: string
  sessionId: string
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthInfo
  }
}

/** Caches short-lived service tokens so most requests don't need an extra round trip to the API. */
export class ServiceTokens {
  private cache = new Map<string, { token: string; expiresAt: number }>()

  constructor(
    private upstream: Upstream,
    private ttlMs = 60_000,
    private now: () => number = Date.now,
  ) {}

  /** A token acting as the user, or null when the API says they're no longer an active user. */
  async get(userId: string): Promise<string | null> {
    const hit = this.cache.get(userId)
    if (hit && hit.expiresAt > this.now()) return hit.token
    const res = await this.upstream.call({ method: 'POST', path: `/internal/users/${userId}/token`, internal: true })
    if (res.status === 404) {
      this.cache.delete(userId)
      return null
    }
    const token = res.json<{ access_token?: string }>()?.access_token
    if (res.status !== 200 || !token) throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')
    this.cache.set(userId, { token, expiresAt: this.now() + this.ttlMs })
    return token
  }

  forget(userId: string) {
    this.cache.delete(userId)
  }
}

export interface Ctx {
  config: Config
  store: Store
  sessions: Sessions
  limiter: RateLimiter
  otp: OtpService
  notifier: Notifier
  storage: Storage
  upstream: Upstream
  tokens: ServiceTokens
  cookieName: string
}

/** Public path prefix of the gateway's API. */
export const API_PREFIX = '/api/v1'

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
export const isUnsafe = (method: string) => UNSAFE.has(method)

export const csrfFor = (ctx: Ctx, sessionId: string) => hmac(ctx.config.gatewaySecret, `csrf:${sessionId}`)

const sessionEnded = () => new HttpError(401, 'Your session has ended. Sign in again.', 'session_expired')

/** preHandler: resolve the session cookie, and for state-changing requests require the CSRF header. */
export function requireSession(ctx: Ctx) {
  return async (req: FastifyRequest): Promise<void> => {
    const sessionId = req.cookies[ctx.cookieName]
    if (!sessionId) throw new HttpError(401, 'Sign in to continue.', 'unauthenticated')
    const session = await ctx.sessions.get(sessionId)
    if (!session) throw sessionEnded()
    req.auth = { userId: session.userId, handle: session.handle, sessionId }
    if (isUnsafe(req.method)) {
      const sent = req.headers['x-csrf-token']
      if (typeof sent !== 'string' || !safeEqual(sent, csrfFor(ctx, sessionId))) {
        throw new HttpError(403, 'Your session check failed. Reload the page and try again.', 'csrf')
      }
    }
  }
}

/** Call the API as the signed-in user. A 401 from the API means the account is gone: end the session. */
export async function asUser(
  ctx: Ctx,
  req: FastifyRequest,
  call: Omit<UpstreamCall, 'token' | 'clientIp' | 'internal'>,
): Promise<UpstreamResponse> {
  const auth = req.auth
  if (!auth) throw new HttpError(401, 'Sign in to continue.', 'unauthenticated')
  const attempt = async () => {
    const token = await ctx.tokens.get(auth.userId)
    if (!token) return null
    return ctx.upstream.call({ ...call, token, clientIp: req.ip })
  }
  let res = await attempt()
  if (res?.status === 401) {
    ctx.tokens.forget(auth.userId) // maybe just a stale cached token: retry once with a fresh one
    res = await attempt()
  }
  if (!res || res.status === 401) {
    await ctx.sessions.destroy(auth.sessionId)
    throw sessionEnded()
  }
  return res
}

/** Pass an API response through to the browser. */
export function relay(reply: FastifyReply, res: UpstreamResponse): FastifyReply {
  reply.code(res.status)
  for (const name of ['content-type', 'retry-after', 'cache-control']) {
    const value = res.headers.get(name)
    if (value) reply.header(name, value)
  }
  return reply.send(res.status === 204 || res.body.length === 0 ? undefined : res.body)
}

/** Validate input with zod, turning failures into a 422 in the API's `{ detail }` shape. */
export function parse<T extends z.ZodType>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input ?? {})
  if (result.success) return result.data
  const issue = result.error.issues[0]
  const field = issue?.path.at(-1)
  throw new HttpError(422, field ? `${String(field).replace(/_/g, ' ')}: ${issue?.message}` : (issue?.message ?? 'Invalid request'), 'validation')
}

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(255)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Enter a valid email address.')

/** bcrypt only uses the first 72 bytes, and FastAPI rejects longer passwords; fail early with the same rule. */
export const passwordSchema = z
  .string()
  .min(8, 'Use at least 8 characters.')
  .refine((p) => Buffer.byteLength(p) <= 72, 'Keep it under 72 bytes (accented letters and emoji count extra).')

export const uuidSchema = z.string().uuid()

/**
 * Sign this browser in as `userId`: a brand-new session id (never one the browser already holds, so a planted
 * cookie can't be adopted), set in an HTTP-only cookie, plus the CSRF token for it.
 */
export async function startSession(ctx: Ctx, req: FastifyRequest, reply: FastifyReply, userId: string): Promise<{ csrf: string }> {
  const previous = req.cookies[ctx.cookieName]
  if (previous) await ctx.sessions.destroy(previous)
  const { id } = await ctx.sessions.create(userId, { ip: req.ip, userAgent: String(req.headers['user-agent'] ?? '') })
  reply.setCookie(ctx.cookieName, id, cookieOptions(ctx, ctx.config.sessionMaxSeconds))
  const csrf = csrfFor(ctx, id)
  reply.header('x-csrf-token', csrf)
  return { csrf }
}

export function cookieOptions(ctx: Ctx, maxAgeSeconds?: number) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: ctx.config.cookieSecure,
    path: '/',
    domain: ctx.config.cookieDomain,
    ...(maxAgeSeconds ? { maxAge: maxAgeSeconds } : {}),
  }
}
