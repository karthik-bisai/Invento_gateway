import cookie from '@fastify/cookie'
import cors from '@fastify/cors'
import multipart from '@fastify/multipart'
import fastifyStatic from '@fastify/static'
import Fastify, { type FastifyInstance } from 'fastify'
import { ZodError } from 'zod'
import type { Config } from './config.js'
import { API_PREFIX, type Ctx, csrfFor, isUnsafe, ServiceTokens } from './context.js'
import { HttpError } from './errors.js'
import type { Mailer } from './mail/mailer.js'
import { Notifier } from './notify.js'
import { OtpService } from './otp.js'
import { RateLimiter } from './rateLimit.js'
import { accessRoutes } from './routes/access.js'
import { accountRoutes } from './routes/account.js'
import { authRoutes } from './routes/auth.js'
import { codeRoutes } from './routes/codes.js'
import { proxyRoutes } from './routes/proxy.js'
import { Sessions } from './sessions.js'
import { LocalStorage, type Storage } from './storage/index.js'
import type { Store } from './store.js'
import type { Upstream } from './upstream.js'

export interface Deps {
  config: Config
  store: Store
  mailer: Mailer
  storage: Storage
  upstream: Upstream
  /** Fastify logger options, or false to silence (tests). */
  logger?: boolean | object
  now?: () => number
  /** Switch the per-address limiters off (tests). The OTP cooldown and attempt caps always apply. */
  rateLimits?: boolean
}

export async function buildApp(deps: Deps): Promise<FastifyInstance> {
  const { config, store, upstream } = deps
  const app = Fastify({
    logger: deps.logger ?? false,
    trustProxy: config.trustProxy,
    bodyLimit: 1024 * 1024,
  })

  const ctx: Ctx = {
    config,
    store,
    upstream,
    storage: deps.storage,
    sessions: new Sessions(store, { idleSeconds: config.sessionIdleSeconds, maxSeconds: config.sessionMaxSeconds, now: deps.now }),
    limiter: new RateLimiter(store, deps.rateLimits ?? true),
    otp: new OtpService(store, config.otp, config.gatewaySecret),
    notifier: new Notifier(deps.mailer, config, app.log),
    tokens: new ServiceTokens(upstream),
    // __Host- locks the cookie to this exact host over HTTPS with no Domain attribute.
    cookieName: config.cookieSecure && !config.cookieDomain ? '__Host-inv_session' : 'inv_session',
  }

  await app.register(cookie)
  await app.register(cors, {
    origin: config.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['content-type', 'x-csrf-token'],
    exposedHeaders: ['x-csrf-token', 'retry-after'],
    maxAge: 600,
  })
  await app.register(multipart, { limits: { fileSize: config.storage.maxBytes, files: 1, fields: 0, parts: 2 } })

  // An empty body with a JSON content type (axios DELETE/POST with no data) is fine, not a 400.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
    if (!body) return done(null, undefined)
    try {
      done(null, JSON.parse(body as string))
    } catch {
      done(new HttpError(400, 'Request body is not valid JSON.', 'bad_json'), undefined)
    }
  })

  // Browsers always send Origin on cross-site writes. Refuse any that isn't one of our own front ends.
  app.addHook('onRequest', async (req) => {
    const origin = req.headers.origin
    if (isUnsafe(req.method) && origin && !config.corsOrigins.includes(origin.replace(/\/$/, ''))) {
      throw new HttpError(403, 'This request came from an origin that isn’t allowed.', 'origin_not_allowed')
    }
  })

  app.addHook('onSend', async (req, reply) => {
    reply.header('x-content-type-options', 'nosniff')
    reply.header('referrer-policy', 'same-origin')
    reply.header('x-frame-options', 'DENY')
    if (!reply.hasHeader('cache-control') && req.url.startsWith(API_PREFIX)) reply.header('cache-control', 'no-store')
    if (req.url.startsWith('/media/')) {
      reply.header('cross-origin-resource-policy', 'cross-origin') // the app runs on another origin
      reply.header('content-security-policy', "default-src 'none'; sandbox")
    }
    // Hand the browser its CSRF token on every authenticated response, so it survives page reloads.
    if (req.auth && !reply.hasHeader('x-csrf-token')) reply.header('x-csrf-token', csrfFor(ctx, req.auth.sessionId))
  })

  app.setErrorHandler((error, req, reply) => {
    const err = error as Error
    if (err instanceof HttpError) {
      for (const [k, v] of Object.entries(err.headers)) reply.header(k, v)
      return reply.code(err.status).send({ detail: err.message, ...(err.code ? { code: err.code } : {}) })
    }
    if (err instanceof ZodError) return reply.code(422).send({ detail: err.issues[0]?.message ?? 'Invalid request', code: 'validation' })
    const code = (err as { code?: string }).code
    if (code === 'FST_REQ_FILE_TOO_LARGE' || code === 'FST_ERR_CTP_BODY_TOO_LARGE') {
      return reply.code(413).send({ detail: 'That upload is too large.', code: 'too_large' })
    }
    if (code === 'FST_INVALID_MULTIPART_CONTENT_TYPE') {
      return reply.code(415).send({ detail: 'Send the image as multipart form data.', code: 'unsupported_type' })
    }
    const status = (err as { statusCode?: number }).statusCode
    if (status && status >= 400 && status < 500) return reply.code(status).send({ detail: err.message, code: 'bad_request' })
    req.log.error({ err }, 'unhandled error')
    return reply.code(500).send({ detail: 'Something went wrong. Please try again.', code: 'internal' })
  })

  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ detail: 'Not found', code: 'not_found' }))

  // Locally stored avatars are served by the gateway; with S3 the browser loads them straight from the bucket/CDN.
  if (deps.storage instanceof LocalStorage) {
    await app.register(fastifyStatic, {
      root: deps.storage.directory,
      prefix: '/media/',
      index: false,
      list: false,
      dotfiles: 'deny',
      cacheControl: true,
      maxAge: '1y',
      immutable: true,
    })
  }

  app.get('/healthz', async (_req, reply) => {
    const [storeOk, upstreamOk] = await Promise.all([
      store.ping().catch(() => false),
      upstream.call({ method: 'GET', path: '/health' }).then((r) => r.status === 200, () => false),
    ])
    const ok = storeOk && upstreamOk
    return reply.code(ok ? 200 : 503).send({ status: ok ? 'ok' : 'degraded', store: storeOk ? 'ok' : 'down', upstream: upstreamOk ? 'ok' : 'down' })
  })

  await app.register(
    async (api) => {
      await authRoutes(api, ctx)
      await codeRoutes(api, ctx)
      await accountRoutes(api, ctx)
      await accessRoutes(api, ctx)
      await proxyRoutes(api, ctx) // last: the catch-all for everything not handled above
    },
    { prefix: API_PREFIX },
  )

  return app
}
