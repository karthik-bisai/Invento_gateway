import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { type Ctx, cookieOptions, emailSchema, parse, passwordSchema, requireSession, startSession } from '../context.js'
import { HttpError } from '../errors.js'
import { detailOf, type UpstreamResponse } from '../upstream.js'

const loginBody = z.object({ email: emailSchema, password: z.string().min(1, 'Enter your password.').max(200) })
const signupBody = z.object({
  email: emailSchema,
  password: passwordSchema,
  full_name: z.string().trim().max(120).optional(),
})
const verifyBody = z.object({ email: emailSchema, code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code.') })
const resendBody = z.object({ email: emailSchema })

interface VerifiedResult {
  user: { email: string; full_name?: string | null }
  auto_approved: boolean
  admins: { email: string; full_name?: string | null; wants_email: boolean }[]
}

const subjectOf = (jwt: string | undefined): string | null => {
  try {
    const payload = JSON.parse(Buffer.from((jwt ?? '').split('.')[1] ?? '', 'base64url').toString('utf8')) as { sub?: unknown }
    return typeof payload.sub === 'string' && payload.sub ? payload.sub : null
  } catch {
    return null
  }
}

function loginError(res: UpstreamResponse): HttpError {
  const message = detailOf(res, 'Unable to sign in. Please try again.')
  if (res.status === 401) return new HttpError(401, message, 'invalid_credentials')
  if (res.status === 403) return new HttpError(403, message, res.headers.get('x-account-status') ?? 'forbidden')
  if (res.status === 429) return new HttpError(429, message, 'rate_limited', { 'Retry-After': res.headers.get('retry-after') ?? '60' })
  if (res.status === 422) return new HttpError(422, message, 'validation')
  return new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')
}

export async function authRoutes(app: FastifyInstance, ctx: Ctx) {
  const { config, limiter, otp, notifier, upstream, sessions } = ctx

  app.post('/auth/login', async (req, reply) => {
    const body = parse(loginBody, req.body)
    await limiter.check('login-ip', req.ip, 30, 60, 'sign-in attempts')
    const res = await upstream.call({ method: 'POST', path: '/auth/login', body, clientIp: req.ip })
    if (res.status !== 200) throw loginError(res)
    const userId = subjectOf(res.json<{ access_token?: string }>()?.access_token)
    if (!userId) throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')

    const { csrf } = await startSession(ctx, req, reply, userId)
    return { status: 'ok', csrf_token: csrf }
  })

  app.post('/auth/logout', async (req, reply) => {
    const id = req.cookies[ctx.cookieName]
    if (id) {
      // Signing out is allowed without CSRF only when the session is already gone; otherwise it needs the header.
      await requireSession(ctx)(req)
      await sessions.destroy(id)
    }
    reply.clearCookie(ctx.cookieName, cookieOptions(ctx))
    return reply.code(204).send()
  })

  app.post('/auth/signup', async (req, reply) => {
    const body = parse(signupBody, req.body)
    await limiter.check('signup', req.ip, 10, 3600, 'sign-up attempts')
    const res = await upstream.call({
      method: 'POST',
      path: '/auth/register',
      body: { email: body.email, password: body.password, full_name: body.full_name || undefined },
      clientIp: req.ip,
    })
    if (res.status === 409) throw new HttpError(409, 'An account with this email already exists. Try signing in instead.', 'email_taken')
    if (res.status === 429) throw new HttpError(429, detailOf(res, 'Too many attempts. Try again later.'), 'rate_limited', { 'Retry-After': res.headers.get('retry-after') ?? '60' })
    if (res.status === 422) throw new HttpError(422, detailOf(res, 'Check your details and try again.'), 'validation')
    if (res.status !== 201) throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')

    await otp.reserveSend(body.email)
    const code = await otp.issue(body.email)
    const emailSent = await notifier.sendOtp(body.email, code)
    return reply.code(201).send({ status: 'verify_email', email: body.email, email_sent: emailSent, resend_in: config.otp.resendSeconds })
  })

  app.post('/auth/verify-otp', async (req) => {
    const { email, code } = parse(verifyBody, req.body)
    await limiter.check('otp-verify-ip', req.ip, 30, 600, 'verification attempts')
    await limiter.check('otp-verify-email', email, 15, 600, 'verification attempts')
    await otp.verify(email, code)

    const res = await upstream.call({ method: 'POST', path: '/internal/signup/verified', internal: true, body: { email } })
    if (res.status === 404) throw new HttpError(404, 'We couldn’t find that sign-up. Start again.', 'no_account')
    const result = res.json<VerifiedResult>()
    if (res.status !== 200 || !result) throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')

    // Emails go out in the background so a slow mail server never holds up the response.
    if (!result.auto_approved) void notifier.accessRequested(result.user, result.admins)
    return { status: result.auto_approved ? 'approved' : 'pending_approval' }
  })

  app.post('/auth/resend-otp', async (req) => {
    const { email } = parse(resendBody, req.body)
    await limiter.check('otp-resend-ip', req.ip, 10, 3600, 'code requests')
    // Cooldown is per address whether or not an account exists, so the response never reveals which emails are registered.
    await otp.reserveSend(email)
    const res = await upstream.call({ method: 'POST', path: '/internal/signup/status', internal: true, body: { email } })
    const status = res.json<{ exists: boolean; email_verified: boolean }>()
    if (res.status === 200 && status?.exists && !status.email_verified) {
      const code = await otp.issue(email)
      void notifier.sendOtp(email, code)
    }
    return { status: 'sent', resend_in: config.otp.resendSeconds }
  })
}
