import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { type Ctx, emailSchema, parse, passwordSchema, startSession } from '../context.js'
import { HttpError } from '../errors.js'
import { detailOf } from '../upstream.js'

const emailBody = z.object({ email: emailSchema })
const codeField = z.string().regex(/^\d{6}$/, 'Enter the 6-digit code.')
const verifyBody = z.object({ email: emailSchema, code: codeField })
const resetBody = z.object({ email: emailSchema, code: codeField, new_password: passwordSchema })

interface Lookup {
  status: string
  id?: string | null
  full_name?: string | null
}

/** What to tell someone whose code was right but whose account can't be used yet. */
const BLOCKED: Record<string, string> = {
  email_unverified: 'Verify your email to continue.',
  pending_approval: 'Your access request is waiting for an administrator.',
  rejected: 'Your access request was declined.',
  deactivated: 'Your account has been deactivated. Contact an administrator.',
}

/**
 * Sign in with an emailed code, and reset a forgotten password. Both start the same way: ask for a code, and the
 * answer is identical whether or not the address has an account, so nobody can use these to find out who is registered.
 * A code is only ever sent to an account that can actually sign in.
 */
export async function codeRoutes(app: FastifyInstance, ctx: Ctx) {
  const { config, limiter, otp, notifier, upstream, sessions } = ctx
  const sent = () => ({ status: 'sent', resend_in: config.otp.resendSeconds })

  async function lookup(email: string): Promise<Lookup> {
    const res = await upstream.call({ method: 'POST', path: '/internal/login/lookup', internal: true, body: { email } })
    const body = res.json<Lookup>()
    if (res.status !== 200 || !body) throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')
    return body
  }

  function requireUsable(who: Lookup): string {
    if (who.status === 'ok' && who.id) return who.id
    throw new HttpError(403, BLOCKED[who.status] ?? 'That account can’t be used right now.', who.status)
  }

  // ---- sign in with a code ------------------------------------------------------------------------

  app.post('/auth/login-code/request', async (req) => {
    const { email } = parse(emailBody, req.body)
    await limiter.check('login-code-ip', req.ip, 10, 3600, 'code requests')
    await otp.reserveSend(email, 'login') // cooldown applies whether or not the account exists
    const who = await lookup(email)
    if (who.status === 'ok') void notifier.sendLoginCode(email, await otp.issue(email, 'login'), who.full_name ?? null)
    return sent()
  })

  app.post('/auth/login-code/verify', async (req, reply) => {
    const { email, code } = parse(verifyBody, req.body)
    await limiter.check('login-code-verify-ip', req.ip, 30, 600, 'sign-in attempts')
    await limiter.check('login-code-verify-email', email, 15, 600, 'sign-in attempts')
    await otp.verify(email, code, 'login')
    const userId = requireUsable(await lookup(email)) // re-check: the account may have changed since the code was sent
    const { csrf } = await startSession(ctx, req, reply, userId)
    return { status: 'ok', csrf_token: csrf }
  })

  // ---- forgotten password -------------------------------------------------------------------------

  app.post('/auth/forgot-password', async (req) => {
    const { email } = parse(emailBody, req.body)
    await limiter.check('reset-code-ip', req.ip, 10, 3600, 'reset requests')
    await otp.reserveSend(email, 'reset')
    const who = await lookup(email)
    if (who.status === 'ok') void notifier.sendResetCode(email, await otp.issue(email, 'reset'), who.full_name ?? null)
    return sent()
  })

  app.post('/auth/reset-password', async (req, reply) => {
    // The new password is checked before the code is spent, so a typo doesn't cost the person their code.
    const { email, code, new_password } = parse(resetBody, req.body)
    await limiter.check('reset-verify-ip', req.ip, 30, 600, 'reset attempts')
    await limiter.check('reset-verify-email', email, 15, 600, 'reset attempts')
    await otp.verify(email, code, 'reset')
    const who = await lookup(email)
    const userId = requireUsable(who)

    const res = await upstream.call({ method: 'POST', path: `/internal/users/${userId}/password`, internal: true, body: { password: new_password } })
    if (res.status === 422) throw new HttpError(422, detailOf(res, 'Choose a different password.'), 'validation')
    if (res.status !== 204) throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')

    await sessions.destroyAllForUser(userId) // whoever else had this account loses access with the old password
    void notifier.passwordChanged({ email, full_name: who.full_name })
    return reply.code(204).send()
  })
}
