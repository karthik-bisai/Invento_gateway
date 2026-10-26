import type { Config } from './config.js'
import type { Mailer } from './mail/mailer.js'
import {
  loginCodeEmail,
  resetCodeEmail,
  accessApprovedEmail,
  accessRejectedEmail,
  accessRequestedEmail,
  otpEmail,
  passwordChangedEmail,
  requestReceivedEmail,
} from './mail/templates.js'

type Log = { error: (obj: object, msg?: string) => void }

export interface Person {
  email: string
  full_name?: string | null
}

export interface AdminContact extends Person {
  wants_email: boolean
}

/**
 * The notification service: turns domain events into the right emails. In-app notifications are written by the
 * API itself (they live next to the data). Delivery here is best-effort: a mail outage is logged and never
 * blocks or fails the action that caused it, except for OTP codes, where the caller needs to know.
 */
export class Notifier {
  constructor(
    private mailer: Mailer,
    private cfg: Pick<Config, 'appUrl' | 'otp'>,
    private log: Log,
  ) {}

  private async safe(to: string, build: () => ReturnType<typeof otpEmail>, what: string): Promise<boolean> {
    try {
      await this.mailer.send({ to, ...build() })
      return true
    } catch (err) {
      this.log.error({ err, to, what }, 'email delivery failed')
      return false
    }
  }

  /** Returns false when the code could not be delivered, so the UI can offer a resend. */
  sendOtp(email: string, code: string) {
    return this.safe(email, () => otpEmail(code, Math.round(this.cfg.otp.ttlSeconds / 60)), 'otp')
  }

  sendLoginCode(email: string, code: string, name: string | null) {
    return this.safe(email, () => loginCodeEmail(code, Math.round(this.cfg.otp.ttlSeconds / 60), name), 'login-code')
  }

  sendResetCode(email: string, code: string, name: string | null) {
    return this.safe(email, () => resetCodeEmail(code, Math.round(this.cfg.otp.ttlSeconds / 60), name), 'reset-code')
  }

  /** After a verified sign-up: confirm to the applicant and tell every admin who opted in. */
  async accessRequested(applicant: Person, admins: AdminContact[]) {
    const name = applicant.full_name ?? null
    await Promise.all([
      this.safe(applicant.email, () => requestReceivedEmail(name, this.cfg.appUrl), 'request-received'),
      ...admins
        .filter((a) => a.wants_email)
        .map((a) =>
          this.safe(a.email, () => accessRequestedEmail(a.full_name ?? null, { email: applicant.email, name }, this.cfg.appUrl), 'access-requested'),
        ),
    ])
  }

  accessDecided(applicant: Person, decision: 'approved' | 'rejected', note: string | null) {
    const name = applicant.full_name ?? null
    return this.safe(
      applicant.email,
      () => (decision === 'approved' ? accessApprovedEmail(name, this.cfg.appUrl) : accessRejectedEmail(name, note)),
      `access-${decision}`,
    )
  }

  passwordChanged(user: Person) {
    return this.safe(user.email, () => passwordChangedEmail(user.full_name ?? null, this.cfg.appUrl), 'password-changed')
  }
}
