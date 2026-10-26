import { randomInt } from 'node:crypto'
import type { Config } from './config.js'
import { hmac, safeEqual } from './crypto.js'
import { HttpError } from './errors.js'
import type { Store } from './store.js'

/** What a code is for. Codes are never interchangeable: a sign-up code can't reset a password. */
export type OtpPurpose = 'signup' | 'login' | 'reset'

interface OtpRecord {
  hash: string
  attempts: number
}

/** Six-digit email codes. Only an HMAC of the code is stored, with attempt limits, expiry and a resend cooldown. */
export class OtpService {
  constructor(
    private store: Store,
    private cfg: Config['otp'],
    private secret: string,
  ) {}

  // Sign-up keys keep their original shape; other purposes get their own namespace.
  private key = (kind: string, email: string, purpose: OtpPurpose) => (purpose === 'signup' ? `${kind}:${email}` : `${kind}:${purpose}:${email}`)

  private digest(email: string, code: string, purpose: OtpPurpose) {
    return hmac(this.secret, purpose === 'signup' ? `${email}:${code}` : `${purpose}:${email}:${code}`)
  }

  /** Enforce the resend cooldown and hourly cap for an address. Throws 429 when sending is not allowed yet. */
  async reserveSend(email: string, purpose: OtpPurpose = 'signup'): Promise<void> {
    const wait = await this.store.ttl(this.key('otp-cooldown', email, purpose))
    if (wait > 0) {
      throw new HttpError(429, `Wait ${wait} second${wait === 1 ? '' : 's'} before asking for another code.`, 'otp_cooldown', {
        'Retry-After': String(wait),
      })
    }
    const { count, ttl } = await this.store.hit(this.key('otp-hourly', email, purpose), 3600)
    if (count > this.cfg.maxPerHour) {
      throw new HttpError(429, 'Too many codes requested. Try again later.', 'otp_hourly', { 'Retry-After': String(ttl) })
    }
    await this.store.set(this.key('otp-cooldown', email, purpose), '1', this.cfg.resendSeconds)
  }

  /** Create a fresh code (invalidating any previous one) and return it for emailing. */
  async issue(email: string, purpose: OtpPurpose = 'signup'): Promise<string> {
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0')
    const record: OtpRecord = { hash: this.digest(email, code, purpose), attempts: 0 }
    await this.store.set(this.key('otp', email, purpose), JSON.stringify(record), this.cfg.ttlSeconds)
    return code
  }

  async verify(email: string, code: string, purpose: OtpPurpose = 'signup'): Promise<void> {
    const recordKey = this.key('otp', email, purpose)
    const raw = await this.store.get(recordKey)
    if (!raw) throw new HttpError(400, 'That code has expired. Ask for a new one.', 'otp_expired')
    const record = JSON.parse(raw) as OtpRecord
    if (record.attempts >= this.cfg.maxAttempts) {
      await this.store.del(recordKey)
      throw new HttpError(400, 'Too many wrong codes. Ask for a new one.', 'otp_locked')
    }
    if (!safeEqual(record.hash, this.digest(email, code, purpose))) {
      record.attempts += 1
      const left = this.cfg.maxAttempts - record.attempts
      const ttl = Math.max(await this.store.ttl(recordKey), 1)
      await this.store.set(recordKey, JSON.stringify(record), ttl)
      throw new HttpError(
        400,
        left > 0 ? `That code isn't right. ${left} ${left === 1 ? 'try' : 'tries'} left.` : 'Too many wrong codes. Ask for a new one.',
        left > 0 ? 'otp_invalid' : 'otp_locked',
      )
    }
    await this.store.del(recordKey) // single use
  }
}
