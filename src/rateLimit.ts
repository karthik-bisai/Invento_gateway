import { HttpError } from './errors.js'
import type { Store } from './store.js'

/**
 * Fixed-window limiter over the store. Throws a 429 with Retry-After once `max` hits land inside `windowSeconds`.
 * If the store is unreachable we let the request through: the upstream API enforces its own limits as well.
 */
export class RateLimiter {
  constructor(
    private store: Store,
    private enabled = true,
  ) {}

  async check(scope: string, subject: string, max: number, windowSeconds: number, what = 'attempts'): Promise<void> {
    if (!this.enabled) return
    let result: { count: number; ttl: number }
    try {
      result = await this.store.hit(`rl:${scope}:${subject.toLowerCase()}`, windowSeconds)
    } catch {
      return
    }
    if (result.count > max) {
      throw new HttpError(
        429,
        `Too many ${what}. Try again in ${result.ttl} second${result.ttl === 1 ? '' : 's'}.`,
        'rate_limited',
        { 'Retry-After': String(result.ttl) },
      )
    }
  }
}
