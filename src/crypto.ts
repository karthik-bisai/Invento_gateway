import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex')

export const hmac = (secret: string, value: string) => createHmac('sha256', secret).update(value).digest('hex')

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url')

/** Constant-time string comparison (length differences still short-circuit, which leaks nothing useful here). */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && timingSafeEqual(left, right)
}
