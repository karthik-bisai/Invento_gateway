import type { Config } from './config.js'
import { HttpError } from './errors.js'

export interface UpstreamResponse {
  status: number
  headers: Headers
  body: Buffer
  json<T = unknown>(): T | undefined
}

export interface UpstreamCall {
  method: string
  /** Path under the API prefix, with query string, e.g. `/auth/me` or `/inventory?page=2`. */
  path: string
  body?: unknown
  /** Acting as a signed-in user. */
  token?: string
  /** Gateway-only endpoints. */
  internal?: boolean
  /** The end user's address, so the API's own rate limits see them rather than the gateway. */
  clientIp?: string
}

type Fetch = typeof fetch

/** The only door to FastAPI. Everything leaving the gateway for the API goes through `call`. */
export class Upstream {
  constructor(
    private cfg: Pick<Config, 'upstreamUrl' | 'upstreamApiPrefix' | 'internalApiKey'>,
    private doFetch: Fetch = fetch,
  ) {}

  async call(req: UpstreamCall): Promise<UpstreamResponse> {
    const headers: Record<string, string> = { accept: 'application/json' }
    if (req.token) headers.authorization = `Bearer ${req.token}`
    if (req.internal) headers['x-internal-key'] = this.cfg.internalApiKey
    if (req.clientIp) headers['x-forwarded-for'] = req.clientIp
    let body: string | undefined
    if (req.body !== undefined && req.method !== 'GET' && req.method !== 'HEAD') {
      body = JSON.stringify(req.body)
      headers['content-type'] = 'application/json'
    }
    let res: Response
    try {
      res = await this.doFetch(`${this.cfg.upstreamUrl}${this.cfg.upstreamApiPrefix}${req.path}`, {
        method: req.method,
        headers,
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(15_000),
      })
    } catch {
      throw new HttpError(502, 'The service is temporarily unavailable. Please try again.', 'upstream_unavailable')
    }
    const buffer = Buffer.from(await res.arrayBuffer())
    return {
      status: res.status,
      headers: res.headers,
      body: buffer,
      json<T>() {
        if (!buffer.length) return undefined
        try {
          return JSON.parse(buffer.toString('utf8')) as T
        } catch {
          return undefined
        }
      },
    }
  }
}

/** FastAPI's `{ detail }` (a string or a validation array) as one readable message. */
export function detailOf(res: UpstreamResponse, fallback: string): string {
  const detail = (res.json<{ detail?: unknown }>() ?? {}).detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail[0] && typeof detail[0] === 'object' && 'msg' in detail[0]) {
    const first = detail[0] as { msg: string; loc?: unknown[] }
    const field = first.loc?.at(-1)
    return field ? `${String(field).replace(/_/g, ' ')}: ${first.msg.replace(/^Value error, /, '')}` : first.msg
  }
  return fallback
}
