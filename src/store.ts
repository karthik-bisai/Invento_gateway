import { Redis } from 'ioredis'
import { HttpError } from './errors.js'

/**
 * The little key-value surface the gateway needs (sessions, OTPs, rate counters).
 * Redis in deployment; an in-process map for tests and for running without Redis locally.
 */
export interface Store {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ttlSeconds?: number): Promise<void>
  del(...keys: string[]): Promise<void>
  /** Count one hit. The window starts at the first hit and the key expires `ttlSeconds` later. */
  hit(key: string, ttlSeconds: number): Promise<{ count: number; ttl: number }>
  ttl(key: string): Promise<number>
  sadd(key: string, member: string, ttlSeconds?: number): Promise<void>
  srem(key: string, member: string): Promise<void>
  smembers(key: string): Promise<string[]>
  ping(): Promise<boolean>
  close(): Promise<void>
}

interface Entry {
  value: string
  expiresAt: number | null
}

export class MemoryStore implements Store {
  private data = new Map<string, Entry>()
  private sets = new Map<string, { members: Set<string>; expiresAt: number | null }>()

  constructor(private now: () => number = Date.now) {}

  private live(key: string): Entry | undefined {
    const entry = this.data.get(key)
    if (entry && entry.expiresAt !== null && entry.expiresAt <= this.now()) {
      this.data.delete(key)
      return undefined
    }
    return entry
  }

  private expiry(ttlSeconds?: number) {
    return ttlSeconds ? this.now() + ttlSeconds * 1000 : null
  }

  async get(key: string) {
    return this.live(key)?.value ?? null
  }

  async set(key: string, value: string, ttlSeconds?: number) {
    this.data.set(key, { value, expiresAt: this.expiry(ttlSeconds) })
  }

  async del(...keys: string[]) {
    for (const k of keys) {
      this.data.delete(k)
      this.sets.delete(k)
    }
  }

  async hit(key: string, ttlSeconds: number) {
    const entry = this.live(key)
    if (!entry) {
      this.data.set(key, { value: '1', expiresAt: this.expiry(ttlSeconds) })
      return { count: 1, ttl: ttlSeconds }
    }
    entry.value = String(Number(entry.value) + 1)
    return { count: Number(entry.value), ttl: await this.ttl(key) }
  }

  async ttl(key: string) {
    const entry = this.live(key)
    if (!entry) return -2
    return entry.expiresAt === null ? -1 : Math.max(Math.ceil((entry.expiresAt - this.now()) / 1000), 1)
  }

  private liveSet(key: string) {
    const s = this.sets.get(key)
    if (s && s.expiresAt !== null && s.expiresAt <= this.now()) {
      this.sets.delete(key)
      return undefined
    }
    return s
  }

  async sadd(key: string, member: string, ttlSeconds?: number) {
    const s = this.liveSet(key) ?? { members: new Set<string>(), expiresAt: null }
    s.members.add(member)
    if (ttlSeconds) s.expiresAt = this.expiry(ttlSeconds)
    this.sets.set(key, s)
  }

  async srem(key: string, member: string) {
    this.liveSet(key)?.members.delete(member)
  }

  async smembers(key: string) {
    return [...(this.liveSet(key)?.members ?? [])]
  }

  async ping() {
    return true
  }

  async close() {}
}

/** Redis is unreachable or timing out. Surfaces to the browser as a quick 503, not a hang or a 500. */
export class StoreUnavailableError extends HttpError {
  constructor() {
    super(503, 'Sign-in is temporarily unavailable. Please try again in a moment.', 'session_store_unavailable', { 'Retry-After': '5' })
  }
}

export interface RedisOptions {
  /** How long to wait for the first connection before giving up. */
  connectTimeoutMs?: number
  /** How long any single command may take. */
  commandTimeoutMs?: number
}

export class RedisStore implements Store {
  constructor(private redis: Redis) {}

  /**
   * Connect and prove it works. Rejects if Redis can't be reached in time, so the caller can decide what to do
   * (fall back in development, refuse to start in production) instead of failing on the first user request.
   * After connecting, commands fail immediately while Redis is down (no queueing) and resume when it is back.
   */
  static async connect(url: string, opts: RedisOptions = {}): Promise<RedisStore> {
    const connectTimeout = opts.connectTimeoutMs ?? 3000
    const redis = new Redis(url, {
      lazyConnect: true,
      connectTimeout,
      commandTimeout: opts.commandTimeoutMs ?? 2000,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      retryStrategy: (attempt) => Math.min(attempt * 500, 5000),
    })
    redis.on('error', () => {}) // surfaced per command; avoids unhandled 'error' events while Redis restarts
    try {
      await redis.connect()
      await redis.ping()
    } catch (err) {
      redis.disconnect()
      throw err
    }
    return new RedisStore(redis)
  }

  private async run<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch {
      throw new StoreUnavailableError()
    }
  }

  get(key: string) {
    return this.run(() => this.redis.get(key))
  }

  set(key: string, value: string, ttlSeconds?: number) {
    return this.run(async () => {
      if (ttlSeconds) await this.redis.set(key, value, 'EX', ttlSeconds)
      else await this.redis.set(key, value)
    })
  }

  del(...keys: string[]) {
    return this.run(async () => {
      if (keys.length) await this.redis.del(...keys)
    })
  }

  hit(key: string, ttlSeconds: number) {
    return this.run(async () => {
      const count = await this.redis.incr(key)
      if (count === 1) await this.redis.expire(key, ttlSeconds)
      let ttl = await this.redis.ttl(key)
      if (ttl < 0) {
        // Lost its expiry (crash between INCR and EXPIRE): restore it so the caller is never locked out for good.
        await this.redis.expire(key, ttlSeconds)
        ttl = ttlSeconds
      }
      return { count, ttl }
    })
  }

  ttl(key: string) {
    return this.run(() => this.redis.ttl(key))
  }

  sadd(key: string, member: string, ttlSeconds?: number) {
    return this.run(async () => {
      const pipeline = this.redis.multi().sadd(key, member)
      if (ttlSeconds) pipeline.expire(key, ttlSeconds)
      await pipeline.exec()
    })
  }

  srem(key: string, member: string) {
    return this.run(async () => {
      await this.redis.srem(key, member)
    })
  }

  smembers(key: string) {
    return this.run(() => this.redis.smembers(key))
  }

  async ping() {
    try {
      return (await this.redis.ping()) === 'PONG'
    } catch {
      return false
    }
  }

  async close() {
    this.redis.disconnect()
  }
}

export interface StoreChoice {
  store: Store
  kind: 'redis' | 'memory'
  /** A message to show the developer when we ended up somewhere unexpected. */
  warning?: string
}

/**
 * Pick the session store. Redis when configured and reachable. If it is configured but down: development falls back
 * to memory with a loud warning, production refuses to start. No REDIS_URL: memory in development, refuse in production.
 */
export async function chooseStore(
  redisUrl: string | undefined,
  env: 'development' | 'test' | 'production',
  connect: (url: string) => Promise<Store> = (u) => RedisStore.connect(u),
): Promise<StoreChoice> {
  if (!redisUrl) {
    if (env === 'production') throw new Error('REDIS_URL is required in production (sessions and OTP codes must survive restarts and span instances).')
    return { store: new MemoryStore(), kind: 'memory', warning: 'REDIS_URL is not set: sessions are kept in memory, so everyone is signed out whenever the gateway restarts.' }
  }
  try {
    return { store: await connect(redisUrl), kind: 'redis' }
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err)
    if (env === 'production') throw new Error(`Cannot reach Redis at ${redactUrl(redisUrl)}: ${reason}`)
    return {
      store: new MemoryStore(),
      kind: 'memory',
      warning: `Cannot reach Redis at ${redactUrl(redisUrl)} (${reason}). Using in-memory sessions for now; start Redis (or remove REDIS_URL) and restart to silence this.`,
    }
  }
}

/** Hide any password in a connection string before it goes into a log. */
export function redactUrl(url: string): string {
  return url.replace(/(\/\/[^:@/]*:)[^@]*@/, '$1***@')
}
