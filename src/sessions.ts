import { randomToken, sha256 } from './crypto.js'
import type { Store } from './store.js'

export interface SessionData {
  userId: string
  ip: string
  userAgent: string
  createdAt: number
  lastSeen: number
}

export interface SessionInfo extends SessionData {
  /** Opaque public handle (a hash of the session id): safe to show, can't be used to sign in. */
  handle: string
  current: boolean
}

interface Options {
  idleSeconds: number
  maxSeconds: number
  now?: () => number
}

const TOUCH_AFTER_MS = 60_000 // don't rewrite the session on every request

/**
 * Server-side sessions. The browser holds only a random id in an HTTP-only cookie; everything else lives
 * in the store under a hash of that id. Deleting the record signs the device out immediately.
 */
export class Sessions {
  private now: () => number

  constructor(
    private store: Store,
    private opts: Options,
  ) {
    this.now = opts.now ?? Date.now
  }

  private key = (handle: string) => `sess:${handle}`
  private userKey = (userId: string) => `user-sessions:${userId}`

  static handleFor(id: string) {
    return sha256(id)
  }

  async create(userId: string, meta: { ip: string; userAgent: string }): Promise<{ id: string; handle: string }> {
    const id = randomToken(32)
    const handle = Sessions.handleFor(id)
    const now = this.now()
    const data: SessionData = { userId, ip: meta.ip, userAgent: meta.userAgent.slice(0, 300), createdAt: now, lastSeen: now }
    await this.store.set(this.key(handle), JSON.stringify(data), this.opts.idleSeconds)
    await this.store.sadd(this.userKey(userId), handle, this.opts.maxSeconds)
    return { id, handle }
  }

  async get(id: string): Promise<(SessionData & { handle: string }) | null> {
    const handle = Sessions.handleFor(id)
    const raw = await this.store.get(this.key(handle))
    if (!raw) return null
    const data = JSON.parse(raw) as SessionData
    const now = this.now()
    if (now - data.createdAt > this.opts.maxSeconds * 1000) {
      await this.destroyHandle(data.userId, handle)
      return null
    }
    if (now - data.lastSeen > TOUCH_AFTER_MS) {
      data.lastSeen = now
      await this.store.set(this.key(handle), JSON.stringify(data), this.opts.idleSeconds) // slide the idle window
    }
    return { ...data, handle }
  }

  async destroy(id: string): Promise<void> {
    const handle = Sessions.handleFor(id)
    const raw = await this.store.get(this.key(handle))
    await this.store.del(this.key(handle))
    if (raw) await this.store.srem(this.userKey((JSON.parse(raw) as SessionData).userId), handle)
  }

  async destroyHandle(userId: string, handle: string): Promise<boolean> {
    const members = await this.store.smembers(this.userKey(userId))
    if (!members.includes(handle)) return false
    await this.store.del(this.key(handle))
    await this.store.srem(this.userKey(userId), handle)
    return true
  }

  /** Sign a user out everywhere, optionally keeping one device. Returns how many were ended. */
  async destroyAllForUser(userId: string, exceptHandle?: string): Promise<number> {
    let ended = 0
    for (const handle of await this.store.smembers(this.userKey(userId))) {
      if (handle === exceptHandle) continue
      await this.store.del(this.key(handle))
      await this.store.srem(this.userKey(userId), handle)
      ended++
    }
    return ended
  }

  async listForUser(userId: string, currentHandle?: string): Promise<SessionInfo[]> {
    const out: SessionInfo[] = []
    for (const handle of await this.store.smembers(this.userKey(userId))) {
      const raw = await this.store.get(this.key(handle))
      if (!raw) {
        await this.store.srem(this.userKey(userId), handle) // expired: tidy the index
        continue
      }
      out.push({ ...(JSON.parse(raw) as SessionData), handle, current: handle === currentHandle })
    }
    return out.sort((a, b) => b.lastSeen - a.lastSeen)
  }
}
