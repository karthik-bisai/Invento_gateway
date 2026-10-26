import type { Redis } from 'ioredis'
import { describe, expect, it } from 'vitest'
import { loadConfig } from '../src/config.js'
import { explainSmtpError } from '../src/mail/mailer.js'
import { chooseStore, MemoryStore, redactUrl, RedisStore, StoreUnavailableError } from '../src/store.js'
import { API, bodyOf, start } from './helpers.js'

describe('choosing the session store', () => {
  const up = async () => new MemoryStore() // stands in for a Redis that connects fine
  const down = async () => {
    throw new Error('connect ECONNREFUSED 127.0.0.1:6379')
  }

  it('uses Redis when it is configured and reachable', async () => {
    const r = await chooseStore('redis://localhost:6379/1', 'development', up)
    expect(r.kind).toBe('redis')
    expect(r.warning).toBeUndefined()
  })

  it('falls back to memory in development when Redis is down, and says exactly why', async () => {
    const r = await chooseStore('redis://localhost:6379/1', 'development', down)
    expect(r.kind).toBe('memory')
    expect(r.warning).toContain('Cannot reach Redis at redis://localhost:6379/1')
    expect(r.warning).toContain('ECONNREFUSED')
    expect(r.warning).toContain('start Redis')
  })

  it('refuses to start in production when Redis is down', async () => {
    await expect(chooseStore('redis://localhost:6379/1', 'production', down)).rejects.toThrow(/Cannot reach Redis/)
  })

  it('refuses to start in production with no Redis configured at all', async () => {
    await expect(chooseStore(undefined, 'production')).rejects.toThrow(/REDIS_URL is required in production/)
  })

  it('uses memory with a warning in development when Redis is not configured', async () => {
    const r = await chooseStore(undefined, 'development')
    expect(r.kind).toBe('memory')
    expect(r.warning).toMatch(/REDIS_URL is not set/)
  })

  it('never prints a Redis password in a log line', async () => {
    expect(redactUrl('redis://default:s3cret@cache.example.com:6379/0')).toBe('redis://default:***@cache.example.com:6379/0')
    const r = await chooseStore('redis://default:s3cret@cache.example.com:6379', 'development', down)
    expect(r.warning).not.toContain('s3cret')
    await expect(chooseStore('redis://default:s3cret@cache.example.com:6379', 'production', down)).rejects.not.toThrow(/s3cret/)
  })
})

describe('Redis going away while running', () => {
  // Every command throws straight away, like ioredis with its offline queue off and no connection.
  const broken = new Proxy({}, { get: (_t, prop) => (prop === 'then' ? undefined : () => { throw new Error('Stream isn’t writeable') }) }) as unknown as Redis

  it('turns any Redis failure into one quick, readable 503 error', async () => {
    const store = new RedisStore(broken)
    await expect(store.get('k')).rejects.toBeInstanceOf(StoreUnavailableError)
    await expect(store.set('k', 'v', 5)).rejects.toMatchObject({ status: 503, code: 'session_store_unavailable' })
    await expect(store.hit('k', 5)).rejects.toBeInstanceOf(StoreUnavailableError)
    await expect(store.sadd('s', 'm', 5)).rejects.toBeInstanceOf(StoreUnavailableError)
    expect(await store.ping()).toBe(false)
  })

  it('shows the person "try again shortly", not a 500, and keeps serving everything else', async () => {
    const store = new MemoryStore()
    store.set = async () => {
      throw new StoreUnavailableError()
    }
    const h = await start({}, { store })
    const res = await h.app.inject({ method: 'POST', url: `${API}/auth/login`, payload: { email: 'admin@acme.com', password: 'AdminPass1' } })
    expect(res.statusCode).toBe(503)
    expect(res.headers['retry-after']).toBe('5')
    expect(bodyOf(res)).toEqual({ detail: 'Sign-in is temporarily unavailable. Please try again in a moment.', code: 'session_store_unavailable' })
    expect((await h.app.inject({ url: '/healthz' })).json()).toMatchObject({ upstream: 'ok' })
  })
})

describe('Gmail setup', () => {
  const gmail = { SMTP_PROVIDER: 'gmail', SMTP_USER: 'team@gmail.com', SMTP_PASS: 'abcd efgh ijkl mnop' }

  it('fills in everything Gmail needs from just a username and an app password', () => {
    const c = loadConfig(gmail)
    expect(c.smtp).toMatchObject({ provider: 'gmail', host: 'smtp.gmail.com', port: 465, secure: true, user: 'team@gmail.com' })
    expect(c.smtp.pass).toBe('abcdefghijklmnop') // Google displays app passwords in groups; the spaces aren't part of it
    expect(c.mailFrom).toBe('Invento <team@gmail.com>') // Gmail only sends as the signed-in account
  })

  it('lets explicit settings win', () => {
    const c = loadConfig({ ...gmail, SMTP_PORT: '587', SMTP_SECURE: 'false', MAIL_FROM: 'Invento Team <team@gmail.com>' })
    expect(c.smtp).toMatchObject({ port: 587, secure: false })
    expect(c.mailFrom).toBe('Invento Team <team@gmail.com>')
  })

  it('says what is missing instead of failing later', () => {
    expect(() => loadConfig({ SMTP_PROVIDER: 'gmail' })).toThrowError(/SMTP_USER[\s\S]*SMTP_PASS/)
    expect(() => loadConfig({ SMTP_HOST: 'smtp.example.com', SMTP_USER: 'u' })).toThrowError(/SMTP_PASS/)
  })

  it('counts as configured email for production', () => {
    const prod = { NODE_ENV: 'production', GATEWAY_SECRET: 'a'.repeat(32), INTERNAL_API_KEY: 'b'.repeat(24), ...gmail }
    expect(loadConfig(prod).smtp.host).toBe('smtp.gmail.com')
    expect(() => loadConfig({ ...prod, SMTP_PROVIDER: undefined, SMTP_USER: undefined, SMTP_PASS: undefined })).toThrowError(/SMTP/)
  })

  it('keeps ordinary SMTP unchanged and names the product in the default From', () => {
    const c = loadConfig({ SMTP_HOST: 'smtp.example.com' })
    expect(c.smtp).toMatchObject({ provider: undefined, host: 'smtp.example.com', port: 587, secure: false })
    expect(c.mailFrom).toBe('Invento <no-reply@invento.local>')
    expect(loadConfig({}).smtp.host).toBeUndefined() // no SMTP: emails go to the dev outbox
  })

  it('explains the usual Gmail failures in plain words', () => {
    const cfg = loadConfig(gmail)
    expect(explainSmtpError({ code: 'EAUTH', responseCode: 535 }, cfg)).toMatch(/app password/i)
    expect(explainSmtpError({ code: 'ECONNREFUSED' }, cfg)).toContain('smtp.gmail.com:465')
    expect(explainSmtpError({ code: 'ETIMEDOUT' }, cfg)).toMatch(/port 465|587/)
    expect(explainSmtpError({ code: 'EAUTH' }, loadConfig({ SMTP_HOST: 'mail.example.com' }))).not.toMatch(/Gmail/)
    expect(explainSmtpError({ message: 'weird' }, cfg)).toBe('weird')
  })
})

describe('settings left blank', () => {
  it('treats empty values (as Docker Compose passes unset options) as not set', () => {
    const c = loadConfig({
      SMTP_PROVIDER: '',
      SMTP_HOST: '',
      SMTP_PORT: '',
      SMTP_SECURE: '',
      SMTP_USER: '',
      SMTP_PASS: '',
      MAIL_FROM: '',
      S3_ENDPOINT: '',
      S3_BUCKET: '  ',
      REDIS_URL: '',
    })
    expect(c.smtp).toMatchObject({ provider: undefined, host: undefined, port: 587, secure: false })
    expect(c.mailFrom).toBe('Invento <no-reply@invento.local>')
    expect(c.redisUrl).toBeUndefined()
  })

  it('still lets a blank be overridden by a real value', () => {
    expect(loadConfig({ SMTP_PROVIDER: 'gmail', SMTP_USER: 'a@gmail.com', SMTP_PASS: 'x', SMTP_PORT: '' }).smtp.port).toBe(465)
  })

  it('accepts a production setup where only the required secrets are filled in', () => {
    const c = loadConfig({
      NODE_ENV: 'production',
      HOST: '0.0.0.0',
      PORT: '4000',
      UPSTREAM_URL: 'http://api:8000',
      INTERNAL_API_KEY: 'k'.repeat(32),
      GATEWAY_SECRET: 's'.repeat(32),
      APP_URL: 'https://invento.example.com',
      TRUST_PROXY: 'true',
      REDIS_URL: 'redis://:pw@redis:6379/1',
      SMTP_PROVIDER: 'gmail',
      SMTP_HOST: '',
      SMTP_PORT: '',
      SMTP_SECURE: '',
      SMTP_USER: 'team@gmail.com',
      SMTP_PASS: 'abcd efgh ijkl mnop',
      MAIL_FROM: '',
      STORAGE_DRIVER: 'local',
      MEDIA_PUBLIC_URL: 'https://invento.example.com/media/',
      S3_BUCKET: '',
      S3_REGION: '',
      S3_ENDPOINT: '',
      S3_ACCESS_KEY_ID: '',
      S3_SECRET_ACCESS_KEY: '',
    })
    expect(c).toMatchObject({ env: 'production', cookieSecure: true, trustProxy: true, host: '0.0.0.0' })
    expect(c.smtp).toMatchObject({ host: 'smtp.gmail.com', port: 465, secure: true })
    expect(c.mailFrom).toBe('Invento <team@gmail.com>')
  })
})
