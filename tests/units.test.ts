import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { DeleteObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3'
import { afterEach, describe, expect, it } from 'vitest'
import { loadConfig } from '../src/config.js'
import { accessApprovedEmail, accessRejectedEmail, accessRequestedEmail, escapeHtml, otpEmail } from '../src/mail/templates.js'
import { LocalStorage, S3Storage, sniffImage } from '../src/storage/index.js'
import { keyFromUrl } from '../src/storage/keys.js'
import { MemoryStore } from '../src/store.js'
import { PNG, JPEG, WEBP } from './helpers.js'

describe('configuration', () => {
  it('runs with safe development defaults', () => {
    const c = loadConfig({})
    expect(c).toMatchObject({ env: 'development', port: 4000, host: '127.0.0.1', cookieSecure: false, trustProxy: false })
    expect(c.corsOrigins).toEqual(['http://localhost:5173'])
    expect(c.storage.mediaPublicUrl).toBe('http://localhost:4000/media/')
  })

  it('refuses to start in production with default secrets, no SMTP or insecure cookies, and lists every problem', () => {
    expect(() => loadConfig({ NODE_ENV: 'production' })).toThrowError(/GATEWAY_SECRET[\s\S]*INTERNAL_API_KEY[\s\S]*SMTP_HOST/)
    const ok = { NODE_ENV: 'production', GATEWAY_SECRET: 'a'.repeat(32), INTERNAL_API_KEY: 'b'.repeat(24), SMTP_HOST: 'smtp.example.com' }
    expect(loadConfig(ok).cookieSecure).toBe(true) // secure by default in production
    expect(() => loadConfig({ ...ok, COOKIE_SECURE: 'false' })).toThrowError(/COOKIE_SECURE/)
  })

  it('requires bucket details for S3', () => {
    expect(() => loadConfig({ STORAGE_DRIVER: 's3' })).toThrowError(/S3_BUCKET[\s\S]*S3_REGION/)
    expect(loadConfig({ STORAGE_DRIVER: 's3', S3_BUCKET: 'b', S3_REGION: 'eu-west-1' }).storage.s3.keyPrefix).toBe('avatars/')
  })

  it('normalises URLs and lists', () => {
    const c = loadConfig({ UPSTREAM_URL: 'http://api:8000/', APP_URL: 'https://app.example.com/', CORS_ORIGINS: 'https://a.test/, https://b.test', MEDIA_PUBLIC_URL: 'https://cdn.example.com/files', S3_KEY_PREFIX: '/pics' })
    expect(c.upstreamUrl).toBe('http://api:8000')
    expect(c.appUrl).toBe('https://app.example.com')
    expect(c.corsOrigins).toEqual(['https://a.test', 'https://b.test'])
    expect(c.storage.mediaPublicUrl).toBe('https://cdn.example.com/files/')
    expect(c.storage.s3.keyPrefix).toBe('pics/')
  })

  it('rejects nonsense values', () => {
    expect(() => loadConfig({ PORT: 'abc' })).toThrowError(/PORT/)
    expect(() => loadConfig({ UPSTREAM_URL: 'not a url' })).toThrowError(/UPSTREAM_URL/)
    expect(() => loadConfig({ GATEWAY_SECRET: 'short' })).toThrowError(/GATEWAY_SECRET/)
  })
})

describe('memory store', () => {
  it('expires keys and counts hits inside a window', async () => {
    let now = 0
    const s = new MemoryStore(() => now)
    await s.set('k', 'v', 10)
    expect(await s.get('k')).toBe('v')
    now += 11_000
    expect(await s.get('k')).toBeNull()

    expect((await s.hit('h', 60)).count).toBe(1)
    expect((await s.hit('h', 60)).count).toBe(2)
    now += 61_000
    expect((await s.hit('h', 60)).count).toBe(1) // a new window
  })

  it('reports ttl and manages sets', async () => {
    let now = 0
    const s = new MemoryStore(() => now)
    expect(await s.ttl('missing')).toBe(-2)
    await s.set('forever', '1')
    expect(await s.ttl('forever')).toBe(-1)
    await s.sadd('set', 'a', 5)
    await s.sadd('set', 'b')
    expect((await s.smembers('set')).sort()).toEqual(['a', 'b'])
    await s.srem('set', 'a')
    expect(await s.smembers('set')).toEqual(['b'])
    now += 10_000
    expect(await s.smembers('set')).toEqual([])
  })
})

describe('image sniffing', () => {
  it('recognises PNG, JPEG and WebP by their bytes', () => {
    expect(sniffImage(PNG)).toEqual({ ext: 'png', contentType: 'image/png' })
    expect(sniffImage(JPEG)).toEqual({ ext: 'jpg', contentType: 'image/jpeg' })
    expect(sniffImage(WEBP)).toEqual({ ext: 'webp', contentType: 'image/webp' })
  })

  it('refuses everything else, including truncated headers', () => {
    for (const buf of [Buffer.alloc(0), Buffer.from('GIF89a......'), Buffer.from('<svg></svg>'), PNG.subarray(0, 5), Buffer.from('RIFF....WAVE....')]) {
      expect(sniffImage(buf)).toBeNull()
    }
  })
})

describe('storage keys', () => {
  const base = 'http://localhost:4000/media/'
  it('extracts keys only from our own URLs under the right prefix', () => {
    expect(keyFromUrl(`${base}avatars/a.png`, base, 'avatars/')).toBe('avatars/a.png')
    expect(keyFromUrl('https://evil.example/avatars/a.png', base, 'avatars/')).toBeNull()
    expect(keyFromUrl(`${base}other/a.png`, base, 'avatars/')).toBeNull()
  })

  it('refuses traversal tricks', () => {
    for (const tail of ['avatars/../secret', 'avatars/..%2f', 'avatars\\a.png', 'avatars//a.png']) {
      expect(keyFromUrl(`${base}${tail}`, base, 'avatars/'), tail).toBeNull()
    }
  })
})

describe('local storage', () => {
  let dir: string | undefined
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
    dir = undefined
  })

  it('writes, returns a public URL and deletes by URL', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'gw-local-'))
    const s = new LocalStorage(dir, 'http://localhost:4000/media/')
    const url = await s.put('avatars/u1.png', PNG)
    expect(url).toBe('http://localhost:4000/media/avatars/u1.png')
    expect((await readFile(path.join(dir, 'avatars/u1.png'))).equals(PNG)).toBe(true)
    await s.deleteByUrl(url)
    await expect(stat(path.join(dir, 'avatars/u1.png'))).rejects.toThrow()
    await expect(s.deleteByUrl(url)).resolves.toBeUndefined() // already gone is fine
  })

  it('will not write outside its directory or delete foreign files', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'gw-local-'))
    const s = new LocalStorage(dir, 'http://localhost:4000/media/')
    await expect(s.put('../escape.png', PNG)).rejects.toThrow(/outside/)
    const outside = path.join(path.dirname(dir), 'keep-me.txt')
    await writeFile(outside, 'x')
    await s.deleteByUrl('http://localhost:4000/media/avatars/../../keep-me.txt')
    await s.deleteByUrl('https://other.example/media/avatars/a.png')
    expect((await stat(outside)).isFile()).toBe(true)
    await rm(outside)
  })
})

describe('S3 storage', () => {
  const make = () => {
    const sent: (PutObjectCommand | DeleteObjectCommand)[] = []
    const storage = new S3Storage({ send: async (c) => void sent.push(c) }, 'my-bucket', 'https://cdn.example.com/', 'avatars/')
    return { sent, storage }
  }

  it('uploads with the right type and long-lived caching, and returns the CDN URL', async () => {
    const { sent, storage } = make()
    const url = await storage.put('avatars/u1-abc.webp', WEBP, 'image/webp')
    expect(url).toBe('https://cdn.example.com/avatars/u1-abc.webp')
    const cmd = sent[0] as PutObjectCommand
    expect(cmd).toBeInstanceOf(PutObjectCommand)
    expect(cmd.input).toMatchObject({ Bucket: 'my-bucket', Key: 'avatars/u1-abc.webp', ContentType: 'image/webp', Body: WEBP })
    expect(cmd.input.CacheControl).toContain('immutable')
    expect(cmd.input.ACL).toBeUndefined() // access is the bucket policy's job, not per-object ACLs
  })

  it('deletes only objects under its own URL and prefix', async () => {
    const { sent, storage } = make()
    await storage.deleteByUrl('https://cdn.example.com/avatars/u1-abc.webp')
    await storage.deleteByUrl('https://evil.example/avatars/u1.png')
    await storage.deleteByUrl('https://cdn.example.com/private/report.pdf')
    await storage.deleteByUrl('https://cdn.example.com/avatars/../private/report.pdf')
    expect(sent).toHaveLength(1)
    expect((sent[0] as DeleteObjectCommand).input).toEqual({ Bucket: 'my-bucket', Key: 'avatars/u1-abc.webp' })
  })

  it('builds from config, honouring a custom endpoint and key prefix', () => {
    const cfg = loadConfig({ STORAGE_DRIVER: 's3', S3_BUCKET: 'b', S3_REGION: 'auto', S3_ENDPOINT: 'https://acct.r2.cloudflarestorage.com', S3_FORCE_PATH_STYLE: 'true', MEDIA_PUBLIC_URL: 'https://media.example.com', S3_KEY_PREFIX: 'profile-pics' })
    expect(S3Storage.fromConfig(cfg)).toBeInstanceOf(S3Storage)
    expect(cfg.storage.s3.keyPrefix).toBe('profile-pics/')
  })
})

describe('email templates', () => {
  it('escapes anything a user typed', () => {
    expect(escapeHtml(`<img src=x onerror="alert('1')">&`)).toBe('&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt;&amp;')
    const mail = accessRequestedEmail('Ada', { email: 'a@b.co', name: '<script>alert(1)</script>' }, 'https://app.example.com')
    expect(mail.html).not.toContain('<script>')
    expect(mail.html).toContain('&lt;script&gt;')
    const rejected = accessRejectedEmail('<i>Bob</i>', null)
    expect(rejected.html).not.toContain('<i>Bob</i>')
  })

  it('does not put the code in the subject, puts it in the body with its lifetime', () => {
    const mail = otpEmail('042917', 10)
    expect(mail.subject).not.toContain('042917')
    expect(mail.subject).toContain('Verify Your Email Address')
    expect(mail.text).toContain('042917')
    expect(mail.text).toContain('10 minutes')
    expect(mail.html).toContain('042917')
  })

  it('links back into the app', () => {
    expect(accessApprovedEmail('Nia', 'https://app.example.com').html).toContain('https://app.example.com/login')
    expect(accessRequestedEmail(null, { email: 'a@b.co', name: null }, 'https://app.example.com').text).toContain('https://app.example.com/users?tab=requests')
  })

  it('stays usable when a name is missing', () => {
    expect(accessApprovedEmail(null, 'https://x.test').text.startsWith('An administrator')).toBe(true)
    expect(accessRejectedEmail(null, 'No capacity').text).toContain('Reason: No capacity')
  })
})
