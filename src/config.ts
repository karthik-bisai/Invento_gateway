import { z } from 'zod'

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1')

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    HOST: z.string().default('127.0.0.1'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),

    UPSTREAM_URL: z.string().url().default('http://localhost:8000'),
    UPSTREAM_API_PREFIX: z.string().default('/api/v1'),
    /** Shared with FastAPI (INTERNAL_API_KEY). Lets the gateway ask it for service tokens and signup state. */
    INTERNAL_API_KEY: z.string().min(8).default('dev-internal-key'),
    /** Signs OTP hashes and CSRF tokens. Independent of FastAPI's JWT secret. */
    GATEWAY_SECRET: z.string().min(16).default('dev-gateway-secret-change-me'),

    /** Where the browser app lives: used for CORS and for links in emails. */
    APP_URL: z.string().url().default('http://localhost:5173'),
    CORS_ORIGINS: z.string().optional(),
    COOKIE_SECURE: bool.optional(),
    COOKIE_DOMAIN: z.string().optional(),
    /** Honour X-Forwarded-For. Only behind a proxy you control. */
    TRUST_PROXY: bool.default(false),

    REDIS_URL: z.string().optional(),

    SESSION_IDLE_HOURS: z.coerce.number().positive().default(168),
    SESSION_MAX_DAYS: z.coerce.number().positive().default(30),

    OTP_TTL_MINUTES: z.coerce.number().positive().default(10),
    OTP_MAX_ATTEMPTS: z.coerce.number().int().positive().default(5),
    OTP_RESEND_SECONDS: z.coerce.number().int().positive().default(60),
    OTP_MAX_PER_HOUR: z.coerce.number().int().positive().default(5),

    /** `gmail` fills in smtp.gmail.com on port 465 with TLS. You only add SMTP_USER and an app password. */
    SMTP_PROVIDER: z.enum(['gmail']).optional(),
    SMTP_HOST: z.string().optional(),
    SMTP_PORT: z.coerce.number().int().optional(),
    SMTP_SECURE: bool.optional(),
    SMTP_USER: z.string().optional(),
    SMTP_PASS: z.string().optional(),
    MAIL_FROM: z.string().optional(),

    STORAGE_DRIVER: z.enum(['local', 's3']).default('local'),
    MEDIA_DIR: z.string().default('./uploads'),
    /** Public base URL of stored files. Must match FastAPI's MEDIA_PUBLIC_URL. */
    MEDIA_PUBLIC_URL: z.string().url().default('http://localhost:4000/media/'),
    S3_BUCKET: z.string().optional(),
    S3_REGION: z.string().optional(),
    S3_ENDPOINT: z.string().url().optional(),
    S3_FORCE_PATH_STYLE: bool.default(false),
    S3_ACCESS_KEY_ID: z.string().optional(),
    S3_SECRET_ACCESS_KEY: z.string().optional(),
    S3_KEY_PREFIX: z.string().default('avatars/'),
    AVATAR_MAX_BYTES: z.coerce.number().int().positive().default(2 * 1024 * 1024),
  })
  .superRefine((env, ctx) => {
    const need = (ok: boolean, path: string, message: string) => ok || ctx.addIssue({ code: 'custom', path: [path], message })
    if (env.NODE_ENV === 'production') {
      need(env.GATEWAY_SECRET !== 'dev-gateway-secret-change-me', 'GATEWAY_SECRET', 'Set a real secret in production')
      need(env.INTERNAL_API_KEY !== 'dev-internal-key', 'INTERNAL_API_KEY', 'Set a real key in production')
      need(!!(env.SMTP_HOST || env.SMTP_PROVIDER), 'SMTP_HOST', 'Production needs SMTP (or SMTP_PROVIDER=gmail) to deliver sign-in codes')
      need(env.COOKIE_SECURE !== false, 'COOKIE_SECURE', 'Session cookies must be Secure in production')
    }
    if (env.SMTP_USER) need(!!env.SMTP_PASS, 'SMTP_PASS', 'SMTP_USER is set but SMTP_PASS is empty')
    if (env.SMTP_PROVIDER === 'gmail') {
      need(!!env.SMTP_USER, 'SMTP_USER', 'Set your Gmail address for SMTP_PROVIDER=gmail')
      need(!!env.SMTP_PASS, 'SMTP_PASS', 'Set a Google app password for SMTP_PROVIDER=gmail (your normal password will not work)')
    }
    if (env.STORAGE_DRIVER === 's3') {
      need(!!env.S3_BUCKET, 'S3_BUCKET', 'Required for STORAGE_DRIVER=s3')
      need(!!env.S3_REGION, 'S3_REGION', 'Required for STORAGE_DRIVER=s3')
    }
  })

export interface Config {
  env: 'development' | 'test' | 'production'
  host: string
  port: number
  upstreamUrl: string
  upstreamApiPrefix: string
  internalApiKey: string
  gatewaySecret: string
  appUrl: string
  corsOrigins: string[]
  cookieSecure: boolean
  cookieDomain: string | undefined
  trustProxy: boolean
  redisUrl: string | undefined
  sessionIdleSeconds: number
  sessionMaxSeconds: number
  otp: { ttlSeconds: number; maxAttempts: number; resendSeconds: number; maxPerHour: number }
  smtp: { provider: 'gmail' | undefined; host: string | undefined; port: number; secure: boolean; user: string | undefined; pass: string | undefined }
  mailFrom: string
  storage: {
    driver: 'local' | 's3'
    mediaDir: string
    mediaPublicUrl: string
    maxBytes: number
    s3: {
      bucket: string | undefined
      region: string | undefined
      endpoint: string | undefined
      forcePathStyle: boolean
      accessKeyId: string | undefined
      secretAccessKey: string | undefined
      keyPrefix: string
    }
  }
}

type Env = z.infer<typeof schema>

function smtp(e: Env): Config['smtp'] {
  const gmail = e.SMTP_PROVIDER === 'gmail'
  return {
    provider: e.SMTP_PROVIDER,
    host: e.SMTP_HOST ?? (gmail ? 'smtp.gmail.com' : undefined),
    port: e.SMTP_PORT ?? (gmail ? 465 : 587),
    secure: e.SMTP_SECURE ?? gmail, // port 465 is TLS from the first byte
    user: e.SMTP_USER,
    // Google shows app passwords in four groups with spaces ("abcd efgh ijkl mnop"); the spaces aren't part of it.
    pass: gmail ? e.SMTP_PASS?.replace(/\s+/g, '') : e.SMTP_PASS,
  }
}

/** Parse and validate the environment once, failing fast with every problem listed. */
export function loadConfig(source: Record<string, string | undefined> = process.env): Config {
  // Docker Compose and some hosts pass settings you didn't fill in as empty strings: those mean "not set", not "".
  const set = Object.fromEntries(Object.entries(source).filter(([, v]) => v !== undefined && v.trim() !== ''))
  const parsed = schema.safeParse(set)
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n')
    throw new Error(`Invalid gateway configuration:\n${problems}`)
  }
  const e = parsed.data
  const base = (u: string) => (u.endsWith('/') ? u : `${u}/`)
  return {
    env: e.NODE_ENV,
    host: e.HOST,
    port: e.PORT,
    upstreamUrl: e.UPSTREAM_URL.replace(/\/$/, ''),
    upstreamApiPrefix: e.UPSTREAM_API_PREFIX.replace(/\/$/, ''),
    internalApiKey: e.INTERNAL_API_KEY,
    gatewaySecret: e.GATEWAY_SECRET,
    appUrl: e.APP_URL.replace(/\/$/, ''),
    corsOrigins: (e.CORS_ORIGINS ?? e.APP_URL).split(',').map((o) => o.trim().replace(/\/$/, '')).filter(Boolean),
    cookieSecure: e.COOKIE_SECURE ?? e.NODE_ENV === 'production',
    cookieDomain: e.COOKIE_DOMAIN,
    trustProxy: e.TRUST_PROXY,
    redisUrl: e.REDIS_URL,
    sessionIdleSeconds: Math.round(e.SESSION_IDLE_HOURS * 3600),
    sessionMaxSeconds: Math.round(e.SESSION_MAX_DAYS * 86400),
    otp: {
      ttlSeconds: Math.round(e.OTP_TTL_MINUTES * 60),
      maxAttempts: e.OTP_MAX_ATTEMPTS,
      resendSeconds: e.OTP_RESEND_SECONDS,
      maxPerHour: e.OTP_MAX_PER_HOUR,
    },
    smtp: smtp(e),
    // Gmail only ever sends as the signed-in account, so default the From address to it.
    mailFrom: e.MAIL_FROM ?? (e.SMTP_USER ? `Invento <${e.SMTP_USER}>` : 'Invento <no-reply@invento.local>'),
    storage: {
      driver: e.STORAGE_DRIVER,
      mediaDir: e.MEDIA_DIR,
      mediaPublicUrl: base(e.MEDIA_PUBLIC_URL),
      maxBytes: e.AVATAR_MAX_BYTES,
      s3: {
        bucket: e.S3_BUCKET,
        region: e.S3_REGION,
        endpoint: e.S3_ENDPOINT,
        forcePathStyle: e.S3_FORCE_PATH_STYLE,
        accessKeyId: e.S3_ACCESS_KEY_ID,
        secretAccessKey: e.S3_SECRET_ACCESS_KEY,
        keyPrefix: e.S3_KEY_PREFIX.replace(/^\/+/, '').replace(/\/?$/, '/'),
      },
    },
  }
}
