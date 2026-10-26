import { existsSync } from 'node:fs'
import { buildApp } from './app.js'
import { loadConfig } from './config.js'
import { createMailer } from './mail/mailer.js'
import { createStorage } from './storage/index.js'
import { chooseStore } from './store.js'
import { Upstream } from './upstream.js'

// Read gateway/.env if there is one. Real environment variables win over the file, so deployments can override it.
if (existsSync('.env')) process.loadEnvFile('.env')

const config = loadConfig()

let choice
try {
  choice = await chooseStore(config.redisUrl, config.env)
} catch (err) {
  console.error(`\nInvento gateway cannot start: ${err instanceof Error ? err.message : err}\n`)
  process.exit(1)
}
const { store, kind, warning } = choice

const mailer = createMailer(config, console)

const app = await buildApp({
  config,
  store,
  upstream: new Upstream(config),
  storage: createStorage(config),
  mailer,
  logger: {
    level: 'info',
    // Readable one-line logs while developing; structured JSON in production for log collectors.
    transport: config.env === 'production' ? undefined : { target: 'pino-pretty', options: { translateTime: 'HH:MM:ss', ignore: 'pid,hostname' } },
    redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
  },
})

const shutdown = async (signal: string) => {
  app.log.info({ signal }, 'shutting down')
  await app.close()
  await store.close()
  process.exit(0)
}
process.on('SIGINT', () => void shutdown('SIGINT'))
process.on('SIGTERM', () => void shutdown('SIGTERM'))

await app.listen({ host: config.host, port: config.port })

app.log.info({ api: config.upstreamUrl, app: config.appUrl, sessions: kind }, `Invento gateway listening on http://${config.host}:${config.port}`)
if (warning) app.log.warn(warning)

// Check email in the background so a slow or wrong SMTP login is reported at startup, not when the first person signs up.
if (mailer.verify) {
  mailer.verify().then(
    () => app.log.info(`SMTP ready (${config.smtp.host}:${config.smtp.port} as ${config.smtp.user ?? 'anonymous'})`),
    (err) => app.log.error(`SMTP is not working, so sign-in codes and notifications will fail: ${err instanceof Error ? err.message : err}`),
  )
} else {
  app.log.warn('No SMTP configured: emails are printed here and saved under .dev-mail/ instead of being sent. Set SMTP_PROVIDER=gmail (or SMTP_HOST) in gateway/.env to send real email.')
}
