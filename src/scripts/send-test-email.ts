/**
 * Prove your email settings work: `npm run mail:test -- you@example.com`
 * Reads gateway/.env, checks the SMTP login, then sends one real message.
 */
import { existsSync } from 'node:fs'
import { loadConfig } from '../config.js'
import { createMailer } from '../mail/mailer.js'
import { testEmail } from '../mail/templates.js'

if (existsSync('.env')) process.loadEnvFile('.env')

const to = process.argv[2]
if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
  console.error('Usage: npm run mail:test -- you@example.com')
  process.exit(2)
}

const config = loadConfig()
const mailer = createMailer(config, console)

if (!mailer.verify) {
  console.error('No SMTP is configured, so there is nothing to test.\nSet SMTP_PROVIDER=gmail, SMTP_USER and SMTP_PASS (or SMTP_HOST) in gateway/.env and try again.')
  process.exit(1)
}

try {
  console.log(`Connecting to ${config.smtp.host}:${config.smtp.port} as ${config.smtp.user ?? 'anonymous'}…`)
  await mailer.verify()
  console.log('Login accepted. Sending a test message…')
  await mailer.send({ to, ...testEmail() })
  console.log(`Sent to ${to} from ${config.mailFrom}. Check the inbox (and spam) for "Invento email is working".`)
} catch (err) {
  console.error(`\nFailed: ${err instanceof Error ? err.message : err}`)
  process.exit(1)
}
