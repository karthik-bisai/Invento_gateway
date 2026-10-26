import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import nodemailer, { type Transporter } from 'nodemailer'
import type { Config } from '../config.js'
import type { Email } from './templates.js'

export interface MailMessage extends Email {
  to: string
}

export interface Mailer {
  send(message: MailMessage): Promise<void>
  /** Prove the connection and credentials work. Rejects with a readable reason. */
  verify?(): Promise<void>
}

type Log = { info: (obj: object, msg?: string) => void; error: (obj: object, msg?: string) => void }

/** Turn a raw SMTP failure into something a person can act on. */
export function explainSmtpError(err: unknown, cfg: Pick<Config, 'smtp'>): string {
  const e = err as { code?: string; responseCode?: number; message?: string }
  const gmail = cfg.smtp.provider === 'gmail' || cfg.smtp.host === 'smtp.gmail.com'
  if (e.code === 'EAUTH' || e.responseCode === 535) {
    return gmail
      ? 'Gmail rejected the login. Use a Google app password (Google Account → Security → 2-Step Verification → App passwords), not your normal password, and make sure SMTP_USER is the same Gmail address.'
      : 'The mail server rejected the username or password.'
  }
  if (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND') return `Cannot reach ${cfg.smtp.host}:${cfg.smtp.port}. Check SMTP_HOST, SMTP_PORT and your network.`
  if (e.code === 'ETIMEDOUT' || e.code === 'ESOCKET') {
    return `Timed out talking to ${cfg.smtp.host}:${cfg.smtp.port}. For Gmail use port 465 with SMTP_SECURE=true, or 587 with SMTP_SECURE=false; some networks block both.`
  }
  return e.message ?? 'Unknown SMTP error.'
}

export class SmtpMailer implements Mailer {
  private transport: Transporter

  constructor(
    private cfg: Pick<Config, 'smtp' | 'mailFrom'>,
    private from = cfg.mailFrom,
  ) {
    this.transport = nodemailer.createTransport({
      host: cfg.smtp.host,
      port: cfg.smtp.port,
      secure: cfg.smtp.secure,
      auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: cfg.smtp.pass } : undefined,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
    })
  }

  async verify(): Promise<void> {
    try {
      await this.transport.verify()
    } catch (err) {
      throw new Error(explainSmtpError(err, this.cfg))
    }
  }

  async send(message: MailMessage): Promise<void> {
    await this.transport.sendMail({ from: this.from, to: message.to, subject: message.subject, text: message.text, html: message.html })
  }
}

/**
 * Local development without an SMTP server: nothing leaves the machine. Each email is printed to the console
 * and saved as a JSON file so the OTP code can be copied from there.
 */
export class DevMailer implements Mailer {
  constructor(
    private dir: string,
    private log: Log,
  ) {}

  async send(message: MailMessage): Promise<void> {
    await mkdir(this.dir, { recursive: true })
    const file = path.join(this.dir, `${Date.now()}-${message.to.replace(/[^a-z0-9@._-]/gi, '_')}.json`)
    await writeFile(file, JSON.stringify(message, null, 2), 'utf8')
    this.log.info({ to: message.to, file }, `[dev mail] ${message.subject}\n${message.text}`)
  }
}

export function createMailer(cfg: Config, log: Log): Mailer {
  return cfg.smtp.host ? new SmtpMailer(cfg) : new DevMailer(path.resolve('.dev-mail'), log)
}
