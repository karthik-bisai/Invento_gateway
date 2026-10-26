export interface Email {
  subject: string
  text: string
  html: string
}

export const BRAND = 'Invento'

export const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

const ACCENT = '#0e7c66'

function layout(opts: { preheader: string; title: string; paragraphs: string[]; action?: { label: string; url: string }; footer?: string }): string {
  const body = opts.paragraphs.map((p) => `<p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#2b302d">${p}</p>`).join('')
  const button = opts.action
    ? `<p style="margin:24px 0 8px"><a href="${escapeHtml(opts.action.url)}" style="display:inline-block;background:${ACCENT};color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;padding:11px 20px;border-radius:10px">${escapeHtml(opts.action.label)}</a></p>`
    : ''
  return `<!doctype html><html><body style="margin:0;background:#f3f4f2;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif">
<span style="display:none;max-height:0;overflow:hidden;opacity:0">${escapeHtml(opts.preheader)}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border:1px solid #e6e8e4;border-radius:14px">
<tr><td style="padding:28px 28px 8px"><div style="font-weight:700;font-size:15px;color:${ACCENT}">${BRAND}</div>
<h1 style="margin:18px 0 14px;font-size:22px;line-height:1.25;color:#101312;font-weight:600">${escapeHtml(opts.title)}</h1>${body}${button}</td></tr>
<tr><td style="padding:16px 28px 24px;font-size:12px;line-height:1.5;color:#747b76;border-top:1px solid #e6e8e4">${opts.footer ?? `You received this because of activity on your ${BRAND} account.`}</td></tr>
</table></td></tr></table></body></html>`
}

const greeting = (name: string | null | undefined) => (name ? `Hi ${escapeHtml(name)},` : 'Hi,')

const codeBox = (code: string) =>
  `<span style="display:inline-block;font-size:32px;letter-spacing:8px;font-weight:700;color:#101312;background:#f3f4f2;border-radius:10px;padding:12px 18px">${escapeHtml(code)}</span>`

export function otpEmail(code: string, ttlMinutes: number): Email {
  return {
    subject: `${code} is your ${BRAND} verification code`,
    text: `Your verification code is ${code}.\n\nIt expires in ${ttlMinutes} minutes. If you didn't create an account, you can ignore this email.`,
    html: layout({
      preheader: `Your code is ${code}`,
      title: 'Confirm your email',
      paragraphs: ['Enter this code to finish creating your account:', codeBox(code), `It expires in ${ttlMinutes} minutes. If you didn't create an account, you can ignore this email.`],
    }),
  }
}

export function loginCodeEmail(code: string, ttlMinutes: number, name: string | null): Email {
  return {
    subject: `${code} is your ${BRAND} sign-in code`,
    text: `${name ? `Hi ${name},\n\n` : ''}Your sign-in code is ${code}.\n\nIt expires in ${ttlMinutes} minutes and works once. If you didn't ask to sign in, ignore this email: nobody can sign in without the code.`,
    html: layout({
      preheader: `Your sign-in code is ${code}`,
      title: 'Your sign-in code',
      paragraphs: [greeting(name), 'Enter this code to sign in:', codeBox(code), `It expires in ${ttlMinutes} minutes and works once. If you didn’t ask to sign in, ignore this email: nobody can sign in without the code.`],
    }),
  }
}

export function resetCodeEmail(code: string, ttlMinutes: number, name: string | null): Email {
  return {
    subject: `${code} is your ${BRAND} password reset code`,
    text: `${name ? `Hi ${name},\n\n` : ''}Your password reset code is ${code}.\n\nIt expires in ${ttlMinutes} minutes. If you didn't ask to reset your password, ignore this email and your password stays as it is.`,
    html: layout({
      preheader: `Your reset code is ${code}`,
      title: 'Reset your password',
      paragraphs: [greeting(name), 'Enter this code to choose a new password:', codeBox(code), `It expires in ${ttlMinutes} minutes. If you didn’t ask to reset your password, ignore this email and your password stays as it is.`],
    }),
  }
}

export function requestReceivedEmail(name: string | null, appUrl: string): Email {
  return {
    subject: 'We received your access request',
    text: `${name ? `Hi ${name},\n\n` : ''}Your email is confirmed and your request is with an administrator. We'll email you as soon as they decide.\n\n${appUrl}/signup/pending`,
    html: layout({
      preheader: 'An administrator will review it shortly.',
      title: 'Your request is in',
      paragraphs: [greeting(name), 'Your email is confirmed and your access request is with an administrator. We’ll email you as soon as they decide.'],
      action: { label: 'Check request status', url: `${appUrl}/signup/pending` },
    }),
  }
}

export function accessRequestedEmail(adminName: string | null, applicant: { email: string; name: string | null }, appUrl: string): Email {
  const who = applicant.name ? `${applicant.name} (${applicant.email})` : applicant.email
  return {
    subject: `Access request from ${applicant.name ?? applicant.email}`,
    text: `${adminName ? `Hi ${adminName},\n\n` : ''}${who} confirmed their email and is asking for access.\n\nReview it: ${appUrl}/users?tab=requests`,
    html: layout({
      preheader: `${who} is asking for access`,
      title: 'New access request',
      paragraphs: [greeting(adminName), `<strong>${escapeHtml(who)}</strong> confirmed their email and is asking for access.`],
      action: { label: 'Review request', url: `${appUrl}/users?tab=requests` },
      footer: 'You get this because you’re an administrator. You can turn these emails off under Settings → Notifications.',
    }),
  }
}

export function accessApprovedEmail(name: string | null, appUrl: string): Email {
  return {
    subject: `Your ${BRAND} access is approved`,
    text: `${name ? `Hi ${name},\n\n` : ''}An administrator approved your request. You can sign in now:\n\n${appUrl}/login`,
    html: layout({
      preheader: 'You can sign in now.',
      title: 'You’re in',
      paragraphs: [greeting(name), 'An administrator approved your request. You can sign in with the email and password you chose.'],
      action: { label: 'Sign in', url: `${appUrl}/login` },
    }),
  }
}

export function accessRejectedEmail(name: string | null, note: string | null): Email {
  return {
    subject: `Your ${BRAND} access request was declined`,
    text: `${name ? `Hi ${name},\n\n` : ''}An administrator declined your access request.${note ? `\n\nReason: ${note}` : ''}\n\nIf you think this is a mistake, contact your administrator.`,
    html: layout({
      preheader: 'Your access request was declined.',
      title: 'Request declined',
      paragraphs: [
        greeting(name),
        'An administrator declined your access request.',
        ...(note ? [`<em style="color:#565d58">“${escapeHtml(note)}”</em>`] : []),
        'If you think this is a mistake, contact your administrator.',
      ],
    }),
  }
}

export function passwordChangedEmail(name: string | null, appUrl: string): Email {
  return {
    subject: `Your ${BRAND} password was changed`,
    text: `${name ? `Hi ${name},\n\n` : ''}Your password was just changed and every other device was signed out. If this wasn't you, contact an administrator right away.\n\n${appUrl}/login`,
    html: layout({
      preheader: 'Every other device was signed out.',
      title: 'Password changed',
      paragraphs: [greeting(name), 'Your password was just changed and every other device was signed out.', 'If this wasn’t you, contact an administrator right away.'],
    }),
  }
}

export function testEmail(): Email {
  return {
    subject: `${BRAND} email is working`,
    text: `This is a test message from your ${BRAND} gateway. If you can read it, sign-in codes and notifications will reach people.`,
    html: layout({
      preheader: 'Your email settings work.',
      title: 'Email is working',
      paragraphs: [`This is a test message from your ${BRAND} gateway. If you can read it, sign-in codes and notifications will reach people.`],
    }),
  }
}
