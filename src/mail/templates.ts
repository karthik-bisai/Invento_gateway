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
    subject: `Verify Your Email Address – verification code – ${BRAND}`,
    text: `Hi,\n\nThank you for registering with ${BRAND}. Please use the verification code below to confirm your email address and activate your account.\n\nVerification Code: ${code}\n\nThis code expires in ${ttlMinutes} minutes. For security, do not share this code with anyone.\n\nIf you did not register for an account, please ignore this email.\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'Your verification code is ready.',
      title: 'Verify Your Email Address',
      paragraphs: [
        'Hi,',
        `Thank you for registering with ${BRAND}. Please enter the verification code below to verify your email address:`,
        codeBox(code),
        `This code will expire in ${ttlMinutes} minutes. For your security, do not share this code with anyone.`,
        'If you did not create an account, you can safely ignore this email.',
      ],
      footer: `— The ${BRAND} Team`,
    }),
  }
}

export function loginCodeEmail(code: string, ttlMinutes: number, name: string | null): Email {
  return {
    subject: `Sign-In Code – ${BRAND}`,
    text: `${name ? `Hi ${name},\n\n` : 'Hi,\n\n'}We received a request to sign in to your ${BRAND} account using a one-time code.\n\nYour sign-in code: ${code}\n\nThis code expires in ${ttlMinutes} minutes and works once. If you did not ask to sign in, ignore this email: nobody can sign in without this code.\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'Your one-time sign-in code.',
      title: 'Sign In to Your Account',
      paragraphs: [
        greeting(name),
        `We received a request to sign in to your ${BRAND} account using a one-time code:`,
        codeBox(code),
        `This code expires in ${ttlMinutes} minutes and can only be used once.`,
        'If you didn’t request to sign in, ignore this email: nobody can sign in without the code.',
      ],
      footer: `— The ${BRAND} Team`,
    }),
  }
}

export function resetCodeEmail(code: string, ttlMinutes: number, name: string | null): Email {
  return {
    subject: `Password Reset Code – ${BRAND}`,
    text: `${name ? `Hi ${name},\n\n` : 'Hi,\n\n'}A password reset was requested for your ${BRAND} account.\n\nYour reset code: ${code}\n\nThis code expires in ${ttlMinutes} minutes. If you did not ask to reset your password, you can safely ignore this email and your password will stay unchanged.\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'Your password reset code.',
      title: 'Reset Your Password',
      paragraphs: [
        greeting(name),
        `A password reset was requested for your ${BRAND} account. Enter this code to set a new password:`,
        codeBox(code),
        `This code will expire in ${ttlMinutes} minutes.`,
        'If you didn’t ask to reset your password, you can safely ignore this email and your password remains secure.',
      ],
      footer: `— The ${BRAND} Team`,
    }),
  }
}

export function requestReceivedEmail(name: string | null, appUrl: string): Email {
  return {
    subject: `Registration Request Submitted – ${BRAND}`,
    text: `${name ? `Hi ${name},\n\n` : 'Hi,\n\n'}Your registration request has been submitted successfully. Access to the application will be granted once an administrator approves your request. You will be notified when your request is reviewed.\n\nCheck request status: ${appUrl}/signup/pending\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'Your registration request is under review.',
      title: 'Registration Request Submitted',
      paragraphs: [
        greeting(name),
        `Your registration request has been submitted successfully. Access to the application will be granted once an administrator approves your request. You will be notified when your request is reviewed.`,
      ],
      action: { label: 'Check request status', url: `${appUrl}/signup/pending` },
      footer: `— The ${BRAND} Team`,
    }),
  }
}

export function accessRequestedEmail(adminName: string | null, applicant: { email: string; name: string | null }, appUrl: string): Email {
  const who = applicant.name ? `${applicant.name} (${applicant.email})` : applicant.email
  return {
    subject: `Access Request from ${applicant.name ?? applicant.email} – ${BRAND}`,
    text: `${adminName ? `Hi ${adminName},\n\n` : 'Hi,\n\n'}${who} has confirmed their email and requested access to your organization.\n\nReview request: ${appUrl}/users?tab=requests\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: `${who} is requesting access to your organization`,
      title: 'New Access Request',
      paragraphs: [
        greeting(adminName),
        `<strong>${escapeHtml(who)}</strong> has confirmed their email address and requested access to your organization.`,
      ],
      action: { label: 'Review request', url: `${appUrl}/users?tab=requests` },
      footer: 'You received this notification because you are an administrator.',
    }),
  }
}

export function accessApprovedEmail(name: string | null, appUrl: string): Email {
  return {
    subject: `Your Access Request Has Been Approved – ${BRAND}`,
    text: `${name ? `Hi ${name},\n\n` : ''}An administrator approved your request. You can now sign in to your workspace:\n\n${appUrl}/login\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'You can now sign in to your workspace.',
      title: 'Access Request Approved',
      paragraphs: [
        greeting(name),
        `An administrator has approved your access request. You can now sign in to ${BRAND} using your email and password.`,
      ],
      action: { label: 'Sign in now', url: `${appUrl}/login` },
      footer: `— The ${BRAND} Team`,
    }),
  }
}

export function accessRejectedEmail(name: string | null, note: string | null): Email {
  return {
    subject: `Access Request Declined – ${BRAND}`,
    text: `${name ? `Hi ${name},\n\n` : ''}An administrator declined your access request.${note ? `\n\nReason: ${note}` : ''}\n\nIf you think this is a mistake, please contact your organization administrator.\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'An update regarding your access request.',
      title: 'Access Request Update',
      paragraphs: [
        greeting(name),
        'An administrator reviewed your access request and was unable to approve it at this time.',
        ...(note ? [`<em style="color:#565d58">“${escapeHtml(note)}”</em>`] : []),
        'If you believe this decision was made in error, please contact your organization administrator.',
      ],
      footer: `— The ${BRAND} Team`,
    }),
  }
}

export function passwordChangedEmail(name: string | null, appUrl: string): Email {
  return {
    subject: `Your Password Was Changed – ${BRAND}`,
    text: `${name ? `Hi ${name},\n\n` : 'Hi,\n\n'}Your password was just changed and all other active sessions were signed out. If you did not make this change, please contact an administrator immediately.\n\n${appUrl}/login\n\n— The ${BRAND} Team`,
    html: layout({
      preheader: 'Your account security notification.',
      title: 'Password Changed',
      paragraphs: [
        greeting(name),
        'Your password was recently changed and all other sessions were signed out for security.',
        'If you did not perform this change, please contact an administrator immediately.',
      ],
      footer: `— The ${BRAND} Team`,
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
