import { sanitizeHeaderValue } from './forms.js';

export interface EmailMessage {
  to: string | string[];
  from: string;
  replyTo?: string | undefined;
  subject: string;
  text: string;
  html?: string | undefined;
}

/** Provider-agnostic interface so the provider can be swapped by config (Resend today, Cloudflare Email Service later). */
export interface EmailProvider {
  send(message: EmailMessage): Promise<void>;
}

const EMAIL_RE = /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[^\s@<>()",;:]+$/;

export function isSafeEmail(value: string): boolean {
  return value.length <= 254 && EMAIL_RE.test(value);
}

function normalize(message: EmailMessage): EmailMessage {
  const to = Array.isArray(message.to) ? message.to : [message.to];
  for (const addr of to) if (!isSafeEmail(addr)) throw new Error('Invalid recipient address.');
  if (message.replyTo && !isSafeEmail(message.replyTo)) throw new Error('Invalid reply-to address.');
  return { ...message, to, subject: sanitizeHeaderValue(message.subject, 200) };
}

export function createResendProvider(
  apiKey: string,
  { fetchImpl = fetch, timeoutMs = 8000 }: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): EmailProvider {
  if (!apiKey) throw new Error('Missing Resend API key.');
  return {
    async send(input) {
      const m = normalize(input);
      const res = await fetchImpl('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${apiKey}`,
          'content-type': 'application/json',
          'idempotency-key': crypto.randomUUID(),
        },
        body: JSON.stringify({
          from: m.from,
          to: m.to,
          reply_to: m.replyTo,
          subject: m.subject,
          text: m.text,
          html: m.html,
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`Email provider responded ${res.status}`);
    },
  };
}
