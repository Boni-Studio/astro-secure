/** A bot filled the hidden honeypot field. */
export function honeypotTriggered(value: unknown): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * The form was submitted faster than a human could fill it.
 * `startedAt` is set by client script when the form becomes visible; it is a weak signal
 * (bots can forge it) and complements Turnstile, it never replaces it.
 */
export function submittedTooFast(startedAt: unknown, minMs = 3000, now = Date.now()): boolean {
  const started = typeof startedAt === 'string' ? Number(startedAt) : typeof startedAt === 'number' ? startedAt : NaN;
  if (!Number.isFinite(started)) return true;
  const elapsed = now - started;
  return elapsed < minMs || elapsed > 24 * 3600 * 1000;
}

/** Remove CR/LF and control chars from values that end up in email headers (subject, reply-to, names). */
export function sanitizeHeaderValue(value: string, maxLength = 200): string {
  return value
    .replace(/[\r\n\t\u0000-\u001f\u007f]+/g, ' ')
    .trim()
    .slice(0, maxLength);
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Client IP as seen by Cloudflare. */
export function clientIp(request: Request): string | null {
  return request.headers.get('cf-connecting-ip');
}
