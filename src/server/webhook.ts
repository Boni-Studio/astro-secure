const encoder = new TextEncoder();

async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Signature header for outgoing webhooks (CRM, n8n, Zapier...):
 *   X-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">
 * The receiver must recompute it and reject timestamps older than a few minutes (replay).
 */
export async function signWebhook(body: string, secret: string, timestamp = Math.floor(Date.now() / 1000)): Promise<string> {
  if (!secret || secret.length < 32) throw new Error('Webhook secret must be at least 32 characters.');
  return `t=${timestamp},v1=${await hmacHex(secret, `${timestamp}.${body}`)}`;
}

export async function verifyWebhookSignature(
  body: string,
  header: string | null,
  secret: string,
  { toleranceSeconds = 300, now = Math.floor(Date.now() / 1000) } = {},
): Promise<boolean> {
  if (!header) return false;
  const parts = Object.fromEntries(header.split(',').map((p) => p.split('=') as [string, string]));
  const t = Number(parts.t);
  if (!Number.isFinite(t) || Math.abs(now - t) > toleranceSeconds || !parts.v1) return false;
  const expected = await hmacHex(secret, `${t}.${body}`);
  return timingSafeEqual(expected, parts.v1);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** POST a JSON payload with a signature header. Throws on non-2xx. */
export async function sendSignedWebhook(
  url: string,
  payload: unknown,
  secret: string,
  { fetchImpl = fetch, timeoutMs = 8000 }: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<void> {
  if (!url.startsWith('https://')) throw new Error('Webhook URL must use https.');
  const body = JSON.stringify(payload);
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-signature': await signWebhook(body, secret) },
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`Webhook responded ${res.status}`);
}
