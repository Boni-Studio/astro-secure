const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export interface TurnstileResult {
  success: boolean;
  errors: string[];
}

export interface VerifyTurnstileOptions {
  token: string | null | undefined;
  secret: string;
  remoteIp?: string | null | undefined;
  /** Hostname the widget must have been solved on (e.g. "example.com"). */
  expectedHostname?: string | string[] | undefined;
  /** Action name set on the widget (data-action). */
  expectedAction?: string | undefined;
  timeoutMs?: number | undefined;
  fetchImpl?: typeof fetch | undefined;
}

/**
 * Server-side Turnstile verification. Fails closed: any network error, timeout or mismatch
 * returns success: false.
 */
export async function verifyTurnstile(opts: VerifyTurnstileOptions): Promise<TurnstileResult> {
  const { token, secret } = opts;
  if (!secret) return { success: false, errors: ['missing-secret'] };
  if (!token || typeof token !== 'string' || token.length > 2048) {
    return { success: false, errors: ['missing-or-invalid-token'] };
  }

  const body = new FormData();
  body.set('secret', secret);
  body.set('response', token);
  if (opts.remoteIp) body.set('remoteip', opts.remoteIp);
  body.set('idempotency_key', crypto.randomUUID());

  let data: {
    success?: boolean;
    hostname?: string;
    action?: string;
    'error-codes'?: string[];
  };
  try {
    const res = await (opts.fetchImpl ?? fetch)(SITEVERIFY, {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
    });
    if (!res.ok) return { success: false, errors: [`http-${res.status}`] };
    data = await res.json();
  } catch {
    return { success: false, errors: ['network-error'] };
  }

  const errors = [...(data['error-codes'] ?? [])];
  if (!data.success) return { success: false, errors: errors.length ? errors : ['unsuccessful'] };

  if (opts.expectedHostname) {
    const allowed = Array.isArray(opts.expectedHostname) ? opts.expectedHostname : [opts.expectedHostname];
    if (!data.hostname || !allowed.includes(data.hostname)) {
      return { success: false, errors: ['hostname-mismatch'] };
    }
  }
  if (opts.expectedAction && data.action !== opts.expectedAction) {
    return { success: false, errors: ['action-mismatch'] };
  }
  return { success: true, errors: [] };
}
