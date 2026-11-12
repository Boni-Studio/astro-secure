import { describe, expect, it, vi } from 'vitest';
import {
  checkRateLimit,
  createResendProvider,
  escapeHtml,
  honeypotTriggered,
  sanitizeHeaderValue,
  signWebhook,
  submittedTooFast,
  summarizeCspReports,
  verifyTurnstile,
  verifyWebhookSignature,
} from '../src/server/index.js';

const jsonResponse = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe('verifyTurnstile', () => {
  const base = { secret: 's', token: 't', expectedHostname: 'example.com', expectedAction: 'contact' };

  it('accepts a valid token for the right hostname and action', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ success: true, hostname: 'example.com', action: 'contact' }));
    expect(await verifyTurnstile({ ...base, fetchImpl })).toEqual({ success: true, errors: [] });
  });
  it('rejects hostname and action mismatches', async () => {
    const wrongHost = vi.fn(async () => jsonResponse({ success: true, hostname: 'evil.com', action: 'contact' }));
    expect((await verifyTurnstile({ ...base, fetchImpl: wrongHost })).errors).toEqual(['hostname-mismatch']);
    const wrongAction = vi.fn(async () => jsonResponse({ success: true, hostname: 'example.com', action: 'x' }));
    expect((await verifyTurnstile({ ...base, fetchImpl: wrongAction })).errors).toEqual(['action-mismatch']);
  });
  it('fails closed on network errors and missing tokens', async () => {
    const boom = vi.fn(async () => {
      throw new Error('down');
    });
    expect((await verifyTurnstile({ ...base, fetchImpl: boom })).success).toBe(false);
    expect((await verifyTurnstile({ ...base, token: '' })).success).toBe(false);
    expect((await verifyTurnstile({ ...base, secret: '' })).success).toBe(false);
  });
});

describe('rate limit', () => {
  it('fails closed when the binding is missing and required', async () => {
    expect(await checkRateLimit(undefined, 'k')).toBe(false);
    expect(await checkRateLimit(undefined, 'k', { required: false })).toBe(true);
  });
  it('uses the binding result', async () => {
    expect(await checkRateLimit({ limit: async () => ({ success: false }) }, 'k')).toBe(false);
    expect(await checkRateLimit({ limit: async () => ({ success: true }) }, 'k')).toBe(true);
  });
});

describe('form helpers', () => {
  it('detects honeypot and too-fast submissions', () => {
    expect(honeypotTriggered('')).toBe(false);
    expect(honeypotTriggered('http://spam')).toBe(true);
    expect(submittedTooFast('1000')).toBe(true);
    expect(submittedTooFast('5000')).toBe(false);
    expect(submittedTooFast('nope')).toBe(true);
    expect(submittedTooFast('-5')).toBe(true);
  });
  it('blocks email header injection', () => {
    expect(sanitizeHeaderValue('Hola\r\nBcc: victim@example.com')).toBe('Hola Bcc: victim@example.com');
    expect(escapeHtml('<script>"x"</script>')).toBe('&lt;script&gt;&quot;x&quot;&lt;/script&gt;');
  });
});

describe('webhook signatures', () => {
  const secret = 'x'.repeat(32);
  it('round-trips and rejects tampering and replays', async () => {
    const now = 1_700_000_000;
    const header = await signWebhook('{"a":1}', secret, now);
    expect(await verifyWebhookSignature('{"a":1}', header, secret, { now })).toBe(true);
    expect(await verifyWebhookSignature('{"a":2}', header, secret, { now })).toBe(false);
    expect(await verifyWebhookSignature('{"a":1}', header, secret, { now: now + 3600 })).toBe(false);
  });
  it('requires a strong secret', async () => {
    await expect(signWebhook('x', 'short')).rejects.toThrow();
  });
});

describe('email provider', () => {
  it('sanitizes the subject and rejects bad addresses', async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response('{}', { status: 200 }));
    const provider = createResendProvider('key', { fetchImpl: fetchImpl as unknown as typeof fetch });
    await provider.send({ to: 'a@example.com', from: 'b@example.com', subject: 'Hi\nBcc: x@y.z', text: 't' });
    const sent = JSON.parse(String(fetchImpl.mock.calls[0]![1]!.body));
    expect(sent.subject).toBe('Hi Bcc: x@y.z');
    await expect(provider.send({ to: 'a@example.com\nbcc', from: 'b@example.com', subject: 's', text: 't' })).rejects.toThrow();
  });
  it('throws when the provider fails (no fake success)', async () => {
    const provider = createResendProvider('key', { fetchImpl: (async () => new Response('', { status: 500 })) as typeof fetch });
    await expect(provider.send({ to: 'a@example.com', from: 'b@example.com', subject: 's', text: 't' })).rejects.toThrow();
  });
});

describe('CSP reports', () => {
  it('summarizes Reporting API and legacy bodies without query strings', () => {
    const modern = [
      {
        type: 'csp-violation',
        body: { effectiveDirective: 'script-src-elem', blockedURL: 'https://evil.com/x.js?u=1', documentURL: 'https://site.com/p?email=a@b.c' },
      },
    ];
    expect(summarizeCspReports(modern)).toEqual([
      { directive: 'script-src-elem', blocked: 'https://evil.com/x.js', document: 'https://site.com/p' },
    ]);
    const legacy = { 'csp-report': { 'violated-directive': 'img-src', 'blocked-uri': 'inline', 'document-uri': 'https://site.com/' } };
    expect(summarizeCspReports(legacy)[0]).toMatchObject({ directive: 'img-src', blocked: 'inline' });
    expect(summarizeCspReports('garbage')).toEqual([]);
  });
});
