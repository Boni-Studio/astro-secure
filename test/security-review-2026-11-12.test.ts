/**
 * Regression tests for docs/security-review-2026-11-12.md (A1–A8, F3–F15).
 * Each test is the original attack with the assertion inverted: it must stay blocked.
 */
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

vi.mock('virtual:astro-secure/config', () => ({
  default: { securityContact: 'security@example.com', cspReportPath: '/_csp-report', cspReportRateLimitBinding: null, permissionsPolicy: {} },
}));

const { assertSafeSource, resolveOptions } = await import('../src/options.js');
const { buildHeaderRules, mergeHeadersFile, renderHeaderRules, validateHeadersFile } = await import('../src/headers.js');
const { withHeaderOnlyDirectives } = await import('../src/csp.js');
const { auditCsp, checkBuild } = await import('../src/check.js');
const { submittedTooFast } = await import('../src/server/forms.js');
const { verifyTurnstile } = await import('../src/server/turnstile.js');
const { summarizeCspReports } = await import('../src/server/csp-report.js');
const secure = (await import('../src/index.js')).default;

const GOOD_CSP = "default-src 'self'; script-src 'self' 'sha256-abc='; style-src 'self'; object-src 'none'; base-uri 'self'";
const headersWith = (csp: string) =>
  `/*\n  Strict-Transport-Security: x\n  X-Frame-Options: DENY\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: x\n  Permissions-Policy: x\n  Cross-Origin-Opener-Policy: same-origin\n  Content-Security-Policy: ${csp}\n`;

async function fakeBuild(headers: string, html = '<html><body>ok</body></html>') {
  const dir = await mkdtemp(join(tmpdir(), 'as-'));
  await writeFile(join(dir, '_headers'), headers);
  await writeFile(join(dir, 'index.html'), html);
  await writeFile(join(dir, 'robots.txt'), 'User-agent: *');
  await mkdir(join(dir, '.well-known'));
  await writeFile(join(dir, '.well-known/security.txt'), 'Contact: mailto:a@b.co\nExpires: 2099-01-01T00:00:00.000Z\n');
  return dir;
}

describe('A1/F10 wildcard allowlist', () => {
  it.each([
    ['scripts', 'https://*.com'],
    ['scripts', 'https://*.example.com'],
    ['connect', 'https://*.example.com'],
    ['frames', 'https://*.com'],
    ['frames', 'https://*.workers.dev'],
    ['images', 'https://*.github.io'],
    ['scripts', "https://a.com'"],
  ])('rejects %s %s', (kind, src) => {
    expect(() => assertSafeSource(kind, src)).toThrow();
  });
  it('still accepts exact hosts and scoped wildcards for non-script kinds', () => {
    expect(() => assertSafeSource('scripts', 'https://cdn.example.com')).not.toThrow();
    expect(() => assertSafeSource('images', 'https://*.example.com')).not.toThrow();
  });
});

describe('A2/F11 option injection', () => {
  it('rejects cspReportPath with directives', () => {
    expect(() => resolveOptions({ securityContact: 'a@b.co', cspReportPath: '/r; script-src-elem *' })).toThrow();
    expect(() => withHeaderOnlyDirectives(GOOD_CSP, '/r; script-src *')).toThrow();
  });
  it('rejects permissionsPolicy values with line breaks or junk', () => {
    expect(() =>
      resolveOptions({ securityContact: 'a@b.co', permissionsPolicy: { fullscreen: '(self)\n/*\n  ! Content-Security-Policy' } }),
    ).toThrow();
    expect(() => resolveOptions({ securityContact: 'a@b.co', permissionsPolicy: { 'bad feature': '()' } })).toThrow();
    expect(() => resolveOptions({ securityContact: 'a@b.co', permissionsPolicy: { fullscreen: '(self "https://a.com")' } })).not.toThrow();
  });
  it('renderHeaderRules refuses line breaks even if validation is bypassed', () => {
    expect(() => renderHeaderRules([{ path: '/*', headers: { X: 'a\n  ! Content-Security-Policy' } }])).toThrow();
  });
});

describe('A3/A8/F6 check catches weakened policies', () => {
  it.each([
    "default-src *; script-src 'self' https: data: *; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "script-src 'UNSAFE-INLINE' 'UNSAFE-EVAL'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "frame-ancestors *; script-src *; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "script-src 'self' https://*.workers.dev; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  ])('fails for %s', async (csp) => {
    const r = await checkBuild(await fakeBuild(headersWith(csp)));
    expect(r.errors.length).toBeGreaterThan(0);
  });
  it('fails when public/_headers detaches security headers', async () => {
    const merged = mergeHeadersFile('/*\n  ! Content-Security-Policy\n  ! X-Frame-Options\n', headersWith(`${GOOD_CSP}; frame-ancestors 'none'`).trim());
    expect(validateHeadersFile(merged).length).toBe(2);
    expect((await checkBuild(await fakeBuild(merged))).errors.length).toBeGreaterThan(0);
  });
  it('catches unquoted / protocol-relative scripts and unquoted handlers', async () => {
    const html = '<script src=//evil.example/x.js></script><img src=x onerror=alert(1)><p style=color:red>x</p>';
    const r = await checkBuild(await fakeBuild(headersWith(`${GOOD_CSP}; frame-ancestors 'none'`), html));
    expect(r.errors.some((e) => e.includes('evil.example'))).toBe(true);
    expect(r.errors.some((e) => e.includes('event handler'))).toBe(true);
    expect(r.errors.some((e) => e.includes('style'))).toBe(true);
  });
  it('the generated policy itself passes the audit', () => {
    const o = resolveOptions({ securityContact: 'a@b.co', embeds: ['youtube'], cloudflareAnalytics: true });
    const [rule] = buildHeaderRules(o, new Map([['/', `${GOOD_CSP}; img-src 'self' data:`]]));
    expect(auditCsp(rule!.headers['Content-Security-Policy']!)).toEqual([]);
  });
});

describe('A4/F3 every on-demand route is allowlisted', () => {
  const hook = (opts = {}) => secure({ securityContact: 'a@b.co', ...opts }).hooks['astro:routes:resolved'] as (o: unknown) => void;
  const r = (pattern: string, origin: string, isPrerendered = false) => ({ pattern, origin, isPrerendered, type: 'endpoint' });
  it('fails for integration-injected or internal routes outside the allowlist', () => {
    expect(() => hook()({ routes: [r('/api/leak', 'external')] })).toThrow(/api\/leak/);
    expect(() => hook()({ routes: [r('/_secret', 'internal')] })).toThrow();
  });
  it('accepts the known Astro routes and explicit allowlist entries', () => {
    expect(() =>
      hook({ allowedServerRoutes: ['/api/ok'] })({
        routes: [r('/_actions/[...path]', 'internal'), r('/_server-islands/[name]', 'internal'), r('/_image', 'internal'), r('/_csp-report', 'external'), r('/api/ok', 'project')],
      }),
    ).not.toThrow();
  });
});

describe('A5/F8 clock skew no longer drops real submissions', () => {
  it('uses a duration, so the client clock is irrelevant', () => {
    expect(submittedTooFast(60_000)).toBe(false);
    expect(submittedTooFast('60000')).toBe(false);
    expect(submittedTooFast(1_000)).toBe(true);
  });
});

describe('A6/F15 turnstile null body', () => {
  it('returns success:false instead of throwing', async () => {
    const fetchImpl = (async () => new Response('null', { status: 200 })) as typeof fetch;
    expect(await verifyTurnstile({ token: 't', secret: 's', fetchImpl })).toEqual({ success: false, errors: ['invalid-response'] });
  });
});

describe('A7/F12 csp-report reads bounded bodies', () => {
  it('stops reading a chunked body after the limit', async () => {
    const { POST, MAX_BYTES } = await import('../src/routes/csp-report.js');
    let pulled = 0;
    const chunk = new Uint8Array(4 * 1024).fill(97);
    const body = new ReadableStream({
      pull(c) {
        if (pulled >= 5 * 1024 * 1024) return c.close();
        pulled += chunk.length;
        c.enqueue(chunk);
      },
    });
    const req = new Request('https://x/_csp-report', {
      method: 'POST',
      body,
      headers: { 'content-type': 'application/json' },
      duplex: 'half',
    } as RequestInit);
    const res = await POST({ request: req, clientAddress: '1.2.3.4' } as never);
    expect(res.status).toBe(413);
    expect(pulled).toBeLessThanOrEqual(MAX_BYTES + 3 * chunk.length);
  });
  it('truncates disposition', () => {
    const [s] = summarizeCspReports([{ type: 'csp-violation', body: { disposition: 'x'.repeat(500) } }]);
    expect(s!.disposition!.length).toBe(20);
  });
});
