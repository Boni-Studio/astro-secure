import { describe, expect, it } from 'vitest';
import { buildAstroCsp, normalizeCsp, parseCsp, withHeaderOnlyDirectives } from '../src/csp.js';
import { baseHeaders, buildHeaderRules, mergeHeadersFile, renderHeaderRules, validateHeadersFile } from '../src/headers.js';
import { resolveOptions } from '../src/options.js';

const opts = (extra = {}) => resolveOptions({ securityContact: 'security@example.com', ...extra });

describe('options', () => {
  it('requires a security contact', () => {
    // @ts-expect-error testing runtime validation
    expect(() => resolveOptions({})).toThrow(/securityContact/);
  });
  it.each(["'unsafe-inline'", '*', 'https:', 'http://example.com', 'example.com', 'https://a.com; script-src *'])(
    'rejects unsafe allowlist source %s',
    (src) => {
      expect(() => opts({ allow: { scripts: [src] } })).toThrow();
    },
  );
  it('accepts specific https hosts', () => {
    expect(() => opts({ allow: { scripts: ['https://cdn.example.com'], images: ['https://*.example.com'] } })).not.toThrow();
  });
});

describe('buildAstroCsp', () => {
  it('has a strict baseline', () => {
    const csp = buildAstroCsp(opts({ turnstile: false, sanityImages: false }));
    expect(csp.directives).toContain("default-src 'self'");
    expect(csp.directives).toContain("object-src 'none'");
    expect(csp.directives).toContain("base-uri 'self'");
    expect(csp.directives).toContain("form-action 'self'");
    expect(csp.directives).toContain("frame-src 'none'");
    expect(csp.scriptDirective.resources).toEqual(["'self'"]);
    expect(JSON.stringify(csp)).not.toContain('unsafe');
  });
  it('adds only the hosts of enabled features', () => {
    const csp = buildAstroCsp(opts({ embeds: ['youtube'], cloudflareAnalytics: true }));
    expect(csp.scriptDirective.resources).toEqual(["'self'", 'https://challenges.cloudflare.com', 'https://static.cloudflareinsights.com']);
    expect(csp.directives.find((d) => d.startsWith('frame-src'))).toBe(
      'frame-src https://challenges.cloudflare.com https://www.youtube-nocookie.com',
    );
    expect(csp.directives.find((d) => d.startsWith('img-src'))).toContain('https://i.ytimg.com');
    expect(csp.directives.find((d) => d.startsWith('connect-src'))).toContain('https://cloudflareinsights.com');
  });
});

describe('CSP strings', () => {
  it('normalizes separators and empty directives', () => {
    expect(normalizeCsp("default-src 'self';;  img-src  'self' ; ")).toBe("default-src 'self'; img-src 'self'");
  });
  it('appends header-only directives once', () => {
    const once = withHeaderOnlyDirectives("default-src 'self'", '/_csp-report');
    expect(once).toBe("default-src 'self'; frame-ancestors 'none'; report-uri /_csp-report; report-to csp");
    expect(withHeaderOnlyDirectives(once, '/_csp-report')).toBe(once);
    expect(parseCsp(once).get('frame-ancestors')).toEqual(["'none'"]);
  });
});

describe('headers', () => {
  it('HSTS has no preload by default', () => {
    expect(baseHeaders(opts())['Strict-Transport-Security']).toBe('max-age=63072000; includeSubDomains');
    expect(baseHeaders(opts({ hstsPreload: true }))['Strict-Transport-Security']).toContain('preload');
  });
  it('adds X-Robots-Tag only for noindex builds', () => {
    expect(baseHeaders(opts())['X-Robots-Tag']).toBeUndefined();
    expect(baseHeaders(opts({ noindex: true }))['X-Robots-Tag']).toBe('noindex, nofollow');
  });
  it('collapses identical route CSPs into a single global rule', () => {
    const csp = "default-src 'self';script-src 'self' 'sha256-abc';;";
    const rules = buildHeaderRules(opts(), new Map([['/', csp], ['/about', csp]]));
    expect(rules).toHaveLength(1);
    expect(rules[0]!.path).toBe('/*');
    expect(rules[0]!.headers['Content-Security-Policy']).toBe(
      "default-src 'self'; script-src 'self' 'sha256-abc'; frame-ancestors 'none'; report-uri /_csp-report; report-to csp",
    );
  });
  it('emits per-route rules when CSPs differ, without CSP in the global rule', () => {
    const rules = buildHeaderRules(opts(), new Map([['/', "default-src 'self'"], ['/about', "default-src 'none'"]]));
    expect(rules.map((r) => r.path)).toEqual(['/*', '/', '/about', '/about/']);
    expect(rules[0]!.headers['Content-Security-Policy']).toBeUndefined();
  });
  it('merges into an existing _headers file and is idempotent', () => {
    const adapterRule = '/_astro/*\n  Cache-Control: public, max-age=31536000, immutable';
    const ours = renderHeaderRules(buildHeaderRules(opts(), new Map()));
    const merged = mergeHeadersFile(adapterRule, ours);
    expect(merged).toContain('Cache-Control: public, max-age=31536000, immutable');
    expect(merged).toContain('X-Frame-Options: DENY');
    expect(mergeHeadersFile(merged, ours)).toBe(merged);
  });
  it('validates Cloudflare limits', () => {
    expect(validateHeadersFile(`/*\n  X: ${'a'.repeat(2100)}`)).toHaveLength(1);
    expect(validateHeadersFile('/*\n  X: y')).toEqual([]);
  });
});
