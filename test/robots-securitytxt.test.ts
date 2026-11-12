import { describe, expect, it } from 'vitest';
import { buildRobotsTxt } from '../src/robots.js';
import { buildSecurityTxt, securityTxtExpiry } from '../src/security-txt.js';

describe('robots.txt', () => {
  it('search-only blocks training crawlers but not search agents', () => {
    const txt = buildRobotsTxt({ policy: 'search-only', site: 'https://example.com', noindex: false });
    expect(txt).toContain('Content-Signal: search=yes, ai-input=yes, ai-train=no');
    expect(txt).toMatch(/User-agent: GPTBot\nDisallow: \//);
    expect(txt).not.toContain('User-agent: OAI-SearchBot');
    expect(txt).toContain('Sitemap: https://example.com/sitemap-index.xml');
  });
  it('noindex blocks everything', () => {
    expect(buildRobotsTxt({ policy: 'allow-all', noindex: true })).toBe('User-agent: *\nDisallow: /\n');
  });
});

describe('security.txt', () => {
  it('builds an RFC 9116 file', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    const txt = buildSecurityTxt({ contact: 'security@example.com', languages: ['es', 'en'], site: 'https://example.com', now });
    expect(txt).toContain('Contact: mailto:security@example.com');
    expect(txt).toContain('Canonical: https://example.com/.well-known/security.txt');
    expect(securityTxtExpiry(txt)?.toISOString()).toBe('2027-01-01T00:00:00.000Z');
  });
});
