import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkBuild } from '../src/check.js';
import { buildHeaderRules, renderHeaderRules } from '../src/headers.js';
import { resolveOptions } from '../src/options.js';
import { buildSecurityTxt } from '../src/security-txt.js';

const o = resolveOptions({ securityContact: 'security@example.com' });
const csp = "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'";

async function fixture(html: string, { headers = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'astro-secure-'));
  if (headers) await writeFile(join(dir, '_headers'), renderHeaderRules(buildHeaderRules(o, new Map([['/', csp]]))));
  await writeFile(join(dir, 'index.html'), html);
  await writeFile(join(dir, 'robots.txt'), 'User-agent: *\nAllow: /\n');
  await mkdir(join(dir, '.well-known'));
  await writeFile(join(dir, '.well-known', 'security.txt'), buildSecurityTxt({ contact: 'a@b.co', languages: ['es'] }));
  return dir;
}

describe('checkBuild', () => {
  it('passes a clean build', async () => {
    const dir = await fixture('<html><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></html>');
    expect((await checkBuild(dir)).errors).toEqual([]);
  });
  it('fails without _headers', async () => {
    expect((await checkBuild(await fixture('<html></html>', { headers: false }))).errors[0]).toMatch(/_headers/);
  });
  it('flags inline handlers, inline styles and non-allowlisted scripts', async () => {
    const dir = await fixture(
      '<html><button onclick="x()">a</button><p style="color:red">b</p><script src="https://evil.com/x.js"></script></html>',
    );
    const { errors } = await checkBuild(dir);
    expect(errors.some((e) => e.includes('inline event handler'))).toBe(true);
    expect(errors.some((e) => e.includes('style=""'))).toBe(true);
    expect(errors.some((e) => e.includes('evil.com'))).toBe(true);
  });
});
