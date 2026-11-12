import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseCsp } from './csp.js';
import { validateHeadersFile } from './headers.js';
import { securityTxtExpiry } from './security-txt.js';

export interface CheckResult {
  errors: string[];
  warnings: string[];
}

const REQUIRED_HEADERS = [
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'content-security-policy',
];

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else yield full;
  }
}

/** Parse `_headers` into rules: path -> headers (lowercased names). */
export function parseHeadersFile(content: string): Map<string, Map<string, string>> {
  const rules = new Map<string, Map<string, string>>();
  let current: Map<string, string> | undefined;
  for (const line of content.split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      current = rules.get(line.trim()) ?? new Map();
      rules.set(line.trim(), current);
    } else if (current) {
      const idx = line.indexOf(':');
      if (idx > 0) current.set(line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim());
    }
  }
  return rules;
}

function hostOf(src: string): string | null {
  try {
    return new URL(src).origin;
  } catch {
    return null;
  }
}

/** Static checks over the build output (dist/client). Run in CI before deploying. */
export async function checkBuild(clientDir: string, { now = new Date() } = {}): Promise<CheckResult> {
  const errors: string[] = [];
  const warnings: string[] = [];

  const headersContent = await readFile(join(clientDir, '_headers'), 'utf8').catch(() => null);
  if (headersContent === null) {
    return { errors: ['Missing _headers in build output.'], warnings };
  }
  errors.push(...validateHeadersFile(headersContent));

  const rules = parseHeadersFile(headersContent);
  const global = rules.get('/*');
  if (!global) errors.push('Missing global "/*" rule in _headers.');

  const cspValues = [...rules.values()].map((h) => h.get('content-security-policy')).filter((v): v is string => !!v);
  for (const name of REQUIRED_HEADERS) {
    if (name === 'content-security-policy') {
      if (!cspValues.length) errors.push('No Content-Security-Policy header in _headers.');
    } else if (!global?.has(name)) {
      errors.push(`Missing ${name} in global _headers rule.`);
    }
  }

  const scriptHosts = new Set<string>();
  for (const csp of cspValues) {
    const d = parseCsp(csp);
    const all = [...d.values()].flat();
    if (all.includes("'unsafe-inline'")) errors.push("CSP contains 'unsafe-inline'.");
    if (all.includes("'unsafe-eval'")) errors.push("CSP contains 'unsafe-eval'.");
    if (!d.get('frame-ancestors')?.includes("'none'")) errors.push("CSP missing frame-ancestors 'none'.");
    if (!d.has('object-src')) errors.push('CSP missing object-src.');
    if (!d.has('base-uri')) errors.push('CSP missing base-uri.');
    if (!d.has('report-to') && !d.has('report-uri')) warnings.push('CSP has no reporting directive.');
    for (const v of d.get('script-src') ?? []) if (v.startsWith('https://')) scriptHosts.add(hostOf(v) ?? v);
  }

  // HTML: inline handlers / style attributes are blocked by the CSP; external scripts must be allowlisted.
  for await (const file of walk(clientDir)) {
    if (!file.endsWith('.html')) continue;
    const html = await readFile(file, 'utf8');
    const rel = file.slice(clientDir.length);
    if (/<meta[^>]+http-equiv=["']?content-security-policy/i.test(html)) {
      warnings.push(`${rel}: CSP <meta> found; expected header-only CSP (is the adapter wrapped?).`);
    }
    if (/\son[a-z]+\s*=\s*["']/i.test(html.replace(/<script[\s\S]*?<\/script>/gi, ''))) {
      errors.push(`${rel}: inline event handler attribute (onclick=...) is blocked by CSP.`);
    }
    if (/<[a-z][^>]*\sstyle\s*=\s*["']/i.test(html)) {
      errors.push(`${rel}: inline style="" attribute is blocked by CSP.`);
    }
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
      const src = m[1]!;
      if (/^https?:\/\//i.test(src)) {
        const origin = hostOf(src);
        if (!origin || !scriptHosts.has(origin)) errors.push(`${rel}: external script ${src} not allowed by CSP script-src.`);
      }
    }
  }

  const robots = await readFile(join(clientDir, 'robots.txt'), 'utf8').catch(() => null);
  if (!robots) errors.push('Missing robots.txt.');

  const securityTxt = await readFile(join(clientDir, '.well-known', 'security.txt'), 'utf8').catch(() => null);
  if (!securityTxt) {
    errors.push('Missing /.well-known/security.txt.');
  } else {
    const expires = securityTxtExpiry(securityTxt);
    if (!expires) errors.push('security.txt has no valid Expires field.');
    else if (expires.getTime() < now.getTime()) errors.push('security.txt has expired.');
    else if (expires.getTime() - now.getTime() < 30 * 24 * 3600 * 1000) warnings.push('security.txt expires in less than 30 days.');
  }

  return { errors, warnings };
}
