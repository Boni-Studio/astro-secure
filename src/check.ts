import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { duplicateDirectives, parseCsp } from './csp.js';
import { validateHeadersFile } from './headers.js';
import { assertSafeSource } from './options.js';
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

/** Directives that control code execution or data exfiltration. */
const SENSITIVE_DIRECTIVES = [
  'default-src',
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'connect-src',
  'frame-src',
  'child-src',
  'worker-src',
  'object-src',
  'base-uri',
  'form-action',
];

const UNSAFE_KEYWORDS = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'", "'unsafe-allow-redirects'"];
const BROAD_SOURCES = ['*', 'http:', 'https:', 'data:', 'blob:', 'filesystem:', 'ws:', 'wss:'];
const SAFE_KEYWORDS = ["'self'", "'none'", "'strict-dynamic'", "'report-sample'"];

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else yield full;
  }
}

/** Parse `_headers` into rules: path -> headers (lowercased names). Detach lines (`! Name`) are kept as `!name`. */
export function parseHeadersFile(content: string): Map<string, Map<string, string>> {
  const rules = new Map<string, Map<string, string>>();
  let current: Map<string, string> | undefined;
  for (const line of content.split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      current = rules.get(line.trim()) ?? new Map();
      rules.set(line.trim(), current);
    } else if (current) {
      const detach = line.trim().match(/^!\s*([A-Za-z-]+)/);
      if (detach) {
        current.set(`!${detach[1]!.toLowerCase()}`, '');
        continue;
      }
      const idx = line.indexOf(':');
      if (idx > 0) {
        const name = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        // Repeated headers are joined: the browser enforces every CSP it receives.
        current.set(name, current.has(name) ? `${current.get(name)}, ${value}` : value);
      }
    }
  }
  return rules;
}

function originOf(src: string): string | null {
  try {
    return new URL(src.startsWith('//') ? `https:${src}` : src).origin;
  } catch {
    return null;
  }
}

/** Validate one CSP header value. Returns error messages. */
export function auditCsp(csp: string): string[] {
  const errors: string[] = [];
  // Several policies in one header (comma-separated) are each enforced: audit them all.
  for (const policy of csp.split(',')) {
    const dups = duplicateDirectives(policy);
    if (dups.length) errors.push(`CSP repeats directives (browsers use only the first): ${dups.join(', ')}.`);

    const d = parseCsp(policy);
    for (const [name, values] of d) {
      for (const v of values) {
        if (UNSAFE_KEYWORDS.includes(v)) errors.push(`CSP ${name} contains ${v}.`);
      }
      if (!SENSITIVE_DIRECTIVES.includes(name)) continue;
      for (const v of values) {
        if (BROAD_SOURCES.includes(v)) {
          errors.push(`CSP ${name} allows "${v}" (any origin).`);
        } else if (v.includes('*')) {
          try {
            assertSafeSource(name === 'connect-src' ? 'connect' : name.startsWith('script') ? 'scripts' : 'frames', v);
          } catch {
            errors.push(`CSP ${name} contains an unsafe wildcard "${v}".`);
          }
        } else if (!v.startsWith("'") && !v.startsWith('https://') && !SAFE_KEYWORDS.includes(v)) {
          errors.push(`CSP ${name} contains a non-https source "${v}".`);
        }
      }
    }
    if (!d.get('frame-ancestors')?.includes("'none'")) errors.push("CSP missing frame-ancestors 'none'.");
    if (!d.get('object-src')?.includes("'none'")) errors.push("CSP missing object-src 'none'.");
    if (!d.has('base-uri')) errors.push('CSP missing base-uri.');
    if (!d.has('script-src') && !d.has('default-src')) errors.push('CSP has neither script-src nor default-src.');
  }
  return errors;
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

  const scriptOrigins = new Set<string>();
  for (const csp of cspValues) {
    errors.push(...auditCsp(csp));
    const d = parseCsp(csp.split(',')[0]!);
    if (!d.has('report-to') && !d.has('report-uri')) warnings.push('CSP has no reporting directive.');
    for (const v of [...(d.get('script-src') ?? []), ...(d.get('script-src-elem') ?? [])]) {
      if (v.startsWith('https://')) scriptOrigins.add(originOf(v) ?? v);
    }
  }

  // HTML: inline handlers / style attributes are blocked by the CSP; external scripts must be allowlisted.
  for await (const file of walk(clientDir)) {
    if (!file.endsWith('.html')) continue;
    const html = await readFile(file, 'utf8');
    const rel = file.slice(clientDir.length);
    const withoutScripts = html.replace(/<script\b[\s\S]*?<\/script\s*>/gi, '<script></script>');

    if (/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy/i.test(html)) {
      warnings.push(`${rel}: CSP <meta> found; expected header-only CSP (is the adapter wrapped?).`);
    }
    if (/<[a-z][^>]*\son[a-z]+\s*=/i.test(withoutScripts)) {
      errors.push(`${rel}: inline event handler attribute (on...=) is blocked by CSP.`);
    }
    if (/<[a-z][^>]*\sstyle\s*=/i.test(withoutScripts)) {
      errors.push(`${rel}: inline style attribute is blocked by CSP.`);
    }
    if (/\/_server-islands\//.test(html)) {
      warnings.push(`${rel}: uses server islands (on-demand rendering).`);
    }
    for (const m of html.matchAll(/<script\b[^>]*?\ssrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
      const src = (m[1] ?? m[2] ?? m[3] ?? '').trim();
      if (/^(https?:)?\/\//i.test(src)) {
        const origin = originOf(src);
        if (!origin || !scriptOrigins.has(origin)) errors.push(`${rel}: external script ${src} not allowed by CSP script-src.`);
      } else if (/^[a-z][a-z0-9+.-]*:/i.test(src)) {
        errors.push(`${rel}: script with non-http src "${src.slice(0, 40)}".`);
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
