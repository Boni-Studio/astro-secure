import type { ResolvedOptions } from './options.js';
import { withHeaderOnlyDirectives } from './csp.js';

/** Cloudflare `_headers` limits (Workers static assets). Verify against current docs when upgrading. */
export const HEADERS_MAX_RULES = 100;
export const HEADERS_MAX_LINE = 2000;

const DEFAULT_PERMISSIONS: Record<string, string> = {
  accelerometer: '()',
  'browsing-topics': '()',
  camera: '()',
  'display-capture': '()',
  geolocation: '()',
  gyroscope: '()',
  magnetometer: '()',
  microphone: '()',
  payment: '()',
  'publickey-credentials-get': '()',
  usb: '()',
  'xr-spatial-tracking': '()',
};

export function permissionsPolicy(overrides: Record<string, string>): string {
  const merged = { ...DEFAULT_PERMISSIONS, ...overrides };
  return Object.entries(merged)
    .map(([feature, allow]) => `${feature}=${allow}`)
    .join(', ');
}

/** Security headers applied to every response (static and on-demand). CSP is handled separately. */
export function baseHeaders(o: ResolvedOptions): Record<string, string> {
  const headers: Record<string, string> = {
    'Strict-Transport-Security': `max-age=63072000; includeSubDomains${o.hstsPreload ? '; preload' : ''}`,
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': permissionsPolicy(o.permissionsPolicy),
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Reporting-Endpoints': `csp="${o.cspReportPath}"`,
  };
  if (o.noindex) headers['X-Robots-Tag'] = 'noindex, nofollow';
  return headers;
}

export interface HeaderRule {
  path: string;
  headers: Record<string, string>;
}

/**
 * Build `_headers` rules. If every static route shares the same CSP (the usual case: Astro
 * collects all hashes), emit a single global rule; otherwise one rule per route.
 */
export function buildHeaderRules(o: ResolvedOptions, routeCsp: Map<string, string>): HeaderRule[] {
  const global: HeaderRule = { path: '/*', headers: baseHeaders(o) };
  const policies = new Set(routeCsp.values());

  if (policies.size === 0) return [global];

  if (policies.size === 1) {
    const [csp] = policies;
    global.headers['Content-Security-Policy'] = withHeaderOnlyDirectives(csp!, o.cspReportPath);
    return [global];
  }

  const rules: HeaderRule[] = [global];
  for (const [route, csp] of [...routeCsp.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const value = withHeaderOnlyDirectives(csp, o.cspReportPath);
    for (const path of routePaths(route)) {
      rules.push({ path, headers: { 'Content-Security-Policy': value } });
    }
  }
  return rules;
}

/** Cloudflare serves "/about" for both "/about" and "/about/" depending on html_handling; cover both. */
function routePaths(route: string): string[] {
  if (route === '/' || route === '') return ['/'];
  const clean = route.replace(/\/+$/, '');
  return [clean, `${clean}/`];
}

export function renderHeaderRules(rules: HeaderRule[]): string {
  return rules
    .map((r) => {
      for (const part of [r.path, ...Object.keys(r.headers), ...Object.values(r.headers)]) {
        if (/[\r\n\0]/.test(part)) throw new Error('[astro-secure] Header rule contains a line break (injection attempt?).');
      }
      return [r.path, ...Object.entries(r.headers).map(([k, v]) => `  ${k}: ${v}`)].join('\n');
    })
    .join('\n');
}

/** Headers no `_headers` rule may detach with `! Header-Name`. */
export const PROTECTED_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'reporting-endpoints',
  'x-robots-tag',
];

const MARK_START = '# --- astro-secure:start (generated, do not edit) ---';
const MARK_END = '# --- astro-secure:end ---';

/**
 * Merge our rules into an existing `_headers` file without clobbering rules written by
 * the user (public/_headers) or by the Cloudflare adapter (immutable cache for /_astro/*).
 */
export function mergeHeadersFile(existing: string, generated: string): string {
  const block = `${MARK_START}\n${generated}\n${MARK_END}`;
  const start = existing.indexOf(MARK_START);
  const end = existing.indexOf(MARK_END);
  if (start !== -1 && end !== -1) {
    return `${existing.slice(0, start)}${block}${existing.slice(end + MARK_END.length)}`;
  }
  const rest = existing.trim();
  return rest ? `${block}\n\n${rest}\n` : `${block}\n`;
}

export function validateHeadersFile(content: string): string[] {
  const errors: string[] = [];
  const lines = content.split('\n');
  const rules = lines.filter((l) => l.trim() && !l.startsWith(' ') && !l.startsWith('\t') && !l.startsWith('#'));
  if (rules.length > HEADERS_MAX_RULES) {
    errors.push(`_headers has ${rules.length} rules (max ${HEADERS_MAX_RULES}).`);
  }
  lines.forEach((line, i) => {
    if (line.length > HEADERS_MAX_LINE) {
      errors.push(`_headers line ${i + 1} has ${line.length} characters (max ${HEADERS_MAX_LINE}).`);
    }
    const detach = line.match(/^\s+!\s*([A-Za-z-]+)/);
    if (detach && PROTECTED_HEADERS.includes(detach[1]!.toLowerCase())) {
      errors.push(`_headers line ${i + 1} removes the security header "${detach[1]}" (! ...). Not allowed.`);
    }
  });
  return errors;
}
