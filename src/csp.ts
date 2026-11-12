import type { Embed, ResolvedOptions } from './options.js';

const EMBED_SOURCES: Record<Embed, { frames: string[]; images?: string[] }> = {
  youtube: { frames: ['https://www.youtube-nocookie.com'], images: ['https://i.ytimg.com'] },
  vimeo: { frames: ['https://player.vimeo.com'] },
  'google-maps': { frames: ['https://www.google.com'] },
  calendly: { frames: ['https://calendly.com'] },
};

const TURNSTILE = 'https://challenges.cloudflare.com';
const CF_ANALYTICS_SCRIPT = 'https://static.cloudflareinsights.com';
const CF_ANALYTICS_CONNECT = 'https://cloudflareinsights.com';

/** Directives that browsers ignore inside <meta>; only valid as a response header. */
export function headerOnlyDirectives(reportPath: string): string[] {
  return ["frame-ancestors 'none'", `report-uri ${reportPath}`, 'report-to csp'];
}

function uniq(values: string[]): string[] {
  return [...new Set(values)];
}

export interface AstroCspConfig {
  algorithm: 'SHA-256';
  directives: string[];
  scriptDirective: { resources: string[] };
  styleDirective: { resources: string[] };
}

/** Build the value for Astro's `security.csp` config. Astro adds the script/style hashes. */
export function buildAstroCsp(o: ResolvedOptions): AstroCspConfig {
  const scripts = ["'self'", ...(o.allow.scripts ?? [])];
  const styles = ["'self'", ...(o.allow.styles ?? [])];
  const images = ["'self'", 'data:', ...(o.allow.images ?? [])];
  const fonts = ["'self'", ...(o.allow.fonts ?? [])];
  const connect = ["'self'", ...(o.allow.connect ?? [])];
  const frames: string[] = [...(o.allow.frames ?? [])];

  if (o.sanityImages) images.push('https://cdn.sanity.io');
  if (o.turnstile) {
    scripts.push(TURNSTILE);
    frames.push(TURNSTILE);
  }
  if (o.cloudflareAnalytics) {
    scripts.push(CF_ANALYTICS_SCRIPT);
    connect.push(CF_ANALYTICS_CONNECT);
  }
  for (const embed of o.embeds) {
    const src = EMBED_SOURCES[embed];
    frames.push(...src.frames);
    images.push(...(src.images ?? []));
  }

  const directives = [
    "default-src 'self'",
    `img-src ${uniq(images).join(' ')}`,
    `font-src ${uniq(fonts).join(' ')}`,
    `connect-src ${uniq(connect).join(' ')}`,
    `frame-src ${frames.length ? uniq(frames).join(' ') : "'none'"}`,
    "media-src 'self'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    'upgrade-insecure-requests',
  ];

  return {
    algorithm: 'SHA-256',
    directives,
    scriptDirective: { resources: uniq(scripts) },
    styleDirective: { resources: uniq(styles) },
  };
}

/** Normalize a CSP string: trim, drop empty directives, single "; " separator. */
export function normalizeCsp(csp: string): string {
  return csp
    .split(';')
    .map((d) => d.trim().replace(/\s+/g, ' '))
    .filter(Boolean)
    .join('; ');
}

/** Append header-only directives unless already present. */
export function withHeaderOnlyDirectives(csp: string, reportPath: string): string {
  if (!/^\/[a-z0-9_/-]{1,100}$/.test(reportPath)) throw new Error(`[astro-secure] Invalid CSP report path "${reportPath}".`);
  const normalized = normalizeCsp(csp);
  const present = new Set(normalized.split('; ').map((d) => d.split(' ')[0]?.toLowerCase()));
  const extra = headerOnlyDirectives(reportPath).filter((d) => !present.has(d.split(' ')[0]));
  return extra.length ? `${normalized}; ${extra.join('; ')}` : normalized;
}

/**
 * Parse a CSP like a browser: directive names and keywords are case-insensitive, and when a
 * directive is repeated the FIRST occurrence wins (later ones are ignored).
 * Values are lowercased so checks cannot be bypassed with 'UNSAFE-INLINE' (hashes keep their case).
 */
export function parseCsp(csp: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const directive of normalizeCsp(csp).split('; ')) {
    const [rawName, ...values] = directive.split(' ');
    const name = rawName?.toLowerCase();
    if (!name || map.has(name)) continue;
    map.set(
      name,
      values.map((v) => (/^'(sha256|sha384|sha512|nonce)-/i.test(v) ? v : v.toLowerCase())),
    );
  }
  return map;
}

/** Directive names that appear more than once (browsers ignore all but the first). */
export function duplicateDirectives(csp: string): string[] {
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const directive of normalizeCsp(csp).split('; ')) {
    const name = directive.split(' ')[0]?.toLowerCase();
    if (!name) continue;
    if (seen.has(name)) dup.add(name);
    seen.add(name);
  }
  return [...dup];
}
