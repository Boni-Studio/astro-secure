export type Embed = 'youtube' | 'vimeo' | 'google-maps' | 'calendly';
export type AiBotPolicy = 'search-only' | 'allow-all' | 'block-all';

export interface CspAllowlist {
  /** Extra hosts allowed to serve scripts (e.g. "https://example.com"). */
  scripts?: string[];
  styles?: string[];
  images?: string[];
  fonts?: string[];
  connect?: string[];
  frames?: string[];
}

export interface SecureOptions {
  /** Contact for /.well-known/security.txt (email address or https URL). */
  securityContact: string;
  /** ISO date when security.txt expires. Defaults to one year after the build. */
  securityTxtExpires?: string;
  /** Preferred languages for security.txt (e.g. ["es", "en"]). */
  securityTxtLanguages?: string[];
  /** Third-party hosts explicitly approved for this site. Changes require CODEOWNERS review. */
  allow?: CspAllowlist;
  /** Click-to-load embeds used by the site. Each one adds only the hosts it needs. */
  embeds?: Embed[];
  /** Load Cloudflare Turnstile (forms). Default: true. */
  turnstile?: boolean;
  /** Cloudflare Web Analytics (cookieless). Default: false. */
  cloudflareAnalytics?: boolean;
  /** Allow images from Sanity's CDN. Default: true. */
  sanityImages?: boolean;
  /** HSTS preload. Only enable after auditing every subdomain. Default: false. */
  hstsPreload?: boolean;
  /** Override or extend Permissions-Policy features (feature -> allowlist, e.g. { fullscreen: "(self)" }). */
  permissionsPolicy?: Record<string, string>;
  /** AI crawler policy for robots.txt. Default: "search-only". */
  aiBots?: AiBotPolicy;
  /** Path that receives CSP violation reports. Default: "/_csp-report". */
  cspReportPath?: string;
  /** Name of the Workers Rate Limiting binding used by the CSP report endpoint. Optional. */
  cspReportRateLimitBinding?: string;
  /**
   * Project routes allowed to render on demand (prerender = false).
   * Any other on-demand project route fails the build.
   */
  allowedServerRoutes?: string[];
  /** Emit noindex everywhere (preview deployments). Default: false. */
  noindex?: boolean;
  /** Allow pages to use server islands (`server:defer`). Default: false (build fails if used). */
  allowServerIslands?: boolean;
  /** Allow a `public/_redirects` file (it can send any route to an external site). Default: false. */
  allowRedirectsFile?: boolean;
}

export interface ResolvedOptions
  extends Required<Omit<SecureOptions, 'cspReportRateLimitBinding' | 'securityTxtExpires'>> {
  cspReportRateLimitBinding?: string;
  securityTxtExpires?: string;
}

export function resolveOptions(options: SecureOptions): ResolvedOptions {
  if (!options || !options.securityContact) {
    throw new Error('[astro-secure] `securityContact` is required (used in /.well-known/security.txt).');
  }
  const resolved: ResolvedOptions = {
    securityContact: options.securityContact,
    securityTxtLanguages: options.securityTxtLanguages ?? ['es', 'en'],
    allow: options.allow ?? {},
    embeds: options.embeds ?? [],
    turnstile: options.turnstile ?? true,
    cloudflareAnalytics: options.cloudflareAnalytics ?? false,
    sanityImages: options.sanityImages ?? true,
    hstsPreload: options.hstsPreload ?? false,
    permissionsPolicy: options.permissionsPolicy ?? {},
    aiBots: options.aiBots ?? 'search-only',
    cspReportPath: options.cspReportPath ?? '/_csp-report',
    allowedServerRoutes: options.allowedServerRoutes ?? [],
    noindex: options.noindex ?? false,
    allowServerIslands: options.allowServerIslands ?? false,
    allowRedirectsFile: options.allowRedirectsFile ?? false,
  };
  if (options.securityTxtExpires) resolved.securityTxtExpires = options.securityTxtExpires;
  if (options.cspReportRateLimitBinding) {
    if (!/^[A-Z][A-Z0-9_]{0,62}$/.test(options.cspReportRateLimitBinding)) {
      throw new Error('[astro-secure] cspReportRateLimitBinding must be an UPPER_SNAKE_CASE binding name.');
    }
    resolved.cspReportRateLimitBinding = options.cspReportRateLimitBinding;
  }

  // Values below end up inside response headers or the CSP: reject anything that could inject.
  if (!/^\/[a-z0-9_/-]{1,100}$/.test(resolved.cspReportPath)) {
    throw new Error(`[astro-secure] Invalid cspReportPath "${resolved.cspReportPath}". Use a path like "/_csp-report".`);
  }
  for (const [feature, allowlist] of Object.entries(resolved.permissionsPolicy)) {
    if (!/^[a-z][a-z0-9-]{0,60}$/.test(feature)) {
      throw new Error(`[astro-secure] Invalid Permissions-Policy feature "${feature}".`);
    }
    if (!/^(\*|\((\s*(self|"https:\/\/[a-z0-9.-]+(:\d+)?")\s*)*\))$/.test(allowlist)) {
      throw new Error(`[astro-secure] Invalid Permissions-Policy allowlist for "${feature}": ${JSON.stringify(allowlist)}.`);
    }
  }
  for (const route of resolved.allowedServerRoutes) {
    if (!/^\/[\w\-./[\]]{0,200}$/.test(route)) throw new Error(`[astro-secure] Invalid allowedServerRoutes entry "${route}".`);
  }
  if (!/^(mailto:)?[^\s@<>]+@[^\s@<>]+\.[a-z]{2,}$/i.test(resolved.securityContact) && !/^https:\/\/\S+$/.test(resolved.securityContact)) {
    throw new Error('[astro-secure] securityContact must be an email address or an https URL.');
  }

  for (const [kind, hosts] of Object.entries(resolved.allow)) {
    for (const host of hosts ?? []) assertSafeSource(kind, host);
  }
  return resolved;
}

/** Shared-hosting suffixes where anyone can get a subdomain: never allowed behind a wildcard. */
export const SHARED_HOSTING_SUFFIXES = [
  'workers.dev',
  'pages.dev',
  'github.io',
  'githubusercontent.com',
  'vercel.app',
  'netlify.app',
  'cloudfront.net',
  'amazonaws.com',
  'herokuapp.com',
  'firebaseapp.com',
  'web.app',
  'azurewebsites.net',
  'appspot.com',
  'onrender.com',
  'fly.dev',
  'glitch.me',
  'ngrok.io',
  'ngrok-free.app',
  'trycloudflare.com',
];

/** Directives where any wildcard host is rejected (they can execute or exfiltrate). */
const NO_WILDCARD_KINDS = new Set(['scripts', 'connect']);

/** Reject sources that would silently weaken the CSP. */
export function assertSafeSource(kind: string, source: string): void {
  const s = source.trim().toLowerCase();
  const forbidden = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'", '*', 'http:', 'https:', 'data:', 'blob:', 'filesystem:'];
  if (forbidden.includes(s) || /[;,\s'"]/.test(s)) {
    throw new Error(`[astro-secure] Unsafe CSP source in allow.${kind}: "${source}". Use a specific https host.`);
  }
  const exact = /^https:\/\/([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(\/[^\s;,]*)?$/;
  const wildcard = /^https:\/\/\*\.(([a-z0-9-]+\.)+[a-z]{2,})$/;
  if (exact.test(s)) return;
  const match = s.match(wildcard);
  if (!match) throw new Error(`[astro-secure] CSP source in allow.${kind} must be an https URL/host: "${source}".`);

  const suffix = match[1]!;
  if (NO_WILDCARD_KINDS.has(kind)) {
    throw new Error(`[astro-secure] Wildcard hosts are not allowed in allow.${kind}: "${source}". List exact hosts.`);
  }
  if (suffix.split('.').length < 2) {
    throw new Error(`[astro-secure] Wildcard over a whole TLD in allow.${kind}: "${source}".`);
  }
  if (SHARED_HOSTING_SUFFIXES.some((h) => suffix === h || suffix.endsWith(`.${h}`))) {
    throw new Error(`[astro-secure] Wildcard over a shared-hosting domain in allow.${kind}: "${source}" (anyone can get a subdomain there).`);
  }
}
