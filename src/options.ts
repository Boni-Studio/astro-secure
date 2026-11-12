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
}

export interface ResolvedOptions extends Required<Omit<SecureOptions, 'cspReportRateLimitBinding' | 'securityTxtExpires'>> {
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
  };
  if (options.securityTxtExpires) resolved.securityTxtExpires = options.securityTxtExpires;
  if (options.cspReportRateLimitBinding) resolved.cspReportRateLimitBinding = options.cspReportRateLimitBinding;

  for (const [kind, hosts] of Object.entries(resolved.allow)) {
    for (const host of hosts ?? []) assertSafeSource(kind, host);
  }
  return resolved;
}

/** Reject sources that would silently disable the CSP. */
export function assertSafeSource(kind: string, source: string): void {
  const s = source.trim();
  const forbidden = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", '*', 'http:', 'https:', 'data:', 'blob:'];
  if (forbidden.includes(s) || s.includes(';') || /\s/.test(s)) {
    throw new Error(`[astro-secure] Unsafe CSP source in allow.${kind}: "${source}". Use a specific https host.`);
  }
  if (!/^https:\/\/[a-z0-9.-]+(:\d+)?(\/[^\s;]*)?$/i.test(s) && !/^https:\/\/\*\.[a-z0-9.-]+$/i.test(s)) {
    throw new Error(`[astro-secure] CSP source in allow.${kind} must be an https URL/host: "${source}".`);
  }
}
