import type { AstroIntegration, RouteToHeaders } from 'astro';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { buildAstroCsp } from './csp.js';
import { buildHeaderRules, mergeHeadersFile, renderHeaderRules, validateHeadersFile } from './headers.js';
import { resolveOptions, type SecureOptions } from './options.js';
import { buildRobotsTxt } from './robots.js';
import { buildSecurityTxt } from './security-txt.js';

export type { SecureOptions, CspAllowlist, Embed, AiBotPolicy } from './options.js';
export { secureCloudflare } from './adapter.js';

const VIRTUAL_ID = 'virtual:astro-secure/config';
const RESOLVED_VIRTUAL_ID = `\0${VIRTUAL_ID}`;

/** Routes Astro itself renders on demand that are always allowed. */
const INTERNAL_SERVER_ROUTES = ['/_actions/[...path]', '/_server-islands/[name]'];

export default function secure(userOptions: SecureOptions): AstroIntegration {
  const o = resolveOptions(userOptions);
  let site: string | undefined;
  let routeToHeaders: RouteToHeaders | undefined;
  let hasPrerenderedPages = false;

  return {
    name: '@boni-studio/astro-secure',
    hooks: {
      'astro:config:setup': ({ config, updateConfig, injectRoute, addMiddleware, logger }) => {
        if (config.security?.csp) {
          logger.warn('`security.csp` is set in astro.config; astro-secure manages it. Your value will be merged.');
        }
        updateConfig({
          security: {
            checkOrigin: true,
            // Directive strings are validated in options.ts; Astro types them as template literals.
            csp: buildAstroCsp(o) as NonNullable<NonNullable<Parameters<typeof updateConfig>[0]['security']>['csp']>,
          },
          vite: {
            plugins: [
              {
                name: 'astro-secure-config',
                resolveId: (id: string) => (id === VIRTUAL_ID ? RESOLVED_VIRTUAL_ID : undefined),
                load: (id: string) =>
                  id === RESOLVED_VIRTUAL_ID
                    ? `export default ${JSON.stringify({
                        cspReportPath: o.cspReportPath,
                        cspReportRateLimitBinding: o.cspReportRateLimitBinding ?? null,
                        hstsPreload: o.hstsPreload,
                        permissionsPolicy: o.permissionsPolicy,
                        noindex: o.noindex,
                      })};`
                    : undefined,
              },
            ],
          },
        });
        injectRoute({
          pattern: o.cspReportPath,
          entrypoint: fileURLToPath(new URL('./routes/csp-report.js', import.meta.url)),
          prerender: false,
        });
        addMiddleware({
          entrypoint: fileURLToPath(new URL('./middleware.js', import.meta.url)),
          order: 'post',
        });
      },

      'astro:config:done': ({ config, logger }) => {
        site = config.site;
        if (!config.adapter) {
          throw new Error('[astro-secure] An adapter is required. Use `secureCloudflare(cloudflare())`.');
        }
        if (!site) logger.warn('`site` is not set: robots.txt and security.txt will not include absolute URLs.');
      },

      'astro:routes:resolved': ({ routes }) => {
        const allowed = new Set([...INTERNAL_SERVER_ROUTES, o.cspReportPath, ...o.allowedServerRoutes]);
        hasPrerenderedPages = routes.some((r) => r.isPrerendered && r.type === 'page');
        const offenders = routes.filter(
          (r) => !r.isPrerendered && r.origin === 'project' && !allowed.has(r.pattern),
        );
        if (offenders.length) {
          throw new Error(
            `[astro-secure] On-demand routes not in allowedServerRoutes: ${offenders
              .map((r) => r.pattern)
              .join(', ')}. Prerender them or add them to allowedServerRoutes (requires security review).`,
          );
        }
      },

      'astro:build:generated': ({ routeToHeaders: headers }) => {
        routeToHeaders = headers;
      },

      'astro:build:done': async ({ dir, logger }) => {
        const routeCsp = new Map<string, string>();
        for (const [route, payload] of routeToHeaders ?? []) {
          const csp = payload.headers.get('content-security-policy');
          if (csp) routeCsp.set(route, csp);
        }

        // Fail closed: without staticHeaders, Astro falls back to <meta> and we would ship
        // a CSP without frame-ancestors or reporting.
        if (hasPrerenderedPages && routeCsp.size === 0) {
          throw new Error(
            '[astro-secure] No CSP headers were collected for static pages. Wrap the adapter: `adapter: secureCloudflare(cloudflare())`.',
          );
        }

        const rules = buildHeaderRules(o, routeCsp);
        const headersUrl = new URL('_headers', dir);
        const existing = await readFile(headersUrl, 'utf8').catch(() => '');
        const merged = mergeHeadersFile(existing, renderHeaderRules(rules));
        const errors = validateHeadersFile(merged);
        if (errors.length) throw new Error(`[astro-secure] ${errors.join(' ')}`);
        await writeFile(headersUrl, merged);

        await writeIfMissing(new URL('robots.txt', dir), buildRobotsTxt({ policy: o.aiBots, site, noindex: o.noindex }), logger);
        await mkdir(new URL('.well-known/', dir), { recursive: true });
        await writeIfMissing(
          new URL('.well-known/security.txt', dir),
          buildSecurityTxt({
            contact: o.securityContact,
            expires: o.securityTxtExpires,
            languages: o.securityTxtLanguages,
            site,
          }),
          logger,
        );

        logger.info(
          `_headers: ${rules.length} rule(s), CSP ${routeCsp.size ? (new Set(routeCsp.values()).size === 1 ? 'global' : 'per route') : 'n/a'}.`,
        );
      },
    },
  };
}

async function writeIfMissing(url: URL, content: string, logger: { warn: (m: string) => void }) {
  try {
    await readFile(url);
    logger.warn(`${fileURLToPath(url)} exists (from public/); not overwritten.`);
  } catch {
    await writeFile(url, content);
  }
}
