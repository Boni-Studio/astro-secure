import type { AstroIntegration, RouteToHeaders } from 'astro';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditCsp } from './check.js';
import { buildAstroCsp } from './csp.js';
import { buildHeaderRules, mergeHeadersFile, renderHeaderRules, validateHeadersFile } from './headers.js';
import { resolveOptions, type SecureOptions } from './options.js';
import { buildRobotsTxt } from './robots.js';
import { buildSecurityTxt } from './security-txt.js';

export type { SecureOptions, CspAllowlist, Embed, AiBotPolicy } from './options.js';
export { secureCloudflare } from './adapter.js';

const VIRTUAL_ID = 'virtual:astro-secure/config';
const RESOLVED_VIRTUAL_ID = `\0${VIRTUAL_ID}`;

/** Routes Astro injects for Actions and server islands (the latter always exists with an adapter). */
const ACTIONS_ROUTE = '/_actions/[...path]';
const SERVER_ISLANDS_ROUTE = '/_server-islands/[name]';

/** Files in public/ that would silently override or bypass security output. */
const FORBIDDEN_PUBLIC_FILES = ['robots.txt', '.well-known/security.txt'];

export default function secure(userOptions: SecureOptions): AstroIntegration {
  const o = resolveOptions(userOptions);
  let site: string | undefined;
  let serverDir: URL | undefined;
  let imageRoute = '/_image';
  let routeToHeaders: RouteToHeaders | undefined;
  let hasPrerenderedPages = false;

  return {
    name: '@boni-studio/astro-secure',
    hooks: {
      'astro:config:setup': ({ config, command, updateConfig, injectRoute, addMiddleware }) => {
        // Fail closed: a user-provided CSP would be merged into ours and could widen it.
        if (config.security?.csp) {
          throw new Error('[astro-secure] Remove `security.csp` from astro.config: astro-secure manages the CSP. Use the `allow` / `embeds` options.');
        }
        imageRoute = config.image?.endpoint?.route ?? '/_image';
        updateConfig({
          security: {
            checkOrigin: true,
            // CSP only for builds: in `astro dev` Vite injects unhashed <style> tags (HMR) that a strict
            // CSP blocks, and Astro does not support CSP in dev. Security is tested on `build` + `wrangler dev`.
            ...(command !== 'dev' && {
              // Directive strings are validated in options.ts; Astro types them as template literals.
              csp: buildAstroCsp(o) as NonNullable<NonNullable<Parameters<typeof updateConfig>[0]['security']>['csp']>,
            }),
          },
          // Images are optimized at build time. Astro still injects an on-demand image endpoint
          // whenever the site has server code; in production it answers 404 instead of proxying.
          ...(command === 'build' && {
            image: {
              endpoint: {
                route: imageRoute,
                entrypoint: fileURLToPath(new URL('./routes/image-disabled.js', import.meta.url)),
              },
            },
          }),
          vite: {
            plugins: [
              {
                name: 'astro-secure-config',
                resolveId: (id: string) => (id === VIRTUAL_ID ? RESOLVED_VIRTUAL_ID : undefined),
                load: (id: string) =>
                  id === RESOLVED_VIRTUAL_ID
                    ? `export default ${JSON.stringify({
                        securityContact: o.securityContact,
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
        serverDir = config.build.server;
        if (!config.adapter) {
          throw new Error('[astro-secure] An adapter is required. Use `secureCloudflare(cloudflare())`.');
        }
        if (!site) logger.warn('`site` is not set: robots.txt and security.txt will not include absolute URLs.');
      },

      // Every on-demand route, whatever its origin (project, integration, Astro), must be allowlisted.
      'astro:routes:resolved': ({ routes }) => {
        const allowed = new Set([ACTIONS_ROUTE, SERVER_ISLANDS_ROUTE, imageRoute, o.cspReportPath, ...o.allowedServerRoutes]);
        hasPrerenderedPages = routes.some((r) => r.isPrerendered && r.type === 'page');
        const offenders = routes.filter((r) => !r.isPrerendered && !allowed.has(r.pattern));
        if (offenders.length) {
          throw new Error(
            `[astro-secure] On-demand routes not in allowedServerRoutes: ${offenders
              .map((r) => `${r.pattern} (${r.origin})`)
              .join(', ')}. Prerender them or add them to allowedServerRoutes (requires security review).`,
          );
        }
      },

      'astro:build:generated': ({ routeToHeaders: headers }) => {
        routeToHeaders = headers;
      },

      'astro:build:done': async ({ dir, logger }) => {
        const errors: string[] = [];

        // public/ overrides that would bypass the generated security files.
        for (const file of FORBIDDEN_PUBLIC_FILES) {
          if (await exists(new URL(file, dir))) {
            errors.push(`public/${file} is not allowed: astro-secure generates it (configure it through the integration options).`);
          }
        }
        if (!o.allowRedirectsFile && (await exists(new URL('_redirects', dir)))) {
          errors.push('public/_redirects is not allowed (it can send any page to an external site). Set allowRedirectsFile: true after review.');
        }
        if (!o.allowServerIslands && (await htmlContains(fileURLToPath(dir), '/_server-islands/'))) {
          errors.push('Server islands (server:defer) are not allowed: they render on demand. Set allowServerIslands: true after review.');
        }

        const routeCsp = new Map<string, string>();
        for (const [route, payload] of routeToHeaders ?? []) {
          const csp = payload.headers.get('content-security-policy');
          if (csp) routeCsp.set(route, csp);
        }

        // Fail closed: without staticHeaders, Astro falls back to <meta> and we would ship
        // a CSP without frame-ancestors or reporting.
        if (hasPrerenderedPages && routeCsp.size === 0) {
          errors.push('No CSP headers were collected for static pages. Wrap the adapter: `adapter: secureCloudflare(cloudflare())`.');
        }

        const rules = buildHeaderRules(o, routeCsp);
        for (const rule of rules) {
          const csp = rule.headers['Content-Security-Policy'];
          if (csp) errors.push(...auditCsp(csp).map((e) => `${rule.path}: ${e}`));
        }

        const headersUrl = new URL('_headers', dir);
        const existing = await readFile(headersUrl, 'utf8').catch(() => '');
        const merged = mergeHeadersFile(existing, renderHeaderRules(rules));
        errors.push(...validateHeadersFile(merged));

        if (errors.length) throw new Error(`[astro-secure]\n- ${[...new Set(errors)].join('\n- ')}`);
        await writeFile(headersUrl, merged);

        await writeFile(new URL('robots.txt', dir), buildRobotsTxt({ policy: o.aiBots, site, noindex: o.noindex }));
        await mkdir(new URL('.well-known/', dir), { recursive: true });
        await writeFile(
          new URL('.well-known/security.txt', dir),
          buildSecurityTxt({ contact: o.securityContact, expires: o.securityTxtExpires, languages: o.securityTxtLanguages, site }),
        );

        // wrangler copies local secrets next to the build output; never leave them in dist/.
        if (serverDir) {
          const devVars = new URL('.dev.vars', serverDir);
          if (await exists(devVars)) {
            await rm(devVars);
            logger.info('Removed .dev.vars from the server build output.');
          }
        }

        logger.info(
          `_headers: ${rules.length} rule(s), CSP ${routeCsp.size ? (new Set(routeCsp.values()).size === 1 ? 'global' : 'per route') : 'n/a'}.`,
        );
      },
    },
  };
}

async function exists(url: URL): Promise<boolean> {
  try {
    await readFile(url);
    return true;
  } catch {
    return false;
  }
}

async function htmlContains(dir: string, needle: string): Promise<boolean> {
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.html')) continue;
    if ((await readFile(join(entry.parentPath, entry.name), 'utf8')).includes(needle)) return true;
  }
  return false;
}
