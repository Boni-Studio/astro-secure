# @boni-studio/astro-secure

Secure-by-default baseline for Astro 7 sites deployed to Cloudflare Workers.

One integration gives every site the same hardened setup; fixes ship as patch releases and reach
all sites through Renovate.

## What it does

| Area | Behavior |
|---|---|
| **CSP** | Enables Astro's hashed CSP and delivers it as a **real response header** (not `<meta>`), so `frame-ancestors` and violation reporting work. No `unsafe-inline` / `unsafe-eval`. |
| **Security headers** | HSTS (no preload by default), X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP, Reporting-Endpoints — on static and on-demand responses. |
| **CSRF** | `security.checkOrigin: true`. |
| **Server surface** | Build fails if a project route renders on demand without being listed in `allowedServerRoutes`. |
| **CSP reports** | `POST /_csp-report` logs sanitized violations (no query strings, no IPs) to Workers Logs. |
| **AI crawlers** | `robots.txt` with Content Signals; default: allow search agents, block training crawlers. |
| **security.txt** | RFC 9116 file at `/.well-known/security.txt`. |
| **Server helpers** | Turnstile verification (fail closed), rate limiting, honeypot/timing, email header sanitization, signed webhooks (HMAC + timestamp), provider-agnostic email (Resend). |
| **Components** | Click-to-load embeds (YouTube, generic iframe), Turnstile widget, Cloudflare Web Analytics. |
| **CI check** | `astro-secure check` validates the build output (headers, CSP, inline handlers/styles, external scripts, security.txt expiry). |

## Usage

```ts
// astro.config.ts
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import secure, { secureCloudflare } from '@boni-studio/astro-secure';

export default defineConfig({
  site: 'https://example.com',
  output: 'static',
  adapter: secureCloudflare(cloudflare({ prerenderEnvironment: 'node', imageService: 'compile' })),
  integrations: [
    secure({
      securityContact: 'security@example.com',
      embeds: ['youtube'],
      cloudflareAnalytics: true,
    }),
  ],
});
```

`secureCloudflare()` is required: it enables Astro's `staticHeaders` adapter feature so the CSP of
static pages can be written to `_headers`. The build fails if it is missing.

```sh
astro build && astro-secure check dist/client
```

## Server helpers

```ts
import { verifyTurnstile, checkRateLimit, rateLimitKey, clientIp } from '@boni-studio/astro-secure/server';
```

## Options

See [`src/options.ts`](src/options.ts). Every third-party host must be declared explicitly
(`allow`, `embeds`, `turnstile`, `cloudflareAnalytics`); unsafe sources are rejected at build time.

## Constraints imposed by the CSP

- No inline `style=""` or `on*=""` attributes.
- No `<ClientRouter />` (view transitions) and no Shiki (inline styles).
- CSP is not applied in `astro dev`; test with `astro build` + `wrangler dev`.

## Known fragility

`secureCloudflare()` intercepts `setAdapter` inside the Cloudflare adapter's `astro:config:done`
hook. `test/adapter.test.ts` runs against the real adapter and must pass on every adapter upgrade.

## Releases

Published from CI only, with npm Trusted Publishing (OIDC) and provenance. Semver:
patch = security fix (auto-merged by Renovate when CI passes), minor = policy change, major = breaking.

See [SECURITY.md](SECURITY.md) to report a vulnerability.
