# Changelog

## 0.2.0 — 2026-11-12

Fixes from the security review of 2026-11-12. Several changes make builds fail where they
used to pass (fail closed), so this is a minor release.

### Breaking

- `submittedTooFast(elapsedMs, minMs)` now takes the **duration** the visitor spent on the form
  (measured client-side with `performance.now()`), not a client timestamp. Clock skew no longer
  drops real submissions with a fake success. Update the form to send `elapsedMs`.
- The build fails if `astro.config` sets `security.csp` (astro-secure manages the CSP).
- The build fails if `public/robots.txt`, `public/.well-known/security.txt` or
  `public/_redirects` exist (opt in with `allowRedirectsFile: true`).
- The build fails if pages use server islands (opt in with `allowServerIslands: true`).
- **Every** on-demand route is validated against the allowlist, whatever its origin
  (project, integration or Astro internal).
- Options are strictly validated: `cspReportPath`, `permissionsPolicy`, `allowedServerRoutes`,
  `securityContact`, `cspReportRateLimitBinding`.
- Allowlist: wildcard hosts are rejected in `scripts` and `connect`, over a whole TLD, and over
  shared-hosting domains (`workers.dev`, `pages.dev`, `github.io`, …).

### Security

- Astro's runtime image endpoint (`/_image`) is replaced in production builds by one that answers
  404: it proxied any `cdn.sanity.io` image (including SVG) through the client's domain.
- `astro-secure check` and the build now audit the CSP like a browser: case-insensitive keywords,
  first-wins duplicate directives, broad sources (`*`, `https:`, `data:`…) and unsafe wildcards in
  sensitive directives, `! Header` lines in `_headers`, unquoted / protocol-relative script `src`,
  unquoted inline handlers and style attributes.
- `_headers` rendering refuses line breaks (header injection).
- CSP report endpoint reads at most 16 KB even without `content-length`, warns when the
  configured rate-limit binding is missing, and truncates `disposition`.
- `verifyTurnstile` returns `success: false` for non-object responses instead of throwing.
- `.dev.vars` is removed from `dist/server` after the build.
