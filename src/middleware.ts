import type { MiddlewareHandler } from 'astro';
// @ts-expect-error virtual module provided by the astro-secure Vite plugin
import config from 'virtual:astro-secure/config';
import { withHeaderOnlyDirectives } from './csp.js';
import { baseHeaders } from './headers.js';
import { resolveOptions } from './options.js';

const o = resolveOptions({ securityContact: 'n/a', ...config });
const BASE = baseHeaders(o);

/**
 * `_headers` only applies to static assets. On-demand responses (Actions, CSP reports and any
 * allowed server route) get the same headers here.
 */
export const onRequest: MiddlewareHandler = async (context, next) => {
  // Static output gets its headers from `_headers`. Touching prerendered responses would leak
  // per-route headers into `routeToHeaders` and fragment the CSP into many rules.
  if (context.isPrerendered) return next();
  const response = await next();
  let headers: Headers;
  try {
    for (const [name, value] of Object.entries(BASE)) {
      if (!response.headers.has(name)) response.headers.set(name, value);
    }
    headers = response.headers;
  } catch {
    // Immutable headers (e.g. a fetched Response): clone.
    const clone = new Response(response.body, response);
    for (const [name, value] of Object.entries(BASE)) {
      if (!clone.headers.has(name)) clone.headers.set(name, value);
    }
    headers = clone.headers;
    applyCsp(headers);
    return clone;
  }
  applyCsp(headers);
  return response;
};

function applyCsp(headers: Headers) {
  const csp = headers.get('content-security-policy');
  if (csp) {
    headers.set('content-security-policy', withHeaderOnlyDirectives(csp, o.cspReportPath));
  } else if (!(headers.get('content-type') ?? '').includes('text/html')) {
    // Non-HTML responses (JSON from Actions): lock everything down.
    headers.set('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
  }
}
