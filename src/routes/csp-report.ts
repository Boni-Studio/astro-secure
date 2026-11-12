import type { APIRoute } from 'astro';
// @ts-expect-error virtual module provided by the astro-secure Vite plugin
import config from 'virtual:astro-secure/config';
import { summarizeCspReports } from '../server/csp-report.js';

export const prerender = false;

const MAX_BYTES = 16 * 1024;
const ACCEPTED = ['application/reports+json', 'application/csp-report', 'application/json'];

export const POST: APIRoute = async ({ request, clientAddress }) => {
  const type = (request.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
  if (!ACCEPTED.includes(type)) return new Response(null, { status: 415 });

  const length = Number(request.headers.get('content-length') ?? '0');
  if (length > MAX_BYTES) return new Response(null, { status: 413 });

  if (config.cspReportRateLimitBinding) {
    try {
      const { env } = (await import(/* @vite-ignore */ 'cloudflare:workers')) as { env: Record<string, unknown> };
      const limiter = env[config.cspReportRateLimitBinding] as
        | { limit: (o: { key: string }) => Promise<{ success: boolean }> }
        | undefined;
      if (limiter && !(await limiter.limit({ key: `csp:${clientAddress ?? 'unknown'}` })).success) {
        return new Response(null, { status: 429 });
      }
    } catch {
      // Not running on Workers (tests/dev): skip rate limiting.
    }
  }

  const raw = await request.text();
  if (raw.length > MAX_BYTES) return new Response(null, { status: 413 });

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return new Response(null, { status: 400 });
  }

  for (const summary of summarizeCspReports(body)) {
    // Structured log → Workers Logs. No query strings, no IPs (privacy).
    console.warn(JSON.stringify({ event: 'csp_violation', ...summary }));
  }
  return new Response(null, { status: 204 });
};
