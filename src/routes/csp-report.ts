import type { APIRoute } from 'astro';
// @ts-expect-error virtual module provided by the astro-secure Vite plugin
import config from 'virtual:astro-secure/config';
import { summarizeCspReports } from '../server/csp-report.js';

export const prerender = false;

export const MAX_BYTES = 16 * 1024;
const ACCEPTED = ['application/reports+json', 'application/csp-report', 'application/json'];

let warnedMissingBinding = false;

/** Read at most `limit` bytes; returns null (and cancels the stream) when the body is larger. */
export async function readLimited(request: Request, limit: number): Promise<string | null> {
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export const POST: APIRoute = async ({ request, clientAddress }) => {
  const type = (request.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
  if (!ACCEPTED.includes(type)) return new Response(null, { status: 415 });

  const length = Number(request.headers.get('content-length') ?? '0');
  if (length > MAX_BYTES) return new Response(null, { status: 413 });

  if (config.cspReportRateLimitBinding) {
    let limiter: { limit: (o: { key: string }) => Promise<{ success: boolean }> } | undefined;
    try {
      const { env } = (await import(/* @vite-ignore */ 'cloudflare:workers')) as { env: Record<string, unknown> };
      limiter = env[config.cspReportRateLimitBinding] as typeof limiter;
    } catch {
      // Not running on Workers (tests/dev).
    }
    if (!limiter) {
      if (!warnedMissingBinding) {
        warnedMissingBinding = true;
        console.warn(JSON.stringify({ event: 'csp_report_rate_limit_missing', binding: config.cspReportRateLimitBinding }));
      }
    } else if (!(await limiter.limit({ key: `csp:${clientAddress ?? 'unknown'}` }).catch(() => ({ success: false }))).success) {
      return new Response(null, { status: 429 });
    }
  }

  // Never trust content-length: chunked bodies have none.
  const raw = await readLimited(request, MAX_BYTES);
  if (raw === null) return new Response(null, { status: 413 });

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
