import type { APIRoute } from 'astro';

export const prerender = false;

/**
 * Replaces Astro's on-demand image endpoint in production builds. Images are optimized at
 * build time; a runtime endpoint would proxy remote images through the client's domain.
 */
export const ALL: APIRoute = () => new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain' } });
