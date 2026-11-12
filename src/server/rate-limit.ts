/** Cloudflare Workers Rate Limiting binding. */
export interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/**
 * Returns true if the request may proceed.
 * When `required` is true (production), a missing binding blocks the request (fail closed).
 */
export async function checkRateLimit(
  binding: RateLimitBinding | undefined,
  key: string,
  { required = true }: { required?: boolean } = {},
): Promise<boolean> {
  if (!binding) return !required;
  try {
    const { success } = await binding.limit({ key });
    return success;
  } catch {
    return false;
  }
}

/** Build a rate-limit key from the client IP and a scope (e.g. form name). */
export function rateLimitKey(scope: string, ip: string | null | undefined): string {
  return `${scope}:${ip ?? 'unknown'}`;
}
