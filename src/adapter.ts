import type { AstroIntegration } from 'astro';

export const SECURE_ADAPTER_MARK = '__astroSecureStaticHeaders';

/**
 * Wrap the Cloudflare adapter so Astro emits the CSP of static pages through `routeToHeaders`
 * (adapter feature `staticHeaders`) instead of a <meta> tag. The `astro-secure` integration
 * then writes it as a real response header in `_headers`, which enables `frame-ancestors`
 * and violation reporting (both ignored by browsers in <meta>).
 *
 * Relies on the adapter calling `setAdapter` in `astro:config:done`. CI must test this
 * against every new adapter version.
 */
export function secureCloudflare(adapter: AstroIntegration): AstroIntegration {
  const original = adapter.hooks['astro:config:done'];
  if (typeof original !== 'function') {
    throw new Error('[astro-secure] Unsupported adapter: missing astro:config:done hook.');
  }
  const wrapped: AstroIntegration = {
    ...adapter,
    hooks: {
      ...adapter.hooks,
      'astro:config:done': (options) => {
        let adapterSet = false;
        const result = original({
          ...options,
          setAdapter: (a) => {
            adapterSet = true;
            options.setAdapter({
              ...a,
              adapterFeatures: { ...a.adapterFeatures, staticHeaders: true },
            });
          },
        });
        const check = () => {
          if (!adapterSet) throw new Error('[astro-secure] Adapter did not call setAdapter; staticHeaders not enabled.');
        };
        return result instanceof Promise ? result.then(check) : check();
      },
    },
  };
  Object.defineProperty(wrapped, SECURE_ADAPTER_MARK, { value: true, enumerable: false });
  return wrapped;
}
