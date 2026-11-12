import { describe, expect, it, vi } from 'vitest';
import type { AstroIntegration } from 'astro';
import cloudflare from '@astrojs/cloudflare';
import { secureCloudflare } from '../src/adapter.js';

/**
 * Guards the one fragile point of the design: the wrapper relies on the Cloudflare adapter
 * calling setAdapter() inside astro:config:done. Renovate bumps of @astrojs/cloudflare run this.
 */
describe('secureCloudflare', () => {
  it('enables staticHeaders on the real Cloudflare adapter', async () => {
    const wrapped = secureCloudflare(cloudflare({ prerenderEnvironment: 'node', imageService: 'compile' }));
    const setAdapter = vi.fn();
    const hook = wrapped.hooks['astro:config:done']!;
    await hook({
      setAdapter,
      config: {
        root: new URL('file:///tmp/project/'),
        outDir: new URL('file:///tmp/project/dist/'),
        build: { client: new URL('file:///tmp/project/dist/client/'), server: new URL('file:///tmp/project/dist/server/') },
        output: 'static',
        base: '/',
        session: undefined,
        experimental: {},
        vite: {},
      },
      logger: { info() {}, warn() {}, error() {}, debug() {}, fork: () => ({}) },
      injectTypes: () => new URL('file:///tmp/x.d.ts'),
      buildOutput: 'static',
    } as unknown as Parameters<NonNullable<AstroIntegration['hooks']['astro:config:done']>>[0]);

    expect(setAdapter).toHaveBeenCalledTimes(1);
    expect(setAdapter.mock.calls[0]![0].adapterFeatures.staticHeaders).toBe(true);
    expect(setAdapter.mock.calls[0]![0].name).toBe('@astrojs/cloudflare');
  });

  it('fails if the adapter never calls setAdapter', () => {
    const fake: AstroIntegration = { name: 'fake', hooks: { 'astro:config:done': () => {} } };
    expect(() =>
      secureCloudflare(fake).hooks['astro:config:done']!({ setAdapter: () => {} } as never),
    ).toThrow(/setAdapter/);
  });
});
