// Shared client logic for click-to-load embeds. No inline handlers (CSP-safe).
export function activateEmbeds() {
  for (const el of document.querySelectorAll('[data-as-embed]')) {
    if (el.dataset.asBound) continue;
    el.dataset.asBound = '1';
    const button = el.querySelector('button');
    button?.addEventListener('click', () => {
      const src = el.dataset.asEmbed;
      if (!src || !src.startsWith('https://')) return;
      const iframe = document.createElement('iframe');
      iframe.src = src;
      iframe.title = el.dataset.asTitle ?? '';
      iframe.loading = 'lazy';
      iframe.referrerPolicy = 'strict-origin-when-cross-origin';
      iframe.allow = 'autoplay; encrypted-media; picture-in-picture; fullscreen';
      iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-presentation allow-popups allow-forms');
      el.replaceChildren(iframe);
      iframe.focus();
    });
  }
}
