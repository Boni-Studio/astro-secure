import type { AiBotPolicy } from './options.js';

/** Crawlers that collect data to train models. Blocked under "search-only". */
export const AI_TRAINING_CRAWLERS = [
  'GPTBot',
  'ClaudeBot',
  'Google-Extended',
  'Applebot-Extended',
  'CCBot',
  'meta-externalagent',
  'Bytespider',
  'Amazonbot',
  'cohere-training-data-crawler',
];

/** Crawlers/agents that search, cite or act for a user. Allowed under "search-only". */
export const AI_SEARCH_AGENTS = [
  'OAI-SearchBot',
  'ChatGPT-User',
  'Claude-SearchBot',
  'Claude-User',
  'PerplexityBot',
  'Perplexity-User',
];

const SIGNALS: Record<AiBotPolicy, string> = {
  'search-only': 'search=yes, ai-input=yes, ai-train=no',
  'allow-all': 'search=yes, ai-input=yes, ai-train=yes',
  'block-all': 'search=yes, ai-input=no, ai-train=no',
};

export function buildRobotsTxt(opts: { policy: AiBotPolicy; site?: string | undefined; noindex: boolean }): string {
  if (opts.noindex) return 'User-agent: *\nDisallow: /\n';

  const lines: string[] = [
    '# Content Signals: https://contentsignals.org',
    'User-agent: *',
    `Content-Signal: ${SIGNALS[opts.policy]}`,
    'Allow: /',
    '',
  ];

  const blocked =
    opts.policy === 'search-only'
      ? AI_TRAINING_CRAWLERS
      : opts.policy === 'block-all'
        ? [...AI_TRAINING_CRAWLERS, ...AI_SEARCH_AGENTS]
        : [];

  for (const agent of blocked) lines.push(`User-agent: ${agent}`, 'Disallow: /', '');

  if (opts.site) lines.push(`Sitemap: ${new URL('/sitemap-index.xml', opts.site).href}`);
  return `${lines.join('\n').trimEnd()}\n`;
}
