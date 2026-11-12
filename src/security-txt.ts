/** RFC 9116 security.txt */
export function buildSecurityTxt(opts: {
  contact: string;
  expires?: string | undefined;
  languages: string[];
  site?: string | undefined;
  now?: Date;
}): string {
  const now = opts.now ?? new Date();
  const expires = opts.expires ? new Date(opts.expires) : new Date(now.getTime() + 365 * 24 * 3600 * 1000);
  if (Number.isNaN(expires.getTime())) throw new Error('[astro-secure] Invalid securityTxtExpires date.');

  const contact = opts.contact.includes('@') && !opts.contact.startsWith('mailto:') ? `mailto:${opts.contact}` : opts.contact;
  const lines = [`Contact: ${contact}`, `Expires: ${expires.toISOString()}`, `Preferred-Languages: ${opts.languages.join(', ')}`];
  if (opts.site) lines.push(`Canonical: ${new URL('/.well-known/security.txt', opts.site).href}`);
  return `${lines.join('\n')}\n`;
}

export function securityTxtExpiry(content: string): Date | null {
  const match = content.match(/^Expires:\s*(.+)$/m);
  if (!match?.[1]) return null;
  const date = new Date(match[1].trim());
  return Number.isNaN(date.getTime()) ? null : date;
}
