export interface CspViolationSummary {
  directive: string;
  blocked: string;
  document: string;
  source?: string;
  disposition?: string;
}

/** Keep origin + path only: no query strings or fragments (may contain personal data). */
export function stripUrl(value: unknown): string {
  if (typeof value !== 'string' || !value) return '';
  if (!value.includes('://')) return value.slice(0, 100); // "inline", "eval", "self"...
  try {
    const u = new URL(value);
    return `${u.origin}${u.pathname}`.slice(0, 300);
  } catch {
    return 'invalid-url';
  }
}

type Rec = Record<string, unknown>;

/** Accepts both Reporting API (application/reports+json) and legacy report-uri bodies. */
export function summarizeCspReports(body: unknown, max = 20): CspViolationSummary[] {
  const items: Rec[] = [];
  if (Array.isArray(body)) {
    for (const r of body) {
      if (r && typeof r === 'object' && (r as Rec).type === 'csp-violation' && typeof (r as Rec).body === 'object') {
        items.push((r as Rec).body as Rec);
      }
    }
  } else if (body && typeof body === 'object' && typeof (body as Rec)['csp-report'] === 'object') {
    const legacy = (body as Rec)['csp-report'] as Rec;
    items.push({
      effectiveDirective: legacy['effective-directive'] ?? legacy['violated-directive'],
      blockedURL: legacy['blocked-uri'],
      documentURL: legacy['document-uri'],
      sourceFile: legacy['source-file'],
      disposition: legacy.disposition,
    });
  }

  return items.slice(0, max).map((b) => {
    const summary: CspViolationSummary = {
      directive: String(b.effectiveDirective ?? '').slice(0, 50),
      blocked: stripUrl(b.blockedURL),
      document: stripUrl(b.documentURL),
    };
    const source = stripUrl(b.sourceFile);
    if (source) summary.source = source;
    if (typeof b.disposition === 'string') summary.disposition = b.disposition.slice(0, 20);
    return summary;
  });
}
