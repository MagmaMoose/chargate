/** Sum of all numeric values in a totals map. */
export function totalCount(totals: Record<string, number>): number {
  return Object.values(totals).reduce((a, b) => a + (b ?? 0), 0);
}

/** Human-friendly relative/absolute timestamp; returns '—' for null. */
export function formatDate(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffMs = Date.now() - d.getTime();
  const diffMin = Math.round(diffMs / 60000);
  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffH = Math.round(diffMin / 60);
  if (diffH < 24) return `${diffH}h ago`;
  const diffD = Math.round(diffH / 24);
  if (diffD < 30) return `${diffD}d ago`;
  return d.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function shortSha(sha: string): string {
  return sha.slice(0, 7);
}
