import type { Severity } from '../types';
import { SEVERITIES } from '../types';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev-badge sev-${severity}`}>{severity}</span>;
}

/**
 * A compact row of per-severity counts (e.g. for a repo row). Zero counts are
 * rendered muted so the columns line up visually.
 */
export function SeverityCounts({ totals }: { totals: Record<string, number> }) {
  return (
    <div className="sev-counts">
      {SEVERITIES.map((sev) => {
        const n = totals[sev] ?? 0;
        return (
          <span
            key={sev}
            className={`sev-count ${n === 0 ? 'muted' : ''}`}
            title={`${n} ${sev}`}
          >
            <span className={`sev-dot bg-${sev}`} />
            {n}
          </span>
        );
      })}
    </div>
  );
}
