import type { Finding } from '../types';
import { SeverityBadge } from './Severity';

function Location({ finding }: { finding: Finding }) {
  if (!finding.path) return <span className="muted">—</span>;
  const label = finding.line
    ? `${finding.path}:${finding.line}`
    : finding.path;
  if (finding.help_uri) {
    return (
      <a
        className="mono"
        href={finding.help_uri}
        target="_blank"
        rel="noreferrer"
        title={`Help: ${finding.help_uri}`}
      >
        {label}
      </a>
    );
  }
  return <span className="mono">{label}</span>;
}

export function FindingsTable({
  findings,
  showRepoColumn,
  repoName,
}: {
  findings: Finding[];
  /** When true, the rule cell links to help_uri for cross-repo context. */
  showRepoColumn?: boolean;
  /** Map of repository_id -> full_name, used when showRepoColumn is set. */
  repoName?: (id: string) => string;
}) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th style={{ width: 90 }}>Severity</th>
            <th style={{ width: 110 }}>Tool</th>
            <th>Rule</th>
            {showRepoColumn && <th>Repository</th>}
            <th>Location</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id}>
              <td>
                <SeverityBadge severity={f.severity} />
              </td>
              <td>
                <span className="tool-tag">{f.tool}</span>
              </td>
              <td>
                {f.help_uri ? (
                  <a href={f.help_uri} target="_blank" rel="noreferrer">
                    {f.rule_name ?? f.rule_id}
                  </a>
                ) : (
                  f.rule_name ?? f.rule_id
                )}
                {f.rule_name && (
                  <div className="muted mono" style={{ fontSize: 11 }}>
                    {f.rule_id}
                  </div>
                )}
              </td>
              {showRepoColumn && (
                <td className="mono" style={{ fontSize: 12 }}>
                  {repoName ? repoName(f.repository_id) : f.repository_id}
                </td>
              )}
              <td>
                <Location finding={f} />
              </td>
              <td className="msg-cell">{f.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
