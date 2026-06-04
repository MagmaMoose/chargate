import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { useApi } from '../useApi';
import { SEVERITIES } from '../types';
import { SeverityCounts } from '../components/Severity';
import { Loading, ErrorState, Empty } from '../components/states';
import { totalCount, formatDate } from '../format';

export function Overview() {
  const navigate = useNavigate();
  const { data, loading, error, reload } = useApi(() => api.summary(), []);

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return null;

  const total = totalCount(data.totals);
  const tools = Object.entries(data.by_tool).sort((a, b) => b[1] - a[1]);

  return (
    <div className="page">
      <div className="container">
        <div className="page-header">
          <div>
            <h1>Overview</h1>
            <div className="sub">
              {data.repo_count} repositories · {data.scan_count} scans
            </div>
          </div>
        </div>

        <div className="cards-grid">
          <div className="stat-card">
            <div className="stat-label">Total findings</div>
            <div className="stat-value">{total}</div>
          </div>
          {SEVERITIES.map((sev) => (
            <div className="stat-card" key={sev}>
              <div className="stat-label">
                <span className={`sev-dot bg-${sev}`} />
                {sev}
              </div>
              <div className={`stat-value sev-${sev}`}>
                {data.totals[sev] ?? 0}
              </div>
            </div>
          ))}
        </div>

        <div className="section-title">By tool</div>
        {tools.length === 0 ? (
          <Empty>No tool results yet.</Empty>
        ) : (
          <div className="by-tool">
            {tools.map(([name, count]) => (
              <div className="chip" key={name}>
                <span>{name}</span>
                <b>{count}</b>
              </div>
            ))}
          </div>
        )}

        <div className="section-title">Repositories</div>
        {data.repos.length === 0 ? (
          <Empty>No repositories have been scanned yet.</Empty>
        ) : total === 0 ? (
          <Empty>
            No findings — clean across {data.repo_count}{' '}
            {data.repo_count === 1 ? 'repository' : 'repositories'}. 🎉
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Repository</th>
                  <th style={{ width: 70 }}>Total</th>
                  <th>Severity</th>
                  <th style={{ width: 140 }}>Last scan</th>
                </tr>
              </thead>
              <tbody>
                {data.repos.map((rs) => (
                  <tr
                    key={rs.repository.id}
                    className="row-link"
                    onClick={() => navigate(`/repos/${rs.repository.id}`)}
                  >
                    <td>
                      <a
                        href={`/repos/${rs.repository.id}`}
                        onClick={(e) => {
                          e.preventDefault();
                          navigate(`/repos/${rs.repository.id}`);
                        }}
                      >
                        {rs.repository.full_name}
                      </a>
                      {rs.repository.archived && (
                        <span className="status-pill" style={{ marginLeft: 8 }}>
                          archived
                        </span>
                      )}
                      {rs.repository.private && (
                        <span className="status-pill" style={{ marginLeft: 8 }}>
                          private
                        </span>
                      )}
                    </td>
                    <td style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {totalCount(rs.totals)}
                    </td>
                    <td>
                      <SeverityCounts totals={rs.totals} />
                    </td>
                    <td className="muted">{formatDate(rs.last_scan_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
