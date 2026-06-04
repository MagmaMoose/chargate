import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api';
import { useApi } from '../useApi';
import type { Severity } from '../types';
import { FindingsTable } from '../components/FindingsTable';
import { FindingsFilterBar } from '../components/FindingsFilterBar';
import { Loading, ErrorState, Empty } from '../components/states';
import { formatDate, shortSha, totalCount } from '../format';

function ScansSection({ repoId }: { repoId: string }) {
  const { data, loading, error, reload } = useApi(
    () => api.scans({ repository_id: repoId, limit: 20 }),
    [repoId],
  );

  if (loading) return <Loading label="Loading scans…" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data || data.items.length === 0)
    return <Empty>No scans recorded for this repository.</Empty>;

  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Commit</th>
            <th>Ref / PR</th>
            <th>Status</th>
            <th>Security</th>
            <th>Lint</th>
            <th style={{ width: 70 }}>Findings</th>
            <th style={{ width: 130 }}>Created</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((s) => (
            <tr key={s.id}>
              <td className="mono">{shortSha(s.head_sha)}</td>
              <td className="mono" style={{ fontSize: 12 }}>
                {s.pull_number ? `#${s.pull_number}` : s.head_ref ?? '—'}
              </td>
              <td>
                <span
                  className={`status-pill ${
                    s.conclusion === 'success'
                      ? 'ok'
                      : s.conclusion === 'failure'
                        ? 'bad'
                        : ''
                  }`}
                >
                  {s.conclusion ?? s.status}
                </span>
              </td>
              <td className="muted">{s.security_result ?? '—'}</td>
              <td className="muted">{s.lint_result ?? '—'}</td>
              <td style={{ fontVariantNumeric: 'tabular-nums' }}>
                {totalCount(s.totals)}
              </td>
              <td className="muted">{formatDate(s.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function RepoDetail() {
  const { id = '' } = useParams();
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [tool, setTool] = useState('');

  const { data, loading, error, reload } = useApi(
    () =>
      api.findings({
        repository_id: id,
        severity: severity || undefined,
        tool: tool || undefined,
        latest_only: true,
        limit: 100,
        offset: 0,
      }),
    [id, severity, tool],
  );

  // Fetch repo metadata for the title (best-effort; falls back to the id).
  const reposState = useApi(() => api.repos(), []);
  const repo = useMemo(
    () => reposState.data?.find((r) => r.id === id),
    [reposState.data, id],
  );

  // Tool list for the filter — derived from the current result set.
  const tools = useMemo(() => {
    const set = new Set<string>();
    data?.items.forEach((f) => set.add(f.tool));
    if (tool) set.add(tool);
    return [...set].sort();
  }, [data, tool]);

  return (
    <div className="page">
      <div className="container">
        <div className="breadcrumb">
          <Link to="/">Overview</Link> / Repository
        </div>
        <div className="page-header">
          <div>
            <h1>{repo ? repo.full_name : 'Repository'}</h1>
            <div className="sub">
              {repo ? (
                <>
                  default branch <code>{repo.default_branch}</code>
                  {repo.private && ' · private'}
                  {repo.archived && ' · archived'}
                </>
              ) : (
                <span className="mono">{id}</span>
              )}
            </div>
          </div>
        </div>

        <div className="section-title">Findings</div>
        <FindingsFilterBar
          severity={severity}
          onSeverity={setSeverity}
          tool={tool}
          onTool={setTool}
          tools={tools}
        />

        {loading ? (
          <Loading />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !data || data.items.length === 0 ? (
          <Empty>
            {severity || tool
              ? 'No findings match the current filters.'
              : 'No findings — this repository is clean. 🎉'}
          </Empty>
        ) : (
          <>
            <div className="muted" style={{ marginBottom: 8 }}>
              {data.total} finding{data.total === 1 ? '' : 's'}
            </div>
            <FindingsTable findings={data.items} />
          </>
        )}

        <div className="section-title">Recent scans</div>
        <ScansSection repoId={id} />
      </div>
    </div>
  );
}
