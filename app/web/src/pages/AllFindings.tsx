import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { useApi } from '../useApi';
import type { Repo, Severity } from '../types';
import { FindingsTable } from '../components/FindingsTable';
import { FindingsFilterBar } from '../components/FindingsFilterBar';
import { Loading, ErrorState, Empty } from '../components/states';

const LIMIT = 100;

export function AllFindings() {
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [tool, setTool] = useState('');
  const [offset, setOffset] = useState(0);

  // Reset to first page whenever a filter changes.
  useEffect(() => {
    setOffset(0);
  }, [severity, tool]);

  const { data, loading, error, reload } = useApi(
    () =>
      api.findings({
        severity: severity || undefined,
        tool: tool || undefined,
        latest_only: true,
        limit: LIMIT,
        offset,
      }),
    [severity, tool, offset],
  );

  const reposState = useApi(() => api.repos(), []);
  const repoNameMap = useMemo(() => {
    const m = new Map<string, string>();
    reposState.data?.forEach((r: Repo) => m.set(r.id, r.full_name));
    return m;
  }, [reposState.data]);

  const tools = useMemo(() => {
    const set = new Set<string>();
    data?.items.forEach((f) => set.add(f.tool));
    if (tool) set.add(tool);
    return [...set].sort();
  }, [data, tool]);

  const total = data?.total ?? 0;
  const page = Math.floor(offset / LIMIT) + 1;
  const pageCount = Math.max(1, Math.ceil(total / LIMIT));
  const rangeStart = total === 0 ? 0 : offset + 1;
  const rangeEnd = Math.min(offset + LIMIT, total);

  return (
    <div className="page">
      <div className="container">
        <div className="page-header">
          <div>
            <h1>All findings</h1>
            <div className="sub">Latest findings across every repository.</div>
          </div>
        </div>

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
              : 'No findings — everything is clean. 🎉'}
          </Empty>
        ) : (
          <>
            <FindingsTable
              findings={data.items}
              showRepoColumn
              repoName={(rid) => repoNameMap.get(rid) ?? rid}
            />
            <div className="pagination">
              <span className="info">
                Showing {rangeStart}–{rangeEnd} of {total} · page {page} of{' '}
                {pageCount}
              </span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - LIMIT))}
                >
                  ← Prev
                </button>
                <button
                  className="btn btn-sm"
                  disabled={rangeEnd >= total}
                  onClick={() => setOffset(offset + LIMIT)}
                >
                  Next →
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
