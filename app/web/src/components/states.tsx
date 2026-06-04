import type { ReactNode } from 'react';
import type { ApiError } from '../api';

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="loading-row">
      <span className="spinner" /> {label}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: ApiError;
  onRetry?: () => void;
}) {
  return (
    <div className="center-state error">
      <p style={{ margin: '0 0 12px' }}>
        Couldn’t load data{error.status ? ` (HTTP ${error.status})` : ''}:{' '}
        {error.message}
      </p>
      {onRetry && (
        <button className="btn btn-sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
