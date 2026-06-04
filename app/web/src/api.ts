import type {
  Me,
  Summary,
  Repo,
  Finding,
  Scan,
  Page,
  Severity,
} from './types';

export const API_BASE =
  import.meta.env.VITE_API_BASE ?? 'http://localhost:8000';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}${path}`, {
      credentials: 'include',
      headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
      ...init,
    });
  } catch (err) {
    throw new ApiError(0, `Network error: ${(err as Error).message}`);
  }

  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      if (body && typeof body === 'object' && 'detail' in body) {
        detail = String((body as { detail: unknown }).detail);
      }
    } catch {
      /* ignore non-JSON error bodies */
    }
    throw new ApiError(resp.status, detail || `HTTP ${resp.status}`);
  }

  if (resp.status === 204) {
    return undefined as T;
  }
  return (await resp.json()) as T;
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') {
      sp.set(key, String(value));
    }
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

/** URL the browser is redirected to in order to sign in. */
export const loginUrl = `${API_BASE}/api/v1/auth/login`;

export const api = {
  me(): Promise<Me> {
    return request<Me>('/api/v1/auth/me');
  },

  logout(): Promise<{ ok: boolean }> {
    return request<{ ok: boolean }>('/api/v1/auth/logout', { method: 'POST' });
  },

  summary(): Promise<Summary> {
    return request<Summary>('/api/v1/summary');
  },

  repos(): Promise<Repo[]> {
    return request<Repo[]>('/api/v1/repos');
  },

  findings(opts: {
    repository_id?: string;
    severity?: Severity | '';
    tool?: string;
    latest_only?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<Page<Finding>> {
    return request<Page<Finding>>(
      `/api/v1/findings${qs({
        repository_id: opts.repository_id,
        severity: opts.severity,
        tool: opts.tool,
        latest_only: opts.latest_only,
        limit: opts.limit,
        offset: opts.offset,
      })}`,
    );
  },

  scans(opts: {
    repository_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<Page<Scan>> {
    return request<Page<Scan>>(
      `/api/v1/scans${qs({
        repository_id: opts.repository_id,
        limit: opts.limit,
        offset: opts.offset,
      })}`,
    );
  },
};
