export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'note';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'note'];

export interface Account {
  id: string;
  login: string;
  account_type: string;
  avatar_url?: string | null;
}

export interface Me {
  login: string;
  name?: string | null;
  avatar_url?: string | null;
  accounts: Account[];
}

export interface Repo {
  id: string;
  full_name: string;
  name: string;
  private: boolean;
  default_branch: string;
  archived: boolean;
}

export interface Finding {
  id: string;
  tool: string;
  rule_id: string;
  rule_name?: string | null;
  severity: Severity;
  message: string;
  path?: string | null;
  line?: number | null;
  help_uri?: string | null;
  repository_id: string;
}

export interface Scan {
  id: string;
  repository_id: string;
  head_sha: string;
  head_ref?: string | null;
  pull_number?: number | null;
  status: string;
  conclusion?: string | null;
  security_result?: string | null;
  lint_result?: string | null;
  totals: Record<string, number>;
  created_at: string;
  completed_at?: string | null;
}

export interface RepoSummary {
  repository: Repo;
  totals: Record<string, number>;
  last_scan_at?: string | null;
}

export interface Summary {
  totals: Record<string, number>;
  by_tool: Record<string, number>;
  repo_count: number;
  scan_count: number;
  repos: RepoSummary[];
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}
