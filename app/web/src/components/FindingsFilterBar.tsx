import type { Severity } from '../types';
import { SEVERITIES } from '../types';

export function FindingsFilterBar({
  severity,
  onSeverity,
  tool,
  onTool,
  tools,
}: {
  severity: Severity | '';
  onSeverity: (s: Severity | '') => void;
  tool: string;
  onTool: (t: string) => void;
  tools: string[];
}) {
  return (
    <div className="filter-bar">
      <label>
        Severity
        <select
          className="input"
          value={severity}
          onChange={(e) => onSeverity(e.target.value as Severity | '')}
        >
          <option value="">All</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </label>
      <label>
        Tool
        <select
          className="input"
          value={tool}
          onChange={(e) => onTool(e.target.value)}
        >
          <option value="">All</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
