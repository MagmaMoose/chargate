import { Link, NavLink } from 'react-router-dom';
import { useAuth } from '../auth';

export function TopBar() {
  const { me, activeAccountId, setActiveAccountId, logout } = useAuth();

  return (
    <header className="topbar">
      <div className="container topbar-inner">
        <Link to="/" className="wordmark">
          <span className="logo">🛡️</span>
          Chargate
        </Link>

        <nav className="topbar-nav">
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/findings">Findings</NavLink>
        </nav>

        <div className="topbar-spacer" />

        <div className="topbar-right">
          {me.accounts.length > 0 && (
            <select
              className="account-switcher"
              value={activeAccountId}
              onChange={(e) => setActiveAccountId(e.target.value)}
              title="Switch account / organisation"
            >
              {me.accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.login}
                  {a.account_type ? ` · ${a.account_type}` : ''}
                </option>
              ))}
            </select>
          )}

          {me.avatar_url ? (
            <img
              className="avatar"
              src={me.avatar_url}
              alt={me.login}
              title={me.name ?? me.login}
            />
          ) : (
            <span className="avatar" title={me.login} />
          )}

          <button className="btn btn-sm" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
