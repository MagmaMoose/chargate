import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { api, ApiError, loginUrl } from './api';
import type { Me } from './types';
import { Loading } from './components/states';

interface AuthValue {
  me: Me;
  activeAccountId: string;
  setActiveAccountId: (id: string) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within <AuthGate>');
  return ctx;
}

function SignIn() {
  return (
    <div className="signin-wrap">
      <div className="signin-card">
        <div className="logo" style={{ fontSize: 40, color: 'var(--accent)' }}>
          🛡️
        </div>
        <h1>Chargate</h1>
        <p>Centralised security findings across your organisation.</p>
        <a className="btn btn-primary" href={loginUrl}>
          Sign in with GitHub
        </a>
      </div>
    </div>
  );
}

/**
 * Gates the whole app on `GET /auth/me`. Renders a sign-in screen on 401,
 * an error on other failures, and provides the authed user via context.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError>();
  const [activeAccountId, setActiveAccountId] = useState('');

  useEffect(() => {
    let active = true;
    api
      .me()
      .then((data) => {
        if (!active) return;
        setMe(data);
        setActiveAccountId(data.accounts[0]?.id ?? '');
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setError(
          err instanceof ApiError ? err : new ApiError(0, (err as Error).message),
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const value = useMemo<AuthValue | null>(() => {
    if (!me) return null;
    return {
      me,
      activeAccountId,
      setActiveAccountId,
      logout: async () => {
        try {
          await api.logout();
        } finally {
          window.location.reload();
        }
      },
    };
  }, [me, activeAccountId]);

  if (loading) {
    return (
      <div className="signin-wrap">
        <Loading label="Checking session…" />
      </div>
    );
  }

  if (error && error.status !== 401) {
    return (
      <div className="signin-wrap">
        <div className="signin-card">
          <h1>Chargate</h1>
          <p>Couldn’t reach the API: {error.message}</p>
          <a className="btn btn-primary" href={loginUrl}>
            Sign in with GitHub
          </a>
        </div>
      </div>
    );
  }

  if (!value) {
    return <SignIn />;
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
