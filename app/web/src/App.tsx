import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { AuthGate } from './auth';
import { TopBar } from './components/TopBar';
import { Overview } from './pages/Overview';
import { RepoDetail } from './pages/RepoDetail';
import { AllFindings } from './pages/AllFindings';

function NotFound() {
  return (
    <div className="page">
      <div className="container">
        <div className="center-state">
          <p>Page not found.</p>
          <Link className="btn btn-sm" to="/">
            Back to overview
          </Link>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthGate>
        <div className="app-shell">
          <TopBar />
          <main>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/repos/:id" element={<RepoDetail />} />
              <Route path="/findings" element={<AllFindings />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
      </AuthGate>
    </BrowserRouter>
  );
}
