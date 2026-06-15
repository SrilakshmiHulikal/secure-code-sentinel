import { useEffect, useState } from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import { ShieldCheck, LayoutDashboard, Search, FileText, Cpu } from "lucide-react";
import Dashboard from "./components/Dashboard";
import AnalysisForm from "./components/AnalysisForm";
import ReportView from "./components/ReportView";
import ReportsList from "./components/ReportsList";
import axios from "axios";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/analyze", label: "Analyze", icon: Search },
  { to: "/reports", label: "Reports", icon: FileText },
];

const PROVIDER_LABELS = {
  anthropic: "Claude",
  grok: "Grok",
  groq: "Groq",
};

export default function App() {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    axios.get("/api/health")
      .then((r) => setHealth(r.data))
      .catch(() => {});
  }, []);

  const providerLabel = health
    ? `${PROVIDER_LABELS[health.provider] ?? health.provider} · ${health.model}`
    : null;

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <ShieldCheck className="text-sentinel-400 w-7 h-7" />
            <span className="font-bold text-lg tracking-tight text-white">
              SecureCode<span className="text-sentinel-400">Sentinel</span>
            </span>
            {providerLabel && (
              <span className="hidden sm:flex items-center gap-1.5 text-xs text-gray-500 bg-gray-800 border border-gray-700 px-2 py-1 rounded-full">
                <Cpu className="w-3 h-3" />
                {providerLabel}
              </span>
            )}
          </div>
          <nav className="flex items-center gap-1">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-sentinel-600/20 text-sentinel-400"
                      : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                {label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<AnalysisForm />} />
          <Route path="/reports" element={<ReportsList />} />
          <Route path="/reports/:id" element={<ReportView />} />
        </Routes>
      </main>

      <footer className="border-t border-gray-800 text-center text-xs text-gray-600 py-4">
        SecureCodeSentinel — AI-Powered Security Analysis
        {providerLabel && (
          <span> &bull; Powered by {providerLabel}</span>
        )}
      </footer>
    </div>
  );
}
