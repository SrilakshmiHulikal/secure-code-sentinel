import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid, Cell,
  PieChart, Pie, Legend,
} from "recharts";
import { ShieldAlert, ShieldCheck, Bug, TrendingUp, ArrowRight } from "lucide-react";
import { getDashboard } from "../api/client";
import RiskBadge from "./RiskBadge";

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW:  "#22c55e",
};

// Shared dark tooltip style used on every chart
const TOOLTIP_STYLE = {
  contentStyle: {
    background: "#1f2937",
    border: "1px solid #374151",
    borderRadius: 8,
    color: "#f3f4f6",
    fontSize: 12,
  },
  labelStyle: { color: "#9ca3af" },
  itemStyle:  { color: "#f3f4f6" },
  cursor:     { fill: "rgba(255,255,255,0.04)" },
};

function StatCard({ icon: Icon, label, value, color = "text-sentinel-400" }) {
  return (
    <div className="card flex items-center gap-4 min-w-0">
      <div className={`p-3 rounded-xl bg-gray-800 shrink-0 ${color}`}>
        <Icon className="w-6 h-6" />
      </div>
      <div className="min-w-0">
        <p className="text-gray-400 text-sm truncate">{label}</p>
        <p className="text-2xl font-bold text-white truncate">{value}</p>
      </div>
    </div>
  );
}

// Custom legend dot for the pie chart
function PieLegend({ payload }) {
  return (
    <ul className="flex flex-wrap justify-center gap-x-4 gap-y-1 mt-2">
      {payload.map((entry, i) => (
        <li key={i} className="flex items-center gap-1.5 text-xs text-gray-400">
          <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: entry.color }} />
          <span>{entry.value}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getDashboard()
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500">
        Loading dashboard…
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-center py-16 text-gray-500">
        <ShieldAlert className="w-12 h-12 mx-auto mb-4 opacity-40" />
        <p>Failed to load dashboard. Make sure the backend is running.</p>
      </div>
    );
  }

  // Severity pie — order: CRITICAL → LOW
  const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const severityData = SEVERITY_ORDER
    .filter((s) => data.by_severity[s] > 0)
    .map((s) => ({ name: s, value: data.by_severity[s], fill: SEVERITY_COLORS[s] }));

  // OWASP bar — trim label to "A03" style so it fits on the Y axis
  const owaspData = Object.entries(data.by_owasp)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, count]) => ({
      name: name.match(/^(A\d+)/)?.[1] ?? name.slice(0, 6),
      full: name,   // kept for tooltip
      count,
    }));

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
        <p className="text-gray-400 mt-1">Real-time security posture across all analysed code</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={ShieldCheck} label="Total Reports"       value={data.total_reports} />
        <StatCard
          icon={ShieldAlert}
          label="Avg Risk Score"
          value={`${data.avg_risk_score}/100`}
          color={data.avg_risk_score > 60 ? "text-red-400" : data.avg_risk_score > 30 ? "text-yellow-400" : "text-green-400"}
        />
        <StatCard icon={Bug}         label="Vulnerabilities"     value={data.total_vulnerabilities} color="text-orange-400" />
        <StatCard icon={TrendingUp}  label="Critical Findings"   value={data.by_severity?.CRITICAL || 0} color="text-red-400" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Severity pie */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Severity Distribution</h2>
          {severityData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-gray-600 text-sm">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="45%"
                  innerRadius={52}
                  outerRadius={78}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  {...TOOLTIP_STYLE}
                  formatter={(value, name) => [value, name]}
                />
                <Legend content={<PieLegend />} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* OWASP bar */}
        <div className="card lg:col-span-2">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Top OWASP Categories</h2>
          {owaspData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-gray-600 text-sm">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={owaspData} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
                <XAxis type="number" tick={{ fill: "#9ca3af", fontSize: 11 }} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={36}
                  tick={{ fill: "#9ca3af", fontSize: 11 }}
                />
                <Tooltip
                  {...TOOLTIP_STYLE}
                  formatter={(value, _name, props) => [value, props.payload.full ?? props.payload.name]}
                />
                <Bar dataKey="count" fill="#2563eb" radius={[0, 4, 4, 0]} maxBarSize={20} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Risk trend */}
      {data.risk_trend.length > 1 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Risk Score Trend (30 days)</h2>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={data.risk_trend} margin={{ left: 0, right: 16, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="date" tick={{ fill: "#9ca3af", fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: "#9ca3af", fontSize: 11 }} width={32} />
              <Tooltip {...TOOLTIP_STYLE} formatter={(v) => [`${v}/100`, "Avg risk score"]} />
              <Line
                type="monotone"
                dataKey="avg_score"
                stroke="#2563eb"
                strokeWidth={2}
                dot={{ fill: "#2563eb", r: 3 }}
                activeDot={{ r: 5, fill: "#60a5fa" }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent reports */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-300">Recent Reports</h2>
          <Link to="/reports" className="text-sentinel-400 hover:text-sentinel-300 text-sm flex items-center gap-1">
            View all <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {data.recent_reports.length === 0 ? (
          <div className="text-center py-8 text-gray-600">
            <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-40" />
            <p>
              No reports yet.{" "}
              <Link to="/analyze" className="text-sentinel-400 hover:underline">
                Analyse some code
              </Link>{" "}
              to get started.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {data.recent_reports.map((r) => (
              <Link
                key={r.id}
                to={`/reports/${r.id}`}
                className="flex items-center gap-3 py-3 hover:bg-gray-800/40 px-2 -mx-2 rounded-lg transition-colors group"
              >
                {/* Text — flex-1 + min-w-0 ensures it shrinks and truncates */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-200 truncate">
                    {r.filename || r.pr_url || "Code snippet"}
                  </p>
                  <p className="text-xs text-gray-500 mt-0.5 truncate">
                    {[
                      r.language,
                      new Date(r.created_at).toLocaleString(),
                      `${r.vulnerability_count} issue${r.vulnerability_count !== 1 ? "s" : ""}`,
                    ].filter(Boolean).join(" · ")}
                    {r.critical_count > 0 && (
                      <span className="text-red-400 font-semibold ml-1">
                        · {r.critical_count} critical
                      </span>
                    )}
                  </p>
                </div>
                <div className="shrink-0">
                  <RiskBadge score={r.risk_score} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
