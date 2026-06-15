import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, ShieldAlert, ShieldCheck, ExternalLink, Bug } from "lucide-react";
import { getReport } from "../api/client";
import RiskBadge from "./RiskBadge";
import VulnerabilityCard from "./VulnerabilityCard";
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from "recharts";

const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function RiskGauge({ score }) {
  const s = Number(score);
  const color = s >= 80 ? "#ef4444" : s >= 60 ? "#f97316" : s >= 40 ? "#eab308" : "#22c55e";
  return (
    <div className="relative w-36 h-36 mx-auto">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          cx="50%"
          cy="50%"
          innerRadius="70%"
          outerRadius="100%"
          barSize={12}
          data={[{ value: s, fill: color }]}
          startAngle={210}
          endAngle={-30}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: "#1f2937" }} dataKey="value" cornerRadius={6} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{s}</span>
        <span className="text-xs text-gray-500">/ 100</span>
      </div>
    </div>
  );
}

export default function ReportView() {
  const { id } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    getReport(id)
      .then(setReport)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="text-center py-20 text-gray-500">Loading report…</div>;
  if (!report) return <div className="text-center py-20 text-gray-500">Report not found.</div>;

  const sorted = [...report.vulnerabilities].sort(
    (a, b) => (ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4)
  );

  const filtered = filter === "ALL" ? sorted : sorted.filter((v) => v.severity === filter);

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const v of report.vulnerabilities) counts[v.severity] = (counts[v.severity] || 0) + 1;

  const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div className="space-y-6">
      {/* Back */}
      <Link to="/reports" className="flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors w-fit">
        <ArrowLeft className="w-4 h-4" /> Back to reports
      </Link>

      {/* Header card */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-6">
          {/* Risk gauge */}
          <div className="shrink-0 flex flex-col items-center gap-2">
            <RiskGauge score={report.risk_score} />
            <p className="text-xs text-gray-500 text-center">Risk Score</p>
            <RiskBadge score={report.risk_score} />
          </div>

          {/* Metadata */}
          <div className="flex-1 space-y-3">
            <div>
              <h1 className="text-xl font-bold text-white">
                {report.filename || report.pr_url || "Code Snippet"}
              </h1>
              <p className="text-sm text-gray-400 mt-0.5">
                {report.language && <span className="mr-2">{report.language}</span>}
                {new Date(report.created_at).toLocaleString()}
                {report.repo_name && <span className="ml-2">· {report.repo_name}</span>}
              </p>
              {report.pr_url && (
                <a
                  href={report.pr_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-sentinel-400 hover:underline flex items-center gap-1 mt-1"
                >
                  <ExternalLink className="w-3 h-3" /> View PR on GitHub
                </a>
              )}
            </div>

            {report.summary && (
              <p className="text-sm text-gray-300 leading-relaxed border-l-2 border-sentinel-700 pl-3">
                {report.summary}
              </p>
            )}

            {/* Severity breakdown */}
            <div className="flex gap-3 flex-wrap">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                <div key={s} className="text-center">
                  <div className={`text-xl font-bold ${
                    s === "CRITICAL" ? "text-red-400" :
                    s === "HIGH" ? "text-orange-400" :
                    s === "MEDIUM" ? "text-yellow-400" : "text-green-400"
                  }`}>{counts[s] || 0}</div>
                  <div className="text-xs text-gray-500">{s}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerability list */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-gray-200">
            {report.vulnerabilities.length === 0
              ? "No vulnerabilities found"
              : `${report.vulnerabilities.length} Vulnerabilit${report.vulnerabilities.length !== 1 ? "ies" : "y"}`}
          </h2>
          {report.vulnerabilities.length > 0 && (
            <div className="flex gap-1">
              {FILTERS.map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-colors ${
                    filter === f
                      ? "bg-sentinel-600 text-white"
                      : "bg-gray-800 text-gray-400 hover:text-gray-200"
                  }`}
                >
                  {f}{f !== "ALL" && counts[f] ? ` (${counts[f]})` : ""}
                </button>
              ))}
            </div>
          )}
        </div>

        {report.vulnerabilities.length === 0 ? (
          <div className="card text-center py-12">
            <ShieldCheck className="w-12 h-12 mx-auto mb-3 text-green-500 opacity-70" />
            <p className="text-gray-300 font-medium">No vulnerabilities detected</p>
            <p className="text-sm text-gray-500 mt-1">This code looks clean according to our analysis.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {filtered.map((v) => (
              <VulnerabilityCard key={v.id} vuln={v} reportId={report.id} />
            ))}
            {filtered.length === 0 && (
              <p className="text-center py-8 text-gray-500">No {filter} severity findings.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
