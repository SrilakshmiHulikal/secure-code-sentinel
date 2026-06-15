import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { Trash2, ExternalLink, FileCode, Github, Clipboard } from "lucide-react";
import { getReports, deleteReport } from "../api/client";
import RiskBadge from "./RiskBadge";

const SOURCE_ICON = { paste: Clipboard, file: FileCode, github_pr: Github };
const SOURCE_LABEL = { paste: "Code paste", file: "File upload", github_pr: "GitHub PR" };

export default function ReportsList() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    getReports({ limit: 100 })
      .then(setReports)
      .catch(() => toast.error("Failed to load reports"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (e, id) => {
    e.preventDefault();
    if (!confirm("Delete this report?")) return;
    try {
      await deleteReport(id);
      toast.success("Report deleted");
      setReports((r) => r.filter((x) => x.id !== id));
    } catch {
      toast.error("Failed to delete");
    }
  };

  if (loading) return <div className="text-center py-20 text-gray-500">Loading…</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-gray-400 mt-1">{reports.length} analysis report{reports.length !== 1 ? "s" : ""}</p>
        </div>
        <Link to="/analyze" className="btn-primary">New Analysis</Link>
      </div>

      {reports.length === 0 ? (
        <div className="card text-center py-16 text-gray-500">
          <FileCode className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No reports yet.</p>
          <Link to="/analyze" className="text-sentinel-400 hover:underline mt-2 inline-block">Run your first analysis</Link>
        </div>
      ) : (
        <div className="space-y-3">
          {reports.map((r) => {
            const Icon = SOURCE_ICON[r.source] || Clipboard;
            return (
              <Link
                key={r.id}
                to={`/reports/${r.id}`}
                className="card flex items-center gap-4 hover:border-gray-700 transition-colors group"
              >
                <div className="p-2.5 rounded-lg bg-gray-800 text-gray-400 shrink-0">
                  <Icon className="w-5 h-5" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-gray-200 truncate">
                      {r.filename || r.pr_url || "Code snippet"}
                    </p>
                    {r.language && (
                      <span className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded shrink-0">
                        {r.language}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                    <span>{SOURCE_LABEL[r.source]}</span>
                    <span>·</span>
                    <span>{new Date(r.created_at).toLocaleString()}</span>
                    <span>·</span>
                    <span>{r.vulnerability_count} issue{r.vulnerability_count !== 1 ? "s" : ""}</span>
                    {r.critical_count > 0 && (
                      <span className="text-red-400 font-semibold">{r.critical_count} critical</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <RiskBadge score={r.risk_score} />
                  <button
                    onClick={(e) => handleDelete(e, r.id)}
                    className="p-1.5 rounded text-gray-600 hover:text-red-400 hover:bg-red-900/20 transition-colors opacity-0 group-hover:opacity-100"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
