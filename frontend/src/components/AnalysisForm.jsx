import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useDropzone } from "react-dropzone";
import toast from "react-hot-toast";
import { Code2, Upload, Github, Loader2, ChevronDown, ChevronUp } from "lucide-react";
import { analyzeCode, analyzeFile, analyzeGithubPR } from "../api/client";

const LANGUAGES = [
  "Auto-detect", "Python", "JavaScript", "TypeScript", "Java", "Go",
  "Ruby", "PHP", "C", "C++", "C#", "Rust", "Kotlin", "Swift", "Bash",
  "SQL", "YAML", "Terraform",
];

const TABS = [
  { id: "paste", label: "Paste Code", icon: Code2 },
  { id: "file", label: "Upload File", icon: Upload },
  { id: "github", label: "GitHub PR", icon: Github },
];

function TabButton({ active, onClick, icon: Icon, label }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-lg transition-colors ${
        active
          ? "bg-sentinel-600 text-white"
          : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
      }`}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}

export default function AnalysisForm() {
  const navigate = useNavigate();
  const [tab, setTab] = useState("paste");
  const [loading, setLoading] = useState(false);

  // Paste tab state
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("Auto-detect");
  const [filename, setFilename] = useState("");

  // File tab state
  const [selectedFile, setSelectedFile] = useState(null);

  // GitHub tab state
  const [prUrl, setPrUrl] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [postReview, setPostReview] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const onDrop = useCallback((accepted) => {
    if (accepted.length) setSelectedFile(accepted[0]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      "text/*": [],
      "application/javascript": [],
      "application/json": [],
    },
    multiple: false,
    maxSize: 500_000,
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (tab === "paste") {
        if (!code.trim()) { toast.error("Please paste some code."); return; }
        const report = await analyzeCode({
          code,
          language: language === "Auto-detect" ? undefined : language,
          filename: filename || undefined,
        });
        toast.success("Analysis complete!");
        navigate(`/reports/${report.id}`);

      } else if (tab === "file") {
        if (!selectedFile) { toast.error("Please select a file."); return; }
        const report = await analyzeFile(selectedFile);
        toast.success("Analysis complete!");
        navigate(`/reports/${report.id}`);

      } else {
        if (!prUrl.trim()) { toast.error("Please enter a GitHub PR URL."); return; }
        const reports = await analyzeGithubPR({
          pr_url: prUrl,
          github_token: githubToken || undefined,
          post_review: postReview,
        });
        toast.success(`Analysed ${reports.length} file(s)!`);
        if (reports.length === 1) {
          navigate(`/reports/${reports[0].id}`);
        } else {
          navigate("/reports");
        }
      }
    } catch (err) {
      const msg = err?.response?.data?.detail || err.message || "Analysis failed.";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Analyse Code</h1>
        <p className="text-gray-400 mt-1">
          Submit code for AI-powered security analysis
        </p>
      </div>

      <div className="card">
        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          {TABS.map(({ id, label, icon }) => (
            <TabButton
              key={id}
              active={tab === id}
              onClick={() => setTab(id)}
              icon={icon}
              label={label}
            />
          ))}
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Paste tab */}
          {tab === "paste" && (
            <>
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Language</label>
                  <select
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-sentinel-500"
                  >
                    {LANGUAGES.map((l) => <option key={l}>{l}</option>)}
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Filename (optional)</label>
                  <input
                    type="text"
                    value={filename}
                    onChange={(e) => setFilename(e.target.value)}
                    placeholder="e.g. auth.py"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sentinel-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1.5">Code</label>
                <textarea
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  rows={18}
                  placeholder="Paste your code here…"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-sm text-gray-200 placeholder-gray-600 font-mono focus:outline-none focus:ring-2 focus:ring-sentinel-500 resize-y"
                  spellCheck={false}
                />
              </div>
            </>
          )}

          {/* File tab */}
          {tab === "file" && (
            <div>
              <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
                  isDragActive
                    ? "border-sentinel-500 bg-sentinel-900/20"
                    : "border-gray-700 hover:border-gray-500"
                }`}
              >
                <input {...getInputProps()} />
                <Upload className="w-10 h-10 mx-auto mb-3 text-gray-500" />
                {selectedFile ? (
                  <div>
                    <p className="text-gray-200 font-medium">{selectedFile.name}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      {(selectedFile.size / 1024).toFixed(1)} KB
                    </p>
                  </div>
                ) : (
                  <>
                    <p className="text-gray-300">Drop a file here, or click to select</p>
                    <p className="text-xs text-gray-500 mt-1">Max 500 KB · Any source file</p>
                  </>
                )}
              </div>
            </div>
          )}

          {/* GitHub PR tab */}
          {tab === "github" && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1.5">
                  GitHub Pull Request URL
                </label>
                <input
                  type="url"
                  value={prUrl}
                  onChange={(e) => setPrUrl(e.target.value)}
                  placeholder="https://github.com/owner/repo/pull/123"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sentinel-500"
                />
              </div>

              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
              >
                {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                Advanced options
              </button>

              {showAdvanced && (
                <div className="space-y-3 border border-gray-800 rounded-lg p-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-400 mb-1.5">
                      GitHub Token (for private repos)
                    </label>
                    <input
                      type="password"
                      value={githubToken}
                      onChange={(e) => setGithubToken(e.target.value)}
                      placeholder="ghp_…"
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-sentinel-500"
                    />
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={postReview}
                      onChange={(e) => setPostReview(e.target.checked)}
                      className="w-4 h-4 accent-sentinel-500"
                    />
                    <span className="text-sm text-gray-300">
                      Post findings as GitHub PR review comment
                    </span>
                  </label>
                </div>
              )}
            </div>
          )}

          <button type="submit" disabled={loading} className="btn-primary w-full flex items-center justify-center gap-2">
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analysing…
              </>
            ) : (
              "Run Security Analysis"
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
