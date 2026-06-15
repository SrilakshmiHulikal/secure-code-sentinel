import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  timeout: 120_000, // analysis can take time
});

// ── Reports ───────────────────────────────────────────────────────────────────
export const getReports = (params = {}) =>
  api.get("/reports", { params }).then((r) => r.data);

export const getReport = (id) =>
  api.get(`/reports/${id}`).then((r) => r.data);

export const deleteReport = (id) =>
  api.delete(`/reports/${id}`).then((r) => r.data);

// ── Analysis ──────────────────────────────────────────────────────────────────
export const analyzeCode = (payload) =>
  api.post("/analyze", payload).then((r) => r.data);

export const analyzeFile = (file) => {
  const form = new FormData();
  form.append("file", file);
  return api.post("/analyze/file", form, {
    headers: { "Content-Type": "multipart/form-data" },
  }).then((r) => r.data);
};

export const analyzeGithubPR = (payload) =>
  api.post("/analyze/github-pr", payload).then((r) => r.data);

// ── Fix ───────────────────────────────────────────────────────────────────────
export const getFix = (reportId, vulnerabilityId) =>
  api.post("/fix", { report_id: reportId, vulnerability_id: vulnerabilityId }).then((r) => r.data);

// ── Dashboard ─────────────────────────────────────────────────────────────────
export const getDashboard = () =>
  api.get("/dashboard").then((r) => r.data);
