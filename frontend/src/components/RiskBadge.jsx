export default function RiskBadge({ score }) {
  const s = Number(score);
  let color, label;
  if (s >= 80) { color = "bg-red-900/60 text-red-300 border-red-700/50"; label = "Critical"; }
  else if (s >= 60) { color = "bg-orange-900/60 text-orange-300 border-orange-700/50"; label = "High"; }
  else if (s >= 40) { color = "bg-yellow-900/60 text-yellow-300 border-yellow-700/50"; label = "Medium"; }
  else if (s > 0) { color = "bg-green-900/60 text-green-300 border-green-700/50"; label = "Low"; }
  else { color = "bg-gray-800 text-gray-400 border-gray-700"; label = "Clean"; }

  return (
    <span className={`inline-flex items-center gap-1.5 border text-xs font-bold px-2.5 py-1 rounded-full ${color}`}>
      <span className="tabular-nums">{s}</span>
      <span className="opacity-70">·</span>
      {label}
    </span>
  );
}
