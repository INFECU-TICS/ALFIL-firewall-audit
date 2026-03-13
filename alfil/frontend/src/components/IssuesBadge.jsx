export function SeverityBadge({ severity }) {
  const map = {
    critical: "badge-critical",
    warning:  "badge-warning",
    info:     "badge-info",
    ok:       "badge-ok",
  };
  const labels = { critical: "Crítico", warning: "Advertencia", info: "Info", ok: "OK" };
  return <span className={map[severity] || "badge-info"}>{labels[severity] || severity}</span>;
}

export function ScoreRing({ score }) {
  const color = score >= 80 ? "text-green-600" : score >= 50 ? "text-yellow-500" : "text-red-600";
  return (
    <div className={`text-5xl font-bold ${color}`}>
      {score}<span className="text-2xl text-gray-400">/100</span>
    </div>
  );
}
