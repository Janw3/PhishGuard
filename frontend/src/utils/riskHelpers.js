export function getRiskColor(risk) {
  if (risk === "high")   return "#ef4444";
  if (risk === "medium") return "#f59e0b";
  return "#22c55e";
}

export function getRiskBg(risk) {
  if (risk === "high")   return "rgba(239,68,68,0.12)";
  if (risk === "medium") return "rgba(245,158,11,0.12)";
  return "rgba(34,197,94,0.12)";
}

export function getRiskLabel(risk) {
  if (risk === "high")   return "HIGH RISK";
  if (risk === "medium") return "MEDIUM RISK";
  return "SAFE";
}