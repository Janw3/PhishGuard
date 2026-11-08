import { getRiskBg, getRiskColor, getRiskLabel } from "../../utils/riskHelpers";

export default function RiskBadge({ risk, size = "small" }) {
  const color = getRiskColor(risk);
  const bg    = getRiskBg(risk);
  const label = getRiskLabel(risk);

  const style = {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    border: `1px solid ${color}30`,
    borderRadius: 4,
    background: bg,
    color: color,
    fontFamily: "'Space Mono', monospace",
    fontWeight: 700,
    letterSpacing: "0.08em",
    whiteSpace: "nowrap",
    fontSize: size === "large" ? 11 : 9,
    padding: size === "large" ? "5px 12px" : "2px 7px",
  };

  const dotStyle = {
    width: 7,
    height: 7,
    borderRadius: "50%",
    background: color,
    boxShadow: `0 0 6px ${color}`,
    flexShrink: 0,
  };

  return (
    <span style={style}>
      <span style={dotStyle} />
      {label}
    </span>
  );
}