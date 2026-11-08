import { getRiskColor } from "../../utils/riskHelpers";
import RiskBadge from "../RiskBadge/RiskBadge";

export default function EmailListItem({ email, selected, onClick }) {
  const risk  = email.analysis?.risk;
  const color = risk ? getRiskColor(risk) : "transparent";

  return (
    <div
      onClick={onClick}
      style={{
        padding: "14px 20px",
        borderBottom: "1px solid #0f172a",
        borderLeft: `3px solid ${selected ? color : "transparent"}`,
        cursor: "pointer",
        background: selected ? "#0f172a" : "transparent",
        transition: "background 0.12s ease",
      }}
      onMouseEnter={e => { if (!selected) e.currentTarget.style.background = "#0d1424"; }}
      onMouseLeave={e => { if (!selected) e.currentTarget.style.background = "transparent"; }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{
          fontFamily: "'Space Mono', monospace",
          fontSize: 11,
          color: "#94a3b8",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          maxWidth: 200,
        }}>
          {email.from}
        </span>
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#475569", flexShrink: 0 }}>
          {email.time}
        </span>
      </div>

      <div style={{
        fontFamily: "'Syne', sans-serif",
        fontWeight: 700,
        fontSize: 13,
        color: "#cbd5e1",
        marginBottom: 4,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}>
        {email.subject}
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <span style={{
          fontSize: 11,
          color: "#475569",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          flex: 1,
        }}>
          {email.preview}
        </span>
        {risk && <RiskBadge risk={risk} size="small" />}
        {email.status === "loading" && (
          <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3b82f6", flexShrink: 0 }}>
            Analysing…
          </span>
        )}
        {email.status === "error" && (
          email.errorCode === "unsupported_language" ? (
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#94a3b8", flexShrink: 0 }}>
              English only
            </span>
          ) : (
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#ef4444", flexShrink: 0 }}>
              Error
            </span>
          )
        )}
      </div>
    </div>
  );
}