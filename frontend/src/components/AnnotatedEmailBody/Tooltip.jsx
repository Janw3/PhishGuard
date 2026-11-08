export default function Tooltip({ reason, onClose }) {
  const isRule = reason.source === "rule";
  const impact = Math.round(reason.impact * 100);
  // Rules: impact is a severity (0-100). Model: impact is a LIME weight (usually 0-30).
  const color = isRule
    ? (impact >= 70 ? "#ef4444" : impact >= 50 ? "#f59e0b" : "#94a3b8")
    : (impact >= 30 ? "#ef4444" : impact >= 15 ? "#f59e0b" : "#94a3b8");
  const title = isRule
    ? `RULE: ${reason.category.replace(/_/g, " ").toUpperCase()}`
    : "MODEL PATTERN";
  const footer = isRule
    ? "Found by a fixed rule"
    : `${impact}% influence on the model's decision`;
  // Explanations written by an LLM are labelled as such (transparency).
  const writtenBy = reason.explanation_by ? `Explanation written by AI (${reason.explanation_by})` : null;

  return (
    <div style={{
      position: "absolute",
      bottom: "calc(100% + 10px)",
      left: "50%",
      transform: "translateX(-50%)",
      width: 280,
      background: "#0f172a",
      border: "1px solid #1e293b",
      borderRadius: 8,
      padding: "14px 16px",
      zIndex: 100,
      boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
      pointerEvents: "all",
    }}>
      {/* Arrow */}
      <div style={{
        position: "absolute",
        top: "100%",
        left: "50%",
        transform: "translateX(-50%)",
        width: 0,
        height: 0,
        borderLeft: "6px solid transparent",
        borderRight: "6px solid transparent",
        borderTop: "6px solid #1e293b",
      }} />

      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: color, flexShrink: 0, display: "inline-block" }} />
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.08em", color }}>
          {title}
        </span>
      </div>

      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 12, color: "#e2e8f0", marginBottom: 8 }}>
        "{reason.feature}"
      </div>

      <p style={{ fontSize: 12, lineHeight: 1.6, color: "#94a3b8", margin: "0 0 12px" }}>
        {reason.explanation}
      </p>
      {writtenBy && (
        <p style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#64748b", margin: "-6px 0 10px" }}>
          ✎ {writtenBy}
        </p>
      )}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color }}>
          {footer}
        </span>
        <button
          onClick={onClose}
          style={{ background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: 12 }}
        >
          ✕
        </button>
      </div>
    </div>
  );
}