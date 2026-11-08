import RiskBadge from "../RiskBadge/RiskBadge";

export default function EmailHeader({ email }) {
  return (
    <div style={{ marginBottom: 24, paddingBottom: 20, borderBottom: "1px solid #1e293b" }}>
      <h1 style={{
        fontFamily: "'Syne', sans-serif",
        fontWeight: 800,
        fontSize: 20,
        color: "#e2e8f0",
        letterSpacing: "-0.01em",
        lineHeight: 1.3,
        margin: "0 0 10px",
      }}>
        {email.subject}
      </h1>
      <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap", marginBottom: 6 }}>
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#475569" }}>
          FROM: <span style={{ color: "#64748b" }}>{email.from}</span>
        </span>
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#475569" }}>
          {email.time}
        </span>
        {email.analysis && <RiskBadge risk={email.analysis.risk} size="large" />}
      </div>
      {email.analysis && (
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#475569" }}>
          Model confidence: <span style={{ color: "#64748b" }}>{Math.round(email.analysis.confidence * 100)}%</span>
        </div>
      )}
    </div>
  );
}