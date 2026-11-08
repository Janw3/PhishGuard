// Findings about the sender (fake sender domain, misleading display name,
// replies redirected elsewhere). They have no position in the body, so they
// are listed above it instead of being highlighted.
export default function SenderSignals({ signals }) {
  if (!signals || signals.length === 0) return null;

  return (
    <div
      role="note"
      aria-label="Sender checks"
      style={{
        border: "1px solid rgba(245,158,11,0.3)",
        background: "rgba(245,158,11,0.06)",
        borderRadius: 6,
        padding: "10px 14px",
        marginBottom: 20,
      }}
    >
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, letterSpacing: "0.08em", color: "#f59e0b", marginBottom: 6 }}>
        ⚠ SENDER CHECKS
      </div>
      <ul style={{ margin: 0, paddingLeft: 18 }}>
        {signals.map((s) => (
          <li key={s.id} style={{ fontSize: 12, lineHeight: 1.6, color: "#94a3b8" }}>
            {s.explanation}
          </li>
        ))}
      </ul>
    </div>
  );
}
