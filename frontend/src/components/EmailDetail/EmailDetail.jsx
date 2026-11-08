import AnnotatedEmailBody from "../AnnotatedEmailBody/AnnotatedEmailBody";
import EmailHeader from "./EmailHeader";
import SenderSignals from "./SenderSignals";

export default function EmailDetail({ email }) {

  if (!email) {
    return (
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 12 }}>
        <div style={{ fontSize: 36, color: "#1e293b" }}>✉</div>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: "#334155" }}>
          Select an email to inspect it
        </div>
      </div>
    );
  }

  if (email.status === "loading") {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: "#334155" }}>Analysing email…</div>
      </div>
    );
  }

  if (email.status === "error") {
    // An unsupported language is not a failure, just outside what PhishGuard can judge.
    const isLanguage = email.errorCode === "unsupported_language";
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 36 }}>
        <div role="alert" style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, lineHeight: 1.7, color: isLanguage ? "#94a3b8" : "#ef4444", maxWidth: 460, textAlign: "center" }}>
          {isLanguage ? "ⓘ " : "✕ "}
          {email.error ?? "Could not reach the backend. Is it running?"}
          {isLanguage && (
            <div style={{ fontSize: 11, color: "#475569", marginTop: 8 }}>
              The models and checks were built for English emails, so a verdict on other languages would not be trustworthy.
            </div>
          )}
        </div>
      </div>
    );
  }

  const reasons = email.analysis?.reasons ?? [];
  const isLegitimate = email.analysis?.label === "legitimate";
  const isUncertain = email.analysis?.uncertain === true;

  return (
    <div style={{
      flex: 1,
      overflow: "visible",
      padding: "28px 36px"
    }}>
      <EmailHeader email={email} />

      <SenderSignals signals={email.analysis?.sender_signals} />

      {isUncertain && (
        <div style={{
          fontFamily: "'Space Mono', monospace",
          fontSize: 11,
          color: "#f59e0b",
          background: "rgba(245,158,11,0.08)",
          border: "1px solid rgba(245,158,11,0.3)",
          borderRadius: 6,
          padding: "10px 14px",
          marginBottom: 20,
        }}>
          ⚠ Uncertain – the checks do not agree. Look at the highlighted passages before you trust this email.
        </div>
      )}

      {isLegitimate && !isUncertain && reasons.length === 0 && (
        <div style={{
          fontFamily: "'Space Mono', monospace",
          fontSize: 11,
          color: "#22c55e",
          background: "rgba(34,197,94,0.08)",
          border: "1px solid rgba(34,197,94,0.2)",
          borderRadius: 6,
          padding: "10px 14px",
          marginBottom: 20,
        }}>
          No suspicious patterns found – this email appears legitimate.
        </div>
      )}

      <AnnotatedEmailBody text={email.body} reasons={reasons} />

      {reasons.length > 0 && (
        <p style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#ffffff", marginTop: 14 }}>
          Click on a highlighted word to see why it was flagged.
        </p>
      )}
    </div>
  );
}