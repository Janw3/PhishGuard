import { useRef } from "react";

const buttonStyle = {
  fontFamily: "'Space Mono', monospace",
  fontSize: 10,
  color: "#3b82f6",
  background: "none",
  border: "1px solid #1e293b",
  borderRadius: 4,
  padding: "6px 12px",
  cursor: "pointer",
  letterSpacing: "0.06em",
};

export default function AppHeader({ onUpload }) {
  const fileInput = useRef(null);

  function handleFile(event) {
    const file = event.target.files?.[0];
    if (file) onUpload(file);
    event.target.value = ""; // allow uploading the same file again
  }

  return (
    <header style={{
      display: "flex",
      alignItems: "center",
      height: 52,
      padding: "0 24px",
      borderBottom: "1px solid #1e293b",
      background: "#060d1a",
      flexShrink: 0,
      gap: 16,
    }}>
      <div style={{
        fontFamily: "'Syne', sans-serif",
        fontWeight: 800,
        fontSize: 16,
        letterSpacing: "0.06em",
        color: "#e2e8f0",
      }}>
        <span style={{ color: "#3b82f6" }}>PHISH</span>GUARD
      </div>
      <div style={{ flex: 1 }} />
      <input
        ref={fileInput}
        type="file"
        accept=".eml,message/rfc822"
        onChange={handleFile}
        style={{ display: "none" }}
        aria-hidden="true"
        tabIndex={-1}
      />
      <button onClick={() => fileInput.current?.click()} style={buttonStyle} title="Analyze an email file (.eml, English only)">
        ↑ Upload .eml
      </button>
    </header>
  );
}
