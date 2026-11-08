import EmailListItem from "./EmailListItem";

export default function EmailList({ emails, selectedId, onSelect }) {
  const sortedEmails = [...emails].sort((a, b) => {
      return b.time.localeCompare(a.time);
  });
  return (
    <aside style={{
      width: 320,
      minWidth: 280,
      borderRight: "1px solid #1e293b",
      display: "flex",
      flexDirection: "column",
      background: "#0a0f1e",
      overflow: "hidden",
    }}>
      <div style={{ padding: "20px 20px 14px", borderBottom: "1px solid #1e293b", flexShrink: 0 }}>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#475569", letterSpacing: "0.12em", marginBottom: 4 }}>
          INBOX
        </div>
        <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 20, color: "#e2e8f0", letterSpacing: "-0.02em" }}>
          {emails.length} messages
        </div>
      </div>
      <div style={{ overflowY: "auto", flex: 1 }}>
        {sortedEmails.map((email) => (
          <EmailListItem
            key={email.id}
            email={email}
            selected={selectedId === email.id}
            onClick={() => onSelect(email.id)}
          />
        ))}
      </div>
    </aside>
  );
}