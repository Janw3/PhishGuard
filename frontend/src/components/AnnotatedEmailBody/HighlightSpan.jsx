import Tooltip from "./Tooltip";

export default function HighlightSpan({ content, reason, isActive, onActivate }) {
  const color = "#ef4444";
  // Not only color: rule highlights get a solid line, model highlights a dashed one.
  const lineStyle = reason.source === "rule" ? "solid" : "dashed";

  return (
    <span style={{ position: "relative", display: "inline" }}>
      <mark
        onClick={(e) => { e.stopPropagation(); onActivate(isActive ? null : reason.id); }}
        style={{
          background: isActive ? `${color}22` : `${color}11`,
          borderBottom: `2px ${lineStyle} ${color}`,
          borderRadius: 2,
          cursor: "pointer",
          color: "inherit",
          padding: "1px 0",
          transition: "background 0.15s ease",
        }}
      >
        {content}
      </mark>
      {isActive && <Tooltip reason={reason} onClose={() => onActivate(null)} />}
    </span>
  );
}