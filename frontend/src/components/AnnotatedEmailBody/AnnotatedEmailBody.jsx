import { useState, useCallback } from "react";
import { splitIntoSegments } from "../../utils/textSegmenter";
import HighlightSpan from "./HighlightSpan";

export default function AnnotatedEmailBody({ text, reasons }) {
  const [activeId, setActiveId] = useState(null);
  const segments = splitIntoSegments(text, reasons);

  const handleActivate = useCallback((id) => setActiveId(id), []);

  return (
    <div
      onClick={() => setActiveId(null)}
      style={{
        fontFamily: "Georgia, serif",
        fontSize: 14,
        lineHeight: 1.85,
        color: "#94a3b8",
        whiteSpace: "pre-wrap",
        background: "#060d1a",
        border: "1px solid #1e293b",
        borderRadius: 8,
        padding: "24px 28px",
      }}
    >
      {segments.map((seg, i) =>
        seg.type === "text" ? (
          <span key={i}>{seg.content}</span>
        ) : (
          <HighlightSpan
            key={seg.reason.id}
            content={seg.content}
            reason={seg.reason}
            isActive={activeId === seg.reason.id}
            onActivate={handleActivate}
          />
        )
      )}
    </div>
  );
}