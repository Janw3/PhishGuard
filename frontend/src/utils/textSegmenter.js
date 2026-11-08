export function splitIntoSegments(text, reasons) {
  if (!reasons || reasons.length === 0) {
    return [{ type: "text", content: text }];
  }

  const sorted = [...reasons]
    .filter((r) => r.start >= 0 && r.end > r.start)
    .sort((a, b) => a.start - b.start);

  const segments = [];
  let cursor = 0;

  for (const reason of sorted) {
    if (reason.start < cursor) continue;

    if (reason.start > cursor) {
      segments.push({ type: "text", content: text.slice(cursor, reason.start) });
    }

    segments.push({ type: "highlight", content: text.slice(reason.start, reason.end), reason });
    cursor = reason.end;
  }

  if (cursor < text.length) {
    segments.push({ type: "text", content: text.slice(cursor) });
  }

  return segments;
}