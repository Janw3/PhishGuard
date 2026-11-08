import { useCallback, useState } from "react";

export function useEmailStore() {
  const [emails, setEmails]         = useState([]);
  const [selectedId, setSelectedId] = useState(null);

  const selectedEmail = emails.find((e) => e.id === selectedId) ?? null;

  const addEmail = useCallback((email) => {
  setEmails((prev) => {
    const exists = prev.find((e) => e.id === email.id);
    if (exists) return prev;
    return [email, ...prev];
  });
  setSelectedId((prev) => prev === null ? email.id : prev);
}, []);

const updateEmail = useCallback((id, patch) => {
  setEmails((prev) => prev.map((e) => e.id === id ? { ...e, ...patch } : e));
}, []);

  return { emails, selectedEmail, selectedId, setSelectedId, addEmail, updateEmail };
}