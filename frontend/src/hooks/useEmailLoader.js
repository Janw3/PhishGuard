import { useEffect, useRef } from "react";
import { analyzeEmail, fetchEmails } from "../services/api";

export function useEmailLoader(addEmail, updateEmail) {
  const loaded = useRef(false);
  const updateEmailRef = useRef(updateEmail);

  useEffect(() => {
    updateEmailRef.current = updateEmail;
  }, [updateEmail]);

  useEffect(() => {
    if (loaded.current) return;
    loaded.current = true;

    async function load() {
      try {
        const emails = await fetchEmails();

        for (const email of emails) {
          addEmail({ ...email, status: "loading", analysis: null });
        }

        await new Promise((r) => setTimeout(r, 200));

        for (const email of emails) {
          try {
            const analysis = await analyzeEmail(email.body, { sender: email.from });
            updateEmailRef.current(email.id, { status: "analyzed", analysis });
          } catch (e) {
            updateEmailRef.current(email.id, { status: "error", error: e.message, errorCode: e.code });
          }
        }
      } catch (e) {
        console.error("Could not load emails:", e);
      }
    }

    load();
    // addEmail is stable (useCallback in useEmailStore), so this effect still runs
    // once; the `loaded` ref additionally guards against StrictMode's double run.
  }, [addEmail]);
}