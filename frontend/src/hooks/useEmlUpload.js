import { useCallback } from "react";
import { analyzeEml } from "../services/api";

// Uploads a .eml file: shows it in the inbox right away ("Analysing…"),
// then fills in subject, sender, body and the analysis from the backend.
export function useEmlUpload(addEmail, updateEmail, setSelectedId) {
  const upload = useCallback(
    async (file) => {
      const id = `upload-${Date.now()}`;
      const time = new Date().toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });

      addEmail({
        id,
        from: "Uploaded file",
        subject: file.name,
        preview: "",
        body: "",
        time,
        status: "loading",
        analysis: null,
      });
      setSelectedId(id);

      try {
        const result = await analyzeEml(file);
        const { email, ...analysis } = result;
        updateEmail(id, {
          status: "analyzed",
          analysis,
          from: email.sender || "Unknown sender",
          subject: email.subject || file.name,
          body: email.body,
          preview: email.body.slice(0, 90).replace(/\s+/g, " "),
        });
      } catch (e) {
        updateEmail(id, { status: "error", error: e.message, errorCode: e.code });
      }
    },
    [addEmail, updateEmail, setSelectedId],
  );

  return { upload };
}
