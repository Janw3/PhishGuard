import EmailDetail from "./components/EmailDetail/EmailDetail";
import EmailList from "./components/EmailList/EmailList";
import AppHeader from "./components/Layout/AppHeader";
import { useEmailLoader } from "./hooks/useEmailLoader";
import { useEmailStore } from "./hooks/useEmailStore";
import { useEmlUpload } from "./hooks/useEmlUpload";

export default function App() {
  const { emails, selectedEmail, selectedId, setSelectedId, addEmail, updateEmail } = useEmailStore();

  useEmailLoader(addEmail, updateEmail);
  const { upload } = useEmlUpload(addEmail, updateEmail, setSelectedId);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: "#060d1a" }}>
      <AppHeader onUpload={upload} />
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        <EmailList
          emails={emails}
          selectedId={selectedId}
          onSelect={setSelectedId}
        />
        <EmailDetail email={selectedEmail} />
      </div>
    </div>
  );
}