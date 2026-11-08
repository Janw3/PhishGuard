// Backend base URL. Vite reads VITE_API_URL from frontend/.env (see .env.example).
const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// An error from the backend, with a message that can be shown to the user and,
// if the backend sends one, a machine-readable code (e.g. "unsupported_language").
export class ApiError extends Error {
  constructor(message, { status, code } = {}) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_URL}${path}`, options);
  } catch {
    // fetch only fails like this if there is no answer at all, or if the browser blocks
    // the answer because the backend does not allow this page's address (CORS).
    throw new ApiError(
      `Could not reach the backend at ${API_URL}. Is it running, and does CORS_ORIGINS in backend/.env include this page's address?`,
    );
  }

  if (!response.ok) {
    // FastAPI puts the reason into `detail`: a string, or an object with `message` and `error`.
    const body = await response.json().catch(() => ({}));
    const detail = body.detail;
    const message =
      typeof detail === "string" ? detail : detail?.message ?? `Backend error: ${response.status}`;
    throw new ApiError(message, { status: response.status, code: detail?.error });
  }

  return response.json();
}

export function fetchEmails() {
  return request("/emails");
}

// The backend normalizes the text for the model itself, so we send it unchanged.
// That way the highlight offsets refer to exactly the text the UI displays.
// `sender` (e.g. "PayPal <service@paypal.com>") enables the sender checks.
// Both options are optional; undefined values are left out of the JSON.
export function analyzeEmail(content, { sender, model } = {}) {
  return request("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, sender, model }),
  });
}

// Sends a complete .eml file. The response contains the analysis plus
// `email` (subject, sender, reply_to, body); highlight offsets refer to `email.body`.
export function analyzeEml(file) {
  return request("/analyze-eml", {
    method: "POST",
    headers: { "Content-Type": "message/rfc822" },
    body: file,
  });
}

export function fetchModels() {
  return request("/models");
}
