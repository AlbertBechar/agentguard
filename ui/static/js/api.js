// api.js -- όλες οι κλήσεις προς τον server και ενιαία διαχείριση σφαλμάτων.
// Κάθε αποτυχία γίνεται ApiError με ελληνικό μήνυμα (ποτέ stack trace, ποτέ ωμό σώμα απάντησης).

export class ApiError extends Error {
  constructor({ code, message, status = 0, reasons = null, items = null }) {
    super(message);
    this.name = "ApiError";
    this.code = code; this.status = status; this.reasons = reasons; this.items = items;
  }
}

async function request(method, path, body) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: method === "GET" ? undefined : JSON.stringify(body === undefined ? {} : body),
      cache: "no-store",
    });
  } catch {
    throw new ApiError({ code: "network", message: "Δεν υπάρχει επικοινωνία με τον server του AgentGuard. Έλεγξε ότι τρέχει (python ui/server.py) και δοκίμασε ξανά." });
  }
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) {
    const e = data && data.error ? data.error : {};
    throw new ApiError({
      code: e.code || `http_${res.status}`,
      message: typeof e.message === "string" && e.message ? e.message : `Ο server απάντησε με σφάλμα (${res.status}). Δοκίμασε ξανά.`,
      status: res.status, reasons: e.reasons || (data && data.reasons) || null, items: e.items || null,
    });
  }
  return data;
}

const enc = encodeURIComponent;

export const api = {
  status: () => request("GET", "/api/status"),
  presets: () => request("GET", "/api/presets"),
  parseTools: (text) => request("POST", "/api/tools/parse", { text }),
  createSession: (body) => request("POST", "/api/session", body),
  answers: (sid, answers) => request("POST", `/api/session/${enc(sid)}/answers`, { answers }),
  generate: (sid) => request("POST", `/api/session/${enc(sid)}/generate`, {}),
  approve: (sid, by, confirm) => request("POST", `/api/session/${enc(sid)}/approve`, { by, confirm }),
  snippet: (sid, lang) => request("GET", `/api/session/${enc(sid)}/snippet/${enc(lang)}`),
  tryCall: (sid, body) => request("POST", `/api/session/${enc(sid)}/try`, body),
  attackRun: (body) => request("POST", "/api/attack/run", body),
  results: () => request("GET", "/api/results"),
  downloadUrl: (sid, name) => `/api/session/${enc(sid)}/download/${enc(name)}`,
};
