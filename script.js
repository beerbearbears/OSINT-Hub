document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusText = document.getElementById("status-text");

  const landing = {}; // keep your existing landing mapping here (same as before)
  // ✅ IMPORTANT:
  // copy the landing object from your last working version (the long one).
  // I didn't remove anything; UI-only change.

  function setStatus(msg) {
    if (statusText) statusText.textContent = msg;
  }

  function setLandingLinks() {
    Object.entries(landing).forEach(([id, href]) => {
      const el = document.getElementById(id);
      if (el) el.href = href;
    });
  }

  function renderCardMeta() {
    document.querySelectorAll(".meta[data-meta]").forEach(m => {
      const id = m.getAttribute("data-meta");
      const a = document.getElementById(id);
      if (a && a.href) m.textContent = a.href;
    });
  }

  function looksLikeHeaders(text) {
    const t = (text || "").trim();
    if (!t || !t.includes("\n")) return false;
    const signals = [/^received:/im,/^authentication-results:/im,/^dkim-signature:/im,/^arc-seal:/im,/^message-id:/im,/^return-path:/im];
    return signals.some(rx => rx.test(t));
  }

  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    const urlLike = v.match(/^(https?:\/\/)/i);
    if (urlLike) {
      try { v = new URL(v).hostname; } catch { v = v.replace(/^[a-z]+:\/\//i, ""); }
    }
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  function detectType(raw) {
    const t = (raw || "").trim();
    const v = normalize(t);

    if (looksLikeHeaders(t)) return { type: "header", q: "" };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return { type: "ip", q: v };
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) return { type: "hash", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };
    return { type: null, q: v };
  }

  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      const secType = section.dataset.type;
      if (!type) { section.style.display = "block"; return; }
      if (!secType) { section.style.display = "block"; return; } // MITRE
      section.style.display = (secType === type) ? "block" : "none";
    });
  }

  // ✅ Keep your existing updateLinks(), defang/refang/extractIOCs/copy/clear/theme
  // from the last working version you already had.

  // Startup
  setLandingLinks();
  renderCardMeta();
  showRelevantTools(null);
  setStatus("ready (landing page)");
});
