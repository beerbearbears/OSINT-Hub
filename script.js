document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  const $ = (id) => document.getElementById(id);
  const enc = encodeURIComponent;

  const setHref = (id, href) => { const el = $(id); if (el) el.href = href; };
  const setStatus = (msg) => { if (statusText) statusText.textContent = msg; };

  // ─── Searchbox UI ────────────────────────────────────────────
  const searchbox = document.getElementById("searchbox");
  const clearBtn = document.getElementById("clear-input");
  function syncSearchboxState() {
    if (!searchbox || !input) return;
    searchbox.classList.toggle("has-value", !!(input.value && input.value.trim()));
  }
  if (input) input.addEventListener("input", syncSearchboxState);
  if (clearBtn && input) clearBtn.addEventListener("click", () => { input.value = ""; syncSearchboxState(); input.focus(); });

  // ─── Helpers ─────────────────────────────────────────────────
  const gsearch = (q) => `https://www.google.com/search?q=${enc(q)}`;
  const anyrunLookupGeneral = (q) =>
    `https://intelligence.any.run/analysis/lookup#${enc(JSON.stringify({ query: q, dateRange: 180 }))}`;

  function isValidIPv4(addr) {
    const parts = (addr || "").trim().split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }
  function isPrivateIPv4(ip) {
    if (!isValidIPv4(ip)) return false;
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }
  function isValidIPv6(addr) {
    const v = (addr || "").trim().replace(/^\[|\]$/g, "");
    try { new URL(`http://[${v}]/`); return true; } catch { return false; }
  }
  function isPrivateIPv6(ip) {
    const v = (ip || "").toLowerCase();
    return v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v === "::1";
  }

  function looksLikeHeaders(text) {
    const t = (text || "").trim();
    if (!t) return false;
    const normalized = t.replace(/\r\n/g, "\n");
    const head = normalized.split("\n").slice(0, 120).join("\n");
    const strong = [
      /(^|\n)\s*received:\s/im, /(^|\n)\s*authentication-results:\s/im,
      /(^|\n)\s*dkim-signature:\s/im, /(^|\n)\s*arc-seal:\s/im,
      /(^|\n)\s*message-id:\s/im, /(^|\n)\s*return-path:\s/im,
      /(^|\n)\s*from:\s/im, /(^|\n)\s*to:\s/im,
      /(^|\n)\s*subject:\s/im, /(^|\n)\s*date:\s/im,
    ];
    const hasAnyStrong = strong.some(rx => rx.test(head));
    const headerLineCount = (head.match(/(^|\n)[A-Za-z0-9-]{2,}:\s.+/g) || []).length;
    return hasAnyStrong || headerLineCount >= 8;
  }

  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.replace(/\[:\]/g, ":");
    if (/^(https?:\/\/)/i.test(v)) {
      try { v = new URL(v).hostname; } catch { v = v.replace(/^[a-z]+:\/\//i, ""); }
    }
    v = v.replace(/^\[|\]$/g, "");
    v = v.replace(/[,;]+$/g, "");
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  // ─── Email header parser ──────────────────────────────────────
  function parseEmailHeaders(text) {
    const t = (text || "").replace(/\r\n/g, "\n");
    const getLine = (re) => (t.match(re) || [])[1]?.trim() || "";
    const from = getLine(/^from:\s*(.+)$/im);
    const to = getLine(/^to:\s*(.+)$/im);
    const subject = getLine(/^subject:\s*(.+)$/im);
    const date = getLine(/^date:\s*(.+)$/im);
    const messageId = getLine(/^message-id:\s*(.+)$/im).replace(/[<>]/g, "");
    const returnPath = getLine(/^return-path:\s*<?([^>\s]+)>?/im);
    const senderEmail = (from.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";
    const receiverEmail = (to.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";
    const returnPathDomain = (returnPath.split("@")[1] || "").toLowerCase();
    const dkimMatch = t.match(/^dkim-signature:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im);
    const dkimBlock = (dkimMatch && dkimMatch[1]) ? dkimMatch[1].replace(/\n\s+/g, " ") : "";
    const dkimSelector = (dkimBlock.match(/\bs=([^;\s]+)/i) || [])[1] || "";
    const dkimDomain = ((dkimBlock.match(/\bd=([^;\s]+)/i) || [])[1] || "").toLowerCase();
    const authMatch = t.match(/^authentication-results:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im);
    const authBlock = (authMatch && authMatch[1]) ? authMatch[1].replace(/\n\s+/g, " ") : "";
    const spfResult = ((authBlock.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();
    const dkimResult = ((authBlock.match(/\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();
    const spfMailfrom = ((authBlock.match(/\bsmtp\.mailfrom=([^;\s]+)/i) || [])[1] || "").toLowerCase();
    const spfMailfromDomain = (spfMailfrom.split("@")[1] || "").toLowerCase();
    const receivedAll = t.match(/^received:\s*[\s\S]*?(?=\n[A-Za-z0-9-]{2,}:\s|$)/gim) || [];
    let originIp = "";
    for (let i = receivedAll.length - 1; i >= 0; i--) {
      const block = receivedAll[i];
      const ip = (block.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || "";
      if (ip && isValidIPv4(ip) && !isPrivateIPv4(ip)) { originIp = ip; break; }
    }
    return { from, to, subject, date, senderEmail, receiverEmail, messageId, returnPath, returnPathDomain, dkimSelector, dkimDomain, spfMailfrom, spfMailfromDomain, spfResult, dkimResult, originIp };
  }

  // ─── Type detection ───────────────────────────────────────────
  function detectType(raw, pastedText) {
    const r = (raw || "").trim();
    const p = (pastedText || "").trim();
    if (looksLikeHeaders(p) || looksLikeHeaders(r)) return { type: "header", q: "" };
    const v = normalize(r);
    const rawTrimmed = r.replace(/^hxxps?:\/\//i, "https://").replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    if (/^https?:\/\/.{4,}/i.test(rawTrimmed)) return { type: "url", q: rawTrimmed };
    if (/^T\d{4,5}$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v.toLowerCase() };
    if (/^\d{3,5}$/.test(v)) return { type: "eventid", q: v };
    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v))
      return { type: "hash", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9._-]{3,}$/.test(v)) return { type: "username", q: v };
    return { type: null, q: v };
  }

  // ─── Session History ──────────────────────────────────────────
  const sessionHistory = [];
  function addToHistory(type, value) {
    const entry = { type, value, time: new Date() };
    sessionHistory.unshift(entry);
    if (sessionHistory.length > 50) sessionHistory.pop();
    renderHistory();
  }
  function renderHistory() {
    const list = $("history-list");
    if (!list) return;
    if (!sessionHistory.length) { list.innerHTML = '<div class="history-empty">No searches yet.</div>'; return; }
    list.innerHTML = sessionHistory.map((e, i) => {
      const t = e.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      const typeColor = { ip:"#38bdf8",domain:"#34d399",hash:"#f59e0b",email:"#a78bfa",url:"#fb923c",cve:"#f87171",username:"#e879f9",header:"#67e8f9",eventid:"#86efac",mitre:"#fbbf24" }[e.type] || "#9ca3af";
      return `<div class="history-item" data-index="${i}">
        <span class="history-badge" style="background:${typeColor}22;color:${typeColor};border-color:${typeColor}44">${e.type.toUpperCase()}</span>
        <span class="history-val" title="${e.value}">${e.value.length > 22 ? e.value.slice(0, 22) + "…" : e.value}</span>
        <span class="history-time">${t}</span>
      </div>`;
    }).join("");
    list.querySelectorAll(".history-item").forEach(item => {
      item.addEventListener("click", () => {
        const idx = Number(item.getAttribute("data-index"));
        const entry = sessionHistory[idx];
        if (entry && input) { input.value = entry.value; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
      });
    });
  }

  const exportHistoryBtn = $("export-history");
  if (exportHistoryBtn) {
    exportHistoryBtn.addEventListener("click", () => {
      if (!sessionHistory.length) return alert("No history to export yet.");
      const lines = ["OSINT Session History Export", `Exported: ${new Date().toISOString()}`, "─".repeat(50)];
      sessionHistory.forEach(e => lines.push(`[${e.time.toISOString()}] ${e.type.toUpperCase().padEnd(10)} ${e.value}`));
      const blob = new Blob([lines.join("\n")], { type: "text/plain" });
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
      a.download = `osint-session-${Date.now()}.txt`; a.click();
    });
  }

  // ─── Tab Switcher ─────────────────────────────────────────────
  function switchTab(name) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.id === `tab-${name}`));
  }
  document.querySelectorAll(".tab-btn").forEach(btn => btn.addEventListener("click", () => switchTab(btn.dataset.tab)));


  // ═══════════════════════════════════════════════════
  // ─── CASE MANAGER ───────────────────────────────
  // ═══════════════════════════════════════════════════
  let activeCase = null;

  function saveCaseToStorage() {
    if (activeCase) localStorage.setItem("osint_active_case", JSON.stringify(activeCase));
    else localStorage.removeItem("osint_active_case");
  }

  function loadCaseFromStorage() {
    try { const d = localStorage.getItem("osint_active_case"); if (d) activeCase = JSON.parse(d); } catch {}
  }

  function updateCaseIndicator() {
    const sec = $("case-indicator-section");
    const ind = $("case-indicator");
    if (!sec || !ind) return;
    if (activeCase) {
      sec.style.display = "block";
      ind.innerHTML = `<div class="case-ind-name">📁 ${activeCase.name}</div>
        <div class="case-ind-meta">${activeCase.iocs.length} IOC(s) · ${activeCase.status}</div>`;
    } else {
      sec.style.display = "none";
    }
  }

  function renderCaseBody() {
    const body = $("case-body");
    const caseStatus = $("case-status");
    if (!body) return;
    if (!activeCase) {
      body.innerHTML = '<div class="bulk-empty">No active case. Create one above.</div>';
      if (caseStatus) caseStatus.querySelector("span").textContent = "No active case.";
      return;
    }
    if (caseStatus) caseStatus.querySelector("span").textContent = `Case: ${activeCase.name} · ${activeCase.iocs.length} IOC(s) · Status: ${activeCase.status}`;
    const statusColors = { Open:"#f87171", Investigating:"#fbbf24", Contained:"#34d399", Closed:"#9ca3af" };
    body.innerHTML = `
      <div class="case-header-card">
        <div class="case-title">${activeCase.name}</div>
        <div class="case-meta-row">
          <span>Created: ${new Date(activeCase.created).toLocaleString()}</span>
          <select id="case-status-select" class="aw-input" style="max-width:140px">
            ${["Open","Investigating","Contained","Closed"].map(s =>
              `<option value="${s}"${activeCase.status===s?" selected":""}>${s}</option>`).join("")}
          </select>
        </div>
        <textarea id="case-notes-area" class="aw-input aw-textarea" rows="3" placeholder="Case notes / analyst observations..."
          style="margin-top:10px;width:100%;box-sizing:border-box">${activeCase.notes||""}</textarea>
        <button id="case-save-notes-btn" type="button" style="margin-top:6px;font-size:12px;padding:5px 10px">💾 Save Notes</button>
      </div>
      <div class="case-ioc-list">
        ${activeCase.iocs.length === 0 ? '<div class="bulk-empty">No IOCs added yet. Search an IOC and click "Add to Case".</div>' :
          activeCase.iocs.map((ioc, i) => {
            const c = {ip:"#38bdf8",domain:"#34d399",hash:"#f59e0b",email:"#a78bfa",url:"#fb923c",cve:"#f87171",username:"#e879f9"}[ioc.type]||"#9ca3af";
            return `<div class="case-ioc-row">
              <span class="case-ioc-badge" style="background:${c}22;color:${c};border-color:${c}44">${ioc.type.toUpperCase()}</span>
              <span class="case-ioc-val">${ioc.value}</span>
              <span class="case-ioc-time">${new Date(ioc.added).toLocaleString()}</span>
              <input type="text" class="case-ioc-note aw-input" value="${ioc.note||""}" placeholder="IOC note..." data-idx="${i}" style="font-size:11px;padding:4px 8px;max-width:200px" />
              <button class="case-remove-ioc" data-idx="${i}" type="button" style="font-size:11px;padding:4px 8px;color:#f87171">✕</button>
            </div>`;
          }).join("")}
      </div>`;

    const statusSel = $("case-status-select");
    if (statusSel) statusSel.addEventListener("change", () => { activeCase.status = statusSel.value; saveCaseToStorage(); renderCaseBody(); updateCaseIndicator(); });

    const notesArea = $("case-notes-area");
    const saveNotesBtn = $("case-save-notes-btn");
    if (saveNotesBtn && notesArea) saveNotesBtn.addEventListener("click", () => { activeCase.notes = notesArea.value; saveCaseToStorage(); });

    body.querySelectorAll(".case-ioc-note").forEach(inp => {
      inp.addEventListener("change", () => {
        const idx = Number(inp.dataset.idx);
        activeCase.iocs[idx].note = inp.value;
        saveCaseToStorage();
      });
    });
    body.querySelectorAll(".case-remove-ioc").forEach(btn => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.idx);
        activeCase.iocs.splice(idx, 1);
        saveCaseToStorage(); renderCaseBody(); updateCaseIndicator();
      });
    });
  }

  function addIOCToCase(type, value) {
    if (!activeCase) {
      const name = prompt("No active case. Enter a case name to create one:","INC-" + Date.now());
      if (!name) return;
      activeCase = { name, created: Date.now(), status: "Open", iocs: [], notes: "" };
    }
    if (activeCase.iocs.find(i => i.value === value)) { alert("IOC already in case."); return; }
    activeCase.iocs.push({ type, value, added: Date.now(), note: "" });
    saveCaseToStorage(); renderCaseBody(); updateCaseIndicator();
    setStatus(`Added to case: ${value}`);
  }

  const caseNewBtn = $("case-new-btn");
  if (caseNewBtn) caseNewBtn.addEventListener("click", () => {
    const nameInp = $("case-name-input");
    const name = (nameInp?.value || "").trim() || "INC-" + Date.now();
    activeCase = { name, created: Date.now(), status: "Open", iocs: [], notes: "" };
    if (nameInp) nameInp.value = "";
    saveCaseToStorage(); renderCaseBody(); updateCaseIndicator();
  });

  const caseClearBtn = $("case-clear-btn");
  if (caseClearBtn) caseClearBtn.addEventListener("click", () => {
    if (!confirm("Clear active case?")) return;
    activeCase = null; saveCaseToStorage(); renderCaseBody(); updateCaseIndicator();
  });

  const caseExportBtn = $("case-export-btn");
  if (caseExportBtn) caseExportBtn.addEventListener("click", () => {
    if (!activeCase) return alert("No active case.");
    const lines = [
      "═══════════════════════════════════════",
      `  OSINT CASE REPORT`,
      "═══════════════════════════════════════",
      `Case Name  : ${activeCase.name}`,
      `Status     : ${activeCase.status}`,
      `Created    : ${new Date(activeCase.created).toISOString()}`,
      `Exported   : ${new Date().toISOString()}`,
      `IOC Count  : ${activeCase.iocs.length}`,
      "",
      "─── ANALYST NOTES ─────────────────────",
      activeCase.notes || "(none)",
      "",
      "─── IOCs ───────────────────────────────",
      ...activeCase.iocs.map((ioc, i) =>
        `${String(i+1).padStart(3)}. [${ioc.type.toUpperCase().padEnd(8)}] ${ioc.value}${ioc.note ? `  // ${ioc.note}` : ""}`),
      "",
      "═══════════════════════════════════════",
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `case-${activeCase.name.replace(/\s+/g,"-")}-${Date.now()}.txt`; a.click();
  });

  const addToCaseBtn = $("add-to-case-btn");
  if (addToCaseBtn) addToCaseBtn.addEventListener("click", () => {
    const raw = (input?.value || "").trim();
    if (!raw) return;
    const { type, q } = detectType(raw, "");
    if (type && q) addIOCToCase(type, q);
    else addIOCToCase("unknown", raw);
  });

  const bulkAddCaseBtn = $("bulk-add-case-btn");
  if (bulkAddCaseBtn) bulkAddCaseBtn.addEventListener("click", () => {
    const text = ($("bulk-input")?.value || "").trim();
    if (!text) return;
    const iocs = extractAllIOCsFromText(text);
    iocs.forEach(ioc => {
      if (!activeCase) activeCase = { name: "INC-" + Date.now(), created: Date.now(), status: "Open", iocs: [], notes: "" };
      if (!activeCase.iocs.find(i => i.value === ioc.q))
        activeCase.iocs.push({ type: ioc.type, value: ioc.q, added: Date.now(), note: "" });
    });
    saveCaseToStorage(); renderCaseBody(); updateCaseIndicator();
    setStatus(`Added ${iocs.length} IOCs to case`);
  });


  // ═══════════════════════════════════════════════════
  // ─── TIMELINE BUILDER ────────────────────────────
  // ═══════════════════════════════════════════════════
  let timelineEvents = [];
  const TL_COLORS = { initial:"#f87171",execution:"#fb923c",persistence:"#fbbf24",lateral:"#38bdf8",exfil:"#a78bfa",discovery:"#34d399",impact:"#6b7280",other:"#9ca3af" };
  const TL_LABELS = { initial:"🔴 Initial Access",execution:"🟠 Execution",persistence:"🟡 Persistence",lateral:"🔵 Lateral Movement",exfil:"🟣 Exfiltration",discovery:"🟢 Discovery",impact:"⚫ Impact",other:"⚪ Other" };

  function renderTimeline() {
    const body = $("timeline-body");
    if (!body) return;
    if (!timelineEvents.length) { body.innerHTML = '<div class="bulk-empty">No events yet. Add your first event above.</div>'; return; }
    const sorted = [...timelineEvents].sort((a, b) => new Date(a.time) - new Date(b.time));
    body.innerHTML = `<div class="timeline-track">` +
      sorted.map((ev, i) => {
        const c = TL_COLORS[ev.type] || "#9ca3af";
        return `<div class="tl-event">
          <div class="tl-dot" style="background:${c};box-shadow:0 0 8px ${c}66"></div>
          <div class="tl-card" style="border-left-color:${c}">
            <div class="tl-time">${new Date(ev.time).toLocaleString()}</div>
            <div class="tl-label" style="color:${c}">${TL_LABELS[ev.type]||ev.type}</div>
            <div class="tl-desc">${ev.desc}</div>
            <button class="tl-remove" data-idx="${ev.id}" type="button">✕ Remove</button>
          </div>
        </div>`;
      }).join("") + `</div>`;
    body.querySelectorAll(".tl-remove").forEach(btn => {
      btn.addEventListener("click", () => {
        timelineEvents = timelineEvents.filter(e => e.id !== btn.dataset.idx);
        renderTimeline();
      });
    });
  }

  const tlAddBtn = $("tl-add-btn");
  if (tlAddBtn) tlAddBtn.addEventListener("click", () => {
    const timeVal = $("tl-time-input")?.value;
    const desc = ($("tl-event-input")?.value || "").trim();
    const type = $("tl-type-select")?.value || "other";
    if (!desc) return;
    timelineEvents.push({ id: String(Date.now()), time: timeVal || new Date().toISOString(), desc, type });
    if ($("tl-event-input")) $("tl-event-input").value = "";
    renderTimeline();
  });

  const tlExportBtn = $("tl-export-btn");
  if (tlExportBtn) tlExportBtn.addEventListener("click", () => {
    if (!timelineEvents.length) return;
    const sorted = [...timelineEvents].sort((a,b) => new Date(a.time) - new Date(b.time));
    const lines = ["ATTACK TIMELINE", `Exported: ${new Date().toISOString()}`, "─".repeat(60),
      ...sorted.map((ev, i) => `[T+${i}] ${new Date(ev.time).toLocaleString().padEnd(22)} | ${(TL_LABELS[ev.type]||ev.type).padEnd(20)} | ${ev.desc}`)];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `timeline-${Date.now()}.txt`; a.click();
  });

  const tlClearBtn = $("tl-clear-btn");
  if (tlClearBtn) tlClearBtn.addEventListener("click", () => { timelineEvents = []; renderTimeline(); });

  // ═══════════════════════════════════════════════════
  // ─── HASH FILE (CLIENT-SIDE) ─────────────────────
  // ═══════════════════════════════════════════════════
  async function computeFileHashes(file) {
    const buf = await file.arrayBuffer();
    const hashTypes = ["SHA-256","SHA-1"];
    const results = {};
    for (const algo of hashTypes) {
      const hashBuf = await crypto.subtle.digest(algo, buf);
      results[algo] = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,"0")).join("");
    }
    // MD5 approximation using SubtleCrypto isn't native; use a simple checksum display note
    results["MD5"] = "(MD5 not natively supported in browser — use SHA-256 above)";
    return results;
  }

  const hashDropzone = $("hash-dropzone");
  const hashFileInput = $("hash-file-input");
  const hashResults = $("hash-results");

  async function handleHashFile(file) {
    if (!hashResults) return;
    hashResults.style.display = "block";
    hashResults.innerHTML = `<div class="hash-computing">⏳ Computing hashes for <strong>${file.name}</strong> (${(file.size/1024).toFixed(1)} KB)...</div>`;
    try {
      const hashes = await computeFileHashes(file);
      const sha256 = hashes["SHA-256"];
      const sha1 = hashes["SHA-1"];
      hashResults.innerHTML = `
        <div class="hash-result-card">
          <div class="hash-file-info">
            <span class="hash-filename">📄 ${file.name}</span>
            <span class="hash-filesize">${(file.size/1024).toFixed(2)} KB · ${file.type || "unknown type"}</span>
          </div>
          <div class="hash-row">
            <span class="hash-algo">SHA-256</span>
            <code class="hash-val" id="hf-sha256">${sha256}</code>
            <button class="hash-copy-btn" data-hash="${sha256}" type="button">📋</button>
            <button class="hash-pivot-btn" data-hash="${sha256}" type="button">🔍 Pivot</button>
          </div>
          <div class="hash-row">
            <span class="hash-algo">SHA-1</span>
            <code class="hash-val">${sha1}</code>
            <button class="hash-copy-btn" data-hash="${sha1}" type="button">📋</button>
            <button class="hash-pivot-btn" data-hash="${sha1}" type="button">🔍 Pivot</button>
          </div>
          <div class="hash-row hash-row-muted">
            <span class="hash-algo">MD5</span>
            <code class="hash-val" style="color:var(--muted);font-size:11px">${hashes["MD5"]}</code>
          </div>
          <div class="hash-pivot-links">
            <div class="hash-pivot-label">Quick pivot links (SHA-256):</div>
            <a href="https://www.virustotal.com/gui/file/${sha256}" target="_blank" class="bulk-link">VirusTotal</a>
            <a href="https://bazaar.abuse.ch/browse.php?search=${sha256}" target="_blank" class="bulk-link">MalwareBazaar</a>
            <a href="https://www.hybrid-analysis.com/search?query=${sha256}" target="_blank" class="bulk-link">Hybrid Analysis</a>
            <a href="https://www.joesandbox.com/analysis/search?q=${sha256}" target="_blank" class="bulk-link">JoeSandbox</a>
            <a href="https://otx.alienvault.com/indicator/file/${sha256}" target="_blank" class="bulk-link">OTX</a>
            <a href="https://tria.ge/s?q=${sha256}" target="_blank" class="bulk-link">Triage</a>
          </div>
        </div>`;
      hashResults.querySelectorAll(".hash-copy-btn").forEach(btn => {
        btn.addEventListener("click", async () => { try { await navigator.clipboard.writeText(btn.dataset.hash); } catch {} });
      });
      hashResults.querySelectorAll(".hash-pivot-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          if (input) { input.value = btn.dataset.hash; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
        });
      });
      addToHistory("hash", sha256);
    } catch (err) {
      hashResults.innerHTML = `<div class="bulk-empty">Error computing hash: ${err.message}</div>`;
    }
  }

  if (hashDropzone) {
    hashDropzone.addEventListener("click", () => hashFileInput?.click());
    hashDropzone.addEventListener("dragover", e => { e.preventDefault(); hashDropzone.classList.add("drag-over"); });
    hashDropzone.addEventListener("dragleave", () => hashDropzone.classList.remove("drag-over"));
    hashDropzone.addEventListener("drop", e => {
      e.preventDefault(); hashDropzone.classList.remove("drag-over");
      const file = e.dataTransfer.files[0]; if (file) handleHashFile(file);
    });
  }
  if (hashFileInput) hashFileInput.addEventListener("change", () => { if (hashFileInput.files[0]) handleHashFile(hashFileInput.files[0]); });

  // Ctrl+H shortcut
  document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "h" || e.key === "H")) { e.preventDefault(); switchTab("hashfile"); hashDropzone?.click(); }
  });


  // ═══════════════════════════════════════════════════
  // ─── BULK DEFANG / REFANG ────────────────────────
  // ═══════════════════════════════════════════════════
  function defangSmart(text) {
    let t = (text || "");
    t = t.replace(/\bhttps?:\/\/[^\s<>"')]+/gi, m => {
      let x = m.replace(/^https:\/\//i,"hxxps://").replace(/^http:\/\//i,"hxxp://");
      x = x.replace(/\./g,"[.]"); return x;
    });
    t = t.replace(/\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, (m,u,d) => `${u}[@]${String(d).replace(/\./g,"[.]")}`);
    t = t.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, m => isValidIPv4(m) ? m.replace(/\./g,"[.]") : m);
    t = t.replace(/(\[?[0-9A-Fa-f:]{2,}\]?)/g, token => {
      if (!token.includes(":")) return token;
      const trail = token.match(/[),.;]+$/)?.[0] || "";
      const core = token.slice(0, token.length - trail.length);
      const cleaned = core.replace(/^\[|\]$/g,"");
      if (!isValidIPv6(cleaned)) return token;
      return core.replace(/:/g,"[:]") + trail;
    });
    t = t.replace(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi, m => {
      if (m.includes("[.]")) return m;
      if (/\.(exe|dll|sys|bat|cmd|ps1|js|vbs)$/i.test(m)) return m;
      if (!/\.[a-z]{2,}$/i.test(m)) return m;
      return m.replace(/\./g,"[.]");
    });
    return t;
  }

  function refangSmart(text) {
    let t = (text || "");
    t = t.replace(/hxxps:\/\//gi,"https://").replace(/hxxp:\/\//gi,"http://");
    t = t.replace(/\[@\]/g,"@").replace(/\[\.\]/g,".").replace(/\[:\]/g,":");
    return t;
  }

  function buildDiffView(original, modified) {
    const origLines = original.split("\n");
    const modLines = modified.split("\n");
    const maxLen = Math.max(origLines.length, modLines.length);
    let changes = 0;
    const rows = [];
    for (let i = 0; i < maxLen; i++) {
      const o = origLines[i] ?? "";
      const m = modLines[i] ?? "";
      if (o !== m) { changes++; rows.push(`<div class="diff-row changed"><span class="diff-minus">- ${o.replace(/</g,"&lt;")}</span><span class="diff-plus">+ ${m.replace(/</g,"&lt;")}</span></div>`); }
    }
    return { html: rows.join(""), changes };
  }

  const dfbDefangBtn = $("dfb-defang-btn");
  const dfbRefangBtn = $("dfb-refang-btn");
  const dfbCopyBtn = $("dfb-copy-btn");
  const dfbClearBtn = $("dfb-clear-btn");
  const dfbInput = $("dfb-input");
  const dfbOutput = $("dfb-output");
  const dfbDiff = $("dfb-diff");

  function runDFB(fn) {
    const src = dfbInput?.value || "";
    if (!src.trim()) return;
    const result = fn(src);
    if (dfbOutput) dfbOutput.value = result;
    if (dfbDiff) {
      const { html, changes } = buildDiffView(src, result);
      if (changes) {
        dfbDiff.style.display = "block";
        dfbDiff.innerHTML = `<div class="diff-head">📊 ${changes} line(s) changed</div>${html}`;
      } else {
        dfbDiff.style.display = "block";
        dfbDiff.innerHTML = `<div class="diff-head">✅ No changes detected</div>`;
      }
    }
  }

  if (dfbDefangBtn) dfbDefangBtn.addEventListener("click", () => runDFB(defangSmart));
  if (dfbRefangBtn) dfbRefangBtn.addEventListener("click", () => runDFB(refangSmart));
  if (dfbCopyBtn) dfbCopyBtn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(dfbOutput?.value || ""); } catch {}
  });
  if (dfbClearBtn) dfbClearBtn.addEventListener("click", () => {
    if (dfbInput) dfbInput.value = "";
    if (dfbOutput) dfbOutput.value = "";
    if (dfbDiff) { dfbDiff.style.display = "none"; dfbDiff.innerHTML = ""; }
  });

  // ═══════════════════════════════════════════════════
  // ─── YARA / SIGMA GENERATOR ──────────────────────
  // ═══════════════════════════════════════════════════
  document.querySelectorAll(".yara-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".yara-tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      $("yara-panel").style.display = btn.dataset.ytab === "yara" ? "block" : "none";
      $("sigma-panel").style.display = btn.dataset.ytab === "sigma" ? "block" : "none";
    });
  });

  function generateYARA() {
    const name = ($("yara-rulename")?.value || "MAL_Custom_Rule").replace(/\s+/g,"_");
    const author = $("yara-author")?.value || "Analyst";
    const hashes = ($("yara-hashes")?.value || "").split(",").map(s=>s.trim()).filter(Boolean);
    const strings = ($("yara-strings")?.value || "").split(",").map(s=>s.trim()).filter(Boolean);
    const urls = ($("yara-urls")?.value || "").split(",").map(s=>s.trim()).filter(Boolean);
    const notes = $("yara-notes")?.value || "";
    const now = new Date().toISOString().split("T")[0];

    let rule = `rule ${name}\n{\n`;
    rule += `    meta:\n`;
    rule += `        description = "${notes || "Auto-generated by Romel OSINT Toolkit"}"\n`;
    rule += `        author = "${author}"\n`;
    rule += `        date = "${now}"\n`;
    rule += `        version = "1.0"\n`;
    if (hashes.length) hashes.forEach((h,i) => rule += `        hash_${i+1} = "${h}"\n`);
    rule += `\n    strings:\n`;
    strings.forEach((s,i) => rule += `        $str_${i+1} = "${s}" nocase\n`);
    urls.forEach((u,i) => rule += `        $url_${i+1} = "${u}" nocase\n`);
    if (!strings.length && !urls.length) rule += `        // TODO: Add detection strings\n        $placeholder = "EDIT_ME"\n`;
    rule += `\n    condition:\n`;
    if (strings.length > 1 || urls.length > 1)
      rule += `        any of them\n`;
    else if (strings.length === 1 && urls.length === 0)
      rule += `        $str_1\n`;
    else if (strings.length === 0 && urls.length === 1)
      rule += `        $url_1\n`;
    else
      rule += `        all of them\n`;
    rule += `}\n`;
    return rule;
  }

  function generateSigma() {
    const title = $("sigma-title")?.value || "Suspicious Activity Detected";
    const author = $("sigma-author")?.value || "Analyst";
    const logsource = $("sigma-logsource")?.value || "windows_process";
    const ioc = $("sigma-ioc")?.value || "EDIT_ME";
    const mitre = ($("sigma-mitre")?.value || "").split(",").map(s=>s.trim()).filter(Boolean);
    const level = $("sigma-level")?.value || "high";
    const now = new Date().toISOString().split("T")[0];

    const logsourceMap = {
      windows_process: "    category: process_creation\n    product: windows",
      windows_security: "    product: windows\n    service: security",
      windows_powershell: "    category: ps_script\n    product: windows",
      windows_sysmon: "    category: process_creation\n    product: windows",
      proxy: "    category: proxy",
      firewall: "    category: firewall",
      linux_auditd: "    product: linux\n    service: auditd",
    };

    let yaml = `title: ${title}\n`;
    yaml += `id: ${crypto.randomUUID ? crypto.randomUUID() : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => (Math.random()*16|0).toString(16))}\n`;
    yaml += `status: experimental\n`;
    yaml += `description: '${title} — generated by Romel OSINT Toolkit'\n`;
    yaml += `author: ${author}\n`;
    yaml += `date: ${now}\n`;
    yaml += `references:\n    - https://attack.mitre.org/\n`;
    yaml += `tags:\n`;
    mitre.forEach(t => yaml += `    - attack.${t.toLowerCase().replace(".","_")}\n`);
    yaml += `logsource:\n${logsourceMap[logsource] || logsourceMap.windows_process}\n`;
    yaml += `detection:\n    selection:\n`;
    ioc.split(",").map(s=>s.trim()).forEach(s => yaml += `        CommandLine|contains: '${s}'\n`);
    yaml += `    condition: selection\n`;
    yaml += `falsepositives:\n    - Legitimate administrative activity\n`;
    yaml += `level: ${level}\n`;
    return yaml;
  }

  const yaraGenBtn = $("yara-gen-btn");
  if (yaraGenBtn) yaraGenBtn.addEventListener("click", () => {
    const out = $("yara-output");
    if (out) { out.style.display = "block"; out.textContent = generateYARA(); }
  });
  const yaraCopyBtn = $("yara-copy-btn");
  if (yaraCopyBtn) yaraCopyBtn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("yara-output")?.textContent || generateYARA()); } catch {}
  });
  const yaraClearBtn = $("yara-clear-btn");
  if (yaraClearBtn) yaraClearBtn.addEventListener("click", () => {
    ["yara-rulename","yara-author","yara-hashes","yara-strings","yara-urls","yara-notes"].forEach(id => { const el=$(id); if(el) el.value=""; });
    const out=$("yara-output"); if(out){out.style.display="none";out.textContent="";}
  });

  const sigmaGenBtn = $("sigma-gen-btn");
  if (sigmaGenBtn) sigmaGenBtn.addEventListener("click", () => {
    const out = $("sigma-output");
    if (out) { out.style.display = "block"; out.textContent = generateSigma(); }
  });
  const sigmaCopyBtn = $("sigma-copy-btn");
  if (sigmaCopyBtn) sigmaCopyBtn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("sigma-output")?.textContent || generateSigma()); } catch {}
  });
  const sigmaUncoderBtn = $("sigma-uncoder-btn");
  if (sigmaUncoderBtn) sigmaUncoderBtn.addEventListener("click", () => window.open("https://uncoder.io/","_blank"));
  const sigmaClearBtn = $("sigma-clear-btn");
  if (sigmaClearBtn) sigmaClearBtn.addEventListener("click", () => {
    ["sigma-title","sigma-author","sigma-ioc","sigma-mitre"].forEach(id=>{const el=$(id);if(el)el.value="";});
    const out=$("sigma-output"); if(out){out.style.display="none";out.textContent="";}
  });

  // Script Analyzer YARA/Sigma quick-gen buttons
  const saYaraBtn = $("sa-yara-btn");
  if (saYaraBtn) saYaraBtn.addEventListener("click", () => {
    const text = ($("sa-input")?.value || "").trim();
    if (!text) return;
    const iocs = extractScriptIOCs(text);
    if ($("yara-strings")) $("yara-strings").value = iocs.urls.slice(0,3).concat(iocs.domains.slice(0,3)).join(",");
    if ($("yara-urls")) $("yara-urls").value = iocs.urls.slice(0,5).join(",");
    switchTab("yara");
    document.querySelector(".yara-tab-btn[data-ytab='yara']")?.click();
    $("yara-gen-btn")?.click();
  });

  const saSigmaBtn = $("sa-sigma-btn");
  if (saSigmaBtn) saSigmaBtn.addEventListener("click", () => {
    const text = ($("sa-input")?.value || "").trim();
    if (!text) return;
    const mode = saCurrentMode === "auto" ? autoDetectMode(text) : saCurrentMode;
    const { mitre } = runIndicators(text, mode);
    if ($("sigma-mitre")) $("sigma-mitre").value = mitre.slice(0,4).join(", ");
    const iocs = extractScriptIOCs(text);
    if ($("sigma-ioc")) $("sigma-ioc").value = iocs.urls.slice(0,2).concat(iocs.domains.slice(0,2)).join(", ") || "EDIT_ME";
    switchTab("yara");
    document.querySelector(".yara-tab-btn[data-ytab='sigma']")?.click();
    $("sigma-gen-btn")?.click();
  });


  // ═══════════════════════════════════════════════════
  // ─── LOG / ALERT AUTO-TRIAGE ─────────────────────
  // ═══════════════════════════════════════════════════
  function triageLog(text) {
    const t = (text || "").replace(/\r\n/g,"\n");
    const results = { eventType: "Unknown", indicators: [], iocs: {}, prefillData: {} };

    // Detect log type
    if (/EventID|EventCode|EvtID|Event ID/i.test(t)) {
      results.eventType = "Windows Event Log";
      const evId = (t.match(/(?:EventID|Event ID|EventCode)[:\s=]+(\d{3,5})/i)||[])[1]||"";
      if (evId) { results.indicators.push(`Event ID: ${evId}`); results.prefillData.eventid = evId; }
    } else if (/SRC=|DST=|PROTO=|DPT=|SPT=/i.test(t)) {
      results.eventType = "Firewall Log";
      const src = (t.match(/SRC=([\d.]+)/i)||[])[1]||"";
      const dst = (t.match(/DST=([\d.]+)/i)||[])[1]||"";
      const proto = (t.match(/PROTO=(\w+)/i)||[])[1]||"";
      const dpt = (t.match(/DPT=(\d+)/i)||[])[1]||"";
      if (src) { results.indicators.push(`Source IP: ${src}`); results.prefillData.src_ip = src; }
      if (dst) { results.indicators.push(`Dest IP: ${dst}`); results.prefillData.dest_ip = dst; }
      if (proto) results.indicators.push(`Protocol: ${proto}`);
      if (dpt) results.indicators.push(`Dest Port: ${dpt}`);
    } else if (looksLikeHeaders(t)) {
      results.eventType = "Email Headers";
      const h = parseEmailHeaders(t);
      results.prefillData = { sender: h.senderEmail, recipient: h.receiverEmail, src_ip: h.originIp, spf_result: h.spfResult, dkim_result: h.dkimResult, subject: h.subject };
      results.indicators.push(`Sender: ${h.senderEmail}`, `SPF: ${h.spfResult}`, `DKIM: ${h.dkimResult}`, `Origin IP: ${h.originIp}`);
    } else if (/sigma|splunk|sentinel|crowdstrike|defender|alert/i.test(t)) {
      results.eventType = "SIEM Alert";
    } else if (/authentication|logon|login|password/i.test(t)) {
      results.eventType = "Authentication Event";
    }

    // Extract all IOCs
    const refanged = refangSmart(t);
    results.iocs.ips = [...new Set((refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)||[]).filter(isValidIPv4))];
    results.iocs.domains = [...new Set((refanged.match(/\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\b/g)||[]).filter(d=>!/^\d+\.\d+/.test(d)))];
    results.iocs.hashes = [...new Set((refanged.match(/\b[a-fA-F0-9]{64}\b/g)||[]))];
    results.iocs.cves = [...new Set((refanged.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(c=>c.toUpperCase()))];
    results.iocs.urls = [...new Set((refanged.match(/https?:\/\/[^\s"'`>)]+/gi)||[]))];
    results.iocs.emails = [...new Set((refanged.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g)||[]))];

    // Event ID lookup hint
    const evId = (t.match(/(?:EventID|Event ID|EventCode)[:\s=]+(\d{3,5})/i)||[])[1]||"";
    const evHints = {"4624":"Successful Logon","4625":"Failed Logon","4648":"Logon w/ Explicit Creds","4688":"Process Created","4698":"Scheduled Task Created","4720":"User Account Created","4768":"Kerberos TGT Request","4769":"Kerberos Service Ticket","7045":"New Service Installed","1102":"Audit Log Cleared","4104":"PowerShell Script Block"};
    if (evId && evHints[evId]) results.indicators.push(`Event Hint: ${evHints[evId]}`);

    return results;
  }

  const ltAnalyzeBtn = $("lt-analyze-btn");
  const ltPrefillBtn = $("lt-prefill-btn");
  const ltCopyBtn = $("lt-copy-btn");
  const ltClearBtn = $("lt-clear-btn");
  const ltResults = $("lt-results");
  const ltStatus = $("lt-status");
  let lastTriageResult = null;

  function setLTStatus(msg) { if (ltStatus) ltStatus.querySelector("span").textContent = msg; }

  function renderLTResults(res) {
    if (!ltResults) return;
    const typeColor = { "Windows Event Log":"#38bdf8","Firewall Log":"#fb923c","Email Headers":"#a78bfa","SIEM Alert":"#f87171","Authentication Event":"#fbbf24","Unknown":"#9ca3af" };
    const color = typeColor[res.eventType] || "#9ca3af";
    let html = `<div class="sa-verdict" style="border-color:${color}44;background:${color}0d">
      <div class="sa-verdict-left">
        <div class="sa-verdict-label" style="color:${color}">📋 ${res.eventType}</div>
        <div class="sa-verdict-meta">${res.indicators.join(" · ")}</div>
      </div>
    </div>`;

    const iocTypes = [["ips","IPs","#38bdf8"],["domains","Domains","#34d399"],["urls","URLs","#fb923c"],["hashes","Hashes","#f59e0b"],["emails","Emails","#a78bfa"],["cves","CVEs","#f87171"]];
    const hasAny = iocTypes.some(([k])=>res.iocs[k]?.length);
    if (hasAny) {
      html += `<div class="sa-section"><div class="sa-section-head">🎯 Extracted IOCs</div><div class="sa-ioc-grid">`;
      iocTypes.forEach(([k,label,c]) => {
        if (!res.iocs[k]?.length) return;
        html += `<div class="sa-ioc-group"><div class="sa-ioc-group-label" style="color:${c}">${label} (${res.iocs[k].length})</div>`;
        res.iocs[k].forEach(v => {
          html += `<div class="sa-ioc-row">
            <code class="sa-ioc-val">${v.slice(0,80)}</code>
            <button class="lt-pivot-btn" data-val="${v}" data-type="${k.slice(0,-1)}" type="button" style="font-size:11px;padding:3px 8px">🔍 Pivot</button>
            <button class="lt-case-btn" data-val="${v}" data-type="${k.slice(0,-1)}" type="button" style="font-size:11px;padding:3px 8px">📁 Case</button>
          </div>`;
        });
        html += `</div>`;
      });
      html += `</div></div>`;
    }

    ltResults.innerHTML = html;
    ltResults.querySelectorAll(".lt-pivot-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        if (input) { input.value = btn.dataset.val; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
      });
    });
    ltResults.querySelectorAll(".lt-case-btn").forEach(btn => {
      btn.addEventListener("click", () => addIOCToCase(btn.dataset.type || "unknown", btn.dataset.val));
    });
  }

  if (ltAnalyzeBtn) ltAnalyzeBtn.addEventListener("click", () => {
    const text = ($("lt-input")?.value || "").trim();
    if (!text) { setLTStatus("Paste a log first."); return; }
    lastTriageResult = triageLog(text);
    renderLTResults(lastTriageResult);
    const total = Object.values(lastTriageResult.iocs).reduce((s,a)=>s+(a?.length||0),0);
    setLTStatus(`Triage complete — ${lastTriageResult.eventType} · ${total} IOCs extracted`);
  });

  if (ltPrefillBtn) ltPrefillBtn.addEventListener("click", () => {
    if (!lastTriageResult?.prefillData) { setLTStatus("Run Auto-Triage first."); return; }
    // Switch to write-up tab, pick closest template, fill fields
    switchTab("writeup");
    const data = lastTriageResult.prefillData;
    Object.entries(data).forEach(([k,v]) => {
      const el = $(`awf_${k}`); if (el && v) el.value = v;
    });
    setLTStatus("Pre-filled write-up fields from triage results");
  });

  if (ltCopyBtn) ltCopyBtn.addEventListener("click", async () => {
    if (!lastTriageResult) return;
    const lines = [`LOG TRIAGE RESULT`, `Type: ${lastTriageResult.eventType}`, `Indicators: ${lastTriageResult.indicators.join(" | ")}`, ""];
    Object.entries(lastTriageResult.iocs).forEach(([k,v]) => { if(v?.length) lines.push(`${k.toUpperCase()}:\n${v.map(x=>"  "+x).join("\n")}`); });
    try { await navigator.clipboard.writeText(lines.join("\n")); } catch {}
  });

  if (ltClearBtn) ltClearBtn.addEventListener("click", () => {
    const inp = $("lt-input"); if(inp) inp.value = "";
    if(ltResults) ltResults.innerHTML = "";
    lastTriageResult = null; setLTStatus("Paste a log or alert above and click Auto-Triage");
  });

  // ═══════════════════════════════════════════════════
  // ─── THREAT ACTOR LOOKUP ─────────────────────────
  // ═══════════════════════════════════════════════════
  const THREAT_ACTORS = [
    { name:"APT29", aliases:["Cozy Bear","The Dukes","Midnight Blizzard","NOBELIUM"], nation:"Russia", mitre:"G0016",
      ttps:["T1566","T1078","T1114","T1071","T1547","T1027","T1057","T1082"],
      tools:["Cobalt Strike","MiniDuke","CosmicDuke","WellMess","SUNBURST"],
      desc:"Russian SVR-linked APT known for sophisticated phishing, supply-chain attacks (SolarWinds), and targeting government/defense/think tanks." },
    { name:"APT28", aliases:["Fancy Bear","Sofacy","STRONTIUM","Forest Blizzard"], nation:"Russia", mitre:"G0007",
      ttps:["T1566.001","T1190","T1059","T1055","T1003","T1071","T1041"],
      tools:["X-Agent","X-Tunnel","Zebrocy","Komplex","LoJax"],
      desc:"Russian GRU Unit 26165. Targets government, military, political organizations worldwide. Known for credential theft and DNC hack." },
    { name:"Lazarus Group", aliases:["HIDDEN COBRA","Zinc","Diamond Sleet","APT38"], nation:"North Korea", mitre:"G0032",
      ttps:["T1566","T1059","T1486","T1041","T1105","T1078","T1027"],
      tools:["Destover","BLINDINGCAN","AppleJeus","FASTCash","Bankshot"],
      desc:"North Korean state-sponsored group targeting financial institutions, cryptocurrency exchanges, defense contractors, and media." },
    { name:"APT41", aliases:["Winnti","Barium","Double Dragon","Brass Typhoon"], nation:"China", mitre:"G0096",
      ttps:["T1190","T1059","T1055","T1547","T1078","T1003","T1041","T1027"],
      tools:["MESSAGETAP","POISONPLUG","Cobalt Strike","PlugX","ShadowPad"],
      desc:"Chinese APT conducting both espionage and financially motivated operations. Targets healthcare, telecom, tech, and gaming industries." },
    { name:"FIN7", aliases:["Carbanak","Navigator Group","Carbon Spider"], nation:"Russia/Ukraine", mitre:"G0046",
      ttps:["T1566","T1204","T1059","T1055","T1003","T1041","T1486"],
      tools:["Carbanak","BABYMETAL","BOOSTWRITE","Cobalt Strike","REvil"],
      desc:"Financially motivated threat actor targeting retail, hospitality, and restaurant sectors. Known for POS malware and ransomware operations." },
    { name:"Sandworm", aliases:["Voodoo Bear","Telebots","Iron Viking","Seashell Blizzard"], nation:"Russia", mitre:"G0034",
      ttps:["T1190","T1059","T1486","T1498","T1489","T1071","T1105"],
      tools:["BlackEnergy","Industroyer","NotPetya","Whispergate","Exaramel"],
      desc:"Russian GRU Unit 74455. Responsible for most destructive cyberattacks in history including NotPetya, Ukraine power grid attacks." },
    { name:"Kimsuky", aliases:["Velvet Chollima","Black Banshee","Emerald Sleet"], nation:"North Korea", mitre:"G0094",
      ttps:["T1566","T1078","T1114","T1059","T1105","T1547"],
      tools:["BabyShark","AppleSeed","Quasar RAT","RandomQuery"],
      desc:"North Korean APT focused on intelligence gathering targeting South Korean gov, think tanks, and sanctions policy experts." },
    { name:"APT10", aliases:["Stone Panda","MenuPass","Red Apollo","Potassium"], nation:"China", mitre:"G0045",
      ttps:["T1566","T1190","T1078","T1021","T1041","T1003"],
      tools:["RedLeaves","PlugX","QuasarRAT","ANEL","UPPERCUT"],
      desc:"Chinese APT targeting managed service providers (MSPs) for supply-chain access to client networks in healthcare, defense, and government." },
    { name:"REvil", aliases:["Sodinokibi","Gold Southfield"], nation:"Russia (criminal)", mitre:"G0115",
      ttps:["T1486","T1490","T1059","T1078","T1566","T1021"],
      tools:["REvil/Sodinokibi ransomware","Cobalt Strike"],
      desc:"Ransomware-as-a-service (RaaS) group responsible for Kaseya, JBS Foods, and Travelex attacks. Operated until late 2021." },
    { name:"LockBit", aliases:["ABCD","LockBit 2.0","LockBit 3.0"], nation:"Russia (criminal)", mitre:"",
      ttps:["T1486","T1490","T1078","T1021","T1059","T1036","T1070"],
      tools:["LockBit ransomware","Cobalt Strike","Mimikatz","Metasploit"],
      desc:"Most prolific ransomware group by victim count 2022-2024. RaaS model targeting critical infrastructure, healthcare, and government." },
  ];

  const taInput = $("ta-input");
  const taSearchBtn = $("ta-search-btn");
  const taResults = $("ta-results");
  const taStatus = $("ta-status");

  function setTAStatus(msg) { if (taStatus) taStatus.querySelector("span").textContent = msg; }

  function renderTAResults(actors) {
    if (!taResults) return;
    if (!actors.length) { taResults.innerHTML = `<div class="bulk-empty">No matching threat actors found. Try a broader term.</div>`; return; }
    taResults.innerHTML = actors.map(a => {
      const nationColors = { Russia:"#f87171", "North Korea":"#38bdf8", China:"#f59e0b", "Russia (criminal)":"#fb923c", "Russia/Ukraine":"#a78bfa" };
      const nc = nationColors[a.nation] || "#9ca3af";
      return `<div class="ta-card">
        <div class="ta-card-head">
          <div>
            <div class="ta-name">${a.name}</div>
            <div class="ta-aliases">Also known as: ${a.aliases.join(" · ")}</div>
          </div>
          <span class="ta-nation" style="background:${nc}22;color:${nc};border-color:${nc}44">${a.nation}</span>
        </div>
        <div class="ta-desc">${a.desc}</div>
        <div class="ta-section-label">🧩 Common TTPs</div>
        <div class="ta-ttp-list">${a.ttps.map(t=>`<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="sa-mitre-tag">${t}</a>`).join("")}</div>
        <div class="ta-section-label">🛠 Tools / Malware</div>
        <div class="ta-tools">${a.tools.map(t=>`<span class="ta-tool-tag">${t}</span>`).join("")}</div>
        <div class="ta-pivot-links">
          ${a.mitre ? `<a href="https://attack.mitre.org/groups/${a.mitre}/" target="_blank" class="bulk-link">ATT&CK Group Page</a>` : ""}
          <a href="https://www.google.com/search?q=${enc(a.name + " threat actor 2024")}" target="_blank" class="bulk-link">Recent News</a>
          <a href="https://otx.alienvault.com/browse/global/pulses?q=${enc(a.name)}" target="_blank" class="bulk-link">OTX Pulses</a>
          <a href="https://www.virustotal.com/gui/search/${enc(a.name)}" target="_blank" class="bulk-link">VirusTotal</a>
          <a href="https://nitter.net/search?q=${enc(a.name)}" target="_blank" class="bulk-link">Twitter/Nitter</a>
        </div>
      </div>`;
    }).join("");
  }

  if (taSearchBtn) taSearchBtn.addEventListener("click", () => {
    const q = (taInput?.value || "").trim().toLowerCase();
    if (!q) return;
    const matches = THREAT_ACTORS.filter(a =>
      a.name.toLowerCase().includes(q) ||
      a.aliases.some(al => al.toLowerCase().includes(q)) ||
      a.nation.toLowerCase().includes(q) ||
      a.tools.some(t => t.toLowerCase().includes(q))
    );
    renderTAResults(matches);
    setTAStatus(`Found ${matches.length} result(s) for "${q}"`);
    addToHistory("username", q);
  });

  if (taInput) taInput.addEventListener("keydown", e => { if (e.key==="Enter") taSearchBtn?.click(); });

  // ═══════════════════════════════════════════════════
  // ─── CUSTOM TOOLS ────────────────────────────────
  // ═══════════════════════════════════════════════════
  let customTools = [];
  try { customTools = JSON.parse(localStorage.getItem("osint_custom_tools") || "[]"); } catch {}

  function saveCustomTools() { localStorage.setItem("osint_custom_tools", JSON.stringify(customTools)); }

  function renderCustomTools() {
    const list = $("ct-list");
    if (!list) return;
    if (!customTools.length) { list.innerHTML = '<div class="bulk-empty">No custom tools yet. Add one above.</div>'; return; }
    list.innerHTML = customTools.map((t, i) => `
      <div class="ct-tool-row">
        <span class="ct-icon">${t.icon||"🔗"}</span>
        <div class="ct-info">
          <div class="ct-tool-name">${t.name}</div>
          <div class="ct-tool-url">${t.url}</div>
          <div class="ct-tool-type">Applies to: ${t.type}</div>
        </div>
        <button class="ct-test-btn" data-idx="${i}" type="button">🔍 Test</button>
        <button class="ct-del-btn" data-idx="${i}" type="button" style="color:#f87171">🗑 Delete</button>
      </div>`).join("");

    list.querySelectorAll(".ct-del-btn").forEach(btn => {
      btn.addEventListener("click", () => { customTools.splice(Number(btn.dataset.idx),1); saveCustomTools(); renderCustomTools(); });
    });
    list.querySelectorAll(".ct-test-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const t = customTools[Number(btn.dataset.idx)];
        const testUrl = t.url.replace("{IOC}", enc("test-ioc"));
        window.open(testUrl, "_blank");
      });
    });
  }

  const ctAddBtn = $("ct-add-btn");
  if (ctAddBtn) ctAddBtn.addEventListener("click", () => {
    const name = ($("ct-name")?.value||"").trim();
    const icon = ($("ct-icon")?.value||"🔗").trim();
    const type = $("ct-type")?.value || "all";
    const url = ($("ct-url")?.value||"").trim();
    if (!name || !url) return;
    if (!url.includes("{IOC}")) { alert('URL must include {IOC} as placeholder. Example: https://siem.corp/search?q={IOC}'); return; }
    customTools.push({ name, icon, type, url });
    saveCustomTools(); renderCustomTools();
    ["ct-name","ct-icon","ct-url"].forEach(id=>{const el=$(id);if(el)el.value="";});
  });


  // ═══════════════════════════════════════════════════
  // ─── CVE ENRICHMENT PANEL ────────────────────────
  // ═══════════════════════════════════════════════════
  const CISA_KEV_KNOWN = ["CVE-2021-44228","CVE-2021-34527","CVE-2021-26855","CVE-2020-1472","CVE-2019-11510","CVE-2019-19781","CVE-2022-30190","CVE-2022-26134","CVE-2022-22954","CVE-2023-44487","CVE-2023-23397","CVE-2023-20198","CVE-2024-3400","CVE-2023-4966","CVE-2021-21985","CVE-2022-1388","CVE-2021-40539","CVE-2022-41040","CVE-2022-41082","CVE-2017-0144","CVE-2018-13379","CVE-2020-0688","CVE-2021-26084","CVE-2022-24086","CVE-2021-36942","CVE-2023-34362","CVE-2023-29357","CVE-2021-44077","CVE-2022-47966","CVE-2023-49103"];

  function showCVEEnrichment(cve) {
    const panel = $("cve-enrichment");
    if (!panel) return;
    const inKEV = CISA_KEV_KNOWN.includes(cve.toUpperCase());
    panel.style.display = "block";
    panel.innerHTML = `
      <div class="cve-enrich-card">
        <div class="cve-enrich-head">
          <span class="cve-enrich-id">${cve}</span>
          ${inKEV ? `<span class="cve-kev-badge">🧨 CISA KEV — Actively Exploited</span>` : `<span class="cve-kev-safe">✅ Not in KEV list (local check)</span>`}
        </div>
        <div class="cve-enrich-links">
          <a href="https://nvd.nist.gov/vuln/detail/${enc(cve)}" target="_blank" class="bulk-link">NVD Details</a>
          <a href="https://www.cve.org/CVERecord?id=${enc(cve)}" target="_blank" class="bulk-link">CVE.org</a>
          <a href="https://www.first.org/epss/?q=${enc(cve)}" target="_blank" class="bulk-link">EPSS Score</a>
          <a href="https://www.exploit-db.com/search?cve=${enc(cve)}" target="_blank" class="bulk-link">Exploit-DB</a>
          <a href="https://github.com/search?q=${enc(cve)}" target="_blank" class="bulk-link">GitHub PoC</a>
          <a href="${gsearch(`${cve} patch advisory`)}" target="_blank" class="bulk-link">Patch Advisory</a>
        </div>
        <div class="cve-enrich-note">ℹ️ CVSS score and EPSS probability available via the NVD and FIRST.org links above. KEV check is local against a curated list of ${CISA_KEV_KNOWN.length} known exploited CVEs.</div>
      </div>`;
  }

  // ═══════════════════════════════════════════════════
  // ─── LANDING LINKS ───────────────────────────────
  // ═══════════════════════════════════════════════════
  const landing = {
    ip_vt:"https://www.virustotal.com/", ip_abuseipdb:"https://www.abuseipdb.com/",
    ip_talos:"https://talosintelligence.com/", ip_ibmxf:"https://exchange.xforce.ibmcloud.com/",
    ip_otx:"https://otx.alienvault.com/", ip_anyrun:"https://intelligence.any.run/",
    ip_mxtoolbox:"https://mxtoolbox.com/", ip_blacklistchecker:"https://blacklistchecker.com/",
    ip_cleantalk:"https://cleantalk.org/blacklists", ip_shodan:"https://www.shodan.io/",
    ip_censys:"https://search.censys.io/", ip_greynoise:"https://viz.greynoise.io/",
    ip_iplocation:"https://iplocation.io/", ip_ipinfo:"https://ipinfo.io/",
    ip_whatismyipaddress:"https://whatismyipaddress.com/", ip_myip:"https://myip.ms/",
    ip_spur:"https://spur.us/", ip_clickfix:"https://clickfix.carsonww.com/",
    ip_ripestat:"https://stat.ripe.net/", ip_bgphe:"https://bgp.he.net/",
    ip_nitter:"https://nitter.net/", ip_threatminer:"https://www.threatminer.org/",
    ip_urlscan:"https://urlscan.io/", ip_viewdns:"https://viewdns.info/",
    ip_scamalytics:"https://scamalytics.com/",
    dom_vt:"https://www.virustotal.com/", dom_talos:"https://talosintelligence.com/",
    dom_ibmxf:"https://exchange.xforce.ibmcloud.com/", dom_otx:"https://otx.alienvault.com/",
    dom_urlscan:"https://urlscan.io/", dom_mxtoolbox:"https://mxtoolbox.com/",
    dom_blacklistchecker:"https://blacklistchecker.com/", dom_cleantalk_bl:"https://cleantalk.org/blacklists",
    dom_cleantalk_malware:"https://cleantalk.org/malware", dom_sucuri:"https://sitecheck.sucuri.net/",
    dom_urlvoid:"https://www.urlvoid.com/", dom_urlhaus:"https://urlhaus.abuse.ch/",
    dom_whois:"https://www.whois.com/whois/", dom_dnslytics:"https://dnslytics.com/",
    dom_netcraft:"https://www.netcraft.com/", dom_webcheck:"https://webcheck.spiderlabs.io/",
    dom_securitytrails:"https://securitytrails.com/", dom_hudsonrock_info:"https://intel.hudsonrock.com/",
    dom_hudsonrock_urls:"https://cavalier.hudsonrock.com/", dom_socradar:"https://socradar.io/",
    dom_wayback:"https://web.archive.org/", dom_wayback_save:"https://web.archive.org/",
    dom_browserling:"https://www.browserling.com/", dom_anyrun:"https://intelligence.any.run/",
    dom_anyrun_safe:"https://any.run/submit/", dom_phishing_checker:"https://phishing.finsin.cl/list.php",
    dom_clickfix:"https://clickfix.carsonww.com/", dom_nitter:"https://nitter.net/",
    dom_netlas:"https://netlas.io/", dom_censys:"https://search.censys.io/",
    dom_shodan:"https://www.shodan.io/", dom_dnstools:"https://whois.domaintools.com/",
    dom_crtsh:"https://crt.sh/", dom_dnsdumpster:"https://dnsdumpster.com/",
    url_vt:"https://www.virustotal.com/", url_urlscan:"https://urlscan.io/",
    url_urlvoid:"https://www.urlvoid.com/", url_urlhaus:"https://urlhaus.abuse.ch/",
    url_phishtank:"https://www.phishtank.com/", url_checkphish:"https://checkphish.ai/",
    url_safebrowsing:"https://transparencyreport.google.com/safe-browsing/search",
    url_sucuri:"https://sitecheck.sucuri.net/", url_browserling:"https://www.browserling.com/",
    url_wayback:"https://web.archive.org/", url_anyrun:"https://any.run/submit/",
    url_otx:"https://otx.alienvault.com/", url_threatfox:"https://threatfox.abuse.ch/",
    url_netcraft:"https://www.netcraft.com/", url_webcheck:"https://web-check.xyz/",
    url_securitytrails:"https://securitytrails.com/", url_hudsonrock_info:"https://www.hudsonrock.com/",
    url_hudsonrock_urls:"https://cavalier.hudsonrock.com/", url_socradar:"https://socradar.io/",
    url_wayback_save:"https://web.archive.org/", url_phishing_checker:"https://phishing.finsin.cl/list.php",
    url_clickfix:"https://clickfix.carsonww.com/", url_cyberchef:"https://gchq.github.io/CyberChef/",
    url_nitter:"https://nitter.net/",
    em_hunter:"https://hunter.io/", em_hibp:"https://haveibeenpwned.com/",
    em_intelbase:"https://intelbase.is/", em_emailrep:"https://emailrep.io/",
    em_epieos:"https://epieos.com/", em_intelx:"https://intelx.io/",
    em_phonebook:"https://phonebook.cz/", em_dehashed:"https://dehashed.com/",
    hdr_mha:"https://mha.azurewebsites.net/pages/mha.html",
    hdr_google:"https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    hdr_mxtoolbox:"https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx",
    hdr_traceemail:"https://whatismyipaddress.com/trace-email",
    hdr_dnschecker:"https://dnschecker.org/email-header-analyzer.php",
    usr_namechk:"https://namechk.com/", usr_whatsmyname:"https://whatsmyname.app/",
    usr_sherlock:"https://github.com/sherlock-project/sherlock",
    usr_socialsearcher:"https://www.social-searcher.com/",
    usr_dehashed:"https://dehashed.com/", usr_intelx:"https://intelx.io/",
    h_vt:"https://www.virustotal.com/", h_hybrid:"https://www.hybrid-analysis.com/",
    h_joesandbox:"https://www.joesandbox.com/", h_triage:"https://tria.ge/",
    h_malshare:"https://malshare.com/", h_malwarebazaar:"https://bazaar.abuse.ch/",
    h_ibmxf:"https://exchange.xforce.ibmcloud.com/", h_talos:"https://talosintelligence.com/",
    h_otx:"https://otx.alienvault.com/", h_anyrun:"https://intelligence.any.run/",
    h_threatminer:"https://www.threatminer.org/", h_intezer:"https://analyze.intezer.com/",
    h_cyberchef:"https://gchq.github.io/CyberChef/", h_nitter:"https://nitter.net/",
    cve_nvd:"https://nvd.nist.gov/", cve_cveorg:"https://www.cve.org/",
    cve_cisa:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cve_exploitdb:"https://www.exploit-db.com/", cve_vulners:"https://vulners.com/",
    cve_github:"https://github.com/search",
    cvep_cisa_kev:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss:"https://www.first.org/epss/",
    emart_msgid_search:"https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    emart_dkim_domain:"https://www.virustotal.com/", emart_spf_domain:"https://www.virustotal.com/",
    lb_lolbas:"https://lolbas-project.github.io/", lb_gtfobins:"https://gtfobins.github.io/",
    lb_hijacklibs:"https://hijacklibs.net/",
    ev_eventidnet:"https://www.eventid.net/", ev_mslearn:"https://learn.microsoft.com/",
    ev_hackthelogs:"https://www.hackthelogs.com/mainpage.html",
    sysmon_mslearn:"https://learn.microsoft.com/",
    sysmon_swift:"https://github.com/SwiftOnSecurity/sysmon-config",
    sysmon_hackthelogs:"https://www.hackthelogs.com/mainpage.html",
    soc_ruler:"https://ruler-project.github.io/ruler-project/RULER/remote/",
    soc_hackthelogs:"https://www.hackthelogs.com/mainpage.html",
    soc_explainshell:"https://explainshell.com/",
    soc_sigma:"https://github.com/SigmaHQ/sigma", soc_uncoder:"https://uncoder.io/",
  };

  function setLandingLinks() { Object.entries(landing).forEach(([id,href]) => setHref(id, href)); }
  function renderCardMeta() {
    document.querySelectorAll(".meta[data-meta]").forEach(m => {
      const id = m.getAttribute("data-meta");
      const a = $(id);
      if (a && a.href) m.textContent = a.href;
    });
  }
  function setSearchMode(on) { document.body.classList.toggle("search-mode", !!on); }
  function showRelevantTools(types) {
    document.querySelectorAll(".tool-section[data-type]").forEach(s => s.classList.remove("active"));
    if (!types || !types.length) return;
    types.forEach(t => { const sec = document.querySelector(`.tool-section[data-type="${t}"]`); if (sec) sec.classList.add("active"); });
  }

  // Custom tools injection into tool grid
  function injectCustomTools(type, q) {
    document.querySelectorAll(".custom-tool-card").forEach(el => el.remove());
    const relevant = customTools.filter(t => t.type === "all" || t.type === type);
    if (!relevant.length) return;
    const grid = document.querySelector(`.tool-section[data-type="${type}"] .tool-grid`);
    if (!grid) return;
    relevant.forEach(t => {
      const a = document.createElement("a");
      a.className = "custom-tool-card";
      a.target = "_blank";
      a.href = t.url.replace("{IOC}", enc(q));
      a.innerHTML = `<div class="title">${t.icon||"🔗"} ${t.name} <span class="lock">⚙</span></div><div class="meta">${t.url.replace("{IOC}","…")}</div>`;
      grid.appendChild(a);
    });
  }


  // ─── MITRE auto-suggest ───────────────────────────────────────
  const mitreByType = {
    ip:["T1071","T1095","T1041","T1105","T1046"],
    domain:["T1071","T1583","T1584","T1566","T1041"],
    url:["T1566","T1071","T1204","T1190"],
    hash:["T1204","T1059","T1027","T1055","T1036"],
    email:["T1566","T1114","T1078"],
    header:["T1566","T1078","T1557","T1114"],
    cve:["T1190","T1068","T1055"],
    username:["T1078","T1110","T1003"],
    eventid:["T1059","T1047","T1053","T1078"],
  };
  function suggestMitreTactics(type) {
    const suggestions = mitreByType[type] || [];
    const panel = $("mitre-suggested"); const tagsEl = $("mitre-suggested-tags");
    if (!panel || !tagsEl) return;
    if (!suggestions.length) { panel.style.display="none"; return; }
    panel.style.display = "block";
    tagsEl.innerHTML = suggestions.map(tid => {
      const lbl = document.querySelector(`#mitre-panel input[value="${tid}"]`)?.closest("label")?.textContent?.trim() || tid;
      return `<button class="mitre-suggest-tag" data-tid="${tid}" type="button">${lbl}</button>`;
    }).join("");
    tagsEl.querySelectorAll(".mitre-suggest-tag").forEach(btn => {
      btn.addEventListener("click", () => {
        const cb = document.querySelector(`#mitre-panel input[value="${btn.dataset.tid}"]`);
        if (cb) { cb.checked=true; btn.classList.add("applied"); btn.textContent="✅ "+btn.textContent; }
      });
    });
  }

  const mitreCopyBtn = $("mitre-copy-btn");
  if (mitreCopyBtn) mitreCopyBtn.addEventListener("click", async () => {
    const checked = [...document.querySelectorAll("#mitre-panel input[type=checkbox]:checked")];
    if (!checked.length) return setStatus("No TTPs tagged.");
    const lines = checked.map(cb => { const lbl=cb.closest("label")?.textContent?.trim()||cb.value; return `${lbl} — https://attack.mitre.org/techniques/${cb.value.replace(".","/")}/`; });
    try { await navigator.clipboard.writeText("Tagged TTPs:\n" + lines.join("\n")); } catch {}
    setStatus(`Copied ${checked.length} tagged TTPs`);
  });

  const mitreClearBtn = $("mitre-clear-btn");
  if (mitreClearBtn) mitreClearBtn.addEventListener("click", () => {
    document.querySelectorAll("#mitre-panel input[type=checkbox]").forEach(cb => cb.checked=false);
    const panel=$("mitre-suggested"); if(panel) panel.style.display="none";
    setStatus("TTPs cleared");
  });

  // ─── Verdict Banner ───────────────────────────────────────────
  function showVerdict(type, q) {
    const banner = $("verdict-banner"); if (!banner) return;
    const verdictMap = {
      ip:{icon:"🛡",label:"IP Address",color:"#38bdf8"},
      domain:{icon:"🌐",label:"Domain",color:"#34d399"},
      url:{icon:"🔗",label:"URL",color:"#fb923c"},
      hash:{icon:"🔒",label:"File Hash",color:"#f59e0b"},
      email:{icon:"📧",label:"Email Address",color:"#a78bfa"},
      header:{icon:"📨",label:"Email Headers Detected",color:"#67e8f9"},
      cve:{icon:"💥",label:"CVE / Vulnerability",color:"#f87171"},
      username:{icon:"👤",label:"Username",color:"#e879f9"},
      eventid:{icon:"🪟",label:"Windows Event ID",color:"#86efac"},
      mitre:{icon:"🧩",label:"MITRE ATT&CK Technique",color:"#fbbf24"},
    };
    const v = verdictMap[type]; if (!v) { banner.style.display="none"; return; }
    banner.style.display="flex"; banner.style.borderColor=v.color+"44"; banner.style.background=v.color+"11";
    banner.innerHTML = `<span class="verdict-icon" style="color:${v.color}">${v.icon}</span><div><span class="verdict-type" style="color:${v.color}">${v.label}</span><span class="verdict-value">${q||"detected from pasted text"}</span></div>`;
  }

  // ─── Smart IOC Extractor ──────────────────────────────────────
  function extractSmartIOCs(text) {
    const now = new Date().toISOString();
    const t = (text || "").replace(/\r\n/g,"\n");
    const headerDetected = looksLikeHeaders(t);
    const h = headerDetected ? parseEmailHeaders(t) : null;
    const originLink = h?.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}` : "-";
    const dkimLink = h?.dkimDomain ? `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}` : "-";
    const spfLink = h?.spfMailfromDomain ? `https://www.virustotal.com/gui/domain/${enc(h.spfMailfromDomain)}` : "-";
    const returnPathLink = h?.returnPathDomain ? `https://www.virustotal.com/gui/domain/${enc(h.returnPathDomain)}` : "-";
    if (headerDetected) return `SMART IOC EXTRACTOR\nExtracted At (UTC): ${now}\n\nEMAIL HEADER INTEL:\n- Sender (From): ${h?.senderEmail||"-"}\n- Receiver (To): ${h?.receiverEmail||"-"}\n- Subject: ${h?.subject||"-"}\n- Date: ${h?.date||"-"}\n- Message-ID: ${h?.messageId||"-"}\n- Return-Path: ${h?.returnPath||"-"}\n- Return-Path Domain: ${h?.returnPathDomain||"-"}\n- Origin IP (heuristic): ${h?.originIp||"-"}\n- SPF Result: ${h?.spfResult||"-"}   (smtp.mailfrom: ${h?.spfMailfrom||"-"})\n- DKIM Result: ${h?.dkimResult||"-"} (d=${h?.dkimDomain||"-"}; s=${h?.dkimSelector||"-"})\n\nQUICK PIVOTS:\n- Return-Path Domain Pivot: ${returnPathLink}\n- Origin IP Pivot: ${originLink}\n- SPF Domain Pivot: ${spfLink}\n- DKIM Domain Pivot: ${dkimLink}\n`;
    const refanged = refangSmart(t);
    const ips = [...new Set((refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)||[]).filter(isValidIPv4))];
    const domains = [...new Set((refanged.match(/\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\b/g)||[]).filter(d=>!/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(d)))];
    const hashes = [...new Set((refanged.match(/\b[a-fA-F0-9]{32,64}\b/g)||[]).filter(h=>[32,40,64].includes(h.length)))];
    const cves = [...new Set((refanged.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(c=>c.toUpperCase()))];
    const emails = [...new Set((refanged.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g)||[]))];
    const urls = [...new Set((refanged.match(/https?:\/\/[^\s<>"']+/gi)||[]))];
    const lines = [`SMART IOC EXTRACTOR`,`Extracted At (UTC): ${now}`,``];
    if (ips.length) lines.push(`IPs (${ips.length}):\n${ips.map(v=>"  "+v).join("\n")}`);
    if (domains.length) lines.push(`\nDomains (${domains.length}):\n${domains.map(v=>"  "+v).join("\n")}`);
    if (urls.length) lines.push(`\nURLs (${urls.length}):\n${urls.map(v=>"  "+v).join("\n")}`);
    if (emails.length) lines.push(`\nEmails (${emails.length}):\n${emails.map(v=>"  "+v).join("\n")}`);
    if (hashes.length) lines.push(`\nHashes (${hashes.length}):\n${hashes.map(v=>"  "+v).join("\n")}`);
    if (cves.length) lines.push(`\nCVEs (${cves.length}):\n${cves.map(v=>"  "+v).join("\n")}`);
    if (!ips.length&&!domains.length&&!hashes.length&&!cves.length&&!emails.length&&!urls.length) lines.push("No recognizable IOCs found.");
    return lines.join("\n");
  }

  // ─── Link builders ────────────────────────────────────────────
  function buildLinksForIP(ip) {
    setHref("ip_vt",`https://www.virustotal.com/gui/ip-address/${enc(ip)}`);
    setHref("ip_abuseipdb",`https://www.abuseipdb.com/check/${enc(ip)}`);
    setHref("ip_talos",`https://talosintelligence.com/reputation_center/lookup?search=${enc(ip)}`);
    setHref("ip_ibmxf",`https://exchange.xforce.ibmcloud.com/ip/${enc(ip)}`);
    setHref("ip_otx",`https://otx.alienvault.com/indicator/ip/${enc(ip)}`);
    setHref("ip_anyrun",anyrunLookupGeneral(ip));
    setHref("ip_mxtoolbox",`https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${enc(ip)}&run=toolpage`);
    setHref("ip_blacklistchecker",`https://blacklistchecker.com/ip/${enc(ip)}`);
    setHref("ip_cleantalk",`https://cleantalk.org/blacklists/${enc(ip)}`);
    setHref("ip_shodan",`https://www.shodan.io/host/${enc(ip)}`);
    setHref("ip_censys",`https://search.censys.io/hosts/${enc(ip)}`);
    setHref("ip_greynoise",`https://viz.greynoise.io/ip/${enc(ip)}`);
    setHref("ip_iplocation",`https://iplocation.io/ip/${enc(ip)}`);
    setHref("ip_ipinfo",`https://ipinfo.io/${enc(ip)}`);
    setHref("ip_whatismyipaddress",`https://whatismyipaddress.com/ip/${enc(ip)}`);
    setHref("ip_myip",`https://myip.ms/info/whois/${enc(ip)}`);
    setHref("ip_spur",`https://spur.us/context/${enc(ip)}`);
    setHref("ip_clickfix",`https://clickfix.carsonww.com/?q=${enc(ip)}`);
    setHref("ip_ripestat",`https://stat.ripe.net/${enc(ip)}`);
    setHref("ip_bgphe",`https://bgp.he.net/ip/${enc(ip)}`);
    setHref("ip_nitter",`https://nitter.net/search?q=${enc(ip)}`);
    setHref("ip_threatminer",`https://www.threatminer.org/host.php?q=${enc(ip)}`);
    setHref("ip_urlscan",`https://urlscan.io/search/#ip:${enc(ip)}`);
    setHref("ip_viewdns",`https://viewdns.info/reverseip/?host=${enc(ip)}&t=1`);
    setHref("ip_scamalytics",`https://scamalytics.com/ip/${enc(ip)}`);
    injectCustomTools("ip", ip);
  }

  function buildLinksForDomain(domain) {
    setHref("dom_vt",`https://www.virustotal.com/gui/domain/${enc(domain)}`);
    setHref("dom_talos",`https://talosintelligence.com/reputation_center/lookup?search=${enc(domain)}`);
    setHref("dom_ibmxf",`https://exchange.xforce.ibmcloud.com/url/${enc(domain)}`);
    setHref("dom_otx",`https://otx.alienvault.com/indicator/domain/${enc(domain)}`);
    setHref("dom_urlscan",`https://urlscan.io/search/#domain:${enc(domain)}`);
    setHref("dom_mxtoolbox",`https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${enc(domain)}&run=toolpage`);
    setHref("dom_blacklistchecker",`https://blacklistchecker.com/domain/${enc(domain)}`);
    setHref("dom_cleantalk_bl",`https://cleantalk.org/blacklists/${enc(domain)}`);
    setHref("dom_cleantalk_malware",`https://cleantalk.org/website/${enc(domain)}`);
    setHref("dom_sucuri",`https://sitecheck.sucuri.net/results/${enc(domain)}`);
    setHref("dom_urlvoid",`https://www.urlvoid.com/scan/${enc(domain)}/`);
    setHref("dom_urlhaus",`https://urlhaus.abuse.ch/browse.php?search=${enc(domain)}`);
    setHref("dom_whois",`https://www.whois.com/whois/${enc(domain)}`);
    setHref("dom_dnslytics",`https://dnslytics.com/domain/${enc(domain)}`);
    setHref("dom_netcraft",`https://searchdns.netcraft.com/?host=${enc(domain)}`);
    setHref("dom_webcheck",`https://webcheck.spiderlabs.io/?q=${enc(domain)}`);
    setHref("dom_securitytrails",`https://securitytrails.com/domain/${enc(domain)}`);
    setHref("dom_hudsonrock_info",`https://intel.hudsonrock.com/?q=${enc(domain)}`);
    setHref("dom_hudsonrock_urls",`https://cavalier.hudsonrock.com/?q=${enc(domain)}`);
    setHref("dom_socradar",gsearch(`SOCRadar dark web report ${domain}`));
    setHref("dom_wayback",`https://web.archive.org/web/*/${enc(domain)}`);
    setHref("dom_wayback_save",`https://web.archive.org/save/${enc(domain)}`);
    setHref("dom_browserling",`https://www.browserling.com/browse/${enc(domain)}`);
    setHref("dom_anyrun",anyrunLookupGeneral(domain));
    setHref("dom_anyrun_safe",`https://any.run/submit/?url=${enc("http://"+domain)}`);
    setHref("dom_phishing_checker",`https://phishing.finsin.cl/list.php?search=${enc(domain)}`);
    setHref("dom_clickfix",`https://clickfix.carsonww.com/?q=${enc(domain)}`);
    setHref("dom_nitter",`https://nitter.net/search?q=${enc(domain)}`);
    setHref("dom_netlas",`https://app.netlas.io/domains/?q=${enc(domain)}`);
    setHref("dom_censys",`https://search.censys.io/search?resource=hosts&q=${enc(domain)}`);
    setHref("dom_shodan",`https://www.shodan.io/search?query=${enc(domain)}`);
    setHref("dom_dnstools",`https://whois.domaintools.com/${enc(domain)}`);
    setHref("dom_crtsh",`https://crt.sh/?q=${enc(domain)}`);
    setHref("dom_dnsdumpster",`https://dnsdumpster.com/`);
    injectCustomTools("domain", domain);
  }

  function buildLinksForURL(url) {
    let urlHost = "";
    try { urlHost = new URL(url).hostname; } catch { urlHost = url; }
    setHref("url_vt",`https://www.virustotal.com/gui/url/${btoa(url).replace(/=/g,"")}`);
    setHref("url_urlscan",`https://urlscan.io/search/#page.url:${enc(url)}`);
    setHref("url_urlvoid",`https://www.urlvoid.com/scan/${enc(url)}/`);
    setHref("url_urlhaus",`https://urlhaus.abuse.ch/browse.php?search=${enc(url)}`);
    setHref("url_phishtank",`https://www.phishtank.com/`);
    setHref("url_checkphish",`https://checkphish.ai/?url=${enc(url)}`);
    setHref("url_safebrowsing",`https://transparencyreport.google.com/safe-browsing/search?url=${enc(url)}`);
    setHref("url_sucuri",`https://sitecheck.sucuri.net/results/${enc(urlHost)}`);
    setHref("url_browserling",`https://www.browserling.com/browse/${enc(url)}`);
    setHref("url_wayback",`https://web.archive.org/web/*/${enc(url)}`);
    setHref("url_anyrun",`https://any.run/submit/?url=${enc(url)}`);
    setHref("url_otx",`https://otx.alienvault.com/indicator/url/${enc(url)}`);
    setHref("url_threatfox",`https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(url)}`);
    setHref("url_netcraft",`https://sitereport.netcraft.com/?url=${enc(url)}`);
    setHref("url_webcheck",`https://web-check.xyz/check/${enc(url)}`);
    setHref("url_securitytrails",`https://securitytrails.com/domain/${enc(urlHost)}`);
    setHref("url_hudsonrock_info",`https://www.hudsonrock.com/search/domain/${enc(urlHost)}`);
    setHref("url_hudsonrock_urls",`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=${enc(urlHost)}`);
    setHref("url_socradar",`https://socradar.io/labs/app/dark-web-report?domain=${enc(urlHost)}`);
    setHref("url_wayback_save",`https://web.archive.org/save/${enc(url)}`);
    setHref("url_phishing_checker",`https://phishing.finsin.cl/list.php?search=${enc(urlHost)}`);
    setHref("url_clickfix",`https://clickfix.carsonww.com/domains?query=${enc(urlHost)}`);
    setHref("url_cyberchef",`https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=${btoa(url)}`);
    setHref("url_nitter",`https://nitter.net/search?f=tweets&q=${enc(url)}&since=&until=&near=&min_faves=`);
    injectCustomTools("url", url);
  }

  function buildLinksForHash(hash) {
    setHref("h_vt",`https://www.virustotal.com/gui/file/${enc(hash)}`);
    setHref("h_hybrid",`https://www.hybrid-analysis.com/search?query=${enc(hash)}`);
    setHref("h_joesandbox",`https://www.joesandbox.com/analysis/search?q=${enc(hash)}`);
    setHref("h_triage",`https://tria.ge/s?q=${enc(hash)}`);
    setHref("h_malshare",`https://malshare.com/sample.php?action=detail&hash=${enc(hash)}`);
    setHref("h_malwarebazaar",`https://bazaar.abuse.ch/browse.php?search=${enc(hash)}`);
    setHref("h_ibmxf",`https://exchange.xforce.ibmcloud.com/malware/${enc(hash)}`);
    setHref("h_talos",`https://talosintelligence.com/talos_file_reputation?s=${enc(hash)}`);
    setHref("h_otx",`https://otx.alienvault.com/indicator/file/${enc(hash)}`);
    setHref("h_anyrun",anyrunLookupGeneral(hash));
    setHref("h_threatminer",`https://www.threatminer.org/sample.php?q=${enc(hash)}`);
    setHref("h_intezer",`https://analyze.intezer.com/`);
    setHref("h_cyberchef",`https://gchq.github.io/CyberChef/`);
    setHref("h_nitter",`https://nitter.net/search?q=${enc(hash)}`);
    injectCustomTools("hash", hash);
  }

  function buildLinksForEmail(email) {
    setHref("em_hunter",`https://hunter.io/email-verifier/${enc(email)}`);
    setHref("em_hibp",`https://haveibeenpwned.com/account/${enc(email)}`);
    setHref("em_intelbase",`https://intelbase.is/search?q=${enc(email)}`);
    setHref("em_emailrep",`https://emailrep.io/${enc(email)}`);
    setHref("em_epieos",`https://epieos.com/?q=${enc(email)}&t=email`);
    setHref("em_intelx",`https://intelx.io/?s=${enc(email)}`);
    setHref("em_phonebook",`https://phonebook.cz/`);
    setHref("em_dehashed",`https://dehashed.com/search?query=${enc(email)}`);
    injectCustomTools("email", email);
  }

  function buildLinksForUsername(user) {
    setHref("usr_namechk",`https://namechk.com/?q=${enc(user)}`);
    setHref("usr_whatsmyname",`https://whatsmyname.app/?q=${enc(user)}`);
    setHref("usr_sherlock",`https://github.com/sherlock-project/sherlock`);
    setHref("usr_socialsearcher",`https://www.social-searcher.com/social-buzz/?q5=${enc(user)}`);
    setHref("usr_dehashed",`https://dehashed.com/search?query=${enc(user)}`);
    setHref("usr_intelx",`https://intelx.io/?s=${enc(user)}`);
  }

  function buildLinksForCVE(cve) {
    setHref("cve_nvd",`https://nvd.nist.gov/vuln/detail/${enc(cve)}`);
    setHref("cve_cveorg",`https://www.cve.org/CVERecord?id=${enc(cve)}`);
    setHref("cve_cisa",gsearch(`site:cisa.gov "Known Exploited Vulnerabilities" ${cve}`));
    setHref("cve_exploitdb",`https://www.exploit-db.com/search?cve=${enc(cve)}`);
    setHref("cve_vulners",`https://vulners.com/search?query=${enc(cve)}`);
    setHref("cve_github",`https://github.com/search?q=${enc(cve)}`);
    setHref("cvep_cisa_kev",gsearch(`CISA KEV ${cve}`));
    setHref("cvep_epss",`https://www.first.org/epss/?q=${enc(cve)}`);
    showCVEEnrichment(cve);
  }

  function buildLinksForEventID(id) {
    setHref("ev_eventidnet",`https://www.eventid.net/display.asp?eventid=${enc(id)}`);
    setHref("ev_mslearn",`https://learn.microsoft.com/en-us/search/?terms=${enc("Event ID "+id)}`);
    setHref("ev_hackthelogs",gsearch(`HackTheLogs Event ID ${id}`));
  }

  function buildLinksForHeaders(headerText) {
    setHref("hdr_dnschecker","https://dnschecker.org/email-header-analyzer.php");
    setHref("hdr_mxtoolbox","https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx");
    setHref("hdr_mha","https://mha.azurewebsites.net/pages/mha.html");
    setHref("hdr_google","https://toolbox.googleapps.com/apps/messageheader/analyzeheader");
    const h = parseEmailHeaders(headerText);
    setHref("emart_msgid_search", h.messageId ? gsearch(`"${h.messageId}"`) : landing.emart_msgid_search);
    if (h.dkimDomain) setHref("emart_dkim_domain",`https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}`);
    const spfDom = h.spfMailfromDomain || (h.spfMailfrom.split("@")[1] || "");
    if (spfDom) setHref("emart_spf_domain",`https://www.virustotal.com/gui/domain/${enc(spfDom)}`);
    return h;
  }


  // ─── Main search ──────────────────────────────────────────────
  function doSearch({ silent = false } = {}) {
    const raw = (input?.value || "").trim();
    const pasted = (output?.value || "").trim();
    syncSearchboxState();
    const cvePanel = $("cve-enrichment");
    if (!raw && !pasted) {
      setSearchMode(false); showRelevantTools([]);
      setLandingLinks(); renderCardMeta();
      setStatus("Status: ready (landing page)");
      const banner = $("verdict-banner"); if (banner) banner.style.display="none";
      const sp = $("mitre-suggested"); if (sp) sp.style.display="none";
      if (cvePanel) cvePanel.style.display="none";
      if (!silent && output) output.value="";
      return;
    }
    const { type, q } = detectType(raw, pasted);
    if (!type) {
      setSearchMode(false); showRelevantTools([]);
      setLandingLinks(); renderCardMeta();
      setStatus("Status: unknown type (landing page)");
      if (!silent && output && raw) output.value=raw;
      return;
    }
    setSearchMode(true);
    if (cvePanel && type !== "cve") cvePanel.style.display="none";
    let sections = [];
    if (type==="header") sections=["header","emailartifacts"];
    else if (type==="cve") sections=["cve","cveplus"];
    else sections=[type];
    showRelevantTools(sections);
    setLandingLinks(); showVerdict(type, q); suggestMitreTactics(type);
    if (type==="mitre"&&q) setHref("mitre-attack-link",`https://attack.mitre.org/techniques/${q.replace(".","/")}/`);
    else setHref("mitre-attack-link","https://attack.mitre.org/");
    if (type==="ip") { buildLinksForIP(q); const priv=(isValidIPv4(q)&&isPrivateIPv4(q))||(isValidIPv6(q)&&isPrivateIPv6(q)); if(!silent&&output) output.value=priv?`IP detected (PRIVATE): ${q}\nNote: external OSINT may not return results for private IPs.`:`IP detected: ${q}`; setStatus(`Status: detected IP → ${q}`); }
    if (type==="domain") { buildLinksForDomain(q); if(!silent&&output) output.value=`Domain detected: ${q}`; setStatus(`Status: detected DOMAIN → ${q}`); }
    if (type==="url") { buildLinksForURL(q); if(!silent&&output) output.value=`URL detected: ${q}`; setStatus(`Status: detected URL → ${q}`); }
    if (type==="hash") { buildLinksForHash(q); if(!silent&&output) output.value=`Hash detected: ${q}`; setStatus(`Status: detected HASH → ${q}`); }
    if (type==="email") { buildLinksForEmail(q); if(!silent&&output) output.value=`Email detected: ${q}`; setStatus(`Status: detected EMAIL → ${q}`); }
    if (type==="username") { buildLinksForUsername(q); if(!silent&&output) output.value=`Username detected: ${q}`; setStatus(`Status: detected USERNAME → ${q}`); }
    if (type==="cve") { buildLinksForCVE(q); if(!silent&&output) output.value=`CVE detected: ${q}`; setStatus(`Status: detected CVE → ${q}`); }
    if (type==="eventid") { buildLinksForEventID(q); if(!silent&&output) output.value=`Event ID detected: ${q}`; setStatus(`Status: detected EVENT ID → ${q}`); }
    if (type==="header") {
      const headerText = pasted||raw;
      const h = buildLinksForHeaders(headerText);
      if (!silent&&output) output.value=`EMAIL HEADERS DETECTED ✅\n\nSender (From): ${h.senderEmail||"-"}\nReceiver (To): ${h.receiverEmail||"-"}\nReturn-Path: ${h.returnPath||"-"}\nReturn-Path Domain: ${h.returnPathDomain||"-"}\nOrigin IP: ${h.originIp||"-"}\nSPF: ${h.spfResult||"-"} (smtp.mailfrom: ${h.spfMailfrom||"-"})\nDKIM: ${h.dkimResult||"-"} (d=${h.dkimDomain||"-"}; s=${h.dkimSelector||"-"})\n\nQuick Pivots:\n- Return-Path Domain: ${h.returnPathDomain?`https://www.virustotal.com/gui/domain/${enc(h.returnPathDomain)}`:"-"}\n- Origin IP: ${h.originIp?`https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}`:"-"}\n- SPF Domain: ${h.spfMailfromDomain?`https://www.virustotal.com/gui/domain/${enc(h.spfMailfromDomain)}`:"-"}\n- DKIM Domain: ${h.dkimDomain?`https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}`:"-"}\n\nTip: Use Extract IOCs for a full summary.`;
      setStatus("Status: detected EMAIL HEADERS → header tools + email artifacts");
    }
    if (type&&q!==undefined) {
      const histVal = type==="header" ? "(email headers)" : (q||raw.slice(0,60));
      addToHistory(type, histVal);
    }
    renderCardMeta();
  }

  document.addEventListener("click", e => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    const raw=(input?.value||"").trim(); const pasted=(output?.value||"").trim();
    if (raw||pasted) doSearch({ silent: true });
  }, true);

  // ─── Keyboard shortcuts ───────────────────────────────────────
  document.addEventListener("keydown", e => {
    if (e.ctrlKey||e.metaKey) {
      if (e.key==="k"||e.key==="K") { e.preventDefault(); input?.focus(); input?.select(); }
      if (e.key==="d"||e.key==="D") { e.preventDefault(); const src=(output?.value||"").trim()?(output.value):(input?.value||""); if(output) output.value=defangSmart(src); setStatus("Status: defanged"); }
      if (e.key==="e"||e.key==="E") { e.preventDefault(); const text=(output?.value||"").trim()||(input?.value||""); if(output) output.value=extractSmartIOCs(text); setStatus("Status: Smart IOC extraction complete"); }
    }
  });

  // ─── Buttons ──────────────────────────────────────────────────
  const searchBtn = $("search-btn");
  if (searchBtn) searchBtn.addEventListener("click", () => doSearch({ silent: false }));
  if (input) input.addEventListener("keydown", e => { if (e.key==="Enter") doSearch({ silent: false }); });

  const defangBtn = $("defang-btn");
  if (defangBtn) defangBtn.addEventListener("click", () => {
    const src=(output?.value||"").trim()?(output.value):(input?.value||"");
    if(output) output.value=defangSmart(src); setStatus("Status: defanged");
  });
  const refangBtn = $("refang-btn");
  if (refangBtn) refangBtn.addEventListener("click", () => {
    const src=(output?.value||"").trim()?(output.value):(input?.value||"");
    if(output) output.value=refangSmart(src); setStatus("Status: refanged");
  });
  const extractBtn = $("extract-btn");
  if (extractBtn) extractBtn.addEventListener("click", () => {
    const text=(output?.value||"").trim()||(input?.value||"");
    if(output) output.value=extractSmartIOCs(text); setStatus("Status: Smart IOC extraction complete");
  });
  const copyBtn = $("copy-btn");
  if (copyBtn) copyBtn.addEventListener("click", async () => {
    if (!output) return;
    try { await navigator.clipboard.writeText(output.value||""); } catch { output.focus(); output.select(); document.execCommand("copy"); }
    setStatus("Status: copied to clipboard");
  });
  const clearAll = $("clear-all");
  if (clearAll) clearAll.addEventListener("click", () => {
    if(input) input.value=""; if(output) output.value="";
    syncSearchboxState(); setSearchMode(false); showRelevantTools([]);
    setLandingLinks(); renderCardMeta(); setStatus("Status: ready (landing page)");
    const banner=$("verdict-banner"); if(banner) banner.style.display="none";
    const sp=$("mitre-suggested"); if(sp) sp.style.display="none";
    const cvePanel=$("cve-enrichment"); if(cvePanel) cvePanel.style.display="none";
  });
  const toggleDark = $("toggle-dark");
  if (toggleDark) toggleDark.addEventListener("click", () => document.body.classList.toggle("light"));


  // ─── BULK IOC Analyzer ───────────────────────────────────────
  const bulkInput   = $("bulk-input");
  const bulkResults = $("bulk-results");
  const bulkStatus  = $("bulk-status");

  function setBulkStatus(msg) {
    if (bulkStatus) bulkStatus.querySelector("span").textContent = msg;
  }

  function extractAllIOCsFromText(text) {
    const refanged = refangSmart(text || "");
    const lines = refanged.split(/\n/).map(l => l.trim()).filter(Boolean);
    const iocs = [];

    lines.forEach(line => {
      const { type, q } = detectType(line, "");
      if (type && type !== "header") {
        iocs.push({ raw: line, type, q: q || line });
      }
    });

    const ips = (refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g) || []).filter(isValidIPv4);
    ips.forEach(ip => { if (!iocs.find(i => i.q === ip)) iocs.push({ raw: ip, type: "ip", q: ip }); });

    const hashes = (refanged.match(/\b[a-fA-F0-9]{64}\b/g) || []);
    hashes.forEach(h => { if (!iocs.find(i => i.q === h)) iocs.push({ raw: h, type: "hash", q: h }); });

    const cves = (refanged.match(/CVE-\d{4}-\d{4,}/gi) || []).map(c => c.toUpperCase());
    cves.forEach(c => { if (!iocs.find(i => i.q === c)) iocs.push({ raw: c, type: "cve", q: c }); });

    const seen = new Set();
    return iocs.filter(i => { if (seen.has(i.q)) return false; seen.add(i.q); return true; });
  }

  function getBulkLinks(type, q) {
    const e = encodeURIComponent;
    // Extract hostname for URL type
    let urlHost = q;
    if (type === "url") {
      try { urlHost = new URL(q).hostname; } catch { urlHost = q; }
    }
    const links = {
      ip: [
        { label: "VirusTotal",   url: `https://www.virustotal.com/gui/ip-address/${e(q)}` },
        { label: "AbuseIPDB",    url: `https://www.abuseipdb.com/check/${e(q)}` },
        { label: "Shodan",       url: `https://www.shodan.io/host/${e(q)}` },
        { label: "GreyNoise",    url: `https://viz.greynoise.io/ip/${e(q)}` },
        { label: "OTX",          url: `https://otx.alienvault.com/indicator/ip/${e(q)}` },
      ],
      domain: [
        { label: "VirusTotal",   url: `https://www.virustotal.com/gui/domain/${e(q)}` },
        { label: "URLScan",      url: `https://urlscan.io/search/#domain:${e(q)}` },
        { label: "Talos",        url: `https://talosintelligence.com/reputation_center/lookup?search=${e(q)}` },
        { label: "crt.sh",       url: `https://crt.sh/?q=${e(q)}` },
        { label: "OTX",          url: `https://otx.alienvault.com/indicator/domain/${e(q)}` },
      ],
      url: [
        { label: "VirusTotal",   url: `https://www.virustotal.com/gui/url/${btoa(q).replace(/=/g,'')}` },
        { label: "URLScan",      url: `https://urlscan.io/search/#page.url:${e(q)}` },
        { label: "URLVoid",      url: `https://www.urlvoid.com/scan/${e(q)}/` },
        { label: "CheckPhish",   url: `https://checkphish.ai/?url=${e(q)}` },
        { label: "ThreatFox",    url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(q)}` },
        { label: "Netcraft",     url: `https://sitereport.netcraft.com/?url=${e(q)}` },
        { label: "WebCheck",     url: `https://web-check.xyz/check/${e(q)}` },
        { label: "Wayback",      url: `https://web.archive.org/web/*/${e(q)}` },
      ],
      hash: [
        { label: "VirusTotal",   url: `https://www.virustotal.com/gui/file/${e(q)}` },
        { label: "MalwareBazaar",url: `https://bazaar.abuse.ch/browse.php?search=${e(q)}` },
        { label: "Hybrid",       url: `https://www.hybrid-analysis.com/search?query=${e(q)}` },
        { label: "OTX",          url: `https://otx.alienvault.com/indicator/file/${e(q)}` },
      ],
      email: [
        { label: "HIBP",         url: `https://haveibeenpwned.com/account/${e(q)}` },
        { label: "Hunter.io",    url: `https://hunter.io/email-verifier/${e(q)}` },
        { label: "EmailRep",     url: `https://emailrep.io/${e(q)}` },
        { label: "Epieos",       url: `https://epieos.com/?q=${e(q)}&t=email` },
      ],
      cve: [
        { label: "NVD",          url: `https://nvd.nist.gov/vuln/detail/${e(q)}` },
        { label: "CVE.org",      url: `https://www.cve.org/CVERecord?id=${e(q)}` },
        { label: "Exploit-DB",   url: `https://www.exploit-db.com/search?cve=${e(q)}` },
        { label: "EPSS",         url: `https://www.first.org/epss/?q=${e(q)}` },
      ],
      username: [
        { label: "WhatsMyName",  url: `https://whatsmyname.app/?q=${e(q)}` },
        { label: "Namechk",      url: `https://namechk.com/?q=${e(q)}` },
        { label: "IntelX",       url: `https://intelx.io/?s=${e(q)}` },
      ],
    };
    return links[type] || [{ label: "Google", url: `https://www.google.com/search?q=${e(q)}` }];
  }

  const typeColors = {
    ip: "#38bdf8", domain: "#34d399", url: "#fb923c", hash: "#f59e0b",
    email: "#a78bfa", cve: "#f87171", username: "#e879f9", eventid: "#86efac"
  };

  function renderBulkResults(iocs) {
    if (!bulkResults) return;
    if (!iocs.length) { bulkResults.innerHTML = '<div class="bulk-empty">No IOCs detected.</div>'; return; }

    const grouped = {};
    iocs.forEach(ioc => { if (!grouped[ioc.type]) grouped[ioc.type] = []; grouped[ioc.type].push(ioc); });

    let html = `<div class="bulk-summary">Found <strong>${iocs.length}</strong> IOC${iocs.length !== 1 ? "s" : ""} across ${Object.keys(grouped).length} type${Object.keys(grouped).length !== 1 ? "s" : ""}</div>`;

    Object.entries(grouped).forEach(([type, items]) => {
      const color = typeColors[type] || "#9ca3af";
      html += `<div class="bulk-group">
        <div class="bulk-group-head" style="color:${color};border-color:${color}33">
          <span>${type.toUpperCase()} <span class="bulk-count">${items.length}</span></span>
        </div>`;
      items.forEach(ioc => {
        const links = getBulkLinks(ioc.type, ioc.q);
        const linksHtml = links.map(l =>
          `<a href="${l.url}" target="_blank" class="bulk-link" style="border-color:${color}33;color:${color}">${l.label}</a>`
        ).join("");
        html += `<div class="bulk-item">
          <div class="bulk-ioc-val">${ioc.q}</div>
          <div class="bulk-links">${linksHtml}</div>
        </div>`;
      });
      html += `</div>`;
    });

    bulkResults.innerHTML = html;
  }

  const bulkAnalyzeBtn = $("bulk-analyze-btn");
  if (bulkAnalyzeBtn) {
    bulkAnalyzeBtn.addEventListener("click", () => {
      const text = (bulkInput?.value || "").trim();
      if (!text) { setBulkStatus("Paste some IOCs first."); return; }
      const iocs = extractAllIOCsFromText(text);
      renderBulkResults(iocs);
      setBulkStatus(`Found ${iocs.length} IOCs — click any link to pivot`);
      iocs.forEach(ioc => addToHistory(ioc.type, ioc.q));
    });
  }

  const bulkClearBtn = $("bulk-clear-btn");
  if (bulkClearBtn) bulkClearBtn.addEventListener("click", () => {
    if (bulkInput) bulkInput.value = "";
    if (bulkResults) bulkResults.innerHTML = "";
    setBulkStatus("Paste IOCs above and click Analyze");
  });

  const bulkCopyBtn = $("bulk-copy-btn");
  if (bulkCopyBtn) bulkCopyBtn.addEventListener("click", async () => {
    if (!bulkResults || !bulkResults.textContent.trim()) return;
    const iocs = extractAllIOCsFromText(bulkInput?.value || "");
    const text = iocs.map(i => `[${i.type.toUpperCase()}] ${i.q}`).join("\n");
    try { await navigator.clipboard.writeText(text); setBulkStatus("Copied IOC list to clipboard"); }
    catch { setBulkStatus("Copy failed — try manually"); }
  });

  // ═══════════════════════════════════════════════════════════════
  // ─── SCRIPT / COMMAND ANALYZER ENGINE ───────────────────────
  // ═══════════════════════════════════════════════════════════════

  let saCurrentMode = "powershell";

  document.querySelectorAll(".sa-mode-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".sa-mode-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      saCurrentMode = btn.dataset.mode;
      const badge = $("sa-mode-badge");
      if (badge) badge.textContent = saCurrentMode.toUpperCase();
    });
  });

  function calcEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((s, f) => {
      const p = f / len;
      return s + p * Math.log2(p);
    }, 0);
  }

  function tryDecodeBase64(str) {
    const clean = str.replace(/[\s\r\n]/g, "");
    if (clean.length < 8) return null;
    try {
      const raw = atob(clean);
      const isUtf16 = raw.split("").every((c, i) => i % 2 === 1 ? c === "\0" : true);
      if (isUtf16) {
        return raw.split("").filter((_, i) => i % 2 === 0).join("");
      }
      const printable = raw.split("").filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
      if (printable / raw.length > 0.6) return raw;
      return null;
    } catch { return null; }
  }

  function deepDecode(text) {
    let current = text;
    const layers = [];
    let maxLayers = 6;
    while (maxLayers-- > 0) {
      const b64Match = current.match(/[A-Za-z0-9+/]{20,}={0,2}/g);
      if (!b64Match) break;
      let decoded = null;
      for (const blob of b64Match) {
        const d = tryDecodeBase64(blob);
        if (d && d.length > 4) { decoded = d; break; }
      }
      if (!decoded || decoded === current) break;
      layers.push({ from: current.slice(0, 120) + (current.length > 120 ? "…" : ""), to: decoded });
      current = decoded;
    }
    return { final: current, layers };
  }

  function decodeCharArray(text) {
    const results = [];
    const pattern = /(\[char\]\d+(?:\s*[+,]\s*\[char\]\d+)+)/gi;
    const matches = text.match(pattern) || [];
    matches.forEach(m => {
      const nums = m.match(/\d+/g) || [];
      const decoded = nums.map(n => String.fromCharCode(Number(n))).join("");
      results.push({ original: m, decoded });
    });
    return results;
  }

  function findReversedStrings(text) {
    const results = [];
    const rev = text.match(/-split\s+''[^']*''.*?-join\s+''[^']*''/gi) || [];
    rev.forEach(m => results.push({ hint: "Possible string reversal/join obfuscation", snippet: m.slice(0, 80) }));
    return results;
  }

  const THREAT_INDICATORS = {
    powershell: [
      { pattern: /\bDownloadString\b/gi,          sev: "critical", label: "Downloads & executes remote string",         mitre: ["T1059.001","T1105"] },
      { pattern: /\bDownloadFile\b/gi,             sev: "high",    label: "Downloads file from remote URL",             mitre: ["T1105"] },
      { pattern: /\bDownloadData\b/gi,             sev: "high",    label: "Downloads raw data from remote",             mitre: ["T1105"] },
      { pattern: /\bWebClient\b/gi,                sev: "medium",  label: "Creates WebClient object (network activity)",mitre: ["T1071","T1105"] },
      { pattern: /\bInvoke-WebRequest\b|\biwr\b/gi,sev: "medium",  label: "Web request via Invoke-WebRequest",          mitre: ["T1105","T1071"] },
      { pattern: /\bcurl\b|\bwget\b/gi,            sev: "low",     label: "curl/wget download attempt",                 mitre: ["T1105"] },
      { pattern: /\bIEX\b|\bInvoke-Expression\b/gi,sev: "critical",label: "IEX — executes arbitrary string as code",    mitre: ["T1059.001"] },
      { pattern: /\bInvoke-Command\b|\bicm\b/gi,   sev: "high",    label: "Remote command execution",                   mitre: ["T1059.001","T1021"] },
      { pattern: /\bStart-Process\b/gi,            sev: "medium",  label: "Spawns a new process",                       mitre: ["T1059","T1204"] },
      { pattern: /\bShellExecute\b/gi,             sev: "high",    label: "ShellExecute — launches external process",   mitre: ["T1059","T1204"] },
      { pattern: /\bcmd\.exe\b|\bcmd\s*\/[ck]/gi,  sev: "medium",  label: "Spawns cmd.exe subprocess",                  mitre: ["T1059.003"] },
      { pattern: /\bwscript\b|\bcscript\b/gi,      sev: "high",    label: "Executes via WScript/CScript host",          mitre: ["T1059.005"] },
      { pattern: /\bmshta\.exe\b|\bmshta\b/gi,     sev: "critical",label: "mshta — HTML Application host abuse (LOLBin)",mitre: ["T1218.005"] },
      { pattern: /\bregsvr32\b/gi,                 sev: "high",    label: "regsvr32 — COM scriptlet abuse",             mitre: ["T1218.010"] },
      { pattern: /\brundll32\b/gi,                 sev: "high",    label: "rundll32 — DLL proxy execution",             mitre: ["T1218.011"] },
      { pattern: /\-enc\b|\-EncodedCommand\b/gi,   sev: "high",    label: "Base64-encoded command (-enc)",              mitre: ["T1027","T1059.001"] },
      { pattern: /\-w\s*hidden|\-WindowStyle\s*[Hh]idden/gi, sev: "high", label: "Hidden window — anti-visibility",    mitre: ["T1564.003"] },
      { pattern: /\-nop\b|\-NonInteractive\b/gi,   sev: "medium",  label: "-nop/-NonInteractive — evasion flag",        mitre: ["T1059.001"] },
      { pattern: /\-ExecutionPolicy\s*[Bb]ypass/gi,sev: "critical",label: "Execution policy bypass",                    mitre: ["T1059.001","T1562"] },
      { pattern: /\[Convert\]::FromBase64String/gi, sev: "high",   label: "Manual Base64 decode",                       mitre: ["T1027"] },
      { pattern: /\[char\]\s*\d+/gi,               sev: "medium",  label: "Char-array obfuscation",                     mitre: ["T1027"] },
      { pattern: /\$env:/gi,                       sev: "low",     label: "References environment variables",           mitre: ["T1082"] },
      { pattern: /\bNew-ScheduledTask\b|\bRegister-ScheduledTask\b/gi, sev: "high", label: "Creates scheduled task (persistence)", mitre: ["T1053.005"] },
      { pattern: /\bSet-ItemProperty.*Run\b/gi,    sev: "critical",label: "Writes to Run registry key (autostart)",     mitre: ["T1547.001"] },
      { pattern: /HKCU:\\|HKLM:\\/gi,             sev: "medium",  label: "Modifies registry keys",                     mitre: ["T1547","T1112"] },
      { pattern: /\bNew-Service\b|\bsc\.exe\b/gi,  sev: "high",    label: "Creates or modifies a Windows service",      mitre: ["T1543.003"] },
      { pattern: /\bAdd-MpPreference\s+-Exclusion/gi,sev:"critical",label:"Adds AV/Defender exclusion (disables protection)",mitre:["T1562.001"] },
      { pattern: /\bSet-MpPreference.*Disable/gi,  sev: "critical",label: "Disables Windows Defender",                  mitre: ["T1562.001"] },
      { pattern: /\bDisable-WindowsOptionalFeature\b/gi,sev:"high",label:"Disables Windows security feature",           mitre: ["T1562"] },
      { pattern: /\bwevtutil\b.*cl\b/gi,           sev: "critical",label: "Clears Windows event logs",                  mitre: ["T1070.001"] },
      { pattern: /\bClear-EventLog\b/gi,           sev: "critical",label: "Clears event log (covers tracks)",           mitre: ["T1070.001"] },
      { pattern: /\bSleep\b|\bStart-Sleep\b/gi,    sev: "low",     label: "Sleep delay — possible sandbox evasion",     mitre: ["T1497"] },
      { pattern: /\bMimikatz\b|\bInvoke-Mimikatz\b/gi, sev:"critical",label:"Mimikatz credential dumping tool",        mitre:["T1003"] },
      { pattern: /\blsass\b/gi,                    sev: "critical",label: "References lsass (credential dump target)",  mitre: ["T1003.001"] },
      { pattern: /\bGet-Credential\b/gi,           sev: "medium",  label: "Credential harvesting attempt",              mitre: ["T1056"] },
      { pattern: /\bSecureString\b/gi,             sev: "low",     label: "Uses SecureString (credential handling)",    mitre: ["T1078"] },
      { pattern: /\bGet-Process\b|\bGet-Service\b/gi,sev:"low",    label: "Process/service enumeration",                mitre: ["T1057","T1007"] },
      { pattern: /\bGet-NetAdapter\b|\bipconfig\b/gi,sev:"low",    label: "Network interface discovery",                mitre: ["T1016"] },
      { pattern: /\bGet-ADUser\b|\bGet-ADComputer\b/gi,sev:"medium",label:"Active Directory enumeration",              mitre: ["T1087.002"] },
      { pattern: /\bnet\s+user\b|\bnet\s+group\b/gi,sev:"medium", label: "User/group enumeration",                     mitre: ["T1087"] },
      { pattern: /\bEnter-PSSession\b|\bNew-PSSession\b/gi,sev:"high",label:"PS remoting — lateral movement",          mitre:["T1021.006"] },
      { pattern: /\bInvoke-WMIMethod\b|\bGet-WMIObject\b/gi,sev:"high",label:"WMI execution",                         mitre:["T1047"] },
      { pattern: /\bwmic\b/gi,                     sev: "high",    label: "WMIC — WMI command-line abuse",              mitre: ["T1047"] },
      { pattern: /\bSend-MailMessage\b/gi,         sev: "high",    label: "Email exfiltration attempt",                 mitre: ["T1048","T1567"] },
      { pattern: /\bUploadString\b|\bUploadData\b/gi,sev:"high",   label: "Uploads data to remote server",              mitre: ["T1041","T1048"] },
    ],
    cmdline: [
      { pattern: /certutil\s+.*(-urlcache|-decode|-encode)/gi,sev:"critical",label:"certutil LOLBin — download or decode payload",mitre:["T1105","T1140","T1218"] },
      { pattern: /\bbitsadmin\b.*\/transfer/gi,    sev: "critical",label: "BITSAdmin — background download (LOLBin)",   mitre: ["T1197"] },
      { pattern: /\bpowershell\b.*-[eE]nc/gi,      sev: "critical",label: "Spawns PowerShell with encoded command",     mitre: ["T1059.001","T1027"] },
      { pattern: /\bpowershell\b.*-[wW]\s*[hH]idden/gi,sev:"high",label:"Hidden PowerShell window",                    mitre: ["T1564.003"] },
      { pattern: /\bpowershell\b.*bypass/gi,       sev: "critical",label: "PowerShell execution policy bypass via CMD", mitre: ["T1059.001","T1562"] },
      { pattern: /\bwscript\b|\bcscript\b/gi,      sev: "high",    label: "Script host execution",                      mitre: ["T1059.005"] },
      { pattern: /\bmshta\b/gi,                    sev: "critical",label: "mshta LOLBin execution",                     mitre: ["T1218.005"] },
      { pattern: /\bregsvr32\b/gi,                 sev: "high",    label: "regsvr32 LOLBin",                            mitre: ["T1218.010"] },
      { pattern: /\brundll32\b/gi,                 sev: "high",    label: "rundll32 proxy execution",                   mitre: ["T1218.011"] },
      { pattern: /\bschtasks\b.*\/create/gi,       sev: "high",    label: "Scheduled task creation",                    mitre: ["T1053.005"] },
      { pattern: /\breg\s+add\b/gi,                sev: "medium",  label: "Registry key modification",                  mitre: ["T1547","T1112"] },
      { pattern: /\bnet\s+user\b.*\/add/gi,        sev: "critical",label: "Creates new user account (backdoor)",        mitre: ["T1136"] },
      { pattern: /\bnet\s+localgroup\s+administrators\b/gi,sev:"critical",label:"Adds user to Administrators group",   mitre:["T1136","T1078"] },
      { pattern: /\bwevtutil\b.*cl\b/gi,           sev: "critical",label: "Clears event logs",                          mitre: ["T1070.001"] },
      { pattern: /\bsc\s+(create|config|start)\b/gi,sev:"high",   label: "Service creation/modification",              mitre: ["T1543.003"] },
      { pattern: /\bnetsh\b.*firewall/gi,          sev: "high",    label: "Firewall rule modification",                  mitre: ["T1562.004"] },
      { pattern: /\bat\b|\bschtasks\b/gi,          sev: "medium",  label: "Task scheduling",                            mitre: ["T1053"] },
      { pattern: /\bwmic\b.*process.*call.*create/gi,sev:"critical",label:"WMIC remote process creation",              mitre:["T1047"] },
      { pattern: /\bftp\b.*-[si]:/gi,             sev: "high",    label: "FTP scripted transfer",                      mitre: ["T1048","T1105"] },
      { pattern: /echo\s+.+>>/gi,                  sev: "low",     label: "File write via echo redirect",               mitre: ["T1027"] },
    ],
    bash: [
      { pattern: /\bcurl\b.*(-o|-O|sh\b|\|\s*bash)/gi,sev:"critical",label:"curl piped to bash — remote exec pattern",mitre:["T1059.004","T1105"] },
      { pattern: /\bwget\b.*(-O\s*-|\|\s*bash|\|\s*sh)/gi,sev:"critical",label:"wget piped to shell",                 mitre:["T1059.004","T1105"] },
      { pattern: /\bchmod\b.*\+x/gi,              sev: "medium",  label: "Makes file executable",                      mitre: ["T1059"] },
      { pattern: /\bcrontab\b/gi,                  sev: "high",    label: "Cron job modification (persistence)",        mitre: ["T1053.003"] },
      { pattern: /\/etc\/cron/gi,                  sev: "high",    label: "Cron directory modification",               mitre: ["T1053.003"] },
      { pattern: /\.bashrc|\.profile|\.bash_profile/gi,sev:"high",label:"Shell profile modification (persistence)",    mitre:["T1546.004"] },
      { pattern: /\bbase64\b.*-d/gi,              sev: "high",    label: "Base64 decode in shell",                     mitre: ["T1027","T1140"] },
      { pattern: /\bnc\b.*-[el]|\bnetcat\b/gi,    sev: "critical",label: "Netcat reverse/bind shell",                  mitre: ["T1059","T1071"] },
      { pattern: /\/dev\/tcp\//gi,                 sev: "critical",label: "Bash TCP redirect — reverse shell indicator",mitre: ["T1059.004"] },
      { pattern: /\bsudo\b.*-[si]/gi,             sev: "high",    label: "sudo privilege escalation attempt",          mitre: ["T1068","T1548"] },
      { pattern: /\bpasswd\b|\bshadow\b/gi,       sev: "critical",label: "References password/shadow file",            mitre: ["T1003.008"] },
      { pattern: /\bssh\b.*-R\b/gi,              sev: "high",    label: "SSH reverse tunnel",                          mitre: ["T1572","T1021.004"] },
      { pattern: /\biptables\b.*-[FXZ]/gi,        sev: "high",    label: "Flushes firewall rules",                     mitre: ["T1562.004"] },
      { pattern: /\bHistory\b|\bhistory\s+-c/gi,  sev: "medium",  label: "Clears shell history",                       mitre: ["T1070.003"] },
      { pattern: /\buname\b|\bwhoami\b|\bid\b/gi, sev: "low",     label: "System/user discovery",                      mitre: ["T1082","T1033"] },
      { pattern: /\bpython\b.*-c\b|\bpython3\b.*-c\b/gi,sev:"high",label:"Python one-liner execution",               mitre:["T1059.006"] },
      { pattern: /\benv\b.*python|\/usr\/bin\/python/gi,sev:"medium",label:"Python invocation via env",               mitre:["T1059.006"] },
    ],
    vbs: [
      { pattern: /\bCreateObject\s*\(\s*["']WScript\.Shell["']\)/gi,sev:"critical",label:"WScript.Shell — command execution",mitre:["T1059.005"] },
      { pattern: /\bCreateObject\s*\(\s*["']MSXML2\.XMLHTTP["']/gi, sev:"critical",label:"XMLHTTP — remote download",      mitre:["T1105","T1071"] },
      { pattern: /\bCreateObject\s*\(\s*["']Scripting\.FileSystemObject["']/gi,sev:"medium",label:"FileSystemObject access",mitre:["T1083"] },
      { pattern: /\bCreateObject\s*\(\s*["']Shell\.Application["']/gi,sev:"high",label:"Shell.Application — LOLBin exec",  mitre:["T1218"] },
      { pattern: /\bWScript\.Run\b/gi,            sev: "critical",label: "WScript.Run — executes command",               mitre: ["T1059.005"] },
      { pattern: /\.Run\s*\([^)]*,\s*0/gi,        sev: "high",    label: "Hidden window execution (,0 parameter)",      mitre: ["T1564.003"] },
      { pattern: /\bExecute\b|\bEval\b/gi,         sev: "high",    label: "Dynamic code evaluation",                     mitre: ["T1059.005","T1027"] },
      { pattern: /Chr\s*\(\s*\d+\s*\)/gi,         sev: "medium",  label: "Chr() obfuscation",                           mitre: ["T1027"] },
      { pattern: /\bRegWrite\b/gi,                 sev: "high",    label: "Registry write operation",                    mitre: ["T1547","T1112"] },
      { pattern: /\bSendKeys\b/gi,                 sev: "medium",  label: "SendKeys — keyboard simulation",              mitre: ["T1056"] },
    ],
    js: [
      { pattern: /\bWScript\.Shell\b|\bWScript\.CreateObject\b/gi,sev:"critical",label:"WScript.Shell via JScript",    mitre:["T1059.007"] },
      { pattern: /\bnew\s+ActiveXObject\s*\(\s*["']WScript/gi,    sev:"critical",label:"ActiveX WScript object",       mitre:["T1059.007"] },
      { pattern: /\bnew\s+ActiveXObject\s*\(\s*["']MSXML/gi,      sev:"critical",label:"MSXML HTTP request (download)",mitre:["T1105","T1071"] },
      { pattern: /\beval\s*\(/gi,                  sev: "critical",label: "eval() — dynamic code execution",            mitre: ["T1059.007","T1027"] },
      { pattern: /\bFunction\s*\(\s*['"].*['"]\s*\)/gi,sev:"high",label:"Function constructor code exec",              mitre:["T1059.007"] },
      { pattern: /document\.write\s*\(/gi,         sev: "medium",  label: "document.write — DOM injection",             mitre: ["T1059.007"] },
      { pattern: /\bunescape\s*\(/gi,              sev: "high",    label: "unescape() — string deobfuscation",          mitre: ["T1027"] },
      { pattern: /String\.fromCharCode\s*\(/gi,    sev: "high",    label: "fromCharCode — char-code obfuscation",       mitre: ["T1027"] },
      { pattern: /\btop\[.+\]\s*\(/gi,             sev: "high",    label: "Property access obfuscation",                mitre: ["T1027"] },
      { pattern: /\\\d{3}|\\\x[0-9a-f]{2}/gi,     sev: "medium",  label: "Octal/hex escape obfuscation",               mitre: ["T1027"] },
    ],
  };

  function autoDetectMode(text) {
    const t = text.toLowerCase();
    const scores = { powershell: 0, cmdline: 0, bash: 0, vbs: 0, js: 0 };
    if (/\biex\b|\binvoke-expression\b|\bdownloadstring\b|\bpowershell\b|-enc\b/.test(t)) scores.powershell += 5;
    if (/\$[a-z_]\w*\s*=/.test(t)) scores.powershell += 2;
    if (/\bcertutil\b|\bschtasks\b|\bwevtutil\b|\bcmd\s*\/[ck]/.test(t)) scores.cmdline += 5;
    if (/@echo\s+off|echo\s+.*>>/.test(t)) scores.cmdline += 3;
    if (/\bcurl\b|\bwget\b|\/dev\/tcp|\.bashrc|\bchmod\b/.test(t)) scores.bash += 5;
    if (/#!/.test(t)) scores.bash += 3;
    if (/\bwscript\b|\bcreateobject\b|\bvbscript\b/.test(t)) scores.vbs += 5;
    if (/\bactivexobject\b|\bwscript\.shell\b|\beval\s*\(/.test(t)) scores.js += 4;
    return Object.entries(scores).sort((a, b) => b[1] - a[1])[0][0];
  }

  function extractScriptIOCs(text) {
    const refanged = refangSmart(text);
    const urls     = [...new Set((refanged.match(/https?:\/\/[^\s"'`>)]+/gi) || []))];
    const ips      = [...new Set((refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g) || []).filter(isValidIPv4))];
    const domains  = [...new Set((refanged.match(/\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\b/g) || [])
      .filter(d => !/^\d+\.\d+\.\d+/.test(d) && !urls.some(u => u.includes(d))))];
    const regKeys  = [...new Set((text.match(/(?:HKCU|HKLM|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[\\\/][^\s"'`,;)]+/gi) || []))];
    const paths    = [...new Set((text.match(/[A-Za-z]:\\[^\s"'`<>|,;]+/g) || []))];
    const unixPaths= [...new Set((text.match(/\/(?:etc|tmp|var|home|usr|bin|dev)\/[^\s"'`]+/g) || []))];
    const emails   = [...new Set((text.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || []))];
    return { urls, ips, domains, regKeys, paths, unixPaths, emails };
  }

  function runIndicators(text, mode) {
    const indicators = THREAT_INDICATORS[mode] || [];
    const hits = [];
    const allMitre = new Set();
    indicators.forEach(ind => {
      const matches = [...new Set((text.match(ind.pattern) || []).map(m => m.trim()))];
      if (matches.length) {
        hits.push({ ...ind, matches });
        ind.mitre.forEach(t => allMitre.add(t));
      }
    });
    return { hits, mitre: [...allMitre] };
  }

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const SEV_CONFIG = {
    critical: { color: "#f87171", bg: "rgba(248,113,113,0.10)", label: "CRITICAL", icon: "🔴" },
    high:     { color: "#fb923c", bg: "rgba(251,146,60,0.10)",  label: "HIGH",     icon: "🟠" },
    medium:   { color: "#fbbf24", bg: "rgba(251,191,36,0.10)",  label: "MEDIUM",   icon: "🟡" },
    low:      { color: "#34d399", bg: "rgba(52,211,153,0.10)",  label: "LOW",      icon: "🟢" },
  };

  function calcVerdict(hits) {
    if (!hits.length) return { label: "✅ CLEAN", color: "#34d399", score: 0 };
    if (hits.some(h => h.sev === "critical")) return { label: "🔴 MALICIOUS", color: "#f87171", score: hits.length };
    if (hits.some(h => h.sev === "high"))     return { label: "🟠 HIGH RISK",  color: "#fb923c", score: hits.length };
    if (hits.some(h => h.sev === "medium"))   return { label: "🟡 SUSPICIOUS", color: "#fbbf24", score: hits.length };
    return { label: "🟢 LOW RISK", color: "#34d399", score: hits.length };
  }

  function renderSAResults(text, mode) {
    const saResults = $("sa-results");
    if (!saResults) return;
    if (!text.trim()) { saResults.innerHTML = ""; return; }

    const effectiveMode = mode === "auto" ? autoDetectMode(text) : mode;
    const { hits, mitre } = runIndicators(text, effectiveMode);
    const iocs = extractScriptIOCs(text);
    const charArrays = decodeCharArray(text);
    const { final: decoded, layers } = deepDecode(text);
    const verdict = calcVerdict(hits);
    const entropy = calcEntropy(text.replace(/\s/g, ""));

    hits.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);

    const critCount = hits.filter(h => h.sev === "critical").length;
    const highCount = hits.filter(h => h.sev === "high").length;
    const medCount  = hits.filter(h => h.sev === "medium").length;
    const lowCount  = hits.filter(h => h.sev === "low").length;

    let html = `
    <div class="sa-verdict" style="border-color:${verdict.color}44;background:${verdict.color}0d">
      <div class="sa-verdict-left">
        <div class="sa-verdict-label" style="color:${verdict.color}">${verdict.label}</div>
        <div class="sa-verdict-meta">
          Mode: <strong>${effectiveMode.toUpperCase()}</strong>
          &nbsp;·&nbsp; Indicators: <strong>${hits.length}</strong>
          &nbsp;·&nbsp; Entropy: <strong>${entropy.toFixed(2)}</strong>${entropy > 5.5 ? " ⚠️ High" : ""}
          &nbsp;·&nbsp; Lines: <strong>${text.split("\n").length}</strong>
        </div>
      </div>
      <div class="sa-sev-pills">
        ${critCount ? `<span class="sa-sev-pill" style="background:rgba(248,113,113,0.15);color:#f87171;border-color:#f8717144">${critCount} CRITICAL</span>` : ""}
        ${highCount ? `<span class="sa-sev-pill" style="background:rgba(251,146,60,0.15);color:#fb923c;border-color:#fb923c44">${highCount} HIGH</span>` : ""}
        ${medCount  ? `<span class="sa-sev-pill" style="background:rgba(251,191,36,0.15);color:#fbbf24;border-color:#fbbf2444">${medCount} MEDIUM</span>` : ""}
        ${lowCount  ? `<span class="sa-sev-pill" style="background:rgba(52,211,153,0.15);color:#34d399;border-color:#34d39944">${lowCount} LOW</span>` : ""}
      </div>
    </div>`;

    if (hits.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🚨 Threat Indicators <span class="sa-section-count">${hits.length}</span></div>
        <div class="sa-indicators">`;
      hits.forEach(h => {
        const sc = SEV_CONFIG[h.sev];
        const mitreTags = h.mitre.map(t =>
          `<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="sa-mitre-tag">${t}</a>`
        ).join("");
        const matchSnippets = h.matches.slice(0, 3).map(m =>
          `<code class="sa-match">${m.replace(/</g,"&lt;").slice(0,60)}${m.length>60?"…":""}</code>`
        ).join(" ");
        html += `<div class="sa-indicator" style="border-left-color:${sc.color};background:${sc.bg}">
          <div class="sa-ind-head">
            <span class="sa-ind-sev" style="color:${sc.color}">${sc.icon} ${sc.label}</span>
            <span class="sa-ind-label">${h.label}</span>
          </div>
          <div class="sa-ind-matches">${matchSnippets}</div>
          <div class="sa-ind-mitre">${mitreTags}</div>
        </div>`;
      });
      html += `</div></div>`;
    } else {
      html += `<div class="sa-section"><div class="sa-section-head">✅ No Threat Indicators Found</div></div>`;
    }

    if (mitre.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🧩 MITRE ATT&CK Mapping <span class="sa-section-count">${mitre.length}</span></div>
        <div class="sa-mitre-grid">`;
      mitre.forEach(t => {
        html += `<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="sa-mitre-card">
          <div class="sa-mitre-tid">${t}</div>
          <div class="sa-mitre-name">${getMitreName(t)}</div>
        </a>`;
      });
      html += `</div></div>`;
    }

    if (layers.length || charArrays.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🔓 Decoded / Deobfuscated Content</div>`;
      if (layers.length) {
        layers.forEach((l, i) => {
          html += `<div class="sa-decode-layer">
            <div class="sa-decode-label">Layer ${i + 1} — Base64 decoded</div>
            <pre class="sa-code">${l.to.replace(/</g,"&lt;").slice(0, 400)}${l.to.length > 400 ? "\n… (truncated)" : ""}</pre>
          </div>`;
        });
        if (layers.length > 0) {
          html += `<div class="sa-decode-layer">
            <div class="sa-decode-label">✅ Final decoded output</div>
            <pre class="sa-code">${decoded.replace(/</g,"&lt;").slice(0, 800)}${decoded.length > 800 ? "\n… (truncated)" : ""}</pre>
          </div>`;
        }
      }
      if (charArrays.length) {
        charArrays.slice(0, 5).forEach(ca => {
          html += `<div class="sa-decode-layer">
            <div class="sa-decode-label">[char] array → <code>${ca.decoded.replace(/</g,"&lt;")}</code></div>
            <pre class="sa-code" style="font-size:10px;opacity:0.6">${ca.original.replace(/</g,"&lt;").slice(0,100)}</pre>
          </div>`;
        });
      }
      html += `</div>`;
    }

    const hasIOCs = Object.values(iocs).some(arr => arr.length > 0);
    if (hasIOCs) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🎯 Extracted IOCs</div>
        <div class="sa-ioc-grid">`;
      const iocTypes = [
        { key: "urls",       label: "URLs",            icon: "🔗", pivot: (v) => `https://urlscan.io/search/#page.url:${enc(v)}` },
        { key: "ips",        label: "IP Addresses",    icon: "🌐", pivot: (v) => `https://www.virustotal.com/gui/ip-address/${enc(v)}` },
        { key: "domains",    label: "Domains",         icon: "🏠", pivot: (v) => `https://www.virustotal.com/gui/domain/${enc(v)}` },
        { key: "emails",     label: "Emails",          icon: "📧", pivot: (v) => `https://haveibeenpwned.com/account/${enc(v)}` },
        { key: "regKeys",    label: "Registry Keys",   icon: "🗝", pivot: (v) => `https://www.google.com/search?q=${enc(v)}` },
        { key: "paths",      label: "File Paths (Win)",icon: "📁", pivot: (v) => `https://www.google.com/search?q=${enc(v + " malware")}` },
        { key: "unixPaths",  label: "File Paths (Unix)",icon:"📂", pivot: (v) => `https://www.google.com/search?q=${enc(v + " malware")}` },
      ];
      iocTypes.forEach(({ key, label, icon, pivot }) => {
        if (!iocs[key].length) return;
        html += `<div class="sa-ioc-group">
          <div class="sa-ioc-group-label">${icon} ${label} (${iocs[key].length})</div>`;
        iocs[key].forEach(v => {
          html += `<div class="sa-ioc-row">
            <code class="sa-ioc-val">${v.replace(/</g,"&lt;").slice(0,80)}${v.length>80?"…":""}</code>
            <a href="${pivot(v)}" target="_blank" class="sa-pivot-link">↗ Pivot</a>
          </div>`;
        });
        html += `</div>`;
      });
      html += `</div></div>`;
    }

    if (entropy > 5.5) {
      html += `<div class="sa-section sa-entropy-warn">
        <div class="sa-section-head">⚠️ High Entropy Detected (${entropy.toFixed(2)})</div>
        <p style="margin:8px 14px 14px;font-size:13px;color:var(--muted);">
          Entropy above 5.5 typically indicates encoded, compressed, or encrypted content. This script likely contains obfuscated payloads. Use <strong>Deep Decode</strong> to attempt extraction.
        </p>
      </div>`;
    }

    saResults.innerHTML = html;

    mitre.forEach(t => {
      const tid = t.split(".")[0];
      const cb = document.querySelector(`#mitre-panel input[value="${tid}"]`);
      if (cb) cb.checked = true;
    });
  }

  function getMitreName(tid) {
    const names = {
      "T1059":    "Command & Scripting Interpreter",
      "T1059.001":"PowerShell",
      "T1059.003":"Windows Command Shell",
      "T1059.004":"Unix Shell",
      "T1059.005":"Visual Basic",
      "T1059.006":"Python",
      "T1059.007":"JavaScript",
      "T1027":    "Obfuscated Files or Info",
      "T1140":    "Deobfuscate / Decode",
      "T1105":    "Ingress Tool Transfer",
      "T1071":    "Application Layer Protocol",
      "T1562":    "Impair Defenses",
      "T1562.001":"Disable/Modify AV",
      "T1562.004":"Disable/Modify Firewall",
      "T1547":    "Boot/Logon Autostart",
      "T1547.001":"Registry Run Keys",
      "T1053":    "Scheduled Task/Job",
      "T1053.003":"Cron",
      "T1053.005":"Scheduled Task",
      "T1003":    "Credential Dumping",
      "T1003.001":"LSASS Memory",
      "T1003.008":"/etc/passwd & Shadow",
      "T1218":    "Signed Binary Proxy Exec",
      "T1218.005":"Mshta",
      "T1218.010":"Regsvr32",
      "T1218.011":"Rundll32",
      "T1112":    "Modify Registry",
      "T1082":    "System Info Discovery",
      "T1033":    "System Owner Discovery",
      "T1016":    "Network Config Discovery",
      "T1087":    "Account Discovery",
      "T1087.002":"Domain Account",
      "T1057":    "Process Discovery",
      "T1007":    "System Service Discovery",
      "T1083":    "File & Dir Discovery",
      "T1021":    "Remote Services",
      "T1021.004":"SSH",
      "T1021.006":"Windows Remote Management",
      "T1047":    "WMI",
      "T1197":    "BITS Jobs",
      "T1041":    "Exfil Over C2 Channel",
      "T1048":    "Exfil Over Alt Protocol",
      "T1567":    "Exfil Over Web Service",
      "T1564.003":"Hidden Window",
      "T1546.004":"Unix Shell Config Mod",
      "T1572":    "Protocol Tunneling",
      "T1136":    "Create Account",
      "T1078":    "Valid Accounts",
      "T1068":    "Exploit for Priv Escalation",
      "T1548":    "Abuse Elevation Control",
      "T1543.003":"Windows Service",
      "T1070":    "Indicator Removal",
      "T1070.001":"Clear Windows Event Logs",
      "T1070.003":"Clear Command History",
      "T1056":    "Input Capture",
      "T1204":    "User Execution",
      "T1497":    "Virtualization/Sandbox Evasion",
    };
    return names[tid] || tid;
  }

  function generateSAReport(text, mode) {
    const effectiveMode = mode === "auto" ? autoDetectMode(text) : mode;
    const { hits, mitre } = runIndicators(text, effectiveMode);
    const iocs = extractScriptIOCs(text);
    const verdict = calcVerdict(hits);
    const entropy = calcEntropy(text.replace(/\s/, ""));
    const now = new Date().toISOString();

    const lines = [
      "═══════════════════════════════════════════════════",
      "  SCRIPT / COMMAND ANALYSIS REPORT",
      "═══════════════════════════════════════════════════",
      `Analyzed At : ${now}`,
      `Script Type : ${effectiveMode.toUpperCase()}`,
      `Verdict     : ${verdict.label}`,
      `Entropy     : ${entropy.toFixed(2)}${entropy > 5.5 ? " ⚠ HIGH — likely obfuscated" : ""}`,
      `Indicators  : ${hits.length}`,
      "",
      "───────────────────────────────────────────────────",
      "THREAT INDICATORS",
      "───────────────────────────────────────────────────",
    ];

    if (hits.length) {
      hits.forEach(h => {
        lines.push(`[${h.sev.toUpperCase()}] ${h.label}`);
        lines.push(`  MITRE: ${h.mitre.join(", ")}`);
        lines.push(`  Matches: ${h.matches.slice(0,3).join(" | ")}`);
        lines.push("");
      });
    } else {
      lines.push("No threat indicators detected.");
      lines.push("");
    }

    lines.push("───────────────────────────────────────────────────");
    lines.push("MITRE ATT&CK TECHNIQUES");
    lines.push("───────────────────────────────────────────────────");
    if (mitre.length) {
      mitre.forEach(t => lines.push(`  ${t.padEnd(14)} ${getMitreName(t)}`));
    } else {
      lines.push("  None mapped.");
    }

    lines.push("");
    lines.push("───────────────────────────────────────────────────");
    lines.push("EXTRACTED IOCs");
    lines.push("───────────────────────────────────────────────────");
    if (iocs.urls.length)     lines.push("URLs:\n" + iocs.urls.map(v => "  " + v).join("\n"));
    if (iocs.ips.length)      lines.push("IPs:\n" + iocs.ips.map(v => "  " + v).join("\n"));
    if (iocs.domains.length)  lines.push("Domains:\n" + iocs.domains.map(v => "  " + v).join("\n"));
    if (iocs.regKeys.length)  lines.push("Registry Keys:\n" + iocs.regKeys.map(v => "  " + v).join("\n"));
    if (iocs.paths.length)    lines.push("File Paths:\n" + iocs.paths.map(v => "  " + v).join("\n"));
    if (!iocs.urls.length && !iocs.ips.length && !iocs.domains.length) lines.push("  None found.");

    lines.push("");
    lines.push("═══════════════════════════════════════════════════");
    lines.push("END OF REPORT");

    return lines.join("\n");
  }

  const saInput      = $("sa-input");
  const saAnalyzeBtn = $("sa-analyze-btn");
  const saClearBtn   = $("sa-clear-btn");
  const saCopyBtn    = $("sa-copy-btn");
  const saDecodeBtn  = $("sa-decode-btn");
  const saStatusEl   = $("sa-status");

  function setSAStatus(msg) {
    if (saStatusEl) saStatusEl.querySelector("span").textContent = msg;
  }

  if (saAnalyzeBtn) {
    saAnalyzeBtn.addEventListener("click", () => {
      const text = (saInput?.value || "").trim();
      if (!text) { setSAStatus("Paste a script first."); return; }
      renderSAResults(text, saCurrentMode);
      const effectiveMode = saCurrentMode === "auto" ? autoDetectMode(text) : saCurrentMode;
      const { hits } = runIndicators(text, effectiveMode);
      const verdict = calcVerdict(hits);
      setSAStatus(`Analysis complete — ${verdict.label} · ${hits.length} indicators`);
      addToHistory("script", `[${effectiveMode}] ${text.slice(0, 40).replace(/\n/g, " ")}…`);
    });
  }

  if (saClearBtn) {
    saClearBtn.addEventListener("click", () => {
      if (saInput) saInput.value = "";
      const saResults = $("sa-results");
      if (saResults) saResults.innerHTML = "";
      setSAStatus("Paste a script above and click Analyze");
    });
  }

  if (saCopyBtn) {
    saCopyBtn.addEventListener("click", async () => {
      const text = (saInput?.value || "").trim();
      if (!text) return setSAStatus("Nothing to copy — run analysis first.");
      const report = generateSAReport(text, saCurrentMode);
      try { await navigator.clipboard.writeText(report); setSAStatus("Report copied to clipboard"); }
      catch { setSAStatus("Copy failed — try manually"); }
    });
  }

  if (saDecodeBtn) {
    saDecodeBtn.addEventListener("click", () => {
      const text = (saInput?.value || "").trim();
      if (!text) return setSAStatus("Paste a script first.");
      const { final, layers } = deepDecode(text);
      const saResults = $("sa-results");
      if (!layers.length) {
        setSAStatus("No Base64 layers found to decode.");
        return;
      }
      if (saResults) {
        let html = `<div class="sa-section"><div class="sa-section-head">🔓 Deep Decode — ${layers.length} layer(s) found</div>`;
        layers.forEach((l, i) => {
          html += `<div class="sa-decode-layer">
            <div class="sa-decode-label">Layer ${i+1}</div>
            <pre class="sa-code">${l.to.replace(/</g,"&lt;").slice(0,600)}</pre>
          </div>`;
        });
        html += `<div class="sa-decode-layer">
          <div class="sa-decode-label">✅ Final output</div>
          <pre class="sa-code">${final.replace(/</g,"&lt;").slice(0,800)}</pre>
        </div></div>`;
        saResults.innerHTML = html;
      }
      setSAStatus(`Deep decode complete — ${layers.length} layer(s) unwrapped`);
    });
  }

  if (saInput) {
    saInput.addEventListener("keydown", e => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        saAnalyzeBtn?.click();
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // ─── ALERT WRITE-UP ENGINE ───────────────────────────────────
  // ═══════════════════════════════════════════════════════════════

  const AW_TEMPLATES = [
    {
      id: "cs_encoded_ps", platform: "crowdstrike", icon: "⚡",
      name: "Base64 Encoded PowerShell Download Cradle",
      desc: "Fires when CrowdStrike Falcon detects a PowerShell script attempting to download and execute Base64-encoded commands. Common in phishing payloads, malicious macros, and LOLBin abuse.",
      severity: "high", mitre: ["T1059.001","T1027","T1105"],
      fields: ["alert_id","alert_time","hostname","username","process","cmdline","parent_process","encoded_string","decoded_string","src_ip","dest_url","verdict","analyst","notes"],
      triage_steps: ["Decode the Base64 string and analyze for malicious cmdlets (IEX, DownloadString, WebClient)","Identify the parent process that spawned PowerShell","Check if the destination URL or IP is known-malicious (VT, URLScan, Cisco Talos)","Review process tree in Falcon for lateral movement indicators","Scope the environment for similar command-lines on other endpoints","Isolate host if payload execution is confirmed"],
      recommendations: ["Block execution of encoded PowerShell via AppLocker or WDAC policy","Enable PowerShell Script Block Logging (Event ID 4104)","Block or sinkhole identified malicious URLs/IPs at proxy/firewall","Reset credentials if user context is involved"]
    },
    {
      id: "cs_cobalt_strike", platform: "crowdstrike", icon: "🕸",
      name: "Cobalt Strike Beacon / C2 Communication",
      desc: "CrowdStrike detects HTTP headers matching default or custom Cobalt Strike malleable profiles, indicating a likely C2 communication channel.",
      severity: "critical", mitre: ["T1071.001","T1055","T1036","T1059"],
      fields: ["alert_id","alert_time","hostname","username","process","src_ip","dest_ip","dest_port","http_headers","beacon_config","verdict","analyst","notes"],
      triage_steps: ["Examine HTTP headers against known Cobalt Strike malleable profile signatures","Identify the process responsible for the outbound connection","Check VirusTotal / Hybrid Analysis for associated hashes","Pivot on destination IP/domain across all endpoints for scope","Determine initial access vector (phishing, exploit, insider)","Immediately isolate the affected host(s)"],
      recommendations: ["Isolate host immediately and revoke active sessions","Block C2 IP/domain at all perimeter controls","Hunt for beacon persistence mechanisms (scheduled tasks, registry Run keys, services)","Initiate full IR process — Cobalt Strike indicates hands-on attacker"]
    },
    {
      id: "cs_malware_hash", platform: "crowdstrike", icon: "☣",
      name: "Malware / Intelligence Indicator Detection",
      desc: "Falcon Intelligence or NGAV flagged a file hash matching a known malicious artifact.",
      severity: "high", mitre: ["T1204.002","T1059","T1027","T1053"],
      fields: ["alert_id","alert_time","hostname","username","file_path","file_hash_sha256","file_hash_md5","process_tree","verdict_confidence","family","campaign","analyst","verdict","notes"],
      triage_steps: ["Cross-reference hash in VirusTotal, MalwareBazaar, Hybrid Analysis","Review the full process tree in Falcon Behavioral Graph","Identify how the file arrived (email, download, lateral movement)","Check if file executed or was blocked pre-execution","Scope across environment for same hash or similar file paths","Review network connections made by the process"],
      recommendations: ["Quarantine the malicious file and block hash at EDR level","Block associated IOCs (domains, IPs, hashes) across all controls","If executed: isolate host, initiate IR, credential reset","Review and close the initial access vector"]
    },
    {
      id: "cs_lsass_dump", platform: "crowdstrike", icon: "🔑",
      name: "LSASS Memory Access / Credential Dumping",
      desc: "Falcon detects a process opening a handle to lsass.exe with suspicious access rights.",
      severity: "critical", mitre: ["T1003.001","T1078"],
      fields: ["alert_id","alert_time","hostname","username","src_process","access_rights","lsass_pid","tool_indicator","verdict","analyst","notes"],
      triage_steps: ["Identify the process and whether it is a known tool (mimikatz, procdump, comsvcs.dll)","Check parent process and execution chain","Determine if dump file was written to disk","Assess if attacker already used dumped credentials (lateral movement, remote logins)","Review all recent authentication events from this host"],
      recommendations: ["Isolate host immediately","Force reset of all domain credentials accessible from this host","Enable Credential Guard on all applicable endpoints","Add lsass.exe to Protected Process Light (PPL) via registry"]
    },
    {
      id: "cs_ransomware", platform: "crowdstrike", icon: "🔒",
      name: "Ransomware / Mass File Encryption",
      desc: "Falcon detects rapid file modification events consistent with ransomware encryption.",
      severity: "critical", mitre: ["T1486","T1490","T1059","T1070"],
      fields: ["alert_id","alert_time","hostname","username","process","files_encrypted_count","extensions_modified","vss_deletion","ransom_note_path","network_shares_impacted","verdict","analyst","notes"],
      triage_steps: ["Immediately network-isolate the affected host","Identify the ransomware family via hash / ransom note / extension","Check if VSS / Shadow Copies were deleted","Scope lateral spread to mapped drives and network shares","Determine initial access vector","Preserve forensic evidence before any remediation"],
      recommendations: ["Isolate all impacted hosts from network immediately","Do NOT restart systems — may destroy evidence","Escalate to senior IR / management immediately","Activate incident response plan and backup recovery procedures","Contact legal and compliance teams"]
    },
    {
      id: "cs_privilege_esc", platform: "crowdstrike", icon: "⬆",
      name: "Privilege Escalation / Token Impersonation",
      desc: "CrowdStrike detects a process attempting to impersonate tokens or exploit a local privilege escalation vulnerability.",
      severity: "high", mitre: ["T1068","T1134","T1548"],
      fields: ["alert_id","alert_time","hostname","username","src_process","target_privilege","technique_detail","cve","verdict","analyst","notes"],
      triage_steps: ["Identify the source process and privilege target","Determine if escalation succeeded (check resulting process token)","Cross-reference CVE if exploit-based","Review subsequent actions taken with elevated privileges","Check for persistence established post-escalation"],
      recommendations: ["Patch the exploited vulnerability immediately","Review and restrict excessive local admin rights","Deploy UAC enforcement and Credential Guard","Reset credentials if account was compromised"]
    },
    {
      id: "ms_impossible_travel", platform: "sentinel", icon: "✈",
      name: "Impossible Travel / Atypical Sign-in Location",
      desc: "Sentinel / Entra ID Protection flags a user signing in from two geographically distant locations within an impossible travel timeframe.",
      severity: "medium", mitre: ["T1078","T1110"],
      fields: ["alert_id","alert_time","username","upn","location_1","location_2","ip_1","ip_2","time_diff_minutes","asn_1","asn_2","user_agent","mfa_status","verdict","analyst","notes"],
      triage_steps: ["Confirm the two sign-in events and calculate travel impossibility","Check if user uses VPN, proxy, or travel frequently","Review IP reputation (VT, AbuseIPDB, Shodan) for both IPs","Contact user to confirm or deny the sign-in","Review all activity performed during the suspicious session","Check for inbox rule modifications or MFA changes"],
      recommendations: ["Revoke all active sessions for the user account","Force password reset and MFA re-enrollment","Block suspicious IP at identity provider if confirmed malicious","Enable Conditional Access policies based on location / risk"]
    },
    {
      id: "ms_brute_force", platform: "sentinel", icon: "🔨",
      name: "Brute Force / Password Spray Attack",
      desc: "Sentinel detects multiple failed authentication attempts against one or more accounts from a single or distributed sources.",
      severity: "medium", mitre: ["T1110.001","T1110.003"],
      fields: ["alert_id","alert_time","target_account","src_ip","src_asn","country","failed_attempts","timespan_minutes","targeted_accounts_count","any_success","successful_account","mfa_status","verdict","analyst","notes"],
      triage_steps: ["Determine if attack is password spray or brute force","Check if any authentication succeeded","Investigate source IP — proxy, botnet, or legitimate infrastructure?","Review successful session activity if any login succeeded","Check for password reuse across other services"],
      recommendations: ["Block attacking IP(s) at firewall / identity provider","Enforce MFA for all targeted accounts","Implement account lockout policies and CAPTCHA on portals","If success: reset password, revoke sessions, review activity"]
    },
    {
      id: "ms_inbox_rule", platform: "sentinel", icon: "📬",
      name: "Suspicious Inbox Manipulation Rule",
      desc: "Sentinel detects an anomalous inbox forwarding or deletion rule created after a suspicious sign-in event.",
      severity: "high", mitre: ["T1114.003","T1078"],
      fields: ["alert_id","alert_time","username","upn","rule_name","rule_action","forward_address","src_ip","sign_in_time","sign_in_ip","mfa_bypass","verdict","analyst","notes"],
      triage_steps: ["Document the exact rule created (name, conditions, actions)","Determine if email is being forwarded externally","Identify the sign-in event associated with the rule creation","Review all mail sent from the account after the rule was created","Check for other BEC indicators"],
      recommendations: ["Delete the malicious inbox rule immediately","Revoke all active sessions and reset credentials","Alert user and relevant managers (potential BEC)","Notify finance/payroll if money transfers may be involved","Implement block on external auto-forwarding at org level"]
    },
    {
      id: "ms_data_exfil", platform: "sentinel", icon: "📤",
      name: "Data Exfiltration / Large SharePoint Download",
      desc: "Sentinel detects anomalously large file downloads or bulk sharing events in SharePoint/OneDrive.",
      severity: "high", mitre: ["T1020","T1078","T1534"],
      fields: ["alert_id","alert_time","username","upn","files_downloaded","total_size_mb","dest_ip","sharepoint_site","src_ip","country","preceded_by_signin_alert","verdict","analyst","notes"],
      triage_steps: ["Identify what data was accessed/downloaded — classify sensitivity","Confirm if the activity was authorized","Review user's recent activity for other anomalies","Identify if the destination IP is personal or corporate","Check if this correlates with a suspicious sign-in or other alerts"],
      recommendations: ["Revoke all sessions and reset credentials","Disable external sharing on implicated SharePoint sites","Notify data owner and DLP/compliance team","Initiate data breach assessment per policy","Implement DLP rules for large-volume downloads"]
    },
    {
      id: "ms_lateral_smb", platform: "sentinel", icon: "↔",
      name: "Lateral Movement via SMB / Pass-the-Hash",
      desc: "Sentinel detects internal SMB authentication events across multiple endpoints from a single source.",
      severity: "high", mitre: ["T1021.002","T1550.002","T1570"],
      fields: ["alert_id","alert_time","src_host","src_ip","dest_hosts","auth_type","account_used","event_ids","timespan","any_success","verdict","analyst","notes"],
      triage_steps: ["Map out all destination hosts contacted from source","Identify authentication type — NTLM (suspicious) vs Kerberos","Check if same hash is being replayed (Pass-the-Hash indicator)","Review NetLogon and Security event logs (4624, 4625, 4648)","Determine initial compromise point on source host"],
      recommendations: ["Isolate source host immediately","Force NTLM restrictions via Group Policy","Reset credentials for involved accounts","Enable SMB signing on all endpoints","Patch any exploitable SMB vulnerabilities"]
    },
    {
      id: "ms_azure_resource", platform: "sentinel", icon: "☁",
      name: "Suspicious Azure Resource Deployment",
      desc: "Sentinel detects unusual or unauthorized Azure resource creation.",
      severity: "high", mitre: ["T1578","T1578.002","T1098"],
      fields: ["alert_id","alert_time","subscription","resource_group","resource_type","resource_name","deploying_user","src_ip","location","mfa_status","verdict","analyst","notes"],
      triage_steps: ["Identify resource type and purpose","Confirm if deployment was authorized by the user","Review the deploying account's recent sign-in activity","Check if any cost spikes are visible in Azure Cost Management","Review deployed resource for malicious workloads"],
      recommendations: ["Delete unauthorized resources immediately","Revoke and rotate all credentials for the account","Review and restrict IAM/RBAC permissions","Enable Azure Defender / Defender for Cloud","Implement Azure Policy to restrict allowed resource types/regions"]
    },
    {
      id: "sp_scheduled_task", platform: "splunk", icon: "⏰",
      name: "Suspicious Scheduled Task Creation (Living-off-the-Land)",
      desc: "Splunk detects Event ID 4698 for a newly created scheduled task using LOLBin tools to download and execute a payload.",
      severity: "high", mitre: ["T1053.005","T1197","T1218"],
      fields: ["alert_id","alert_time","hostname","username","task_name","task_action","task_trigger","process_created_by","cmdline","parent_process","dest_url","verdict","analyst","notes"],
      triage_steps: ["Review the scheduled task command-line for LOLBin abuse","Identify who created the task and from which process","Determine if the task has already executed","Investigate the payload URL/file","Look for related alerts on the same host"],
      recommendations: ["Delete the malicious scheduled task","Block destination URL at proxy/firewall","Restrict scheduled task creation rights via Group Policy","Monitor Event ID 4698 / 4702 for future task creation"]
    },
    {
      id: "sp_webshell", platform: "splunk", icon: "🐚",
      name: "Web Shell Exploitation",
      desc: "Splunk detects a web application spawning a system shell — a strong indicator of web shell upload and active exploitation.",
      severity: "critical", mitre: ["T1505.003","T1059","T1190"],
      fields: ["alert_id","alert_time","hostname","web_server","web_app","src_ip","country","user_agent","web_shell_path","spawn_process","cmdline","files_created","verdict","analyst","notes"],
      triage_steps: ["Confirm web server process spawning unexpected child process","Locate and preserve the web shell file on disk","Identify how the web shell was uploaded","Review all commands executed via the web shell","Check for persistence, data access, or lateral movement indicators","Assess exploited CVE if applicable"],
      recommendations: ["Remove the web shell file immediately and patch the upload vector","Block source IP at WAF and perimeter","Isolate the web server and conduct forensic analysis","Rotate all credentials accessible from the server","Patch exploited vulnerability and harden web application"]
    },
    {
      id: "sp_ssh_brute", platform: "splunk", icon: "🐧",
      name: "Linux SSH Brute Force / Successful Login",
      desc: "Splunk detects a high volume of failed SSH authentication attempts, potentially followed by a successful login.",
      severity: "medium", mitre: ["T1110.001","T1021.004","T1078"],
      fields: ["alert_id","alert_time","hostname","src_ip","country","target_user","failed_count","success","success_time","commands_run","new_users_created","verdict","analyst","notes"],
      triage_steps: ["Confirm if any successful authentication occurred","Review commands executed after successful login","Check /etc/passwd for new accounts, /etc/crontab for persistence","Identify if attacker escalated privileges","Review bash_history for lateral movement or data access"],
      recommendations: ["Block attacking IP at firewall","Disable password-based SSH — enforce key-based authentication","Review and remove unauthorized accounts or cron jobs","If compromised: isolate, rebuild, rotate all keys and credentials"]
    },
    {
      id: "mde_malicious_macro", platform: "defender", icon: "📎",
      name: "Malicious Office Macro Execution",
      desc: "Microsoft Defender for Endpoint detects an Office process spawning a suspicious child process.",
      severity: "high", mitre: ["T1566.001","T1059","T1204.002"],
      fields: ["alert_id","alert_time","hostname","username","parent_process","child_process","cmdline","document_name","document_hash","email_src","verdict","analyst","notes"],
      triage_steps: ["Identify the Office document and whether it came via email","Analyze the macro content if possible (VBA, XLM, Xlm4)","Trace child process execution chain for full payload delivery","Check if payload connected to a C2 or dropped additional files","Pivot to email source to identify other recipients"],
      recommendations: ["Block the document hash and associated email sender","Disable macros by default via Group Policy / Defender Attack Surface Reduction rules","Notify other recipients of the malicious document","Isolate host if payload confirmed executed"]
    },
    {
      id: "mde_defender_exclusion", platform: "defender", icon: "🛑",
      name: "Defender Exclusion / AV Tampering",
      desc: "Defender detects a process adding Windows Defender exclusions or disabling real-time protection.",
      severity: "critical", mitre: ["T1562.001","T1059.001"],
      fields: ["alert_id","alert_time","hostname","username","process","cmdline","exclusion_path","exclusion_extension","av_disabled","verdict","analyst","notes"],
      triage_steps: ["Identify the process that made the AV configuration change","Check parent process — was it spawned by malware or a script?","Review what was excluded and whether malware was already present","Check if other defenses were also disabled","Treat this as active attacker until proven otherwise"],
      recommendations: ["Isolate host immediately","Re-enable Defender and remove exclusions via Intune/Group Policy","Full endpoint investigation — assume compromise","Restrict Defender configuration rights via Tamper Protection"]
    },
    {
      id: "gen_phishing", platform: "generic", icon: "🎣",
      name: "Phishing / Suspicious Email Delivery",
      desc: "A user received an email with malicious links or attachments.",
      severity: "medium", mitre: ["T1566.001","T1566.002","T1598"],
      fields: ["alert_id","alert_time","recipient","sender","sender_domain","subject","attachment_name","attachment_hash","malicious_url","spf_result","dkim_result","dmarc_result","user_clicked","verdict","analyst","notes"],
      triage_steps: ["Analyze email headers for spoofing (SPF/DKIM/DMARC failures)","Inspect attachment in sandbox (AnyRun, Hybrid Analysis, Joe Sandbox)","Check malicious URL in URLScan, VirusTotal, PhishTank","Determine if user clicked link or opened attachment","Identify other recipients in the organization for the same campaign","Review user activity post-click"],
      recommendations: ["Block sender domain and malicious URLs at email gateway and proxy","Delete email from all affected mailboxes","Notify user and conduct phishing awareness","If user clicked: investigate endpoint and potentially isolate","Implement DMARC/DKIM/SPF enforcement"]
    },
    {
      id: "gen_c2_traffic", platform: "generic", icon: "📡",
      name: "Suspicious C2 / Beaconing Network Traffic",
      desc: "Network or endpoint alert detects regular, periodic outbound connections to a suspicious or known-malicious external IP/domain.",
      severity: "high", mitre: ["T1071","T1095","T1571","T1008"],
      fields: ["alert_id","alert_time","hostname","src_ip","dest_ip","dest_domain","dest_port","protocol","beacon_interval","bytes_sent","bytes_recv","process","jitter","verdict","analyst","notes"],
      triage_steps: ["Analyze beacon pattern: interval, jitter, data size","Check dest IP/domain reputation across VT, Shodan, AbuseIPDB","Identify the process making outbound connections","Review DNS queries associated with the domain","Check if HTTPS is used to hide C2 payload content","Scope across environment for same destination"],
      recommendations: ["Block destination IP/domain at all network controls","Isolate affected host","Identify and remove the malicious process/service","Hunt for persistence mechanisms left by the implant"]
    },
    {
      id: "gen_account_compromise", platform: "generic", icon: "👤",
      name: "Account Compromise / Unauthorized Access",
      desc: "General account compromise alert: unexpected login from new device/location, MFA bypass, or user reports unauthorized access.",
      severity: "high", mitre: ["T1078","T1556","T1621"],
      fields: ["alert_id","alert_time","username","upn","src_ip","country","device","auth_method","mfa_bypassed","prior_failed_count","activity_after_login","data_accessed","verdict","analyst","notes"],
      triage_steps: ["Confirm legitimacy of the sign-in with the user","Review all activity performed in the session","Identify if any sensitive data was accessed or modified","Check for post-compromise persistence (new MFA methods, inbox rules, OAuth apps)","Determine initial access method"],
      recommendations: ["Revoke all active sessions immediately","Force password reset and re-enroll MFA","Remove any unauthorized OAuth app grants or MFA methods","Review and revert any configuration changes made during the session","Implement Conditional Access / risk-based authentication"]
    },
    {
      id: "gen_vuln_exploit", platform: "generic", icon: "💥",
      name: "Vulnerability / CVE Exploitation Attempt",
      desc: "IDS/WAF/EDR detects exploitation attempt against a known CVE.",
      severity: "high", mitre: ["T1190","T1203","T1211"],
      fields: ["alert_id","alert_time","target_host","target_service","target_port","cve","src_ip","country","payload_snippet","exploited","rce_confirmed","process_spawned","verdict","analyst","notes"],
      triage_steps: ["Confirm if exploitation was successful or blocked","Identify the CVE and cross-reference patch status on the target","If RCE confirmed: treat as full compromise and investigate process tree","Check src IP for prior scanning/enumeration activity","Scope — are other hosts with same vulnerability also targeted?"],
      recommendations: ["Patch the exploited CVE immediately across all affected assets","If exploited: isolate host, conduct full forensic analysis","Block source IP at perimeter","Apply virtual patching via WAF/IPS until patch is deployed"]
    },
  ];

  const AW_FIELD_LABELS = {
    alert_id:"Alert ID / Ticket #",alert_time:"Alert Timestamp (UTC)",hostname:"Affected Hostname",
    username:"Username",upn:"User Principal Name (UPN)",process:"Malicious Process",cmdline:"Command Line",
    parent_process:"Parent Process",encoded_string:"Encoded String (Base64)",decoded_string:"Decoded String",
    src_ip:"Source IP",dest_ip:"Destination IP",dest_url:"Destination URL",dest_domain:"Destination Domain",
    dest_port:"Destination Port",http_headers:"Suspicious HTTP Headers",beacon_config:"Beacon Config Notes",
    file_path:"File Path",file_hash_sha256:"SHA256 Hash",file_hash_md5:"MD5 Hash",process_tree:"Process Tree",
    verdict_confidence:"Falcon Confidence Score",family:"Malware Family",campaign:"Threat Campaign",
    src_process:"Source Process",access_rights:"Access Rights",lsass_pid:"LSASS PID",
    tool_indicator:"Tool / Technique Indicator",cve:"CVE Reference",files_encrypted_count:"Files Encrypted (count)",
    extensions_modified:"Modified File Extensions",vss_deletion:"VSS / Shadow Copy Deleted?",
    ransom_note_path:"Ransom Note Path",network_shares_impacted:"Network Shares Impacted",
    target_privilege:"Target Privilege Level",technique_detail:"Technique Detail",
    location_1:"Location 1 (IP / Country)",location_2:"Location 2 (IP / Country)",
    ip_1:"IP Address 1",ip_2:"IP Address 2",time_diff_minutes:"Time Between Sign-ins (mins)",
    asn_1:"ASN 1",asn_2:"ASN 2",user_agent:"User-Agent",mfa_status:"MFA Status",
    target_account:"Target Account",src_asn:"Source ASN",country:"Country",
    failed_attempts:"Failed Attempts Count",timespan_minutes:"Timespan (minutes)",
    targeted_accounts_count:"Targeted Accounts Count",any_success:"Any Successful Login?",
    successful_account:"Account that Succeeded",rule_name:"Inbox Rule Name",rule_action:"Rule Action",
    forward_address:"Forward-to Address",sign_in_time:"Associated Sign-in Time",
    sign_in_ip:"Associated Sign-in IP",mfa_bypass:"MFA Bypassed?",files_downloaded:"Files Downloaded (count)",
    total_size_mb:"Total Data Size (MB)",sharepoint_site:"SharePoint Site",
    preceded_by_signin_alert:"Preceded by Suspicious Sign-in?",src_host:"Source Host",
    dest_hosts:"Destination Hosts",auth_type:"Auth Type (NTLM/Kerberos)",account_used:"Account Used",
    event_ids:"Relevant Event IDs",timespan:"Timespan",subscription:"Azure Subscription",
    resource_group:"Resource Group",resource_type:"Resource Type",resource_name:"Resource Name",
    deploying_user:"Deploying User",location:"Deployment Location",task_name:"Scheduled Task Name",
    task_action:"Task Action / Command",task_trigger:"Task Trigger",process_created_by:"Process That Created Task",
    web_server:"Web Server",web_app:"Web Application",web_shell_path:"Web Shell File Path",
    spawn_process:"Spawned Process",files_created:"Files Created on Disk",target_user:"Target Username",
    failed_count:"Failed Attempts",success:"Authentication Succeeded?",success_time:"Success Timestamp",
    commands_run:"Commands Run Post-Login",new_users_created:"New Users/Crons Created?",
    child_process:"Child Process",document_name:"Document Name",document_hash:"Document Hash",
    email_src:"Email Source",exclusion_path:"Exclusion Path Added",exclusion_extension:"Exclusion Extension",
    av_disabled:"AV Disabled?",recipient:"Recipient(s)",sender:"Sender Email",sender_domain:"Sender Domain",
    subject:"Email Subject",attachment_name:"Attachment Name",attachment_hash:"Attachment Hash",
    malicious_url:"Malicious URL",spf_result:"SPF Result",dkim_result:"DKIM Result",dmarc_result:"DMARC Result",
    user_clicked:"User Clicked / Opened?",protocol:"Protocol",beacon_interval:"Beacon Interval (seconds)",
    bytes_sent:"Bytes Sent",bytes_recv:"Bytes Received",jitter:"Jitter",device:"Device / User-Agent",
    auth_method:"Auth Method",mfa_bypassed:"MFA Bypassed?",prior_failed_count:"Prior Failed Count",
    activity_after_login:"Activity After Login",data_accessed:"Data Accessed",target_host:"Target Host",
    target_service:"Target Service",target_port:"Target Port",payload_snippet:"Payload Snippet",
    exploited:"Exploitation Successful?",rce_confirmed:"RCE Confirmed?",
    process_spawned:"Process Spawned After Exploit",verdict:"Analyst Verdict",analyst:"Analyst Name",notes:"Investigation Notes",
  };

  const AW_PLAT_COLORS = {
    crowdstrike: { bg: "rgba(255,57,57,0.12)", border: "rgba(255,57,57,0.30)", text: "#f87171", label: "CrowdStrike Falcon" },
    sentinel:    { bg: "rgba(56,189,248,0.10)", border: "rgba(56,189,248,0.30)", text: "#38bdf8", label: "Microsoft Sentinel" },
    splunk:      { bg: "rgba(251,146,60,0.10)", border: "rgba(251,146,60,0.30)", text: "#fb923c", label: "Splunk" },
    defender:    { bg: "rgba(96,165,250,0.10)", border: "rgba(96,165,250,0.30)", text: "#60a5fa", label: "Microsoft Defender" },
    generic:     { bg: "rgba(167,139,250,0.10)", border: "rgba(167,139,250,0.30)", text: "#a78bfa", label: "Generic SOC" },
  };

  const AW_SEV = {
    critical: { color: "#f87171", label: "CRITICAL" },
    high:     { color: "#fb923c", label: "HIGH" },
    medium:   { color: "#fbbf24", label: "MEDIUM" },
    low:      { color: "#34d399", label: "LOW" },
  };

  let awCurrentTemplate = null;
  let awCurrentOut = "structured";
  let awCurrentPlat = "all";

  function renderAWTemplateList(plat) {
    const list = $("aw-template-list");
    if (!list) return;
    const filtered = plat === "all" ? AW_TEMPLATES : AW_TEMPLATES.filter(t => t.platform === plat);
    list.innerHTML = filtered.map(t => {
      const pc = AW_PLAT_COLORS[t.platform];
      const sev = AW_SEV[t.severity];
      return `<div class="aw-tpl-item${awCurrentTemplate?.id === t.id ? " active" : ""}" data-id="${t.id}" role="button" tabindex="0">
        <span class="aw-tpl-icon">${t.icon}</span>
        <div class="aw-tpl-meta">
          <div class="aw-tpl-name">${t.name}</div>
          <div class="aw-tpl-tags">
            <span class="aw-tpl-plat" style="color:${pc.text};border-color:${pc.border};background:${pc.bg}">${pc.label}</span>
            <span class="aw-tpl-sev" style="color:${sev.color}">${sev.label}</span>
          </div>
        </div>
      </div>`;
    }).join("") || `<div style="padding:16px;font-size:12px;color:var(--muted);text-align:center">No templates for this platform</div>`;

    list.querySelectorAll(".aw-tpl-item").forEach(el => {
      el.addEventListener("click", () => selectAWTemplate(el.dataset.id));
    });
  }

  function selectAWTemplate(id) {
    awCurrentTemplate = AW_TEMPLATES.find(t => t.id === id);
    if (!awCurrentTemplate) return;

    document.querySelectorAll(".aw-tpl-item").forEach(el => {
      el.classList.toggle("active", el.dataset.id === id);
    });

    const pc = AW_PLAT_COLORS[awCurrentTemplate.platform];
    const sev = AW_SEV[awCurrentTemplate.severity];
    const ti = $("aw-template-info");
    if (ti) {
      $("aw-ti-icon").textContent = awCurrentTemplate.icon;
      $("aw-ti-name").textContent = awCurrentTemplate.name;
      $("aw-ti-plat").innerHTML = `<span style="color:${pc.text}">${pc.label}</span> &nbsp;·&nbsp; <span style="color:${sev.color}">${sev.label}</span>`;
      $("aw-ti-desc").textContent = awCurrentTemplate.desc;
      $("aw-ti-mitre").innerHTML = awCurrentTemplate.mitre.map(t =>
        `<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="sa-mitre-tag">${t}</a>`
      ).join("");
      ti.style.display = "block";
    }

    const form = $("aw-form");
    if (form) {
      form.innerHTML = `
        <div class="aw-form-grid">
          ${awCurrentTemplate.fields.map(f => `
            <div class="aw-field">
              <label class="aw-label">${AW_FIELD_LABELS[f] || f}</label>
              ${f === "notes" ? `<textarea id="awf_${f}" class="aw-input aw-textarea" placeholder="${AW_FIELD_LABELS[f] || f}..." rows="3"></textarea>`
                : `<input id="awf_${f}" class="aw-input" type="text" placeholder="${AW_FIELD_LABELS[f] || f}..." autocomplete="off" spellcheck="false">`}
            </div>`).join("")}
        </div>`;
    }

    const bar = $("aw-action-bar");
    if (bar) bar.style.display = "flex";
    const out = $("aw-output");
    if (out) out.style.display = "none";
  }

  function getAWFormData() {
    if (!awCurrentTemplate) return {};
    const data = {};
    awCurrentTemplate.fields.forEach(f => {
      const el = $(`awf_${f}`);
      data[f] = el ? el.value.trim() : "";
    });
    return data;
  }

  function getAWField(data, key, fallback = "[not provided]") {
    return data[key] || fallback;
  }

  function generateAWReport(data, mode) {
    const t = awCurrentTemplate;
    const pc = AW_PLAT_COLORS[t.platform];
    const sev = AW_SEV[t.severity];
    const now = new Date().toISOString();
    const analyst = getAWField(data, "analyst", "SOC Analyst");

    if (mode === "structured") {
      return [
        "═══════════════════════════════════════════════════════════",
        `  SECURITY ALERT INVESTIGATION REPORT`,
        "═══════════════════════════════════════════════════════════",
        `Alert Name   : ${t.name}`,
        `Platform     : ${pc.label}`,
        `Severity     : ${sev.label}`,
        `Alert ID     : ${getAWField(data, "alert_id")}`,
        `Alert Time   : ${getAWField(data, "alert_time")}`,
        `Report Time  : ${now}`,
        `Analyst      : ${analyst}`,
        `Verdict      : ${getAWField(data, "verdict", "PENDING")}`,
        "",
        "───────────────────────────────────────────────────────────",
        "ALERT DESCRIPTION",
        "───────────────────────────────────────────────────────────",
        t.desc,
        "",
        "───────────────────────────────────────────────────────────",
        "KEY INDICATORS / IOCs",
        "───────────────────────────────────────────────────────────",
        ...t.fields.filter(f => !["verdict","analyst","notes"].includes(f)).map(f => {
          const val = data[f];
          if (!val) return null;
          return `  ${(AW_FIELD_LABELS[f] || f).padEnd(35)} : ${val}`;
        }).filter(Boolean),
        "",
        "───────────────────────────────────────────────────────────",
        "MITRE ATT&CK TECHNIQUES",
        "───────────────────────────────────────────────────────────",
        ...t.mitre.map(m => `  ${m.padEnd(14)} ${getMitreName(m)}`),
        "",
        "───────────────────────────────────────────────────────────",
        "TRIAGE STEPS PERFORMED",
        "───────────────────────────────────────────────────────────",
        ...t.triage_steps.map((s, i) => `  ${i + 1}. ${s}`),
        "",
        "───────────────────────────────────────────────────────────",
        "RECOMMENDATIONS",
        "───────────────────────────────────────────────────────────",
        ...t.recommendations.map((r, i) => `  ${i + 1}. ${r}`),
        "",
        "───────────────────────────────────────────────────────────",
        "ANALYST NOTES",
        "───────────────────────────────────────────────────────────",
        `  ${getAWField(data, "notes", "No additional notes.")}`,
        "",
        "═══════════════════════════════════════════════════════════",
        "END OF REPORT",
        "═══════════════════════════════════════════════════════════",
      ].join("\n");
    }

    if (mode === "ticket") {
      const host = getAWField(data, "hostname", getAWField(data, "target_host", "N/A"));
      const user = getAWField(data, "username", getAWField(data, "upn", "N/A"));
      return [
        `[${sev.label}] ${t.name}`,``,
        `Alert ID : ${getAWField(data, "alert_id")} | ${getAWField(data, "alert_time")}`,
        `Platform : ${pc.label} | Analyst: ${analyst}`,
        `Host     : ${host} | User: ${user}`,
        `Verdict  : ${getAWField(data, "verdict", "PENDING")}`,``,
        `SUMMARY`,`${t.desc}`,``,`KEY IOCs`,
        ...t.fields.filter(f => ["src_ip","dest_ip","dest_url","file_hash_sha256","cmdline","process","sender","malicious_url","cve"].includes(f)).map(f => {
          const val = data[f]; return val ? `- ${AW_FIELD_LABELS[f]}: ${val}` : null;
        }).filter(Boolean),``,
        `MITRE: ${t.mitre.join(" | ")}`,``,`NEXT STEPS`,
        ...t.recommendations.slice(0, 3).map((r, i) => `${i + 1}. ${r}`),``,
        `NOTES: ${getAWField(data, "notes", "N/A")}`,
      ].join("\n");
    }

    if (mode === "exec") {
      const sev_desc = { critical: "requires immediate executive attention and incident response activation", high: "requires urgent investigation and containment", medium: "requires timely investigation by the security team", low: "is informational and under routine review" };
      return [
        `EXECUTIVE SECURITY ALERT SUMMARY`,``,
        `Date     : ${getAWField(data, "alert_time", now)}`,
        `Severity : ${sev.label}`,
        `Prepared by: ${analyst}`,``,
        `WHAT HAPPENED`,
        `Our security monitoring platform (${pc.label}) detected a ${t.name.toLowerCase()} alert that ${sev_desc[t.severity] || "requires investigation"}.`,``,
        `AFFECTED SYSTEMS`,
        `  - Host   : ${getAWField(data, "hostname", getAWField(data, "target_host", "Under Investigation"))}`,
        `  - User   : ${getAWField(data, "username", getAWField(data, "upn", "Under Investigation"))}`,``,
        `WHAT THIS MEANS`,`${t.desc}`,``,
        `CURRENT STATUS`,
        `Analyst Verdict: ${getAWField(data, "verdict", "Investigation In Progress")}`,``,
        `IMMEDIATE ACTIONS RECOMMENDED`,
        ...t.recommendations.slice(0, 3).map((r, i) => `  ${i + 1}. ${r}`),``,
        `This summary is based on initial findings. A full technical report is available upon request.`,
      ].join("\n");
    }

    return "";
  }

  document.querySelectorAll(".aw-plat-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".aw-plat-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      awCurrentPlat = btn.dataset.plat;
      renderAWTemplateList(awCurrentPlat);
    });
  });

  document.querySelectorAll(".aw-out-tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".aw-out-tab").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      awCurrentOut = btn.dataset.out;
    });
  });

  const awGenerateBtn = $("aw-generate-btn");
  if (awGenerateBtn) {
    awGenerateBtn.addEventListener("click", () => {
      if (!awCurrentTemplate) return;
      const data = getAWFormData();
      const report = generateAWReport(data, awCurrentOut);
      const out = $("aw-output");
      const outText = $("aw-output-text");
      if (out && outText) {
        outText.textContent = report;
        out.style.display = "block";
        out.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  }

  const awCopyBtn = $("aw-copy-btn");
  if (awCopyBtn) {
    awCopyBtn.addEventListener("click", async () => {
      const outText = $("aw-output-text");
      if (!outText || !outText.textContent.trim()) {
        const data = getAWFormData();
        if (!awCurrentTemplate) return;
        const report = generateAWReport(data, awCurrentOut);
        try { await navigator.clipboard.writeText(report); } catch {}
        return;
      }
      try { await navigator.clipboard.writeText(outText.textContent); } catch {}
    });
  }

  const awClearBtn = $("aw-clear-btn");
  if (awClearBtn) {
    awClearBtn.addEventListener("click", () => {
      document.querySelectorAll(".aw-input").forEach(el => { el.value = ""; });
      const out = $("aw-output");
      if (out) out.style.display = "none";
    });
  }

  // Init
  loadCaseFromStorage();
  renderAWTemplateList("all");
  syncSearchboxState();
  setSearchMode(false);
  setLandingLinks();
  renderCardMeta();
  setStatus("Status: ready (landing page)");
  renderHistory();
  renderCaseBody();
  updateCaseIndicator();
  renderTimeline();
  renderCustomTools();
  // Set default datetime for timeline
  const tlTimeInput = $("tl-time-input");
  if (tlTimeInput) {
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    tlTimeInput.value = now.toISOString().slice(0,16);
  }
});
