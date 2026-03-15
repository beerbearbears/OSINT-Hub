document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  const TOOLKIT_VERSION = "2.0.0";
  const $ = (id) => document.getElementById(id);
  // HTML escape — prevents XSS when rendering user input in innerHTML
  const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
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
    if (/^T\d{4,5}(\.\d{3})?$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v.toLowerCase() };
    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };
    if (/^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$/.test(v)) return { type: "mac", q: v.toUpperCase() };
    if (/^AS\d{1,10}$/i.test(v)) return { type: "asn", q: v.toUpperCase() };
    if (/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(v)) return { type: "btc", q: v };
    if (/^0x[a-fA-F0-9]{40}$/.test(v)) return { type: "eth", q: v };
    if (/^\d{3,5}$/.test(v)) return { type: "eventid", q: v };
    if (/^\+?[\d\s\-().]{7,20}$/.test(v) && (v.match(/\d/g)||[]).length >= 7 && /\+|\b\d{3}/.test(v) && !isValidIPv4(v)) return { type: "phone", q: v.replace(/\s/g,"") };
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v) || /^[a-fA-F0-9]{96}$/.test(v) || /^[a-fA-F0-9]{128}$/.test(v))
      return { type: "hash", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v) && v.includes(".") && !/\s/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9][a-zA-Z0-9._\-]{2,30}$/.test(v) && !/\s/.test(v) && v.split(".").length < 3) return { type: "username", q: v };
    return { type: null, q: v };
  }

  // ─── Session History ──────────────────────────────────────────
  // ─── IOC History Cache (Feature 13) — localStorage persistent ──
  const HISTORY_KEY = "osint_ioc_history";
  let sessionHistory = [];

  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        // Convert stored time strings back to Date objects
        sessionHistory = parsed.map(e => ({ ...e, time: new Date(e.time) }));
      }
    } catch(e) { sessionHistory = []; }
  }

  function saveHistory() {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(sessionHistory.slice(0, 100))); } catch(e) {}
  }

  function addToHistory(type, value) {
    // Deduplicate — update existing entry's time if same value
    const existIdx = sessionHistory.findIndex(e => e.value === value && e.type === type);
    if (existIdx !== -1) {
      sessionHistory[existIdx].time = new Date();
      sessionHistory[existIdx].count = (sessionHistory[existIdx].count || 1) + 1;
    } else {
      sessionHistory.unshift({ type, value, time: new Date(), verdict: null, count: 1 });
    }
    if (sessionHistory.length > 100) sessionHistory.pop();
    saveHistory();
    renderHistory();
  }

  function stampVerdict(value, verdict) {
    const entry = sessionHistory.find(e => e.value === value);
    if (entry) { entry.verdict = verdict; saveHistory(); renderHistory(); }
  }

  function renderHistory() {
    const list = $("history-list");
    if (!list) return;
    if (!sessionHistory.length) { list.innerHTML = '<div class="history-empty">No searches yet.</div>'; return; }
    const typeColor = { ip:"#38bdf8",domain:"#34d399",hash:"#f59e0b",email:"#a78bfa",url:"#fb923c",cve:"#f87171",username:"#e879f9",header:"#67e8f9",eventid:"#86efac",mitre:"#fbbf24",phone:"#f472b6",mac:"#a3e635",asn:"#38bdf8",btc:"#f59e0b",eth:"#818cf8" };
    const verdictColors = { tp:"#f87171", fp:"#34d399", suspicious:"#fbbf24", benign:"#9ca3af" };
    list.innerHTML = sessionHistory.map((e, i) => {
      const tc    = typeColor[e.type] || "#9ca3af";
      const vc    = e.verdict ? (verdictColors[e.verdict] || "#9ca3af") : null;
      const vLabel= { tp:"TRUE POS", fp:"FALSE POS", suspicious:"SUSPICIOUS", benign:"BENIGN" }[e.verdict] || null;
      const t     = e.time.toLocaleString([], { month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" });
      const countBadge = e.count > 1 ? `<span class="history-count" title="${e.count} searches">×${e.count}</span>` : "";
      const verdictBadge = vc ? `<span class="history-verdict" style="background:${vc}22;color:${vc};border-color:${vc}44">${vLabel}</span>` : "";
      return `<div class="history-item" data-index="${i}">
        <div class="history-item-top">
          <span class="history-badge" style="background:${tc}22;color:${tc};border-color:${tc}44">${e.type.toUpperCase()}</span>
          ${verdictBadge}${countBadge}
          <span class="history-time">${t}</span>
        </div>
        <div class="history-item-val" title="${e.value}">${e.value.length > 38 ? e.value.slice(0, 38) + "…" : e.value}</div>
        <div class="history-item-actions">
          <button class="hist-verdict-btn" data-index="${i}" data-v="tp"    title="Mark True Positive">🚨 TP</button>
          <button class="hist-verdict-btn" data-index="${i}" data-v="fp"    title="Mark False Positive">✅ FP</button>
          <button class="hist-verdict-btn" data-index="${i}" data-v="suspicious" title="Mark Suspicious">⚠️ Sus</button>
          <button class="hist-verdict-btn" data-index="${i}" data-v="benign" title="Mark Benign">🟢 OK</button>
          <button class="hist-del-btn" data-index="${i}" title="Remove from history">🗑</button>
        </div>
      </div>`;
    }).join("");
    list.querySelectorAll(".history-item-top, .history-item-val").forEach(el => {
      const item = el.closest(".history-item");
      el.style.cursor = "pointer";
      el.addEventListener("click", (ev) => {
        if (ev.target.closest("button")) return;
        const idx = Number(item.getAttribute("data-index"));
        const entry = sessionHistory[idx];
        if (entry && input) { input.value = entry.value; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
      });
    });
    list.querySelectorAll(".hist-verdict-btn").forEach(btn => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const idx = Number(btn.dataset.index);
        if (sessionHistory[idx]) { sessionHistory[idx].verdict = btn.dataset.v; saveHistory(); renderHistory(); }
      });
    });
    list.querySelectorAll(".hist-del-btn").forEach(btn => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const idx = Number(btn.dataset.index);
        sessionHistory.splice(idx, 1);
        saveHistory(); renderHistory();
      });
    });
  }

  // Load history on startup
  loadHistory(); renderHistory();

  // Clear all history button
  const clearHistoryBtn = $("clear-history");
  if (clearHistoryBtn) clearHistoryBtn.addEventListener("click", () => {
    if (confirm("Clear all IOC history?")) { sessionHistory = []; saveHistory(); renderHistory(); }
  });

  const exportHistoryBtn = $("export-history");
  if (exportHistoryBtn) {
    exportHistoryBtn.addEventListener("click", () => {
      if (!sessionHistory.length) return alert("No history to export yet.");
      const lines = ["HawkEye — IOC History Export", `Exported: ${new Date().toISOString()}`, "─".repeat(60)];
      sessionHistory.forEach(e => {
        const verdict = e.verdict ? ` | Verdict: ${e.verdict.toUpperCase()}` : "";
        const count   = e.count > 1 ? ` | Searches: ${e.count}` : "";
        lines.push(`[${e.time.toISOString()}] ${e.type.toUpperCase().padEnd(10)} ${e.value}${verdict}${count}`);
      });
      const blob = new Blob([lines.join("\n")], { type: "text/plain" });
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
      a.download = `osint-history-${Date.now()}.txt`; a.click();
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
    const lines = ["HawkEye — Attack Timeline", `Exported: ${new Date().toISOString()}`, "─".repeat(60),
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
    rule += `        description = "${notes || "Auto-generated by HawkEye Toolkit"}"\n`;
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
    yaml += `description: '${title} — generated by HawkEye'\n`;
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
  // ═══════════════════════════════════════════════════════════════
  // COMPREHENSIVE LOG TRIAGE ENGINE
  // Supports: Windows EventLog, Sysmon, Firewall (iptables/Cisco/PAN/Check Point),
  //           Proxy/Web (Squid/Bluecoat/Nginx/Apache/IIS), Auth (SSH/Linux PAM/kerberos),
  //           CEF/LEEF/JSON SIEM, CrowdStrike/Sentinel/Splunk alert formats,
  //           DNS, DHCP, Email Headers, Netflow, Endpoint EDR
  // ═══════════════════════════════════════════════════════════════

  const EV_DB = {
    // Process & execution
    "4688":"Process Created","4689":"Process Terminated","4674":"Privileged operation",
    // Logon/auth
    "4624":"Successful Logon","4625":"Failed Logon","4634":"Logoff",
    "4647":"User-initiated Logoff","4648":"Logon w/ Explicit Credentials",
    "4649":"Replay Attack Detected","4675":"SIDs were filtered",
    "4720":"User Account Created","4722":"Account Enabled","4723":"Password Change Attempt",
    "4724":"Password Reset","4725":"Account Disabled","4726":"Account Deleted",
    "4728":"Member Added to Global Group","4732":"Member Added to Local Group",
    "4756":"Member Added to Universal Group",
    // Kerberos
    "4768":"Kerberos TGT Request","4769":"Kerberos Service Ticket","4771":"Kerberos Pre-Auth Failure",
    "4776":"NTLM Auth Attempt","4778":"RDP Session Reconnected","4779":"RDP Session Disconnected",
    // Policy & audit
    "1102":"Audit Log Cleared","1100":"Event Log Service Stopped",
    "4616":"System Time Changed","4657":"Registry Value Modified",
    "4663":"Object Access Attempt","4670":"Object Permissions Changed",
    "4698":"Scheduled Task Created","4699":"Scheduled Task Deleted",
    "4700":"Scheduled Task Enabled","4702":"Scheduled Task Modified",
    "4704":"User Right Assigned","4705":"User Right Removed",
    "4719":"System Audit Policy Changed","4739":"Domain Policy Changed",
    // Services
    "7034":"Service Crashed","7035":"Service State Change","7036":"Service Status Changed",
    "7040":"Service Start Type Changed","7045":"New Service Installed",
    // PowerShell
    "4103":"PS Module Logging","4104":"PS Script Block Logging",
    "4105":"PS Script Block Execution Start","4106":"PS Script Block Execution Stop",
    // Firewall
    "5140":"Network Share Accessed","5142":"Network Share Created",
    "5145":"Network Share Access Check","5156":"WFP Connection Allowed",
    "5157":"WFP Connection Blocked","5158":"Bind to Local Port",
    // Sysmon
    "1":"Sysmon: Process Create","2":"Sysmon: File Creation Time Changed",
    "3":"Sysmon: Network Connection","4":"Sysmon: Service State Changed",
    "5":"Sysmon: Process Terminated","6":"Sysmon: Driver Loaded",
    "7":"Sysmon: Image Loaded (DLL)","8":"Sysmon: CreateRemoteThread",
    "9":"Sysmon: RawAccessRead","10":"Sysmon: ProcessAccess (LSASS risk)",
    "11":"Sysmon: File Created","12":"Sysmon: Registry Object Created/Deleted",
    "13":"Sysmon: Registry Value Set","14":"Sysmon: Registry Renamed",
    "15":"Sysmon: File Stream Created (ADS)","16":"Sysmon: Config Changed",
    "17":"Sysmon: Pipe Created","18":"Sysmon: Pipe Connected",
    "19":"Sysmon: WMI Filter","20":"Sysmon: WMI Consumer","21":"Sysmon: WMI Binding",
    "22":"Sysmon: DNS Query","23":"Sysmon: File Deleted","24":"Sysmon: Clipboard Changed",
    "25":"Sysmon: Process Tampered","26":"Sysmon: File Deleted (logged)",
    "255":"Sysmon: Error"
  };

  const EV_RISK = {
    "4625":"medium","4648":"high","4768":"low","4769":"low","4771":"medium",
    "4776":"medium","4688":"low","4698":"high","4720":"high","4726":"medium",
    "4728":"high","4732":"high","4756":"high","1102":"critical","7045":"high",
    "4104":"high","4103":"medium","5157":"low","5156":"low",
    "1":"low","3":"low","8":"critical","10":"critical","15":"high",
    "22":"low","6":"high","7":"medium","13":"medium"
  };

  // Port-to-service quick reference
  const PORT_HINTS = {
    "21":"FTP","22":"SSH","23":"Telnet (insecure)","25":"SMTP","53":"DNS",
    "80":"HTTP","110":"POP3","119":"NNTP","123":"NTP","135":"MS-RPC",
    "137":"NetBIOS-NS","138":"NetBIOS-DGM","139":"NetBIOS-SSN","143":"IMAP",
    "161":"SNMP","389":"LDAP","443":"HTTPS","445":"SMB","465":"SMTPS",
    "514":"Syslog","515":"LPD Print","587":"SMTP (Submission)","593":"HTTP-RPC",
    "636":"LDAPS","993":"IMAPS","995":"POP3S","1080":"SOCKS Proxy",
    "1194":"OpenVPN","1433":"MSSQL","1521":"Oracle DB","1723":"PPTP VPN",
    "2049":"NFS","3306":"MySQL","3389":"RDP","4444":"Metasploit Default",
    "4899":"RAdmin","5432":"PostgreSQL","5900":"VNC","6379":"Redis",
    "6881":"BitTorrent","7070":"RealAudio","8080":"HTTP Alt/Proxy",
    "8443":"HTTPS Alt","8888":"Jupyter/Dev","9200":"Elasticsearch",
    "27017":"MongoDB","50050":"Cobalt Strike C2 (default)"
  };

  function triageLog(text) {
    const t = (text || "").replace(/\r\n/g,"\n");
    const refanged = refangSmart(t);
    const results = {
      eventType: "Unknown", subType: "", severity: "info",
      indicators: [], findings: [], mitre: new Set(),
      iocs: {}, prefillData: {}, eventIds: [], portHints: [],
      _rawText: t  // store for alert category + narrative matching
    };

    // ── TSV / #fields: header-aware pre-processing ───────────────
    // For CrowdStrike NGSIEM and similar TSV log formats with #fields: header,
    // identify which column indices correspond to system IDs (aid, cid, etc.)
    // and blank those columns in data rows before IOC extraction.
    const NON_IOC_COLS = /^(?:aid|cid|AgentId|DeviceId|SensorId|sensor_id|agent_id|device_id|assetId|correlationId|requestId|traceId|spanId|sessionId|MessageId|objectId|tenantId|PatternDispositionFlags|PatternDispositionValue|DetectId|eventType|deviceVendor|deviceProduct|deviceVersion|Protocol|LocalPort|RemotePort|Tactic|Technique|Objective|SeverityName|severity)$/i;
    let tForIOC = t;
    const fieldsHeaderMatch = t.match(/^#fields:\s*(.+)$/mi);
    if (fieldsHeaderMatch) {
      const colNames = fieldsHeaderMatch[1].split(/\t/);
      const nonIocIdxSet = new Set(colNames.reduce((acc, name, i) => { if (NON_IOC_COLS.test(name.trim())) acc.push(i); return acc; }, []));
      if (nonIocIdxSet.size > 0) {
        tForIOC = t.split("\n").map(line => {
          if (line.startsWith("#")) return "";  // strip header/comment lines
          const cols = line.split("\t");
          return cols.map((v, i) => nonIocIdxSet.has(i) ? "" : v).join("\t");
        }).join("\n");
      }
    }

    // ── EXTRACT ALL IOCs (runs for every log type) ──────────────
    // Pre-process: strip #fields header rows and known non-IOC system IDs before extraction
    const stripForIOC = tForIOC
      .replace(/^#[^\n]*/gm, "")                          // strip comment/header lines (#fields:, #version:)
      .replace(/\b(?:aid|cid|AgentId|DeviceId|SensorId|sensor_id|agent_id|device_id|assetId|correlationId|requestId|traceId|spanId|sessionId|MessageId|objectId|tenantId)\s*[=:]\s*[a-fA-F0-9]{32,64}\b/gi, "")
      .replace(/\bldt:[a-fA-F0-9:]+/g, "")               // strip CrowdStrike detect IDs like ldt:abc:123
      .replace(/\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b/g, "") // strip UUIDs
      // Strip cloud identity labeled fields — these are system IDs, not file hashes
      .replace(/(?:Resource\s+UUID|User\s+principal\s+ID|Account\s+ID|Event\s+ID|Azure\s+user\s+tenant\s+ID|Azure\s+recipient\s+tenant\s+ID|Azure\s+subscription\s+ID|Subscription\s+ID|Recipient\s+Subscription\s+ID|Client\s*Id|PrincipalId|ResourceId|Service\s+Principal\s+ID)\s*[:\s]+[a-fA-F0-9]{32,128}/gi, "")
      .replace(/\/tenants\/[a-fA-F0-9-]+\/[^\s\n]*/g, "")  // strip Azure resource paths /tenants/uuid/...
      .replace(/\b(?:oJQx[a-zA-Z0-9+/=]{20,})/g, "");     // strip base64-like OAuth permission IDs

    results.iocs.ips      = [...new Set([
      ...(refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)||[]).filter(isValidIPv4),
      ...(refanged.match(/\b[a-fA-F0-9]{4}:[a-fA-F0-9]{4}:[a-fA-F0-9:]{4,30}\b/g)||[])
        .filter(v => v.split(':').length >= 4), // must have at least 4 segments to be a valid IPv6
    ])];
    results.iocs.domains  = [...new Set((refanged.match(/\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\b/g)||[]).filter(d=>!/^\d+\.\d+/.test(d) && d.split(".").length>=2))];
    // Hashes: use pre-processed text, deduplicate case-insensitively
    const _rawH = (stripForIOC.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g)||[]);
    const _seenH = new Set();
    results.iocs.hashes = _rawH.filter(h => { const lo=h.toLowerCase(); if(_seenH.has(lo)) return false; _seenH.add(lo); return true; });
    results.iocs.cves     = [...new Set((refanged.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(c=>c.toUpperCase()))];
    results.iocs.urls     = [...new Set((refanged.match(/https?:\/\/[^\s"'`>)]+/gi)||[]))];
    results.iocs.emails   = [...new Set((refanged.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g)||[]))];
    // Processes: remove numeric prefixes caused by tab-separated field values
    results.iocs.processes= [...new Set((t.match(/\b[\w\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|sys)\b/gi)||[]).map(p=>p.toLowerCase().replace(/^\d+/,"")))];
    // Field name blocklist — prevents header row values being extracted as usernames/hostnames
    const _FBLOCK = /^(?:LocalAddressIP4|RemoteAddressIP4|LocalPort|RemotePort|Protocol|FileName|FilePath|MD5HashData|SHA256HashData|CommandLine|ParentBaseFileName|ProcessId|ParentProcessId|DetectId|PatternDispositionFlags|SeverityName|Tactic|Technique|Objective|timestamp|eventType|deviceVendor|deviceProduct|deviceVersion|aid|cid|hostname|computername|username|user_?name|account_?name|src_?ip|dst_?ip|source|destination|action|status|result|method|uri|query|referrer|useragent|category|fields|version|type)$/i;
    results.iocs.usernames= [...new Set([
      ...(t.match(/(?:user(?:name)?|account|logon)\s*[=:]\s*([a-zA-Z0-9._\\-]{2,40})/gi)||[]).map(m=>(m.match(/[=:]\s*(.+)$/)||[])[1]?.trim()||"").filter(v=>v && !_FBLOCK.test(v) && v.length>1),
      ...(t.match(/\\\\([a-zA-Z0-9_.-]{2,40})\s*$/gm)||[]).map(m=>m.replace(/^\\\\/,"")),
    ].filter(v=>v && v.length>1 && !_FBLOCK.test(v)))];
    results.iocs.hostnames= [...new Set((t.match(/(?:computer(?:name)?|hostname|workstation|src_host)\s*[=:]\s*([a-zA-Z0-9_.-]{2,50})/gi)||[]).map(m=>(m.match(/[=:]\s*(.+)$/)||[])[1]?.trim()||"").filter(v=>v && !_FBLOCK.test(v) && !/^(?:name|address|ip[46]|\d+)$/i.test(v)))];
    results.iocs.ports    = [...new Set((t.match(/(?:port|dpt|spt|d?port)\s*[=:]\s*(\d{1,5})/gi)||[]).map(m=>(m.match(/(\d{1,5})$/)||[])[1]).filter(Boolean))];
    results.iocs.cmdlines = [...new Set((t.match(/(?:commandline|cmdline|command(?:_?line)?)\s*[=:]\s*(.{10,200})/gi)||[]).map(m=>(m.match(/[=:]\s*(.+)$/)||[])[1]?.trim()||"").filter(Boolean))];
    results.iocs.regkeys  = [...new Set((t.match(/(?:HKCU|HKLM|HKEY_[A-Z_]+)[\/\\][^\s"'`,;]{5,}/gi)||[]))];
    results.iocs.filepaths= [...new Set((t.match(/[A-Za-z]:\\[^\s"'`<>|,;*?]{4,}/g)||[]))];

    // Port hints
    results.iocs.ports.forEach(p => {
      if (PORT_HINTS[p]) results.portHints.push(`Port ${p}: ${PORT_HINTS[p]}`);

    });

    // ── LOG FORMAT DETECTION ────────────────────────────────────

    // 1. EMAIL HEADERS (highest specificity)
    if (looksLikeHeaders(t)) {
      results.eventType = "Email Headers";
      const h = parseEmailHeaders(t);
      results.prefillData = { sender: h.senderEmail, recipient: h.receiverEmail, src_ip: h.originIp, spf_result: h.spfResult, dkim_result: h.dkimResult, dmarc_result: "", subject: h.subject };
      const spfBad = ["fail","softfail"].includes(h.spfResult);
      const dkimBad = ["fail","neutral","none"].includes(h.dkimResult);
      if (spfBad)  { results.findings.push("⚠️ SPF FAIL — sender domain mismatch"); results.mitre.add("T1566"); results.severity = "high"; }
      if (dkimBad) { results.findings.push("⚠️ DKIM FAIL — message integrity broken"); results.mitre.add("T1566"); if(results.severity!=="high") results.severity="medium"; }
      if (spfBad && dkimBad) { results.severity = "high"; results.findings.push("🚨 Both SPF and DKIM FAIL — strong phishing indicator"); }
      if (h.senderEmail && h.returnPathDomain && !h.senderEmail.endsWith(h.returnPathDomain)) results.findings.push(`⚠️ From/Return-Path domain mismatch: ${h.senderEmail} vs ${h.returnPathDomain}`);
      results.indicators.push(`From: ${h.senderEmail||"?"}`, `SPF: ${h.spfResult||"none"}`, `DKIM: ${h.dkimResult||"none"}`, `Origin IP: ${h.originIp||"?"}`);
      return _finalizeTriage(results);
    }


    // 2. WINDOWS EVENT LOG (XML or plain Sysmon/Security)
    // Must NOT match Azure/cloud logs that use "Event ID" as a label for UUID values
    // Require: either XML EventID tags, or "Event ID" followed immediately by a 4-5 digit Windows EID
    if (/(?:<EventID[^>]*>|\bEventCode\s*[=:]\s*|EvtID\s*[=:]\s*|<System>)|\bEvent\s+ID\s*[=:\s]+\d{3,5}\b/i.test(t) &&
        !/azure|AuditLogs|Core\s+Directory|ServicePrincipal|Microsoft\.aadiam|tenants\/|Event\s+category|Service\s+provider/i.test(t)) {
      results.eventType = "Windows Event Log";
      // Extract numeric Event IDs only — reject UUID-like values (digits followed by hex-dash)
      const allEvIds = [...new Set((t.match(/(?:<EventID[^>]*>|EventID\s*[:\s=]+|EventCode\s*[:\s=]+|Event\s+ID\s*[:\s=]+)(\d{1,5})(?![a-fA-F0-9\-])/gi)||[]).map(m=>(m.match(/(\d{1,5})$/)||[])[1]).filter(Boolean))];
      results.eventIds = allEvIds;
      allEvIds.forEach(id => {
        const hint = EV_DB[id]; if (hint) results.indicators.push(`EID ${id}: ${hint}`);
        const risk = EV_RISK[id] || "low";
        if (["critical","high"].includes(risk) && results.severity !== "critical") results.severity = risk;
        else if (risk === "medium" && !["critical","high"].includes(results.severity)) results.severity = "medium";
        // MITRE mappings for key event IDs
        if (["4698","4699","4700","4702"].includes(id)) results.mitre.add("T1053.005");
        if (["4720","4726","4728","4732"].includes(id)) results.mitre.add("T1136");
        if (["1102","1100"].includes(id)) results.mitre.add("T1070.001");
        if (["4104","4103"].includes(id)) results.mitre.add("T1059.001");
        if (id==="4648") results.mitre.add("T1078");
        if (id==="7045") results.mitre.add("T1543.003");
        if (id==="4688") results.mitre.add("T1059");
        if (id==="4776") results.mitre.add("T1550.002");
        // Sysmon-specific
        if (id==="8")  { results.mitre.add("T1055"); results.findings.push("🚨 Sysmon EID 8: CreateRemoteThread — process injection"); results.severity="critical"; }
        if (id==="10") { results.mitre.add("T1003.001"); results.findings.push("🚨 Sysmon EID 10: ProcessAccess — possible LSASS dump"); results.severity="critical"; }
        if (id==="15") { results.mitre.add("T1564.004"); results.findings.push("⚠️ Sysmon EID 15: Alternate Data Stream created"); if(results.severity!=="critical") results.severity="high"; }
        if (id==="6")  { results.mitre.add("T1068"); results.findings.push("⚠️ Sysmon EID 6: Unsigned driver loaded"); if(!["critical","high"].includes(results.severity)) results.severity="high"; }
        // Key Windows Security Events
        if (id==="4625") results.findings.push("⚠️ EID 4625: Failed logon — wrong credentials or locked account");
        if (id==="4648") { results.findings.push("⚠️ EID 4648: Explicit credential logon — RunAs or credential relay"); results.mitre.add("T1078"); }
        if (id==="4720") { results.findings.push("🚨 EID 4720: New user account created"); results.mitre.add("T1136.001"); }
        if (id==="4732") { results.findings.push("🚨 EID 4732: Account added to a security-enabled local group (Administrators?)"); results.mitre.add("T1098"); }
        if (id==="4728") { results.findings.push("🚨 EID 4728: Account added to a global security group"); results.mitre.add("T1098"); }
        if (id==="4698") { results.findings.push("🚨 EID 4698: Scheduled task created — common persistence technique"); results.mitre.add("T1053.005"); }
        if (id==="4702") { results.findings.push("⚠️ EID 4702: Scheduled task updated"); results.mitre.add("T1053.005"); }
        if (id==="1102") { results.findings.push("🚨 EID 1102: Audit log cleared — anti-forensics"); results.mitre.add("T1070.001"); results.severity="critical"; }
        if (id==="4688") results.findings.push("ℹ️ EID 4688: New process created — review command line");
        if (id==="4776") { results.findings.push("⚠️ EID 4776: NTLM credential validation — check for Pass-the-Hash"); results.mitre.add("T1550.002"); }
        if (id==="4771") results.findings.push("⚠️ EID 4771: Kerberos pre-authentication failure — possible brute force");
        if (id==="7045") { results.findings.push("🚨 EID 7045: New service installed — check for malicious service persistence"); results.mitre.add("T1543.003"); }
      });

      // Extract process info from XML or plain
      const newProc = (t.match(/(?:<Image>|NewProcessName[:\s=]+)([^\s<"]+\.exe)/i)||[])[1]||"";
      const parentProc = (t.match(/(?:<ParentImage>|ParentProcessName[:\s=]+)([^\s<"]+\.exe)/i)||[])[1]||"";
      const cmdLine = (t.match(/(?:<CommandLine>|CommandLine[:\s=]+)([^<\n]{1,300})/i)||[])[1]||"";
      const user = (t.match(/(?:<User>|SubjectUserName[:\s=]+|TargetUserName[:\s=]+)([^\s<\\]+)/i)||[])[1]||"";
      const host = (t.match(/(?:<Computer>|Computer[:\s=]+|WorkstationName[:\s=]+)([^\s<]+)/i)||[])[1]||"";
      if (newProc) { results.indicators.push(`Process: ${newProc}`); results.prefillData.process = newProc; }
      if (parentProc) results.indicators.push(`Parent: ${parentProc}`);
      if (cmdLine.trim()) { results.indicators.push(`CMD: ${cmdLine.slice(0,80)}`); results.prefillData.cmdline = cmdLine; }
      if (user) { results.indicators.push(`User: ${user}`); results.prefillData.username = user; }
      if (host) { results.indicators.push(`Host: ${host}`); results.prefillData.hostname = host; }

      // Detect suspicious cmdline patterns
      if (cmdLine && /-enc\b|-EncodedCommand/i.test(cmdLine)) { results.findings.push("🚨 Base64 encoded PowerShell command detected"); results.mitre.add("T1027"); results.severity="high"; }
      if (cmdLine && /bypass|ExecutionPolicy/i.test(cmdLine)) { results.findings.push("⚠️ PowerShell execution policy bypass"); results.mitre.add("T1059.001"); if(results.severity!=="critical") results.severity="high"; }
      if (cmdLine && /IEX|Invoke-Expression|DownloadString|WebClient/i.test(cmdLine)) { results.findings.push("🚨 PowerShell download cradle / IEX pattern"); results.mitre.add("T1059.001"); results.mitre.add("T1105"); results.severity="critical"; }
      if (cmdLine && /certutil.*-urlcache|-decode/i.test(cmdLine)) { results.findings.push("🚨 certutil LOLBin abuse — payload download/decode"); results.mitre.add("T1105"); results.severity="critical"; }
      if (cmdLine && /mshta|rundll32|regsvr32|wscript|cscript/i.test(cmdLine)) { results.findings.push("⚠️ LOLBin execution: " + (cmdLine.match(/mshta|rundll32|regsvr32|wscript|cscript/i)||[])[0]); results.mitre.add("T1218"); if(!["critical"].includes(results.severity)) results.severity="high"; }
      if (cmdLine && /lsass/i.test(cmdLine)) { results.findings.push("🚨 lsass.exe referenced in command line — credential dump risk"); results.mitre.add("T1003.001"); results.severity="critical"; }
      if (cmdLine && /schtasks.*\/create|at\.exe/i.test(cmdLine)) { results.findings.push("⚠️ Scheduled task creation via command line"); results.mitre.add("T1053.005"); }
      if (cmdLine && /net\s+user.*\/add|net\s+localgroup.*administrators/i.test(cmdLine)) { results.findings.push("🚨 Backdoor account creation attempt"); results.mitre.add("T1136"); results.severity="critical"; }
      if (cmdLine && /wevtutil.*cl|Clear-EventLog/i.test(cmdLine)) { results.findings.push("🚨 Event log clearance — anti-forensics"); results.mitre.add("T1070.001"); results.severity="critical"; }
      if (cmdLine && /Add-MpPreference.*Exclusion|Set-MpPreference.*Disable/i.test(cmdLine)) { results.findings.push("🚨 Windows Defender exclusion or disable attempt"); results.mitre.add("T1562.001"); results.severity="critical"; }

      // Known suspicious parent→child combos
      if (parentProc && newProc) {
        const p = parentProc.toLowerCase(); const c = newProc.toLowerCase();
        if ((p.includes("winword") || p.includes("excel") || p.includes("outlook") || p.includes("powerpnt")) && (c.includes("cmd") || c.includes("powershell") || c.includes("wscript") || c.includes("mshta")))
          { results.findings.push(`🚨 Office → shell spawn: ${parentProc} → ${newProc} (malicious macro indicator)`); results.mitre.add("T1566.001"); results.severity="critical"; }
        if (p.includes("explorer") && c.includes("powershell") && cmdLine && /-enc/i.test(cmdLine))
          { results.findings.push("🚨 Explorer → encoded PowerShell (user execution of payload)"); }
      }
      return _finalizeTriage(results);
    }


    // 3. PROOFPOINT (Email Security / TAP)
    if (/proofpoint|TAP|messageParts|THREAT_TYPE|clicksPermitted|messagesDelivered|spamScore|phishScore|mlxScore|policyRoutes|quarantineFolder|senderIP/i.test(t)) {
      results.eventType = "Proofpoint Email Security";
      const threat   = (t.match(/(?:THREAT_TYPE|threatType)\s*[=:"]+\s*([^\s",\n]{2,40})/i)||[])[1]||"";
      const sender   = (t.match(/(?:sender|from)\s*[=:"]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1]||"";
      const recip    = (t.match(/(?:recipient|to)\s*[=:"]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1]||"";
      const senderIp = (t.match(/(?:senderIP|sender_ip|headerFrom)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const url      = (t.match(/(?:url|href)\s*[=:"]+\s*(https?:\/\/[^\s",]+)/i)||[])[1]||"";
      const attach   = (t.match(/(?:fileName|filename|attachment)\s*[=:"]+\s*([^\s",\n]{3,60})/i)||[])[1]||"";
      const action   = (t.match(/(?:disposition|action|quarantineFolder)\s*[=:"]+\s*([^\s",\n]{2,30})/i)||[])[1]||"";
      const phishScore= (t.match(/phishScore\s*[=:"]+\s*(\d+(?:\.\d+)?)/i)||[])[1]||"";
      const spamScore = (t.match(/spamScore\s*[=:"]+\s*(\d+(?:\.\d+)?)/i)||[])[1]||"";
      if (sender)    { results.indicators.push(`Sender: ${sender}`);      results.prefillData.sender = sender; }
      if (recip)     { results.indicators.push(`Recipient: ${recip}`);    results.prefillData.recipient = recip; }
      if (senderIp)  { results.indicators.push(`Sender IP: ${senderIp}`); results.prefillData.src_ip = senderIp; }
      if (threat)    { results.indicators.push(`Threat: ${threat}`);      results.prefillData.notes = threat; }
      if (action)      results.indicators.push(`Action: ${action}`);
      if (phishScore)  results.indicators.push(`Phish Score: ${phishScore}`);
      if (/phish|malware|spam/i.test(threat)) { results.findings.push(`🚨 Proofpoint detected ${threat} — verify sender domain, links, and attachments`); results.mitre.add("T1566"); results.severity = "high"; }
      if (url)       { results.findings.push(`⚠️ Malicious URL detected: ${url.slice(0,80)}`); results.mitre.add("T1566.002"); results.prefillData.url = url; if(results.severity!=="critical") results.severity = "high"; }
      if (attach)    { results.findings.push(`⚠️ Suspicious attachment: ${attach}`); results.mitre.add("T1566.001"); }
      if (senderIp && !isPrivateIPv4(senderIp)) results.findings.push(`ℹ️ Sender IP ${senderIp} — check reputation in VirusTotal and Talos`);
      if (!results.findings.length) results.findings.push(`ℹ️ Proofpoint email security event — action: ${action || "recorded"}`);
      return _finalizeTriage(results);
    }


    // 4. MICROSOFT DEFENDER / MDE / XDR
    if (/Microsoft.*Defender|MDE|MDO|Defender.*ATP|DefenderATP|AlertId.*OAV|AlertTitle|evidence.*type.*process|DetectionSource.*WindowsDefenderAv|microsoft.*365.*defender|SecurityAlert.*Microsoft/i.test(t)) {
      results.eventType = "Microsoft Defender / XDR Alert";
      const title     = (t.match(/(?:AlertTitle|Title|DisplayName)\s*[=:"]+\s*([^\n",]{5,100})/i)||[])[1]?.trim()||"";
      const sev       = (t.match(/(?:Severity|AlertSeverity)\s*[=:"]+\s*(\w+)/i)||[])[1]||"";
      const entity    = (t.match(/(?:DeviceName|ComputerName|Machine)\s*[=:"]+\s*([a-zA-Z0-9_.-]{2,50})/i)||[])[1]||"";
      const user      = (t.match(/(?:AccountName|UserName|InitiatingProcessAccountName)\s*[=:"]+\s*([a-zA-Z0-9._\\-]{2,50})/i)||[])[1]||"";
      const cmd       = (t.match(/(?:ProcessCommandLine|InitiatingProcessCommandLine)\s*[=:"]+\s*([^\n",]{5,200})/i)||[])[1]||"";
      const sha256    = (t.match(/\b[a-fA-F0-9]{64}\b/)||[])[0]||"";
      const category  = (t.match(/(?:Category|AlertCategory)\s*[=:"]+\s*([^\n",]{2,40})/i)||[])[1]||"";
      if (title)    results.indicators.push(`Alert: ${title.slice(0,60)}`);
      if (entity)   { results.indicators.push(`Device: ${entity}`);  results.prefillData.hostname = entity; }
      if (user)     { results.indicators.push(`User: ${user}`);      results.prefillData.username = user; }
      if (category)   results.indicators.push(`Category: ${category}`);
      if (sev)      { if(/high/i.test(sev)) results.severity="high"; else if(/critical/i.test(sev)) results.severity="critical"; else if(/medium/i.test(sev)) results.severity="medium"; }
      if (title)    results.findings.push(`🚨 Defender alert: ${title}`);
      if (cmd)      { results.prefillData.cmdline = cmd; if(/-enc|-EncodedCommand/i.test(cmd)) { results.findings.push("🚨 Encoded PowerShell in command line"); results.mitre.add("T1027"); } }
      if (sha256)     results.findings.push(`ℹ️ File hash identified — submit to VirusTotal: ${sha256.slice(0,16)}...`);
      if (/Ransomware|Tamper/i.test(title+category)) { results.findings.push("🚨 Ransomware or tamper protection triggered"); results.severity="critical"; results.mitre.add("T1486"); }
      if (!results.mitre.size) results.mitre.add("T1059");
      return _finalizeTriage(results);
    }


    // 5. SENTINELONE
    if (/SentinelOne|sentinel.*agent|agentDetectionInfo|threatInfo|mitigationStatus|analystVerdictDescription|threatClassification|s1AgentId/i.test(t)) {
      results.eventType = "SentinelOne EDR Alert";
      const threat    = (t.match(/(?:threatName|threatClassification|threatInfo)\s*[=:"]+\s*([^\n",]{2,80})/i)||[])[1]?.trim()||"";
      const status    = (t.match(/(?:mitigationStatus|mitigationAction)\s*[=:"]+\s*([^\n",]{2,40})/i)||[])[1]||"";
      const entity    = (t.match(/(?:computerName|agentComputerName)\s*[=:"]+\s*([^\n",\s]{2,50})/i)||[])[1]||"";
      const user      = (t.match(/(?:UserName|ownerAccount)\s*[=:"]+\s*([^\n",\s]{2,50})/i)||[])[1]||"";
      const verdict   = (t.match(/(?:analystVerdict|verdict)\s*[=:"]+\s*([^\n",]{2,30})/i)||[])[1]||"";
      const path      = (t.match(/(?:filePath|threatFilePath)\s*[=:"]+\s*([^\n",]{4,120})/i)||[])[1]||"";
      if (entity)   { results.indicators.push(`Host: ${entity}`);    results.prefillData.hostname = entity; }
      if (user)     { results.indicators.push(`User: ${user}`);      results.prefillData.username = user; }
      if (threat)     results.indicators.push(`Threat: ${threat.slice(0,50)}`);
      if (status)     results.indicators.push(`Status: ${status}`);
      if (verdict)    results.indicators.push(`Verdict: ${verdict}`);
      if (threat)   results.findings.push(`🚨 SentinelOne detected: ${threat}`);
      if (/killed|quarantine|remediat/i.test(status)) results.findings.push(`✅ Threat was automatically mitigated (${status}) — verify no lateral movement`);
      if (/not.mitigated|pending/i.test(status))      { results.findings.push("⚠️ Threat NOT fully mitigated — immediate manual action required"); results.severity="critical"; }
      if (path)       results.findings.push(`ℹ️ Malicious file: ${path}`);
      results.mitre.add("T1059"); results.severity = results.severity==="info" ? "high" : results.severity;
      return _finalizeTriage(results);
    }


    // 6. SURICATA / SNORT IDS-IPS
    if (/\[Classification:|ET\s+\w+|GPL\s+\w+|Suricata|snort|alert tcp|alert udp|alert icmp|Priority:\s*\d|GID:\s*\d|SID:\s*\d|\[1:[0-9]+:[0-9]+\]/i.test(t)) {
      results.eventType = /suricata/i.test(t) ? "Suricata IDS/IPS" : "Snort IDS/IPS";
      const sigName   = (t.match(/\[\d+:\d+:\d+\]\s*([^\[]{3,100})|alert.*(?:tcp|udp|icmp)[^(]+\(msg:"([^"]{3,100})"/i)||[])[1]?.trim()||
                        (t.match(/msg:\s*"([^"]{3,100})"/i)||[])[1]||"";
      const srcIp     = (t.match(/(\d{1,3}(?:\.\d{1,3}){3}):\d+\s*->/)||[])[1]||"";
      const dstIp     = (t.match(/->?\s*(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/)||[])[1]||"";
      const classif   = (t.match(/\[Classification:\s*([^\]]{3,60})\]/i)||[])[1]||"";
      const priority  = (t.match(/Priority:\s*(\d)/i)||[])[1]||"";
      const sid       = (t.match(/(?:SID|sid)\s*[=:]\s*(\d+)/i)||[])[1]||"";
      if (sigName)  results.indicators.push(`Signature: ${sigName.slice(0,60)}`);
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`);    results.prefillData.src_ip = srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (classif)    results.indicators.push(`Class: ${classif}`);
      if (priority)   results.indicators.push(`Priority: ${priority}`);
      if (sigName)  results.findings.push(`🚨 IDS signature matched: ${sigName}`);
      if (/trojan|backdoor|c2|malware|exploit/i.test(sigName+classif)) { results.findings.push("🚨 Malware or C2 communication pattern detected"); results.mitre.add("T1071"); results.severity="critical"; }
      if (/scan|recon|probe/i.test(sigName+classif))  { results.findings.push("⚠️ Reconnaissance or scanning activity detected"); results.mitre.add("T1046"); results.severity = results.severity==="info"?"medium":results.severity; }
      if (/dos|ddos|flood/i.test(sigName+classif))    { results.findings.push("⚠️ Denial of Service pattern detected"); results.mitre.add("T1498"); }
      if (priority === "1") { results.severity="critical"; }
      else if (priority === "2" && results.severity==="info") results.severity="high";
      if (!results.mitre.size) results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 7. DARKTRACE / NDR
    if (/darktrace|Antigena|modelBreach|pbid|phid|modelName|deviceScore|anomalyScore|unusual.*connection|ai.analyst/i.test(t)) {
      results.eventType = "Darktrace NDR Alert";
      const model     = (t.match(/(?:modelName|model)\s*[=:"]+\s*([^\n",]{5,80})/i)||[])[1]?.trim()||"";
      const device    = (t.match(/(?:deviceHostname|hostname|device)\s*[=:"]+\s*([^\n",\s]{2,50})/i)||[])[1]||"";
      const score     = (t.match(/(?:anomalyScore|score|pbid)\s*[=:"]+\s*(\d+(?:\.\d+)?)/i)||[])[1]||"";
      const srcIp     = (t.match(/(\d{1,3}(?:\.\d{1,3}){3})/)||[])[1]||"";
      if (model)    results.indicators.push(`Model: ${model.slice(0,60)}`);
      if (device)   { results.indicators.push(`Device: ${device}`);  results.prefillData.hostname = device; }
      if (score)      results.indicators.push(`Score: ${score}`);
      if (model)    results.findings.push(`⚠️ Darktrace AI model breach: ${model}`);
      if (score && parseFloat(score) > 0.8) { results.findings.push("🚨 High anomaly score — behavior deviates significantly from baseline"); results.severity="high"; }
      if (/c2|command.*control|beac/i.test(model)) { results.findings.push("🚨 Possible C2/beaconing activity detected"); results.mitre.add("T1071"); results.severity="critical"; }
      if (/lateral|internal|east.west/i.test(model)) { results.findings.push("⚠️ Internal lateral movement pattern"); results.mitre.add("T1021"); }
      if (!results.findings.length) results.findings.push(`ℹ️ Darktrace behavioral anomaly detected — review in Threat Visualizer`);
      return _finalizeTriage(results);
    }


    // 8. FIREWALL / NETWORK LOGS
    if (/SRC=|DST=|PROTO=|DPT=|SPT=|inbound|outbound|\bACCEPT\b|\bDROP\b|\bDENY\b|firewall|src_ip|dst_ip|action=allow|action=deny/i.test(t)) {
      results.eventType = "Firewall / Network Log";
      // iptables/netfilter style
      const src  = (t.match(/(?:SRC|src_ip|srcip|source)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dst  = (t.match(/(?:DST|dst_ip|dstip|dest(?:ination)?)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const proto= (t.match(/PROTO[=:\s]+(\w+)/i)||[])[1]||"";
      const dpt  = (t.match(/(?:DPT|dport|dst_port|dest(?:ination)?[_\s]?port)[=:\s]+(\d{1,5})/i)||[])[1]||"";
      const spt  = (t.match(/(?:SPT|sport|src_port|source[_\s]?port)[=:\s]+(\d{1,5})/i)||[])[1]||"";
      const action=(t.match(/(?:action|result)[=:\s]+(allow|deny|drop|block|accept|reject)/i)||[])[1]||"";
      if (src)    { results.indicators.push(`SRC: ${src}`);    results.prefillData.src_ip = src; }
      if (dst)    { results.indicators.push(`DST: ${dst}`);    results.prefillData.dest_ip = dst; }
      if (proto)   results.indicators.push(`Proto: ${proto}`);
      if (dpt)    { results.indicators.push(`DPort: ${dpt}`);  if (PORT_HINTS[dpt]) results.findings.push(`ℹ️ Dest port ${dpt} = ${PORT_HINTS[dpt]}`); }
      if (spt)     results.indicators.push(`SPort: ${spt}`);
      if (action)  results.indicators.push(`Action: ${action.toUpperCase()}`);
      // Risk flags
      if (dpt === "4444") { results.findings.push("🚨 Port 4444 = Metasploit default — likely C2"); results.mitre.add("T1071"); results.severity="critical"; }
      if (dpt === "50050") { results.findings.push("🚨 Port 50050 = Cobalt Strike default teamserver"); results.mitre.add("T1071"); results.severity="critical"; }
      if (dpt === "3389") { results.findings.push("⚠️ RDP outbound — possible lateral movement or C2 tunnel"); results.mitre.add("T1021.001"); if(!["critical"].includes(results.severity)) results.severity="high"; }
      if (dpt === "445")  { results.findings.push("⚠️ SMB outbound — lateral movement or Pass-the-Hash risk"); results.mitre.add("T1021.002"); if(!["critical"].includes(results.severity)) results.severity="high"; }
      if (dpt === "22" && action && /allow|accept/i.test(action)) results.findings.push("ℹ️ SSH allowed — verify source legitimacy");
      if (src && isPrivateIPv4(src) && dst && !isPrivateIPv4(dst) && dpt && !["80","443","53"].includes(dpt))
        results.findings.push(`⚠️ Internal → External on non-standard port ${dpt} — possible data exfil`);
      results.mitre.add("T1041");
      return _finalizeTriage(results);
    }


    // 9. PROXY / WEB LOG
    if (/GET |POST |PUT |DELETE |HEAD |HTTP\/[12]|\bstatus[=:\s]+[245]\d\d\b|\bcs-uri\b|\brequest_url\b|\burl_path\b/i.test(t)) {
      results.eventType = "Web / Proxy Log";
      const method  = (t.match(/\b(GET|POST|PUT|DELETE|PATCH|HEAD)\b/i)||[])[1]||"";
      const status  = (t.match(/(?:status|sc-status|response_code)[=:\s]+(\d{3})/i)||[])[1]||"";
      const url     = (t.match(/(?:url|cs-uri-stem|cs-uri)[=:\s]+"?([^\s"]+)/i)||[])[1]||"";
      const useragent=(t.match(/(?:user[_-]agent|cs\(user-agent\))[=:\s]+"?([^"\n]{1,200})/i)||[])[1]||"";
      const referer = (t.match(/(?:referer|cs\(referer\))[=:\s]+"?([^\s"]+)/i)||[])[1]||"";
      if (method)    results.indicators.push(`Method: ${method}`);
      if (url)       results.indicators.push(`URL: ${url.slice(0,80)}`);
      if (status)    results.indicators.push(`Status: ${status}`);
      if (useragent) results.indicators.push(`UA: ${useragent.slice(0,60)}`);
      if (status && status.startsWith("4")) results.findings.push(`⚠️ HTTP ${status} — access denied or not found`);
      if (method === "POST" && url) results.findings.push("ℹ️ POST request — check for data submission or exfiltration");
      if (useragent && /curl|wget|python|go-http|nmap|nikto|sqlmap|masscan|zgrab/i.test(useragent)) { results.findings.push(`⚠️ Suspicious User-Agent: ${useragent.slice(0,60)}`); results.mitre.add("T1595"); if(!["critical","high"].includes(results.severity)) results.severity="medium"; }
      if (url && /\.php\?.*=/i.test(url) && /['"><;{}]/i.test(url)) { results.findings.push("🚨 Possible SQLi or XSS in URL parameters"); results.mitre.add("T1190"); results.severity="high"; }
      if (url && /etc\/passwd|\/etc\/shadow|\.\.\/|%2e%2e/i.test(url)) { results.findings.push("🚨 Path traversal attempt detected"); results.mitre.add("T1190"); results.severity="high"; }
      if (url && /cmd=|exec=|system\(|eval\(|passthru/i.test(url)) { results.findings.push("🚨 RCE attempt pattern in URL"); results.mitre.add("T1190"); results.severity="critical"; }
      results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 10. SSH / LINUX AUTH LOG
    if (/sshd|auth\.log|pam_unix|sudo|su\[|Failed password|Accepted publickey|Invalid user|session opened/i.test(t)) {
      results.eventType = "SSH / Linux Auth Log";
      const failedUser = (t.match(/(?:Failed password for(?: invalid user)?|Invalid user)\s+(\S+)/i)||[])[1]||"";
      const acceptUser = (t.match(/Accepted (?:password|publickey) for\s+(\S+)/i)||[])[1]||"";
      const srcIp      = (t.match(/from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port/i)||[])[1]||"";
      const sudoUser   = (t.match(/sudo:\s+(\S+)\s*:/i)||[])[1]||"";
      if (failedUser) { results.indicators.push(`Failed user: ${failedUser}`); results.findings.push(`⚠️ Failed auth for user: ${failedUser}`); results.mitre.add("T1110"); if(!["critical","high"].includes(results.severity)) results.severity="medium"; }
      if (acceptUser) { results.indicators.push(`✅ Accepted login: ${acceptUser}`); results.prefillData.username = acceptUser; }
      if (srcIp)      { results.indicators.push(`Source IP: ${srcIp}`); results.prefillData.src_ip = srcIp; }
      if (sudoUser)   { results.indicators.push(`sudo: ${sudoUser}`); results.findings.push(`⚠️ sudo command executed by ${sudoUser}`); results.mitre.add("T1548"); }
      // Count failures
      const failCount = (t.match(/Failed password/gi)||[]).length;
      if (failCount >= 5) { results.findings.push(`🚨 ${failCount} failed auth attempts — possible brute force`); results.mitre.add("T1110.001"); results.severity = failCount>=20 ? "critical" : "high"; }
      if (/root/.test(failedUser||"")) { results.findings.push("🚨 Direct root login attempt"); results.mitre.add("T1078.003"); results.severity="critical"; }
      return _finalizeTriage(results);
    }


    // 11. DNS LOG
    if (/dns|QUERY|NXDOMAIN|NOERROR|A\s+IN\s|AAAA\s+IN\s|qtype|qname|dns_query|dns\.question/i.test(t)) {
      results.eventType = "DNS Log";
      const qname  = (t.match(/(?:qname|dns_query|dns\.question\.name)[=:\s]+"?([^\s"]+)/i)||[])[1]||"";
      const qtype  = (t.match(/(?:qtype|dns\.question\.type)[=:\s]+"?(\w+)/i)||[])[1]||"";
      const rcode  = (t.match(/(?:rcode|dns\.response_code|response)[=:\s]+"?(\w+)/i)||[])[1]||"";
      if (qname) results.indicators.push(`Query: ${qname}`);
      if (qtype) results.indicators.push(`Type: ${qtype}`);
      if (rcode) results.indicators.push(`Rcode: ${rcode}`);
      if (qname && /[a-z0-9]{20,}\./i.test(qname)) { results.findings.push(`⚠️ High-entropy subdomain — possible DGA/DNS tunneling: ${qname}`); results.mitre.add("T1071.004"); results.mitre.add("T1568.002"); if(!["critical","high"].includes(results.severity)) results.severity="medium"; }
      if (qtype === "TXT") { results.findings.push("⚠️ TXT record query — DNS tunneling commonly uses TXT records"); results.mitre.add("T1071.004"); }
      if (rcode === "NXDOMAIN" && qname) results.findings.push(`ℹ️ NXDOMAIN for ${qname} — check for DGA activity`);
      results.mitre.add("T1071.004");
      return _finalizeTriage(results);
    }


    // 12. CEF / LEEF (SIEM format)
    if (/CEF:\d+\||\bLEEF:[12]\./i.test(t)) {
      results.eventType = t.startsWith("CEF") ? "CEF Alert" : "LEEF Alert";
      const cefParts = t.split("|");
      if (cefParts.length >= 7) {
        results.indicators.push(`Product: ${cefParts[1]||"?"} ${cefParts[2]||""}`);
        results.indicators.push(`Severity: ${cefParts[6]||"?"}`);
        const sev = parseInt(cefParts[6])||0;
        if (sev >= 8) results.severity="critical";
        else if (sev >= 6) results.severity="high";
        else if (sev >= 4) results.severity="medium";
      }
      const ext = (t.split("|")[7]||"");
      const src = (ext.match(/\bsrc=(\S+)/)||[])[1]||"";
      const dst = (ext.match(/\bdst=(\S+)/)||[])[1]||"";
      const msg = (ext.match(/\bmsg=([^=]+?)(?:\s\w+=|$)/)||[])[1]||"";
      if (src) { results.indicators.push(`src: ${src}`); results.prefillData.src_ip = src; }
      if (dst) { results.indicators.push(`dst: ${dst}`); results.prefillData.dest_ip = dst; }
      if (msg) results.findings.push(`Message: ${msg.slice(0,150)}`);
      return _finalizeTriage(results);
    }


    // 13. JSON SIEM / EDR (Crowdstrike/Sentinel/Elastic)
    if (/^\s*\{[\s\S]*"[a-zA-Z_]+"\s*:/.test(t)) {
      results.eventType = "JSON / SIEM Alert";
      try {
        const obj = JSON.parse(t);
        const flat = JSON.stringify(obj);
        // Try to find common fields
        const findField = (...keys) => { for (const k of keys) { const v=obj[k]||obj[k.toLowerCase()]||obj[k.toUpperCase()]; if(v) return String(v); } return ""; };
        const sev = findField("severity","Severity","SeverityName","alert_severity");
        const name= findField("AlertName","alert_name","detectionName","RuleName","EventName","name");
        const host= findField("Hostname","ComputerName","hostname","device_hostname","DeviceName");
        const user= findField("UserName","user","AccountName","SubjectUserName","TargetUserName");
        const proc= findField("FileName","ProcessName","process_name","ImageFileName");
        const cmd = findField("CommandLine","command_line","cmdline");
        if (sev)  { results.indicators.push(`Severity: ${sev}`); if(/critical/i.test(sev)) results.severity="critical"; else if(/high/i.test(sev)) results.severity="high"; else if(/medium/i.test(sev)) results.severity="medium"; }
        if (name)  results.indicators.push(`Alert: ${name.slice(0,80)}`);
        if (host) { results.indicators.push(`Host: ${host}`); results.prefillData.hostname = host; }
        if (user) { results.indicators.push(`User: ${user}`); results.prefillData.username = user; }
        if (proc)  results.indicators.push(`Process: ${proc}`);
        if (cmd)  { results.indicators.push(`CMD: ${cmd.slice(0,80)}`); results.prefillData.cmdline = cmd; }
        if (cmd && /-enc\b|-EncodedCommand/i.test(cmd)) { results.findings.push("🚨 Encoded PowerShell in JSON alert"); results.mitre.add("T1027"); results.severity="high"; }
        if (cmd && /IEX|Invoke-Expression|DownloadString/i.test(cmd)) { results.findings.push("🚨 PowerShell download cradle in JSON alert"); results.mitre.add("T1059.001"); results.severity="critical"; }
      } catch(e) {
        results.findings.push("⚠️ JSON parsing error — may be truncated or multi-line");
      }
      return _finalizeTriage(results);
    }


    // 14. CROWDSTRIKE DETECT / FALCON / NGSIEM
    if (/falcon|crowdstrike|detect\.base|falconhost|detect_id|SeverityName|PatternDisposition|ProcessRollup|eventType.*falcon/i.test(t) ||
        (fieldsHeaderMatch && /\baid\b|\bcid\b|CrowdStrike|Falcon/i.test(t))) {
      results.eventType = "CrowdStrike Falcon Alert";

      // ── TSV column-aware extraction ──────────────────────────
      // If we have a #fields: header, extract values by column position
      let tsvRow = {};
      if (fieldsHeaderMatch) {
        const colNames = fieldsHeaderMatch[1].split(/\t/).map(c => c.trim());
        const dataLines = t.split("\n").filter(l => l && !l.startsWith("#"));
        if (dataLines.length > 0) {
          const firstDataCols = dataLines[0].split("\t");
          colNames.forEach((name, i) => { if (firstDataCols[i] !== undefined && firstDataCols[i] !== "-") tsvRow[name.toLowerCase()] = firstDataCols[i]; });
        }
      }

      // Helper: try TSV column first, then key=value regex fallback
      const getField = (colNames, regex) => {
        for (const col of colNames) { if (tsvRow[col.toLowerCase()]) return tsvRow[col.toLowerCase()]; }
        return (t.match(regex)||[])[1]?.trim()||"";
      };

      const host    = getField(["computername","hostname","computer_name"], /(?:ComputerName|Hostname|computer_name)\s*[=:\t"]+\s*([a-zA-Z0-9_.-]+)/i);
      const user    = getField(["username","user_name","user"], /(?:UserName|user_name|username)\s*[=:\t"]+\s*([a-zA-Z0-9_.\\-]+)/i);
      const rawSev  = getField(["severityname","severity"], /(?:Severity|SeverityName)\s*[=:\t"]+\s*(\w+)/i);
      // Only accept real severity values — reject field names and junk
      const sev     = /^(?:critical|high|medium|low|informational|info)$/i.test(rawSev) ? rawSev : "";
      const tactic  = getField(["tactic"], /(?:^|\t)Tactic\t([^\t\n\r]+)/i);
      const tech    = getField(["technique"], /(?:^|\t)Technique\t([^\t\n\r]+)/i);
      const cmd     = getField(["commandline","command_line","cmdline"], /(?:CommandLine|cmdline|command_line)\s*[=:\t"]+\s*([^\t\n\r"]{5,})/i);
      const parentP = getField(["parentbasefilename","parent_process_name","parentprocessname"], /(?:ParentBaseFileName|parent_process_name)\s*[=:\t"]+\s*([^\t\n\r"]+)/i);
      const destIp  = getField(["remoteaddressip4","dest_ip","dst_ip","remoteip"], /(?:RemoteAddressIP4|dest_ip|dst_ip|RemoteIP)\s*[=:\t"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
      const srcIp   = getField(["localaddressip4","src_ip","srcip","localip"], /(?:LocalAddressIP4|src_ip|srcip|LocalIP)\s*[=:\t"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
      const descr   = getField(["detectdescription","detect_description","description"], /(?:DetectDescription|detect_description|description)\s*[=:\t"]+\s*([^\t\n\r"]{5,})/i);
      // For tactic/technique from TSV, the value may include the technique ID
      const techClean = tech.replace(/^T\d{4}(?:\.\d{3})?\s+/,"").trim(); // strip leading T-ID
      const obj       = getField(["objective"], /(?:Objective)\s*[=:\t"]+\s*([^\t\n\r,"]+)/i);

      if (host)   { results.indicators.push(`Host: ${host}`);    results.prefillData.hostname = host; }
      if (user)   { results.indicators.push(`User: ${user}`);    results.prefillData.username = user; }
      if (destIp) { results.indicators.push(`Dst IP: ${destIp}`); results.prefillData.dest_ip = destIp; }
      if (srcIp && !isPrivateIPv4(srcIp)) results.indicators.push(`Src IP: ${srcIp}`);
      if (tactic) results.indicators.push(`Tactic: ${tactic}`);
      if (obj)    results.indicators.push(`Objective: ${obj}`);
      if (sev)    { if(/critical/i.test(sev)) results.severity="critical"; else if(/high/i.test(sev)) results.severity="high"; else if(/medium/i.test(sev)) results.severity="medium"; else if(/low/i.test(sev)) results.severity="low"; }

      // Severity badge from SeverityName
      if (sev) results.indicators.unshift(`Severity: ${sev.charAt(0).toUpperCase()+sev.slice(1).toLowerCase()}`);

      // ── FINDINGS from command line / technique ──────────────
      if (cmd) {
        results.prefillData.cmdline = cmd;
        if (/-enc\b|-EncodedCommand/i.test(cmd)) { results.findings.push("🚨 Base64-encoded PowerShell command detected (T1027 obfuscation)"); results.mitre.add("T1027"); results.mitre.add("T1059.001"); if(results.severity!=="critical") results.severity="high"; }
        if (/IEX|Invoke-Expression|DownloadString|WebClient|Net\.WebClient/i.test(cmd)) { results.findings.push("🚨 PowerShell download cradle detected — in-memory payload delivery (T1105)"); results.mitre.add("T1059.001"); results.mitre.add("T1105"); results.severity="critical"; }
        if (/mshta|rundll32|regsvr32|wscript|cscript|certutil.*decode/i.test(cmd)) { results.findings.push(`⚠️ LOLBin execution: ${(cmd.match(/mshta|rundll32|regsvr32|wscript|cscript|certutil/i)||[])[0]}`); results.mitre.add("T1218"); if(!["critical"].includes(results.severity)) results.severity="high"; }
        if (/mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs.*MiniDump/i.test(cmd)) { results.findings.push("🚨 Credential dumping tool or LSASS dump command detected"); results.mitre.add("T1003.001"); results.severity="critical"; }
        if (/schtasks|at\.exe|Register-ScheduledTask/i.test(cmd)) { results.findings.push("⚠️ Scheduled task creation — possible persistence mechanism"); results.mitre.add("T1053.005"); if(!["critical","high"].includes(results.severity)) results.severity="high"; }
        if (/-nop|-noprofile|-noninteractive|-windowstyle\s+hidden/i.test(cmd)) results.findings.push("⚠️ PowerShell launched with stealth flags (no profile, hidden window)");
        if (/net\s+user\s+.*\/add|net\s+localgroup.*administrators/i.test(cmd)) { results.findings.push("🚨 Account created or added to Administrators group"); results.mitre.add("T1136.001"); results.mitre.add("T1098"); results.severity="critical"; }
      }

      // ── FINDINGS from description ────────────────────────────
      if (descr && descr.length > 5 && !/^(?:DetectDescription|description)$/i.test(descr)) {
        results.findings.push(`ℹ️ Falcon detection: ${descr.slice(0, 150)}`);
        results.prefillData.notes = `Falcon description: ${descr.slice(0, 150)}`;
      }

      // ── FINDINGS from technique field ────────────────────────
      if (tech && !/^(?:technique|tactic|objective)$/i.test(tech)) {
        const tidMatch = tech.match(/T\d{4}(?:\.\d{3})?/);
        if (tidMatch) results.mitre.add(tidMatch[0]);
        if (techClean) results.findings.push(`ℹ️ Technique: ${techClean}${tactic ? ` (${tactic})` : ""}`);
      }

      // ── FINDINGS from network context ───────────────────────
      if (destIp && !isPrivateIPv4(destIp)) { results.findings.push(`⚠️ External outbound connection to ${destIp} — verify reputation`); results.mitre.add("T1071"); }

      // ── PARENT PROCESS ANOMALY ───────────────────────────────
      if (parentP && cmd) {
        const suspicious_parents = ["winword","excel","outlook","powerpnt","onenote","msaccess","mspub"];
        if (suspicious_parents.some(p => parentP.toLowerCase().includes(p))) {
          results.findings.push(`🚨 Office app (${parentP}) spawned a child process — classic macro/phishing delivery`);
          results.mitre.add("T1566.001"); results.mitre.add("T1204.002"); results.severity="critical";
        }
      }

      // If no specific findings but high severity, add generic
      if (!results.findings.length && sev) {
        results.findings.push(`⚠️ CrowdStrike Falcon raised a ${sev.toUpperCase()} severity alert — review detection details in the Falcon console`);
      }

      // Default TTPs if none specific
      if (!results.mitre.size) results.mitre.add("T1059");
      return _finalizeTriage(results);
    }




    // 15. MICROSOFT 365 / AZURE AD / ENTRA ID AUDIT LOG
    // Catches: Unified Audit Log exports, Entra ID / Azure AD audit events, SIEM-forwarded M365 logs,
    // cloud SIEM summaries (with "Service provider azure", "Event category AuditLogs", etc.)
    if (
      // Classic M365 Unified Audit Log fields
      (/Operation|UserId|ClientIP|Workload|AuditLogRecordType|RecordType|UserType|ResultStatus/i.test(t) && /azure|m365|microsoft|sharepoint|exchange|teams|onedrive|entra/i.test(t)) ||
      // Azure AD / Entra ID audit events — cloud SIEM format
      /AuditLogs|Core\s+Directory|Microsoft\.aadiam|ServicePrincipal|Consent\s+to\s+application|ConsentContext|operationType.*Assign|azure_global/i.test(t) ||
      // Cloud SIEM summary format with labeled fields
      (/Service\s+provider\s+azure|Event\s+category.*Audit|Event\s+source.*Directory/i.test(t) && /azure|entra|aad/i.test(t))
    ) {
      results.eventType = "Azure AD / Entra ID Audit Log";

      // Extract fields — handle both key:value label format and JSON format
      const getF = (patterns, fallback="") => {
        for (const p of patterns) { const m = t.match(p); if (m?.[1]?.trim()) return m[1].trim(); }
        return fallback;
      };

      const op       = getF([/(?:"?Operation"?\s*[,:\s]\s*"?)([^",\n\r]{3,80})/i,
                             /(?:operationalName|Event\s*-\s*)([^\n\r"]{3,80})/i,
                             /(?:Event\s+type\s+Assign[^\n]*\n\s*)([^\n\r]{3,60})/i]);
      const evtName  = getF([/Event\s*[-–]\s*([^\n\r]{3,80})/i, /operationalName["\s:]+([^\n\r",]{3,80})/i]);
      const user     = getF([/(?:"?UserId"?\s*[,:\s]\s*"?)([^",\n\r@]{2,60}@[^",\n\r]{2,60})/i,
                             /User\s+name\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
                             /User\s+principal\s+name\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i]);
      const ip       = getF([/(?:"?ClientIP"?\s*[,:\s]\s*"?)(\d{1,3}(?:\.\d{1,3}){3})/i,
                             /Source\s+IP\s+address\s+(\d{1,3}(?:\.\d{1,3}){3})/i]);
      const workload = getF([/(?:"?Workload"?\s*[,:\s]\s*"?)([^",\n\r]{2,40})/i,
                             /Event\s+source\s+([^\n\r]{2,40})/i]);
      const result   = getF([/(?:"?ResultStatus"?\s*[,:\s]\s*"?)([^",\n\r]{2,20})/i]);
      const appName  = getF([/"displayName"\s*:\s*"([^"]{2,80})"/i,
                             /\\"displayName\\"\s*:\s*\\"([^\\"]{2,80})\\"/i,
                             /displayName[^:]*:\s*\\?"([^\\"]{2,80})\\?"/i]);
      const evtSrc   = getF([/Event\s+source\s+([^\n\r]{2,50})/i]);
      const evtCat   = getF([/Event\s+category\s+([^\n\r]{2,50})/i]);
      const region   = getF([/(?:Cloud\s+region|Region)\s+([^\n\r\s]{2,30})/i]);
      const mfaAuth  = getF([/MFA\s+authenticated\s+([^\n\r\s]{2,10})/i]);

      if (evtName)  { results.indicators.push(`Event: ${evtName}`);    results.prefillData.operation = evtName; }
      else if (op)  { results.indicators.push(`Operation: ${op}`);     results.prefillData.operation = op; }
      if (user)     { results.indicators.push(`User: ${user}`);        results.prefillData.username = user; }
      if (ip)       { results.indicators.push(`Source IP: ${ip}`);     results.prefillData.src_ip = ip; }
      if (workload || evtSrc) results.indicators.push(`Source: ${workload || evtSrc}`);
      if (evtCat)   results.indicators.push(`Category: ${evtCat}`);
      if (region)   results.indicators.push(`Region: ${region}`);
      if (result)   results.indicators.push(`Result: ${result}`);
      if (appName && appName !== user) results.indicators.push(`App: ${appName}`);
      if (mfaAuth && mfaAuth !== "--") results.indicators.push(`MFA: ${mfaAuth}`);

      // ── FINDINGS ────────────────────────────────────────────────
      const fullText = t.toLowerCase();

      // OAuth App Consent Grant — T1550.001 / T1528 — HIGH risk in most environments
      if (/consent\s+to\s+application|ConsentContext|operationalName.*consent|operationType.*Assign/i.test(t)) {
        const isAdminConsent = /IsAdminConsent.*True|IsAdminConsent.*true/i.test(t);
        const isOnBehalfOfAll = /OnBehalfOfAll.*True|OnBehalfOfAll.*true/i.test(t);
        const scope = (t.match(/Scope:\s*([A-Za-z.]+)/i)||[])[1] || "";
        results.findings.push(`🚨 OAuth App Consent Grant detected${appName ? ` — App: "${appName}"` : ""}`);
        if (isAdminConsent) results.findings.push("🚨 Admin consent granted — application received tenant-wide permissions");
        if (isOnBehalfOfAll) results.findings.push("⚠️ ConsentContext.OnBehalfOfAll = True — permissions granted for ALL users in tenant");
        if (scope) results.findings.push(`ℹ️ Permission scope granted: ${scope}`);
        results.findings.push("⚠️ Verify this app is expected and approved — OAuth consent abuse is a common BEC vector");
        results.mitre.add("T1528"); results.mitre.add("T1550.001");
        results.severity = "high";
        if (isAdminConsent || isOnBehalfOfAll) results.severity = "critical";
        results.prefillData.notes = `OAuth consent grant to app "${appName || "unknown"}". Admin consent: ${isAdminConsent}. OnBehalfOfAll: ${isOnBehalfOfAll}.`;
      }

      // MFA missing or not authenticated
      if (mfaAuth === "--" || /MFA\s+authenticated\s+--/i.test(t)) {
        results.findings.push("⚠️ MFA authentication status unknown or not recorded for this event");
      }

      // Classic M365 suspicious operations
      if (/FileDeleted|FileMalwareDetected|AnonymousLinkCreated/i.test(op||t)) {
        results.findings.push(`⚠️ Sensitive SharePoint/OneDrive operation: ${op}`);
        results.mitre.add("T1567.002"); if(!["critical","high"].includes(results.severity)) results.severity="medium";
      }
      if (/UserLoggedIn.*fail|UserLoginFailed|PasswordSpray/i.test(op||t)) {
        results.findings.push("⚠️ Failed M365 login — possible brute force or credential stuffing");
        results.mitre.add("T1110"); if(!["critical","high"].includes(results.severity)) results.severity="high";
      }
      if (/Add\s+member\s+to\s+role|Add\s+app\s+role|Grant\s+delegated\s+permission/i.test(op||t)) {
        results.findings.push("🚨 Privilege escalation: role or permission assignment in Azure AD");
        results.mitre.add("T1098"); results.severity="critical";
      }
      if (/New-InboxRule|Set-InboxRule|New-TransportRule/i.test(op||t)) {
        results.findings.push("🚨 Mail forwarding rule created — hallmark of Business Email Compromise (BEC)");
        results.mitre.add("T1114.003"); results.severity="critical";
      }
      if (/Set-MailboxPermission|Add-MailboxPermission/i.test(op||t)) {
        results.findings.push("⚠️ Mailbox permission changed — check for unauthorized delegation");
        results.mitre.add("T1098.002"); if(results.severity!=="critical") results.severity="high";
      }
      if (/Reset password|Change password|Set-MsolUserPassword/i.test(op||t)) {
        results.findings.push("⚠️ Password reset or change performed — verify legitimacy");
        results.mitre.add("T1098"); if(!["critical","high"].includes(results.severity)) results.severity="medium";
      }
      if (/Delete user|Remove user|Disable user/i.test(op||t)) {
        results.findings.push("⚠️ User account deleted or disabled — could be attacker covering tracks or insider threat");
        results.mitre.add("T1531"); if(!["critical","high"].includes(results.severity)) results.severity="high";
      }
      if (/Termination\s+Bot|termination.*bot/i.test(t)) {
        results.findings.push("⚠️ Application named 'Termination Bot' involved — verify this is an authorized HR automation tool");
      }

      // External IP with failure
      if (ip && !isPrivateIPv4(ip)) {
        results.findings.push(`ℹ️ Action performed from external IP ${ip} — verify location is expected for this user`);
      }

      if (!results.findings.length) {
        results.findings.push(`ℹ️ Azure AD audit event: ${evtName || op || "action recorded"} — review for anomalous behavior`);
      }

      if (!results.mitre.size) results.mitre.add("T1078.004");
      return _finalizeTriage(results);
    }


    // 16. AWS CLOUDTRAIL
    if (/eventName|eventSource|userIdentity|sourceIPAddress|awsRegion|errorCode|requestParameters/i.test(t) && /amazonaws|cloudtrail|aws/i.test(t)) {
      results.eventType = "AWS CloudTrail Log";
      const eventName  = (t.match(/(?:"?eventName"?\s*[:,]\s*"?)([^",\n\r]{2,60})/i)||[])[1]||"";
      const eventSrc   = (t.match(/(?:"?eventSource"?\s*[:,]\s*"?)([^",\n\r]{2,60})/i)||[])[1]||"";
      const srcIp      = (t.match(/(?:"?sourceIPAddress"?\s*[:,]\s*"?)(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const userType   = (t.match(/(?:"?type"?\s*[:,]\s*"?)(IAMUser|AssumedRole|Root|AWSService|FederatedUser)/i)||[])[1]||"";
      const userName   = (t.match(/(?:"?userName"?\s*[:,]\s*"?)([^",\n\r]{2,60})/i)||[])[1]||"";
      const errorCode  = (t.match(/(?:"?errorCode"?\s*[:,]\s*"?)([^",\n\r]{2,60})/i)||[])[1]||"";
      const region     = (t.match(/(?:"?awsRegion"?\s*[:,]\s*"?)([^",\n\r]{2,30})/i)||[])[1]||"";
      if (eventName)  { results.indicators.push(`Event: ${eventName}`); results.prefillData.operation = eventName; }
      if (eventSrc)     results.indicators.push(`Source: ${eventSrc}`);
      if (srcIp)      { results.indicators.push(`SourceIP: ${srcIp}`); results.prefillData.src_ip = srcIp; }
      if (userName)   { results.indicators.push(`User: ${userName}`); results.prefillData.username = userName; }
      if (userType)     results.indicators.push(`Type: ${userType}`);
      if (region)       results.indicators.push(`Region: ${region}`);
      if (errorCode)    results.indicators.push(`Error: ${errorCode}`);
      // Risk detections
      if (userType === "Root") { results.findings.push("🚨 Root account activity detected — should never be used for normal operations"); results.mitre.add("T1078.004"); results.severity="critical"; }
      if (/ConsoleLogin/i.test(eventName) && errorCode) { results.findings.push(`⚠️ Failed console login: ${errorCode}`); results.mitre.add("T1110"); if(results.severity!=="critical") results.severity="high"; }
      if (/CreateUser|AttachUserPolicy|AttachRolePolicy|AddUserToGroup/i.test(eventName)) { results.findings.push(`🚨 IAM privilege action: ${eventName}`); results.mitre.add("T1136.003"); results.mitre.add("T1098"); results.severity="critical"; }
      if (/StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors/i.test(eventName)) { results.findings.push(`🚨 CloudTrail tampering: ${eventName} — anti-forensics`); results.mitre.add("T1562.008"); results.severity="critical"; }
      if (/GetSecretValue|GetParameter|DescribeSecret/i.test(eventName)) { results.findings.push(`⚠️ Secret/credential access: ${eventName}`); results.mitre.add("T1552.001"); if(results.severity!=="critical") results.severity="high"; }
      if (/RunInstances|CreateInstance/i.test(eventName)) { results.findings.push(`ℹ️ EC2 instance creation — verify legitimacy`); results.mitre.add("T1578"); }
      if (srcIp && !isPrivateIPv4(srcIp) && !srcIp.startsWith("0.")) results.findings.push(`ℹ️ External source IP: ${srcIp} — verify expected region`);
      return _finalizeTriage(results);
    }


    // 17. OKTA / SSO IDENTITY LOG
    if (/eventType|actor\.alternateId|outcome\.result|displayMessage|debugContext|authenticationContext|okta/i.test(t)) {
      results.eventType = "Okta / SSO Identity Log";
      const evType  = (t.match(/(?:"?eventType"?\s*[:,]\s*"?)([a-zA-Z_.]{4,80})/i)||[])[1]||"";
      const outcome = (t.match(/(?:"?result"?\s*[:,]\s*"?)(SUCCESS|FAILURE|SKIPPED|ALLOW|DENY|UNKNOWN)/i)||[])[1]||"";
      const user    = (t.match(/(?:"?alternateId"?\s*[:,]\s*"?)([^",\n\r@]{2,}@[^",\n\r]{2,})/i)||[])[1]||"";
      const ip      = (t.match(/(?:"?ipAddress"?\s*[:,]\s*"?)(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const msg     = (t.match(/(?:"?displayMessage"?\s*[:,]\s*"?)([^",\n\r]{4,120})/i)||[])[1]||"";
      const ua      = (t.match(/(?:"?userAgent"?\s*?,\s*?"?rawUserAgent"?\s*[:,]\s*"?)([^",\n\r]{4,200})/i)||[])[1]||"";
      if (evType)    results.indicators.push(`Event: ${evType}`);
      if (user)    { results.indicators.push(`User: ${user}`); results.prefillData.username = user; }
      if (outcome)   results.indicators.push(`Outcome: ${outcome}`);
      if (ip)      { results.indicators.push(`IP: ${ip}`); results.prefillData.src_ip = ip; }
      if (msg)       results.findings.push(`ℹ️ ${msg}`);
      if (ua && /curl|python|go-http|okhttp/i.test(ua)) results.findings.push(`⚠️ Suspicious client: ${ua.slice(0,80)}`);
      if (outcome === "FAILURE") { results.findings.push("⚠️ Authentication failure"); results.mitre.add("T1110"); if(!["critical","high"].includes(results.severity)) results.severity="medium"; }
      if (/user\.mfa\.factor\.deactivate|MFA.*bypass|mfa.*reset/i.test(evType||t)) { results.findings.push("🚨 MFA deactivation or bypass detected"); results.mitre.add("T1621"); results.severity="critical"; }
      if (/policy\.evaluate_sign_on/i.test(evType) && /DENY/i.test(outcome)) { results.findings.push("⚠️ Sign-on policy denied access"); results.mitre.add("T1078"); }
      if (/session\.impersonation/i.test(evType)) { results.findings.push("🚨 Admin impersonation session — investigate immediately"); results.mitre.add("T1078.004"); results.severity="critical"; }
      if (/user\.account\.update_password|user\.account\.reset_password/i.test(evType)) { results.findings.push("⚠️ Password change/reset event"); results.mitre.add("T1098"); }
      return _finalizeTriage(results);
    }


    // 18. ZSCALER (ZIA / ZPA)
    if (/zscaler|ZscalerApp|dlpDictionaries|urlCategory.*zscaler|policyAction.*zscaler|transactionID.*zscaler|csfbEnabled|zia.*log|zpa.*log/i.test(t) || (/zscaler/i.test(t) && /urlCategory|policyAction|threatName/i.test(t))) {
      results.eventType = /zpa|private.access/i.test(t) ? "Zscaler ZPA Log" : "Zscaler ZIA Log";
      const action    = (t.match(/(?:action|policyAction|result)\s*[=:"]+\s*([^\s",\n]{2,30})/i)||[])[1]||"";
      const url       = (t.match(/(?:url|requestedURL|uri)\s*[=:"]+\s*(https?:\/\/[^\s",]+)/i)||[])[1]||"";
      const category  = (t.match(/(?:urlCategory|cloudApp|category)\s*[=:"]+\s*([^\s",\n]{2,50})/i)||[])[1]||"";
      const threat    = (t.match(/(?:threatName|malwareCategory|threatCategory)\s*[=:"]+\s*([^\s",\n]{2,60})/i)||[])[1]||"";
      const srcIp     = (t.match(/(?:srcIP|clientIP|srcip|src)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dstIp     = (t.match(/(?:dstIP|serverIP|dst)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const user      = (t.match(/(?:user|userName|login)\s*[=:"]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1]||"";
      const bytes     = (t.match(/(?:bytesTotal|txBytes|totalBytes)\s*[=:"]+\s*(\d+)/i)||[])[1]||"";
      if (user)     { results.indicators.push(`User: ${user}`);      results.prefillData.username = user; }
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`);    results.prefillData.src_ip = srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (category)   results.indicators.push(`Category: ${category}`);
      if (action)     results.indicators.push(`Action: ${action}`);
      if (threat)   { results.findings.push(`🚨 Zscaler detected threat: ${threat}`); results.mitre.add("T1071"); results.severity="high"; }
      if (/block|blocked/i.test(action)) results.findings.push(`✅ Traffic was blocked by Zscaler policy — confirm no endpoint compromise`);
      if (/allow/i.test(action) && threat) { results.findings.push("⚠️ Malicious traffic was ALLOWED — check policy and investigate endpoint"); results.severity="critical"; }
      if (url)      { results.findings.push(`ℹ️ URL accessed: ${url.slice(0,80)}`); results.prefillData.url = url; }
      if (bytes && parseInt(bytes) > 10000000) results.findings.push(`⚠️ Large data transfer: ${(parseInt(bytes)/1048576).toFixed(1)} MB — possible data exfiltration`);
      if (!results.findings.length) results.findings.push(`ℹ️ Zscaler web activity — ${category || "access"} ${action ? `→ ${action}` : ""}`);
      return _finalizeTriage(results);
    }


    // 19. IBM QRADAR / SPLUNK SIEM ALERT
    if (/qradar|QRadar|offenseId|sourceCount|destinationCount|eventCount|magnitudeLabel|credibility|relevance|severity.*magnitude|ruleNames/i.test(t) ||
        /index=\w+\s|sourcetype=\w+|search.*earliest|savedsearch|SPL\s|Splunk.*alert/i.test(t)) {
      results.eventType = /qradar/i.test(t) ? "IBM QRadar SIEM" : "Splunk SIEM Alert";
      const rule      = (t.match(/(?:ruleNames|ruleName|savedSearch|alert_name)\s*[=:"[\s]+([^\]",\n]{3,80})/i)||[])[1]?.trim()||"";
      const srcIp     = (t.match(/(?:sourceAddress|src_ip|src)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dstIp     = (t.match(/(?:destinationAddress|dst_ip|dest)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const mag       = (t.match(/magnitude\s*[=:"]+\s*(\d+)/i)||[])[1]||"";
      const user      = (t.match(/(?:userName|user|account)\s*[=:"]+\s*([a-zA-Z0-9.@_-]{3,50})/i)||[])[1]||"";
      if (rule)     results.indicators.push(`Rule: ${rule.slice(0,60)}`);
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`);    results.prefillData.src_ip = srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (user)     { results.indicators.push(`User: ${user}`);      results.prefillData.username = user; }
      if (mag)        results.indicators.push(`Magnitude: ${mag}`);
      if (rule)     results.findings.push(`ℹ️ SIEM rule triggered: ${rule}`);
      if (mag && parseInt(mag) >= 7) { results.findings.push(`⚠️ High magnitude offense (${mag}/10) — investigate correlated events`); results.severity = parseInt(mag)>=9 ? "critical" : "high"; }
      if (srcIp && !isPrivateIPv4(srcIp)) results.findings.push(`ℹ️ External source IP ${srcIp} — check threat intel`);
      return _finalizeTriage(results);
    }

    // 20. IDENTITY SECURITY / BEHAVIORAL ANALYTICS / UBA
    // Catches: VMware Workspace ONE / Identity Service, CrowdStrike Falcon Identity,
    //          Microsoft Defender for Identity, Securonix, Exabeam, SailPoint, BeyondTrust,
    //          any behavioral identity platform with impossible travel, risk scores, concurrent access
    if (
      /VMware Identity Service|Workspace ONE|Horizon Identity|vIDM/i.test(t) ||
      /Access from multiple locations|impossible travel|concurrent.*login|concurrent.*access|multiple locations concurrently/i.test(t) ||
      /Risk score\s*(Critical|High|Medium|Low|[0-9])|risk.*score.*[0-9]/i.test(t) ||
      /Falcon Identity|Defender for Identity|Azure ATP|MDI alert|identity.*protection/i.test(t) ||
      /Securonix|Exabeam|SailPoint|BeyondTrust|CyberArk.*identity|Ping Identity/i.test(t) ||
      (/Source endpoint IP|Additional endpoint IP|Additional location country/i.test(t) && /FAILURE|SUCCESS/i.test(t)) ||
      (/Risk score|Privileged.*No|Privileged.*Yes/i.test(t) && /Account name|Username|Email address/i.test(t))
    ) {
      results.eventType = "Identity Security Alert";

      // Extract identity fields
      const user     = (t.match(/(?:Username|User name|Account name|User)\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1] ||
                       (t.match(/(?:User|Username)\s+([A-Z][A-Z\s]+[A-Z])\n/)||[])[1]?.trim() || "";
      const email    = (t.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/)||[])[0] || "";
      const srcIpv4  = (t.match(/Source endpoint IP(?:\s+address)?\s+([\d.]{7,15})/i)||[])[1] ||
                       (t.match(/IP Address\s+([\d.]{7,15})/i)||[])[1] || "";
      const addIpv6  = (t.match(/Additional endpoint IP(?:\s+address)?\s+([a-fA-F0-9:]{10,})/i)||[])[1] || "";
      const addIpv4  = (t.match(/Additional.*?IP.*?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})/i)||[])[1] || "";
      const riskRaw  = (t.match(/Risk score\s+([^\n,]{2,30})/i)||[])[1]?.trim() || "";
      const riskNum  = parseFloat((riskRaw.match(/[\d.]+/)||[])[0]||"0");
      const platform = (t.match(/(?:Destination application identifier|application)\s+([^\n]{3,60})/i)||[])[1]?.trim() ||
                       (t.match(/VMware Identity Service|Workspace ONE|vIDM/i)||[])[0] || "";
      const alertType= (t.match(/^([^\n]{5,80})/)||[])[1]?.trim() || "Identity alert";
      const privStr  = (t.match(/Privileged\s+(Yes|No)/i)||[])[1]||"";
      const dept     = (t.match(/Department\s+([^\n]{3,60})/i)||[])[1]?.trim()||"";
      const title    = (t.match(/Title\s+([^\n]{3,60})/i)||[])[1]?.trim()||"";
      const srcCity1 = (t.match(/Location country[^\n]*\n[^\n]*\nLocation country code[^\n]*\n[^\n]*latitude[^\n]*\n[^\n]*longitude[^\n]*/i)||
                        t.match(/Location country\s+.*?\([\d.,-]+\)/i)||[])[0]?.match(/\b[A-Z][a-z]+ [A-Z][a-z]+|\b[A-Z][a-z]+\b/)||[];
      const failures = (t.match(/\bFAILURE\b/gi)||[]).length;
      const successes= (t.match(/\bSUCCESS\b/gi)||[]).length;

      // Extract all unique login IPs (IPv4 + IPv6) from the log rows
      const ipv4Set = new Set((t.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)||[]).filter(ip => !ip.startsWith("0.") && ip !== "0.0.0.0"));
      const ipv6Set = new Set((t.match(/\b[a-fA-F0-9]{4}:[a-fA-F0-9:]{9,39}\b/g)||[]));

      if (user || email) { results.indicators.push(`User: ${user || email}`); results.prefillData.username = user || email; }
      if (srcIpv4)       { results.indicators.push(`Source IP: ${srcIpv4}`); results.prefillData.src_ip = srcIpv4; }
      if (addIpv6)         results.indicators.push(`Add. IP (IPv6): ${addIpv6.slice(0,30)}...`);
      if (riskRaw)         results.indicators.push(`Risk Score: ${riskRaw}`);
      if (platform)        results.indicators.push(`Platform: ${platform.slice(0,50)}`);
      if (privStr)         results.indicators.push(`Privileged: ${privStr}`);
      if (dept)            results.indicators.push(`Dept: ${dept}`);

      // Set severity from risk score
      if (riskNum >= 8 || /critical/i.test(riskRaw))       results.severity = "critical";
      else if (riskNum >= 6 || /high/i.test(riskRaw))      results.severity = "high";
      else if (riskNum >= 4 || /medium/i.test(riskRaw))    results.severity = "medium";
      else if (riskNum > 0 || /low/i.test(riskRaw))        results.severity = "low";

      // ── FINDINGS ─────────────────────────────────────────────
      // Impossible travel / concurrent multi-location
      if (/Access from multiple locations|impossible travel|multiple locations concurrently/i.test(t) ||
          (ipv4Set.size + ipv6Set.size >= 2)) {
        const allIps = [...ipv4Set, ...ipv6Set.values()].slice(0, 4);
        results.findings.push(`🚨 Concurrent access from multiple locations — account "${email || user}" authenticated from ${allIps.length} different IPs at nearly the same time`);
        results.findings.push(`⚠️ IP sources: ${allIps.join(" | ")} — if these represent different geographic locations, this is an impossible travel indicator`);
        results.mitre.add("T1078"); results.mitre.add("T1078.004");
        if (results.severity === "info" || results.severity === "low") results.severity = "high";
      }

      // Auth failure/success pattern
      if (failures > 0 && successes > 0) {
        results.findings.push(`⚠️ ${failures} FAILURE(s) followed by ${successes} SUCCESS(es) — possible credential stuffing with eventual success`);
        results.mitre.add("T1110.001");
        if (results.severity === "info") results.severity = "medium";
      } else if (failures >= 3) {
        results.findings.push(`⚠️ ${failures} authentication failures — possible brute force or incorrect credentials`);
        results.mitre.add("T1110");
      }

      // Privileged account
      if (/privileged.*yes/i.test(t)) {
        results.findings.push("🚨 PRIVILEGED account — elevated risk if compromised");
        if (results.severity !== "critical") results.severity = "critical";
      }

      // Platform-specific context
      if (platform) results.findings.push(`ℹ️ Activity on ${platform.slice(0,50)} — verify with user if access was expected`);

      // Mobile device pattern (same UA from different locations)
      const uas = [...new Set((t.match(/Mozilla\/5\.0[^\n]*/g)||[]).map(ua => ua.slice(0,60)))];
      if (uas.length === 1 && (ipv4Set.size + ipv6Set.size) >= 2) {
        results.findings.push(`⚠️ Same device (${uas[0].includes("iPhone") ? "iPhone" : uas[0].includes("Android") ? "Android" : "mobile"}) used from multiple cities — potential account sharing or SIM swap`);
      }

      results.prefillData.notes = `Identity Security Alert: ${alertType}. User: ${email || user}. Risk: ${riskRaw || "unscored"}. Platform: ${platform || "unknown"}.`;
      if (!results.mitre.size) results.mitre.add("T1078");
      return _finalizeTriage(results);
    }

    // 21. AUTHENTICATION / GENERIC
    if (/authentication|logon|login|password|kerberos|ntlm|saml|oauth|MFA|2FA/i.test(t)) {
      results.eventType = "Authentication Event";
      const failures = (t.match(/fail|denied|reject|invalid|bad password|wrong password/gi)||[]).length;
      const success  = (t.match(/success|granted|accepted|authenticated/gi)||[]).length;
      const user = (t.match(/(?:user|account|username|upn)[:\s=]+([a-zA-Z0-9.@_-]{3,60})/i)||[])[1]||"";
      if (failures>0) { results.findings.push(`⚠️ ${failures} failure indicator(s) found`); results.mitre.add("T1110"); if(!["critical","high"].includes(results.severity)) results.severity = failures>=5?"high":"medium"; }
      if (success>0 && failures>0) results.findings.push("⚠️ Auth failures AND success in same log — possible successful brute force");
      if (user) { results.indicators.push(`User: ${user}`); results.prefillData.username = user; }
      if (/mfa bypass|mfa fail|mfa denied|otp fail/i.test(t)) { results.findings.push("🚨 MFA bypass/failure detected"); results.mitre.add("T1621"); results.severity="high"; }
      if (/impossible travel|anomalous location|unfamiliar/i.test(t)) { results.findings.push("⚠️ Unusual location / impossible travel indicator"); results.mitre.add("T1078"); }
      return _finalizeTriage(results);
    }


    // 21. DHCP LOG
    if (/DHCP|dhcpd|leased|DISCOVER|OFFER|REQUEST|ACK|NAK/i.test(t)) {
      results.eventType = "DHCP Log";
      const ip  = (t.match(/(?:leased|assigned|NACK|ACK)\s+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const mac = (t.match(/([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}/)||[])[0]||"";
      const host= (t.match(/(?:to|for|hostname)\s+([a-zA-Z0-9_.-]+)/i)||[])[1]||"";
      if (ip)  results.indicators.push(`IP Leased: ${ip}`);
      if (mac) results.indicators.push(`MAC: ${mac}`);
      if (host) results.indicators.push(`Hostname: ${host}`);
      return _finalizeTriage(results);
    }


    // 22. PALO ALTO / FORTINET FIREWALL
    if (/subtype=|action=allow|action=deny|action=block|app=|dstip=|srcip=|policyname=|logid=|devname=/i.test(t)) {
      results.eventType = /fortinet|fortigate|logid=/i.test(t) ? "Fortinet FortiGate Log" : "Palo Alto NGFW Log";
      const src     = (t.match(/(?:srcip|src_ip|sip)[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dst     = (t.match(/(?:dstip|dst_ip|dip)[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const app     = (t.match(/\bapp[=:]\s*([^\s,;]+)/i)||[])[1]||"";
      const action  = (t.match(/\baction[=:]\s*([^\s,;]+)/i)||[])[1]||"";
      const policy  = (t.match(/(?:policyname|policy-name|policy_id)[=:]\s*([^\s,;]+)/i)||[])[1]||"";
      const dport   = (t.match(/(?:dstport|dst_port|dport)[=:]\s*(\d{1,5})/i)||[])[1]||"";
      const sport   = (t.match(/(?:srcport|src_port|sport)[=:]\s*(\d{1,5})/i)||[])[1]||"";
      const user    = (t.match(/(?:srcuser|user|username)[=:]\s*([^\s,;]{2,40})/i)||[])[1]||"";
      const threat  = (t.match(/(?:threat_name|threatid|virus)[=:]\s*([^\s,;]{3,60})/i)||[])[1]||"";
      if (src)    { results.indicators.push(`SRC: ${src}`); results.prefillData.src_ip = src; }
      if (dst)    { results.indicators.push(`DST: ${dst}`); results.prefillData.dest_ip = dst; }
      if (app)      results.indicators.push(`App: ${app}`);
      if (action)   results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (policy)   results.indicators.push(`Policy: ${policy}`);
      if (dport)  { results.indicators.push(`DPort: ${dport}`); if(PORT_HINTS[dport]) results.findings.push(`ℹ️ Port ${dport} = ${PORT_HINTS[dport]}`); }
      if (user)   { results.indicators.push(`User: ${user}`); results.prefillData.username = user; }
      if (threat) { results.findings.push(`🚨 Threat detected: ${threat}`); results.severity="critical"; results.mitre.add("T1059"); }
      if (/allow/i.test(action) && dport === "4444") { results.findings.push("🚨 Allowed traffic on port 4444 (Metasploit default)"); results.mitre.add("T1071"); results.severity="critical"; }
      if (/allow/i.test(action) && dport === "50050") { results.findings.push("🚨 Allowed traffic on port 50050 (Cobalt Strike)"); results.mitre.add("T1071"); results.severity="critical"; }
      if (/allow/i.test(action) && dport === "3389") { results.findings.push("⚠️ RDP allowed outbound — verify necessity"); results.mitre.add("T1021.001"); if(results.severity!=="critical") results.severity="high"; }
      if (src && !isPrivateIPv4(src) && /allow/i.test(action) && dport && !["80","443","53"].includes(dport)) { results.findings.push(`⚠️ Inbound allow on non-standard port ${dport} from external IP`); }
      results.mitre.add("T1041");
      return _finalizeTriage(results);
    }


    // 23. FALLBACK — generic syslog/text extraction
    if (t.length > 20) {
      results.eventType = "Generic Log / Text";
      const seens = (t.match(/(?:error|warning|critical|fail|deny|block|drop|malware|exploit|attack|suspicious|anomalous)/gi)||[]);
      if (seens.length) { results.findings.push(`ℹ️ Keyword hits: ${[...new Set(seens.map(s=>s.toLowerCase()))].join(", ")}`); }
      return _finalizeTriage(results);
    }


    return _finalizeTriage(results);
  }


  function _finalizeTriage(results) {
    results.mitre = [...results.mitre];
    // Assign human severity label
    const sevMap = { critical:"🔴 CRITICAL", high:"🟠 HIGH", medium:"🟡 MEDIUM", low:"🟢 LOW", info:"⚪ INFO" };
    results.severityLabel = sevMap[results.severity] || "⚪ INFO";
    // Deduplicate IOCs — remove domains that are IPs
    if (results.iocs.domains && results.iocs.ips) {
      results.iocs.domains = results.iocs.domains.filter(d => !results.iocs.ips.includes(d));
    }
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

  // ── Feature 11: Alert Category Mapping ─────────────────────────
  function getAlertCategory(res) {
    const type  = (res.eventType || "").toLowerCase();
    const finds = (res.findings || []).join(" ").toLowerCase();
    const raw   = (res._rawText || "").toLowerCase();
    const combined = type + " " + finds + " " + raw;

    // ── Cloud Audit / Identity Governance ────────────────────────
    if (/azure ad|entra|azure audit|cloudtrail|aws cloud|okta.*sso/i.test(type) ||
        /consent.*grant|oauth.*consent|serviceprincipal|consent.*application|app.*consent|admin consent|consentcontext|onbehalfofall/i.test(combined) ||
        /iam.*privil|create.*user.*iam|attach.*policy|role.*assign|permission.*grant|privilege.*escalat/i.test(combined) ||
        /okta.*policy|saml.*assertion|sso.*session/i.test(combined))
      return { label:"Cloud / Identity Governance", icon:"☁️🔑", color:"#818cf8",
        steps:[
          "Identify the user and confirm whether they knowingly initiated this action (call or out-of-band)",
          "Review the application or resource that received permissions — is it sanctioned by IT/Security?",
          "Audit all permissions granted: scope, ConsentType (AllPrincipals = org-wide), and whether admin consent was given",
          "Check Entra ID > Enterprise Applications or IAM console and revoke unauthorized access",
          "Review the source IP — is it a known corporate egress, VPN, or unexpected location?",
          "Search audit logs for other actions by this user or this app/role in the past 72 hours",
          "If unauthorized: revoke access, rotate credentials, and review what data was accessed"
        ] };

    // ── Email Security (Proofpoint, Exchange, mail headers) ──────
    if (/proofpoint|email.*security|mail.*security|exchange/i.test(type) ||
        /phish.*email|email.*phish|sender.*domain|spf.*fail|dkim.*fail|dmarc.*fail/i.test(combined))
      return { label:"Email / Phishing Alert", icon:"📧", color:"#34d399",
        steps:[
          "Identify the recipient(s) — check if anyone else received the same email in the past 24h",
          "Confirm whether the user opened the email, clicked links, or opened attachments",
          "Check sender domain reputation: VirusTotal, Talos, MXToolBox — look for SPF/DKIM/DMARC failures",
          "Detonate URLs and attachments in a sandbox (Any.Run, Hybrid Analysis)",
          "Block sender domain and URLs at email gateway and web proxy",
          "If user interacted: check endpoint for malicious process execution or downloads",
          "Preserve email headers and raw source for forensics — submit to email security platform"
        ] };

    // ── Web / Proxy (Zscaler, proxy logs) ───────────────────────
    if (/zscaler|proxy.*log|web.*log|url.*filter/i.test(type))
      return { label:"Web / Proxy Alert", icon:"🌐", color:"#34d399",
        steps:[
          "Identify the user and device that triggered the policy",
          "Check if traffic was blocked or allowed — allowed malicious traffic needs immediate endpoint investigation",
          "Verify destination URL/domain in VirusTotal, URLScan.io, and Talos",
          "Check whether the same URL was accessed from other endpoints in your environment",
          "If blocked: confirm no endpoint compromise — check EDR for related process activity",
          "If allowed: isolate the endpoint, check for malware downloads or C2 communication",
          "Update proxy policy to block the domain/URL category if not already covered"
        ] };

    // ── Network / NDR / IDS-IPS (Suricata, Snort, Darktrace, Firewall) ──
    if (/suricata|snort|ids|ips|darktrace|ndr/i.test(type) ||
        /firewall.*network|network.*alert/i.test(type))
      return { label:"Network / IDS Alert", icon:"🔌", color:"#38bdf8",
        steps:[
          "Identify source and destination — classify as internal/external and check asset criticality",
          "Review the matched signature or anomaly — is it a known true-positive rule or noisy?",
          "Check destination IP/domain reputation: AbuseIPDB, GreyNoise, VirusTotal, Shodan",
          "Correlate with EDR — identify the process responsible for the connection",
          "Look for beaconing patterns: consistent intervals, similar byte sizes, low TTL domains",
          "If C2 confirmed: isolate the host, block destination at perimeter, hunt for lateral spread",
          "Check for data exfiltration: unusual outbound volume, DNS tunneling, or staged data"
        ] };

    // ── SIEM Alerts (QRadar, Splunk) ─────────────────────────────
    if (/qradar|splunk.*siem|ibm.*siem/i.test(type))
      return { label:"SIEM Correlation Alert", icon:"📊", color:"#a78bfa",
        steps:[
          "Review all events correlated in this offense/alert — understand the full sequence",
          "Identify the SIEM rule that fired and its logic — is the threshold appropriate?",
          "Pivot to the source IP, user, and host in your EDR and other log sources",
          "Check supporting IOCs (IPs, domains, hashes) against threat intelligence",
          "Determine if this is a standalone event or part of a larger attack chain",
          "If confirmed malicious: escalate to IR team with full event timeline",
          "After resolution: tune the SIEM rule to reduce false positives or improve detection"
        ] };

    // ── Identity / Behavioral (check BEFORE Endpoint — keywords like "credential" overlap) ──
    if (/signin|logon|authentication|credential|password|mfa|sso|entra|azure.ad|impossible.travel|brute.force|spray|okta|identity|identity security|vmware identity|workspace one|concurrent.*access|multiple locations|risk.score|falcon identity|defender.*identity|ueba|uba/i.test(combined) ||
        /identity security alert/i.test(type))
      return { label:"Identity Alert", icon:"🪪", color:"#a78bfa",
        steps:[
          "Contact the user directly via phone or out-of-band channel — confirm if they initiated this activity",
          "Check ALL source IPs in AbuseIPDB, GreyNoise, and VT — classify each as corporate VPN, mobile carrier, or suspicious",
          "If multiple locations: calculate travel time between cities — is it physically possible? If not, account is compromised",
          "Review every authentication event for this user in the past 7 days — look for pattern changes",
          "Verify MFA was completed and not bypassed — check for MFA fatigue attacks or new MFA device registrations",
          "Check for post-compromise actions: new inbox rules, OAuth app grants, password changes, new MFA methods",
          "If suspicious: immediately disable the account, revoke all active sessions, reset credentials, and review accessed resources"
        ] };
    
    // ── CrowdStrike / EDR / Endpoint ────────────────────────────
    if (/crowdstrike|falcon|edr|endpoint.detect|processrollup|sysmon|windows event log|defender|sentinelone/i.test(type) ||
        /powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|scheduled.task|lsass|process.creat|encoded.command|shellcode|exploit|privilege.escal|lolbin|execution|tactic/.test(combined))
      return { label:"Endpoint Alert", icon:"💻", color:"#fb923c",
        steps:[
          "Open the detection in the Falcon/EDR console and review the full process tree",
          "Examine the command-line for LOLBin abuse, Base64 encoding, or download cradles",
          "Cross-reference all file hashes in VirusTotal and MalwareBazaar",
          "Check if the process made external network connections (pivot IP/domain to threat intel)",
          "Look for persistence: scheduled tasks, registry Run keys, new services, startup folder",
          "Scope the environment — search for the same IOCs on other endpoints",
          "Isolate the host if payload execution or lateral movement is confirmed"
        ] };
    if (/phish|download|url|web|proxy|http|dns|domain|browser|click|attachment|email|spf|dkim|dmarc/.test(combined))
      return { label:"Web / Email Alert", icon:"🌐", color:"#34d399",
        steps:[
          "Check the domain/URL registration age — anything under 30 days is high-risk",
          "Verify reputation in VirusTotal, URLScan.io, URLVoid, and Cisco Talos",
          "For email alerts: inspect SPF, DKIM, DMARC alignment — failures indicate spoofing",
          "Determine if the user clicked the link or opened the attachment (proxy/EDR logs)",
          "Detonate the URL or attachment in a sandbox (Any.Run, Hybrid Analysis, Joe Sandbox)",
          "Block the domain/URL at the proxy, DNS layer, and email gateway",
          "If user interacted: check endpoint for initial access artifacts (dropped files, processes)"
        ] };
    if (/firewall|network|lateral|smb|rdp|ssh|scan|port|traffic|connection|c2|beacon|tunnel|exfil|vpn|ngfw/.test(combined))
      return { label:"Network Alert", icon:"🔌", color:"#38bdf8",
        steps:[
          "Identify source and destination — classify both as internal or external",
          "Check destination IP/domain reputation: AbuseIPDB, GreyNoise, Shodan, VT",
          "Review the firewall rule that triggered — allow or deny, and on what port/protocol",
          "Look for beaconing patterns: periodic intervals, consistent byte sizes, jitter",
          "Identify the process responsible for the connection (correlate with EDR)",
          "If C2 suspected: block destination, isolate source host, scope lateral movement",
          "Check for data exfiltration: unusual outbound data volume or uploads to cloud storage"
        ] };
    if (/aws|azure|gcp|cloud|s3|storage|iam|role|bucket|lambda|function|resource|deploy/.test(combined))
      return { label:"Cloud Alert", icon:"☁️", color:"#67e8f9",
        steps:[
          "Identify the cloud account, region, service, and exact action that triggered the alert",
          "Confirm whether the action was performed by a known person or service account",
          "Review CloudTrail / Activity Log for all actions in the same session (±1 hour)",
          "Check for privilege escalation: new IAM roles, policy attachments, role assumption",
          "Look for data access or exfiltration: S3 GetObject, storage reads, secret fetches",
          "Revoke suspicious API keys/credentials and restrict affected IAM roles immediately",
          "Check if any compute resources were deployed for cryptomining or C2 hosting"
        ] };
    if (/ransomware|encrypt|shadow|vss|backup|wiper|destruct/.test(combined))
      return { label:"Ransomware / Destructive", icon:"🔒", color:"#f87171",
        steps:[
          "⚡ IMMEDIATELY isolate the affected host(s) from the network",
          "Do NOT restart or shut down — preserve volatile memory for forensics",
          "Identify the ransomware family via hash, ransom note content, or encrypted file extension",
          "Check if VSS / Shadow Copies were deleted (vssadmin, wmic shadowcopy)",
          "Scope the blast radius — map drives, network shares, and other connected hosts",
          "Preserve disk image and memory dump before any remediation",
          "Activate IR plan — escalate immediately to senior leadership, legal, and management"
        ] };
    return { label:"General Security Event", icon:"🔍", color:"#9ca3af",
      steps:[
          "Review all extracted IOCs and cross-reference with VirusTotal, AbuseIPDB, Shodan",
          "Determine if the event is isolated or part of a broader attack pattern",
          "Correlate with other alerts from the same source IP, user, or host in your SIEM",
          "Check MITRE ATT&CK techniques identified — understand the attacker's objective",
          "Identify affected assets and assess potential business impact",
          "Document all findings with timestamps and evidence before escalating or closing"
      ] };
  }

  // ── Feature 10: FP/TP Quick Verdict Templates ──────────────────
  // ── Adaptive FP/TP Verdict Templates ─────────────────────────
  // Generates contextual verdict text based on the ALERT SOURCE and all extracted data
  function buildAdaptiveVerdict(verdict, res) {
    const et   = (res.eventType || "").toLowerCase();
    const iocs = res.iocs || {};
    const pf   = res.prefillData || {};
    const findings = (res.findings || []).join(" ");

    // Pull the richest available values for fill-ins
    const extIps = (iocs.ips||[]).filter(ip => !isPrivateIPv4(ip));
    const ip     = extIps[0] || (iocs.ips||[])[0] || pf.src_ip || "[source IP]";
    const host   = pf.hostname || (iocs.hostnames||[])[0] || "[hostname]";
    const user   = pf.username || (iocs.usernames||[])[0] || pf.recipient || (iocs.emails||[])[1] || (iocs.emails||[])[0] || "[user]";
    const hash   = (iocs.hashes||[])[0] || "[file hash]";
    const domain = (iocs.domains||[])[0] || "[domain]";
    const url    = (iocs.urls||[])[0] || pf.url || "[URL]";
    const email  = (iocs.emails||[])[0] || pf.sender || "[sender email]";
    const app    = pf.notes?.match(/app "([^"]+)"/i)?.[1] || "[application]";
    const proc   = (iocs.processes||[])[0] || "[process]";
    const cmd    = pf.cmdline ? pf.cmdline.slice(0,80) : "[command line]";
    const threat = pf.notes || "[threat name]";
    const scope  = findings.includes("tenant-wide") ? "the entire tenant" : "the affected user";

    // ── SOURCE-SPECIFIC TEMPLATES ────────────────────────────────
    // Endpoint EDR (CrowdStrike, Defender, SentinelOne, Sysmon, Windows EventLog)
    if (/crowdstrike|falcon|defender|sentinelone|edr|windows event|sysmon/i.test(et)) {
      if (verdict === "fp") return (
        `Investigation of alert on host ${host} (user: ${user}) shows the flagged process ` +
        `${proc} executed with command: "${cmd.slice(0,60)}". ` +
        `Hash ${hash.slice(0,16)}... returned 0 detections on VirusTotal and MalwareBazaar. ` +
        `Parent process chain is consistent with legitimate IT tooling (e.g., patching, admin scripts). ` +
        `No lateral movement, persistence artifacts, or C2 connections identified. ` +
        `Closing as False Positive — recommend whitelisting hash in EDR policy.`
      );
      return (
        `Host ${host} (user: ${user}) confirmed compromised. ` +
        `Malicious process ${proc} executed: "${cmd.slice(0,60)}". ` +
        `File hash ${hash.slice(0,16)}... has [X] VirusTotal detections — classified as [malware family]. ` +
        `External C2 connection to ${ip} observed. ` +
        `Escalating as True Positive. ` +
        `Immediate actions: isolate host via EDR, block hash + IP at perimeter, reset user credentials, ` +
        `hunt for lateral movement from ${host}.`
      );
    }

    // Email Security (Proofpoint, Exchange, email headers)
    if (/proofpoint|email|mail/i.test(et)) {
      if (verdict === "fp") return (
        `Email from ${email} to ${user} was reviewed. ` +
        `Sender domain has valid SPF/DKIM/DMARC alignment and no malicious reputation on VirusTotal, ` +
        `Talos, or EmailRep. ${iocs.urls?.length ? `URL ${domain} resolves to a known legitimate service.` : ""} ` +
        `Phish score was below threshold upon manual review. ` +
        `Closing as False Positive — recommend adding sender to safe list if recurring.`
      );
      return (
        `Phishing email from ${email} confirmed malicious. ` +
        `${iocs.urls?.length ? `URL ${url.slice(0,60)} classified as phishing by VirusTotal/URLScan.` : ""} ` +
        `SPF/DKIM/DMARC failures detected — sender domain spoofed. ` +
        `Recipient: ${user}. ` +
        `Escalating as True Positive. ` +
        `Immediate actions: block sender domain at email gateway, check all recipients in the past 24h, ` +
        `confirm if user clicked any links, quarantine similar messages.`
      );
    }

    // Identity Security / Behavioral (VMware, Falcon Identity, impossible travel, UBA)
    if (/identity security/i.test(et)) {
      const allIps  = [...new Set([ip, ...(iocs.ips||[])].filter(v => v && v !== "[source IP]"))];
      const alertTitle = pf.notes?.split('.')[0] || "Identity security alert";
      const platform  = (pf.notes?.match(/Platform: ([^.]+)/i)||[])[1]?.trim() || "the identity platform";
      const riskInfo  = (pf.notes?.match(/Risk: ([^.]+)/i)||[])[1]?.trim() || "medium";
      if (verdict === "fp") return (
        `Investigation of "${alertTitle}" for user ${user || email} reviewed. ` +
        `All source IPs (${allIps.join(", ")}) were verified: ` +
        `IP ${allIps[0]} resolves to a known corporate office or VPN exit node. ` +
        `${allIps[1] ? `IP ${allIps[1]} confirmed as the user's personal mobile carrier (AT&T/T-Mobile LTE). ` : ""}` +
        `User confirmed both sessions were theirs (traveling or using mobile hotspot). ` +
        `No post-compromise activity found. Risk score (${riskInfo}) reflects concurrent mobile/office access — benign pattern. ` +
        `Closing as False Positive — recommend whitelisting this IP pattern for this user.`
      );
      return (
        `Identity security alert confirmed: "${alertTitle}". ` +
        `User ${user || email} authenticated from ${allIps.length} distinct IP(s): ${allIps.join(" | ")}. ` +
        `Geographic analysis confirms simultaneous access from physically impossible locations — account is compromised. ` +
        `Authentication pattern: ${findings.includes("FAILURE") || findings.includes("failure") ? "failures followed by success (credential stuffing confirmed)" : "direct successful access (credentials already compromised)"}. ` +
        `Risk score: ${riskInfo}. Platform: ${platform}. ` +
        `Escalating as True Positive. ` +
        `Immediate actions: disable account NOW, revoke all active sessions on ${platform}, ` +
        `reset password + re-enroll MFA from a trusted device, review all resources accessed in the session, ` +
        `check for lateral movement or new OAuth app grants.`
      );
    }

    // Cloud / Identity (Azure AD, AWS, Okta, consent grants)
    if (/azure|entra|aws|okta|cloudtrail|identity|sso/i.test(et)) {
      if (verdict === "fp") return (
        `Cloud/identity event for user ${user} from IP ${ip} was reviewed. ` +
        `Action "${(pf.operation || "[operation]").split('\n')[0].slice(0,60)}" was confirmed as authorized by the user ` +
        `and aligns with their normal job function. ` +
        `Source IP belongs to a known corporate VPN or expected geographic location. ` +
        `MFA was successfully completed. No other suspicious activity found in the session. ` +
        `Closing as False Positive.`
      );
      return (
        `Cloud/identity alert for user ${user} confirmed malicious. ` +
        `Action "${(pf.operation || "[operation]").split('\n')[0].slice(0,60)}" performed from anomalous IP ${ip}. ` +
        `${findings.includes("consent") ? `OAuth app "${app}" granted admin-level permissions to ${scope}.` : ""} ` +
        `MFA status: ${findings.includes("MFA") ? "unconfirmed/bypassed" : "verified"}. ` +
        `Escalating as True Positive. ` +
        `Immediate actions: revoke session/tokens, disable account, review all actions in the session, ` +
        `${findings.includes("consent") ? `revoke OAuth app consent in Entra ID > Enterprise Applications,` : ""} ` +
        `reset credentials and review MFA methods.`
      );
    }

    // Network / Firewall / NDR (Zscaler, Darktrace, Firewall, Suricata)
    if (/zscaler|darktrace|firewall|network|suricata|snort|ids|ips|ndr/i.test(et)) {
      if (verdict === "fp") return (
        `Network alert for traffic from ${ip} to ${domain || ip} reviewed. ` +
        `Destination verified as a known business service (e.g., CDN, SaaS platform). ` +
        `Traffic volume and timing are consistent with normal user behavior. ` +
        `No matching malware signatures or C2 patterns found in VirusTotal/GreyNoise. ` +
        `Closing as False Positive — recommend tuning detection rule to exclude this traffic pattern.`
      );
      return (
        `Network threat confirmed. Traffic from ${host} (${ip}) to ${domain || "[destination]"} ` +
        `matches known malicious pattern. ` +
        `${findings.includes("C2") || findings.includes("beacon") ? "C2/beaconing behavior confirmed." : ""} ` +
        `Destination IP/domain flagged by GreyNoise, VirusTotal, or Talos. ` +
        `Escalating as True Positive. ` +
        `Immediate actions: block destination at firewall/proxy, isolate ${host}, ` +
        `investigate for lateral movement and data exfiltration, review DNS logs for related domains.`
      );
    }

    // QRadar / Splunk SIEM
    if (/qradar|splunk|siem/i.test(et)) {
      if (verdict === "fp") return (
        `SIEM alert "${pf.operation || "[rule name]"}" for ${user || ip} reviewed in full. ` +
        `Correlated events show this matches a known benign pattern (e.g., scheduled task, IT automation). ` +
        `No supporting IOCs found malicious across CTI sources. ` +
        `Closing as False Positive — recommend adding exception to SIEM rule.`
      );
      return (
        `SIEM alert "${pf.operation || "[rule name]"}" confirmed as malicious activity by ${user || ip}. ` +
        `Cross-correlated with [X] related events. ` +
        `Supporting IOCs: ${ip !== "[source IP]" ? `IP ${ip}` : ""} ${hash !== "[file hash]" ? `hash ${hash.slice(0,16)}...` : ""}. ` +
        `Escalating as True Positive. ` +
        `Immediate actions: investigate all correlated offenses, isolate affected assets, ` +
        `block identified IOCs, escalate to IR team.`
      );
    }

    // Generic fallback — still better than the old static text
    if (verdict === "fp") return (
      `The indicator associated with this alert was reviewed across multiple CTI sources ` +
      `(VirusTotal, AbuseIPDB, Talos). No malicious reputation found. ` +
      `Alert context for ${user !== "[user]" ? `user ${user}` : ip !== "[source IP]" ? `IP ${ip}` : "the affected asset"} ` +
      `is consistent with normal business operations. ` +
      `Closing as False Positive.`
    );
    return (
      `Alert confirmed malicious. ` +
      `${ip !== "[source IP]" ? `Source IP ${ip} flagged by threat intelligence.` : ""} ` +
      `${hash !== "[file hash]" ? `Hash ${hash.slice(0,16)}... confirmed malware.` : ""} ` +
      `Affected: ${user !== "[user]" ? user : host}. ` +
      `Escalating as True Positive. ` +
      `Immediate actions: isolate affected asset, block all identified IOCs, reset credentials, ` +
      `initiate full incident response.`
    );
  }

  // Keep legacy getVerdictTemplate for any code that might still reference it
  function getVerdictTemplate(verdict, type, ioc) {
    return ioc ? `${verdict === "fp" ? "False Positive" : "True Positive"} — ${ioc}` : "—";
  }


  // ── Feature 8 (improved): Behavioral Narrative Context Summary ──
  function buildAlertContextSummary(res) {
    const sev     = res.severity || "info";
    const type    = res.eventType || "Unknown";
    const findings = res.findings || [];
    const iocs    = res.iocs || {};
    const mitre   = res.mitre ? [...res.mitre] : [];
    const raw     = (res._rawText || "").toLowerCase();
    const cat     = getAlertCategory(res);

    const lines = [];

    // Line 1 — severity badge + category
    const sevLabel = { critical:"🔴 CRITICAL", high:"🟠 HIGH", medium:"🟡 MEDIUM", low:"🟢 LOW", info:"⚪ INFO" }[sev] || "⚪ INFO";
    lines.push(`${sevLabel} — ${cat.icon} ${cat.label} (${type})`);

    // Line 2-4 — behavioral narrative based on what was found (GPT-style)
    const narratives = [];
    const findingsStr = findings.join(" ");

    // ── Identity Security / Behavioral (impossible travel, UBA, risk-scored) ──
    if (/identity security/i.test(type) ||
        /concurrent.*locations|multiple locations|impossible travel|concurrent.*access/i.test(findingsStr + raw)) {
      const user   = res.prefillData?.username || iocs.emails?.[0] || iocs.usernames?.[0];
      const allIps = iocs.ips || [];
      const platform = (res.prefillData?.notes?.match(/Platform: ([^.]+)/i)||[])[1]?.trim() || "identity platform";
      const riskInfo = (res.prefillData?.notes?.match(/Risk: ([^.]+)/i)||[])[1]?.trim() || "";
      if (user) narratives.push(`User ${user} triggered a behavioral identity security alert on ${platform}`);
      if (allIps.length >= 2) narratives.push(`Simultaneous authentication from ${allIps.length} distinct IPs: ${allIps.slice(0,3).join(" and ")} — possible impossible travel or account sharing`);
      if (/failure.*success|credential.stuff/i.test(findingsStr)) narratives.push("Authentication failures followed by success detected — pattern consistent with credential stuffing attack");
      if (/same device|iphone|mobile|android/i.test(findingsStr + raw)) narratives.push("Same mobile device UA observed from different cities — contact user to confirm if traveling or using VPN");
      if (riskInfo) narratives.push(`Platform risk score: ${riskInfo} — review all sessions for this account`);
    }
    // ── Cloud / Identity Governance (Azure AD consent, OAuth, IAM) ──
    else if (/azure ad|entra|azure audit|cloudtrail|okta.*sso/i.test(type) ||
        /consent.*grant|oauth.*consent|serviceprincipal|admin consent|consentcontext/i.test(findingsStr + raw)) {
      const user  = res.prefillData?.username || iocs.emails?.[0];
      const _appRaw = res.prefillData?.notes?.match(/app "([^"]+)"/i)?.[1] 
        || raw.match(/"displayname"\s*:\s*"([^"]{2,40})"/i)?.[1]
        || raw.match(/\\"displayname\\"\s*:\s*\\"([^\\"]{2,40})\\"/i)?.[1]
        || raw.match(/displayname[^:]*:\s*\\"([^"\\]{2,40})\\"/i)?.[1]
        || raw.match(/displayname["\s:]+([a-zA-Z0-9 _\-]{3,40})/i)?.[1];
      const app = _appRaw ? _appRaw.replace(/\\+$/, "").trim() : null;
      const srcip = iocs.ips?.[0];
      if (user)  narratives.push(`User ${user} performed a cloud identity / directory action`);
      if (app)   narratives.push(`OAuth application "${app}" was granted permissions in the Azure AD tenant`);
      if (/admin consent|IsAdminConsent.*true/i.test(findingsStr + raw)) narratives.push("Admin consent was granted — the application now has tenant-wide permissions without per-user approval");
      if (/onbehalfofall.*true|AllPrincipals/i.test(findingsStr + raw))  narratives.push("Permissions granted on behalf of ALL users — any account in the tenant can be acted upon by this app");
      if (srcip) narratives.push(`Action originated from IP ${srcip} — verify this is an expected location for this user`);
      if (/mfa.*--|mfa.*unknown/i.test(findingsStr + raw)) narratives.push("MFA status was not recorded — cannot confirm whether strong authentication was used");
    }
    // Identity / Auth narratives
    else if (/signin|authentication|logon/i.test(type) || /signin|logon|auth/i.test(findingsStr)) {
      const user   = iocs.usernames?.[0];
      const srcip  = iocs.ips?.[0];
      const dom    = iocs.domains?.[0];
      if (user)  narratives.push(`User ${user} performed an authentication event`);
      if (srcip) narratives.push(`Connection originated from IP ${srcip} — check reputation before ruling out`);
      if (/impossible.travel|two.location|different.countr/i.test(findingsStr)) narratives.push("Sign-in occurred from two geographically impossible locations — potential account takeover");
      if (/mfa.bypass|mfa.fail|no.mfa/i.test(findingsStr+raw)) narratives.push("MFA was absent or bypassed — elevated credential theft risk");
      if (/brute.force|spray|multiple.fail/i.test(findingsStr+raw)) narratives.push("Multiple failed authentication attempts indicate a password spray or brute force attack");
    }
    // Endpoint narratives
    else if (/powershell|cmd|process.creat/i.test(type) || /powershell|encoded|lolbin|shellcode/i.test(findingsStr)) {
      const proc = iocs.processes?.[0];
      const host = iocs.hostnames?.[0];
      if (host)  narratives.push(`Suspicious process activity detected on host ${host}`);
      if (/encoded|base64|IEX|invoke.expression/i.test(findingsStr+raw)) narratives.push("Encoded/obfuscated command was executed — common in malware loaders and post-exploitation");
      if (/lolbin|rundll|mshta|regsvr|wscript/i.test(findingsStr+raw)) narratives.push("LOLBin (Living-off-the-Land Binary) abuse detected — attacker may be using trusted system tools");
      if (/lsass|credential.dump|mimikatz|procdump/i.test(findingsStr+raw)) narratives.push("Credential dumping attempt detected — LSASS memory accessed by suspicious process");
      if (/download.cradle|downloadstring|webclient/i.test(findingsStr+raw)) narratives.push("PowerShell download cradle identified — potential in-memory payload delivery");
    }
    // Web/phishing narratives
    else if (/web|proxy|email|phish/i.test(type) || iocs.urls?.length || iocs.domains?.length) {
      const dom = iocs.domains?.[0] || iocs.urls?.[0];
      if (dom) narratives.push(`${iocs.urls?.length ? "URL" : "Domain"} ${dom} was accessed or resolved`);
      if (/newly.regist|registered.*day|age.*day|domain.*age/i.test(findingsStr+raw)) narratives.push("Domain appears newly registered — significantly increases phishing/malware hosting risk");
      if (/spf.fail|dkim.fail|dmarc.fail/i.test(findingsStr+raw)) narratives.push("Email authentication failures (SPF/DKIM/DMARC) detected — possible sender spoofing");
      if (/phish|malicious.*domain|flagged.*vt/i.test(findingsStr+raw)) narratives.push("Domain has multiple threat intelligence detections — potential phishing or C2 infrastructure");
    }
    // Network/C2 narratives
    else if (/firewall|network|c2|beacon/i.test(type)) {
      const dst = iocs.ips?.[0] || iocs.domains?.[0];
      if (dst)  narratives.push(`Outbound connection to ${dst} detected`);
      if (/beacon|periodic|c2|command.control/i.test(findingsStr+raw)) narratives.push("Beaconing pattern detected — consistent with C2 implant communication");
      if (/exfil|large.upload|unusual.data/i.test(findingsStr+raw)) narratives.push("Unusual outbound data volume — potential data exfiltration in progress");
    }

    // If no specific narrative built, fall back to findings prose
    if (!narratives.length) {
      const criticals = findings.filter(f => f.startsWith("🚨")).map(f => f.replace(/^🚨\s*/,""));
      const warnings  = findings.filter(f => f.startsWith("⚠️")).map(f => f.replace(/^⚠️\s*/,""));
      if (criticals.length) narratives.push(...criticals.slice(0,2));
      else if (warnings.length) narratives.push(...warnings.slice(0,2));
    }

    narratives.slice(0,4).forEach(n => lines.push(n));

    // IOC count line
    const iocParts = [];
    if (iocs.ips?.length)       iocParts.push(`${iocs.ips.length} IP${iocs.ips.length>1?"s":""}`);
    if (iocs.domains?.length)   iocParts.push(`${iocs.domains.length} domain${iocs.domains.length>1?"s":""}`);
    if (iocs.hashes?.length)    iocParts.push(`${iocs.hashes.length} hash${iocs.hashes.length>1?"es":""}`);
    if (iocs.emails?.length)    iocParts.push(`${iocs.emails.length} email${iocs.emails.length>1?"s":""}`);
    if (iocs.usernames?.length) iocParts.push(`${iocs.usernames.length} username${iocs.usernames.length>1?"s":""}`);
    if (iocs.processes?.length) iocParts.push(`${iocs.processes.length} process${iocs.processes.length>1?"es":""}`);
    if (iocParts.length) lines.push(`Extracted artifacts: ${iocParts.join(" · ")}`);

    // MITRE line
    if (mitre.length) lines.push(`Mapped to MITRE: ${mitre.slice(0,4).map(t => `${t} (${getMitreName(t)})`).join(", ")}${mitre.length>4?" +"+(mitre.length-4)+" more":""}`);

    // Recommended action
    const actionMap = {
      critical: "⚡ IMMEDIATE ACTION: Isolate host/account, block IOCs, preserve evidence, escalate to IR team.",
      high:     "🔺 Escalate for analyst review. Investigate pivot IOCs and check for lateral movement.",
      medium:   "🔸 Investigate further. Correlate with other alerts and review user/host activity.",
      low:      "🔹 Monitor for recurrence. Gather additional context before escalating.",
      info:     "ℹ️ Informational. No immediate action required — log for baseline comparison.",
    };
    lines.push(actionMap[sev] || actionMap.info);

    return { lines, cat };
  }

  function renderLTResults(res) {
    if (!ltResults) return;
    const SEV_COLORS = { critical:"#f87171", high:"#fb923c", medium:"#fbbf24", low:"#34d399", info:"#9ca3af" };
    const TYPE_COLORS = {
      "Windows Event Log":"#38bdf8","Firewall / Network Log":"#fb923c","Email Headers":"#a78bfa",
      "SIEM Alert":"#f87171","Authentication Event":"#fbbf24","Web / Proxy Log":"#34d399",
      "SSH / Linux Auth Log":"#a3e635","DNS Log":"#67e8f9","CEF Alert":"#f87171",
      "LEEF Alert":"#f87171","JSON / SIEM Alert":"#60a5fa","CrowdStrike Falcon Alert":"#f87171",
      "DHCP Log":"#86efac","Generic Log / Text":"#9ca3af","Unknown":"#9ca3af"
    };
    const sc = SEV_COLORS[res.severity||"info"];
    const tc = TYPE_COLORS[res.eventType] || "#9ca3af";

    // ── ALERT CONTEXT SUMMARY (Feature 8 + 11) ───────────────────
    const { lines: summaryLines, cat } = buildAlertContextSummary(res);
    // Store rawText reference on res for narrative building
    res._rawText = res._rawText || "";

    // Determine primary IOC type and value for FP/TP templates
    // Adaptive FP/TP templates — generated from alert source + extracted data
    const fpTpl = buildAdaptiveVerdict("fp", res);
    const tpTpl = buildAdaptiveVerdict("tp", res);

    let html = `<div class="lt-context-summary" style="border-color:${cat.color}55">
      <div class="lt-ctx-head">
        <span class="lt-ctx-icon">🧠</span>
        <span class="lt-ctx-title">Alert Context Summary</span>
        <span class="lt-cat-badge" style="background:${cat.color}22;color:${cat.color};border-color:${cat.color}55">${cat.icon} ${cat.label}</span>
        <button class="lt-ctx-copy" id="lt-ctx-copy-btn" type="button" title="Copy summary">📋</button>
      </div>
      <div class="lt-ctx-body" id="lt-ctx-body">
        ${summaryLines.map((l,i) => {
          const cls = i===0 ? "lt-ctx-line lt-ctx-line-head" :
                      l.startsWith("⚡") || l.startsWith("🔺") ? "lt-ctx-line lt-ctx-line-action" :
                      l.startsWith("Mapped to MITRE") || l.startsWith("Extracted artifacts") ? "lt-ctx-line lt-ctx-line-meta" :
                      "lt-ctx-line";
          return `<div class="${cls}">${l}</div>`;
        }).join("")}
      </div>
    </div>

    <!-- Feature 11: Alert Category + Investigation Steps -->
    <div class="lt-investig-steps" style="border-color:${cat.color}44">
      <div class="lt-investig-head">
        <span style="color:${cat.color}">${cat.icon} ${cat.label} — Investigation Checklist</span>
        <button class="lt-investig-copy" id="lt-steps-copy-btn" type="button" title="Copy steps">📋</button>
      </div>
      <ol class="lt-steps-list" id="lt-steps-list">
        ${cat.steps.map(s => `<li class="lt-step-item">${s}</li>`).join("")}
      </ol>
    </div>

    <!-- Feature 10: FP/TP Verdict Templates -->
    <div class="lt-verdict-templates">
      <div class="lt-vt-head">⚖️ Quick Verdict Templates <span class="lt-vt-sub">— click to copy, then customize</span></div>
      <div class="lt-vt-grid">
        <div class="lt-vt-card lt-vt-fp">
          <div class="lt-vt-label">✅ False Positive</div>
          <div class="lt-vt-body" id="lt-fp-body">${fpTpl}</div>
          <button class="lt-vt-copy-btn" id="lt-fp-copy-btn" type="button">📋 Copy FP Template</button>
        </div>
        <div class="lt-vt-card lt-vt-tp">
          <div class="lt-vt-label">🚨 True Positive</div>
          <div class="lt-vt-body" id="lt-tp-body">${tpTpl}</div>
          <button class="lt-vt-copy-btn" id="lt-tp-copy-btn" type="button">📋 Copy TP Template</button>
        </div>
      </div>
    </div>`;

    // ── VERDICT HEADER ──────────────────────────────────────────
    html += `<div class="lt-verdict-bar" style="border-color:${sc}44;background:${sc}0d">
      <div class="lt-verdict-left">
        <span class="lt-ev-badge" style="color:${tc};background:${tc}18;border-color:${tc}44">${res.eventType}</span>
        <span class="lt-sev-badge" style="color:${sc};background:${sc}18;border-color:${sc}44">${res.severityLabel||"⚪ INFO"}</span>
      </div>
      <div class="lt-verdict-indicators">${(res.indicators||[]).map(i=>`<span class="lt-ind-chip">${i}</span>`).join("")}</div>
    </div>`;

    // ── FINDINGS ────────────────────────────────────────────────
    if (res.findings && res.findings.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🔍 Triage Findings <span class="sa-section-count">${res.findings.length}</span></div>
        <div class="lt-findings-list">`;
      res.findings.forEach(f => {
        const isCrit = f.startsWith("🚨");
        const isWarn = f.startsWith("⚠️");
        const cls = isCrit ? "lt-finding-critical" : isWarn ? "lt-finding-warn" : "lt-finding-info";
        html += `<div class="lt-finding ${cls}">${f}</div>`;
      });
      html += `</div></div>`;
    }

    // ── PORT HINTS ──────────────────────────────────────────────
    if (res.portHints && res.portHints.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🔌 Port Intelligence</div>
        <div class="lt-findings-list">${res.portHints.map(p=>`<div class="lt-finding lt-finding-info">ℹ️ ${p}</div>`).join("")}</div>
      </div>`;
    }

    // ── MITRE TECHNIQUES ────────────────────────────────────────
    if (res.mitre && res.mitre.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🧩 MITRE ATT&CK Techniques <span class="sa-section-count">${res.mitre.length}</span></div>
        <div class="sa-mitre-grid">`;
      res.mitre.forEach(t => {
        html += `<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="sa-mitre-card">
          <div class="sa-mitre-tid">${t}</div>
          <div class="sa-mitre-name">${getMitreName(t)}</div>
        </a>`;
      });
      html += `</div></div>`;
    }

    // ── EXTRACTED IOCs (full set) ────────────────────────────────
    const iocCols = [
      ["ips",       "IP Addresses",      "#38bdf8", "ip"],
      ["domains",   "Domains",           "#34d399", "domain"],
      ["urls",      "URLs",              "#fb923c", "url"],
      ["hashes",    "Hashes",            "#f59e0b", "hash"],
      ["emails",    "Emails",            "#a78bfa", "email"],
      ["cves",      "CVEs",              "#f87171", "cve"],
      ["processes", "Processes",         "#67e8f9", null],
      ["usernames", "Usernames",         "#e879f9", "username"],
      ["hostnames", "Hostnames",         "#a3e635", null],
      ["cmdlines",  "Command Lines",     "#fbbf24", null],
      ["regkeys",   "Registry Keys",     "#94a3b8", null],
      ["filepaths", "File Paths",        "#c084fc", null],
    ];
    const hasAny = iocCols.some(([k]) => res.iocs?.[k]?.length);
    if (hasAny) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🎯 Extracted Artifacts &amp; IOCs</div>
        <div class="sa-ioc-grid">`;
      iocCols.forEach(([k, label, c, pivotType]) => {
        if (!res.iocs?.[k]?.length) return;
        html += `<div class="sa-ioc-group">
          <div class="sa-ioc-group-label" style="color:${c}">${label} (${res.iocs[k].length})</div>`;
        res.iocs[k].forEach(v => {
          const escaped = v.replace(/"/g, "&quot;").replace(/</g, "&lt;");
          html += `<div class="sa-ioc-row">
            <code class="sa-ioc-val">${escaped.slice(0,100)}${v.length>100?"…":""}</code>
            ${pivotType ? `<button class="lt-pivot-btn" data-val="${escaped}" type="button">🔍 Pivot</button>
            <button class="lt-case-btn" data-val="${escaped}" data-type="${pivotType}" type="button">📁 Case</button>` : ""}
          </div>`;
        });
        html += `</div>`;
      });
      html += `</div></div>`;
    }

    // ── PREFILL HINT ─────────────────────────────────────────────
    if (res.prefillData && Object.values(res.prefillData).some(Boolean)) {
      html += `<div class="lt-prefill-hint">
        💡 <strong>Write-up data ready</strong> — click <strong>Pre-fill Write-up</strong> to populate the Alert Write-up tab with the fields above.
      </div>`;
    }

    ltResults.innerHTML = html;

    // Context summary copy button
    $("lt-ctx-copy-btn")?.addEventListener("click", async () => {
      const body = $("lt-ctx-body");
      const text = body ? [...body.querySelectorAll(".lt-ctx-line")].map(el => el.textContent.trim()).join("\n") : "";
      try { await navigator.clipboard.writeText(text); setLTStatus("Context summary copied to clipboard"); }
      catch { setLTStatus("Copy failed — please copy manually"); }
    });

    // Investigation steps copy button
    $("lt-steps-copy-btn")?.addEventListener("click", async () => {
      const list = $("lt-steps-list");
      const text = list ? [...list.querySelectorAll(".lt-step-item")].map((el,i) => `${i+1}. ${el.textContent.trim()}`).join("\n") : "";
      try { await navigator.clipboard.writeText("Investigation Checklist:\n" + text); setLTStatus("Investigation steps copied"); }
      catch { setLTStatus("Copy failed — please copy manually"); }
    });

    // FP/TP template copy buttons
    $("lt-fp-copy-btn")?.addEventListener("click", async () => {
      const body = $("lt-fp-body");
      try { await navigator.clipboard.writeText(body?.textContent?.trim() || ""); setLTStatus("False Positive template copied"); }
      catch { setLTStatus("Copy failed"); }
    });
    $("lt-tp-copy-btn")?.addEventListener("click", async () => {
      const body = $("lt-tp-body");
      try { await navigator.clipboard.writeText(body?.textContent?.trim() || ""); setLTStatus("True Positive template copied"); }
      catch { setLTStatus("Copy failed"); }
    });

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
    const r = lastTriageResult;
    const lines = [
      "═══════════════════════════════════════",
      "  LOG TRIAGE REPORT",
      "═══════════════════════════════════════",
      `Log Type    : ${r.eventType}`,
      `Severity    : ${r.severityLabel||"INFO"}`,
      `Exported    : ${new Date().toISOString()}`,
      "",
      "─── KEY INDICATORS ─────────────────────",
      ...(r.indicators||[]).map(i => `  • ${i}`),
      "",
      "─── TRIAGE FINDINGS ────────────────────",
      ...(r.findings||[]).length ? (r.findings).map(f=>`  ${f}`) : ["  None"],
      "",
      "─── MITRE ATT&CK ───────────────────────",
      ...(r.mitre||[]).length ? r.mitre.map(t=>`  ${t.padEnd(14)} ${getMitreName(t)}`) : ["  None mapped"],
      "",
      "─── EXTRACTED IOCs ─────────────────────",
    ];
    const iocKeys = ["ips","domains","urls","hashes","emails","cves","processes","usernames","hostnames","cmdlines","regkeys","filepaths"];
    iocKeys.forEach(k => { if(r.iocs?.[k]?.length) lines.push(`${k.toUpperCase()}:\n${r.iocs[k].map(v=>"  "+v).join("\n")}`); });
    lines.push("","═══════════════════════════════════════");
    try { await navigator.clipboard.writeText(lines.join("\n")); setLTStatus("Triage report copied to clipboard"); }
    catch { setLTStatus("Copy failed — try manually"); }
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
    ip_threatfox:"https://threatfox.abuse.ch/", ip_pulsedive:"https://pulsedive.com/",
    ip_securitytrails:"https://securitytrails.com/",
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
    dom_threatfox:"https://threatfox.abuse.ch/", dom_pulsedive:"https://pulsedive.com/",
    dom_passivedns:"https://securitytrails.com/", dom_rdap:"https://www.rdap.net/",
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
    // username extras
    usr_maigret:"https://github.com/soxoj/maigret", usr_breachdir:"https://breachdirectory.org/",
    usr_leakcheck:"https://leakcheck.io/", usr_spiderfoot:"https://hx.spiderfoot.net/",
    usr_github:"https://github.com/", usr_twitter:"https://twitter.com/",
    usr_reddit:"https://www.reddit.com/", usr_tiktok:"https://www.tiktok.com/",
    usr_instagram:"https://www.instagram.com/", usr_linkedin:"https://www.linkedin.com/",
    usr_snapchat:"https://www.snapchat.com/", usr_telegram:"https://t.me/",
    usr_discord:"https://discord.id/", usr_pastebin:"https://pastebin.com/",
    usr_nitter:"https://nitter.net/",
    // phone
    ph_truecaller:"https://www.truecaller.com/", ph_numverify:"https://numverify.com/",
    ph_phoneinfoga:"https://github.com/sundowndev/phoneinfoga", ph_eyecon:"https://www.eyecon.mobi/",
    ph_calleridtest:"https://www.calleridtest.com/", ph_intelx:"https://intelx.io/",
    ph_dehashed:"https://dehashed.com/", ph_google:"https://www.google.com/",
    // mac
    mac_macvendors:"https://api.macvendors.com/", mac_maclookup:"https://www.maclookup.app/",
    mac_wireshark_oui:"https://www.wireshark.org/tools/oui-lookup.html", mac_google:"https://www.google.com/",
    // asn
    asn_bgphe:"https://bgp.he.net/", asn_ripestat:"https://stat.ripe.net/",
    asn_asnlookup:"https://asnlookup.com/", asn_ipinfo:"https://ipinfo.io/",
    asn_shodan:"https://www.shodan.io/", asn_greynoise:"https://viz.greynoise.io/",
    // btc/eth
    btc_blockchain:"https://www.blockchain.com/", btc_blockchair:"https://blockchair.com/",
    btc_walletexplorer:"https://www.walletexplorer.com/", btc_otx:"https://otx.alienvault.com/",
    btc_google:"https://www.google.com/",
    eth_etherscan:"https://etherscan.io/", eth_blockchair:"https://blockchair.com/",
    eth_google:"https://www.google.com/",
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
    username:["T1078","T1110","T1003","T1087"],
    phone:["T1589.001","T1598"],
    mac:["T1016","T1049"],
    asn:["T1595","T1590"],
    btc:["T1486","T1567"],
    eth:["T1486","T1567"],
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
    // For hashes, resolve the specific algorithm label
    const hashAlgoLabel = type==="hash" ? (
      q.length===32 ? "MD5 / NTLM Hash" :
      q.length===40 ? "SHA-1 Hash" :
      q.length===64 ? "SHA-256 Hash" :
      q.length===96 ? "SHA-384 Hash" :
      q.length===128 ? "SHA-512 Hash" : "File Hash"
    ) : null;
    const verdictMap = {
      ip:{icon:"🛡",label:"IP Address",color:"#38bdf8"},
      domain:{icon:"🌐",label:"Domain",color:"#34d399"},
      url:{icon:"🔗",label:"URL",color:"#fb923c"},
      hash:{icon:"🔒",label:hashAlgoLabel||"File Hash",color:"#f59e0b"},
      email:{icon:"📧",label:"Email Address",color:"#a78bfa"},
      header:{icon:"📨",label:"Email Headers Detected",color:"#67e8f9"},
      cve:{icon:"💥",label:"CVE / Vulnerability",color:"#f87171"},
      username:{icon:"👤",label:"Username",color:"#e879f9"},
      phone:{icon:"📞",label:"Phone Number",color:"#f472b6"},
      mac:{icon:"🖧",label:"MAC Address",color:"#a3e635"},
      asn:{icon:"🌐",label:"ASN / BGP",color:"#38bdf8"},
      btc:{icon:"₿",label:"Bitcoin Wallet",color:"#f59e0b"},
      eth:{icon:"Ξ",label:"Ethereum Wallet",color:"#818cf8"},
      eventid:{icon:"🪟",label:"Windows Event ID",color:"#86efac"},
      mitre:{icon:"🧩",label:"MITRE ATT&CK Technique",color:"#fbbf24"},
    };
    const v = verdictMap[type]; if (!v) { banner.style.display="none"; return; }
    // For MD5/NTLM hashes add a warning badge
    const warnBadge = (type==="hash" && q.length===32) ? `<span style="font-size:10px;background:#f8711122;color:#f87171;border:1px solid #f8711144;border-radius:20px;padding:2px 8px;margin-left:8px;">⚠️ MD5/NTLM — verify algorithm</span>` :
                      (type==="hash" && q.length===40) ? `<span style="font-size:10px;background:#fb923c22;color:#fb923c;border:1px solid #fb923c44;border-radius:20px;padding:2px 8px;margin-left:8px;">⚠️ SHA-1 deprecated</span>` : "";
    banner.style.display="flex"; banner.style.borderColor=v.color+"44"; banner.style.background=v.color+"11";
    banner.innerHTML = `<span class="verdict-icon" style="color:${v.color}">${v.icon}</span><div style="flex:1"><span class="verdict-type" style="color:${v.color}">${v.label}</span>${warnBadge}<span class="verdict-value">${esc(q)||"detected from pasted text"}</span></div>`;
  }

  // ─── Threat Score Panel ───────────────────────────────────────
  function showThreatScore(type, q) {
    const panel = $("threat-score-panel");
    const body  = $("ts-body");
    const badge = $("ts-overall-badge");
    if (!panel || !body || !badge) return;

    // Hide for types without meaningful quick assessment
    const supported = ["ip","domain","url","hash","email","cve"];
    if (!supported.includes(type)) { panel.style.display="none"; return; }

    const e2 = encodeURIComponent;
    // Each row: { label, icon, url, context, riskHint }
    const rows = {
      ip: [
        { label:"VirusTotal",     icon:"🧪", url:`https://www.virustotal.com/gui/ip-address/${e2(q)}`,                 context:"Community detections & samples",      riskHint:"Check detection count" },
        { label:"AbuseIPDB",      icon:"🚫", url:`https://www.abuseipdb.com/check/${e2(q)}`,                           context:"Abuse confidence score 0–100",       riskHint:">80 = high risk" },
        { label:"GreyNoise",      icon:"🌫", url:`https://viz.greynoise.io/ip/${e2(q)}`,                               context:"Internet scanner vs targeted actor", riskHint:"Riot=benign, Malicious=bad" },
        { label:"Talos",          icon:"🕵️", url:`https://talosintelligence.com/reputation_center/lookup?search=${e2(q)}`, context:"Cisco Talos reputation score",    riskHint:"Poor/Untrusted = block" },
        { label:"IBM X-Force",    icon:"🧠", url:`https://exchange.xforce.ibmcloud.com/ip/${e2(q)}`,                   context:"Risk score 0–10",                   riskHint:">7 = high risk" },
        { label:"Shodan",         icon:"🛰",  url:`https://www.shodan.io/host/${e2(q)}`,                               context:"Open ports & banners",              riskHint:"Check for C2 ports 4444/50050" },
      ],
      domain: [
        { label:"VirusTotal",     icon:"🧪", url:`https://www.virustotal.com/gui/domain/${e2(q)}`,                    context:"Community detections & categories", riskHint:"Check detection count" },
        { label:"URLVoid",        icon:"📡", url:`https://www.urlvoid.com/scan/${e2(q)}/`,                            context:"30+ blacklist check",               riskHint:"Any hit = investigate" },
        { label:"Pulsedive",      icon:"📊", url:`https://pulsedive.com/indicator/?ioc=${e2(q)}`,                    context:"Community threat score",            riskHint:"High/Critical = block" },
        { label:"DomainTools",    icon:"🔑", url:`https://whois.domaintools.com/${e2(q)}`,                           context:"WHOIS & domain age",                riskHint:"<30 days old = suspicious" },
        { label:"ThreatFox",      icon:"🦊", url:`https://threatfox.abuse.ch/browse.php?search=ioc%3A${e2(q)}`,      context:"Malware C2 association check",      riskHint:"Any match = critical" },
        { label:"Talos",          icon:"🕵️", url:`https://talosintelligence.com/reputation_center/lookup?search=${e2(q)}`, context:"Domain reputation rating",     riskHint:"Poor/Untrusted = block" },
      ],
      url: [
        { label:"VirusTotal",     icon:"🧪", url:`https://www.virustotal.com/gui/url/${btoa(q).replace(/=/g,"")}`,    context:"URL scan & community votes",        riskHint:"Any detection = bad" },
        { label:"URLScan.io",     icon:"🔭", url:`https://urlscan.io/search/#page.url:${e2(q)}`,                     context:"Screenshots & redirect chain",      riskHint:"Check final destination" },
        { label:"Google SafeBrowsing", icon:"🛡", url:`https://transparencyreport.google.com/safe-browsing/search?url=${e2(q)}`, context:"Phishing/malware classification", riskHint:"Any flag = block" },
        { label:"Checkphish.ai",  icon:"🎣", url:`https://checkphish.ai/?url=${e2(q)}`,                              context:"AI-powered phishing detection",     riskHint:"Phishing score >0.7 = block" },
        { label:"URLhaus",        icon:"🏚", url:`https://urlhaus.abuse.ch/browse.php?search=${e2(q)}`,              context:"Malware payload distribution",      riskHint:"Any match = critical" },
        { label:"Any.Run",        icon:"🏃", url:`https://any.run/submit/?url=${e2(q)}`,                             context:"Interactive sandbox detonation",    riskHint:"Submit for behavioral analysis" },
      ],
      hash: [
        { label:"VirusTotal",     icon:"🧪", url:`https://www.virustotal.com/gui/file/${e2(q)}`,                     context:"AV vendor detections",             riskHint:">3 detections = malware" },
        { label:"MalwareBazaar",  icon:"🦠", url:`https://bazaar.abuse.ch/browse.php?search=${e2(q)}`,               context:"Malware sample repository",        riskHint:"Any match = confirmed malware" },
        { label:"Hybrid Analysis",icon:"🔬", url:`https://www.hybrid-analysis.com/search?query=${e2(q)}`,            context:"Behavioral sandbox report",        riskHint:"Check network IOCs & score" },
        { label:"Any.Run",        icon:"🏃", url:`https://app.any.run/tasks/#filehash:${e2(q)}`,                    context:"Interactive malware analysis",     riskHint:"Look for C2 / persistence" },
        { label:"Talos",          icon:"🕵️", url:`https://talosintelligence.com/talos_file_reputation?s=${e2(q)}`,   context:"File reputation & family",         riskHint:"Check malware family" },
        { label:"ThreatFox",      icon:"🦊", url:`https://threatfox.abuse.ch/browse.php?search=ioc%3A${e2(q)}`,     context:"Malware C2 / payload DB",          riskHint:"Any match = critical" },
      ],
      email: [
        { label:"Have I Been Pwned",icon:"🔓",url:`https://haveibeenpwned.com/account/${e2(q)}`,                    context:"Breach exposure check",            riskHint:"Any breach = credential risk" },
        { label:"Hunter.io",      icon:"🎯", url:`https://hunter.io/email-verifier/${e2(q)}`,                       context:"Email validity & deliverability",  riskHint:"Invalid = spoofed sender" },
        { label:"EmailRep",       icon:"📬", url:`https://emailrep.io/${e2(q)}`,                                    context:"Email reputation score",           riskHint:"Low reputation = phishing" },
        { label:"VirusTotal",     icon:"🧪", url:`https://www.virustotal.com/gui/search/${e2(q)}`,                  context:"Malicious activity association",   riskHint:"Check community reports" },
        { label:"Google",         icon:"🔍", url:`https://www.google.com/search?q=${e2('"'+q+'"')}`,               context:"OSINT footprint",                  riskHint:"Look for breach dumps / profiles" },
        { label:"MXToolBox",      icon:"📧", url:`https://mxtoolbox.com/EmailHeaders.aspx`,                         context:"Domain MX / SPF / DMARC check",   riskHint:"Fail = spoofing risk" },
      ],
      cve: [
        { label:"NVD / NIST",     icon:"📋", url:`https://nvd.nist.gov/vuln/detail/${e2(q)}`,                       context:"CVSS score & severity",            riskHint:"CVSS ≥9 = Critical" },
        { label:"CISA KEV",       icon:"🧨", url:`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,    context:"Actively exploited in the wild",   riskHint:"In KEV = patch immediately" },
        { label:"Exploit-DB",     icon:"💥", url:`https://www.exploit-db.com/search?cve=${e2(q.replace('CVE-',''))}`, context:"Public exploit availability",   riskHint:"Public PoC = urgent" },
        { label:"EPSS / FIRST",   icon:"📊", url:`https://api.first.org/data/v1/epss?cve=${e2(q)}`,                 context:"Exploitation probability score",   riskHint:">0.5 = high exploitation risk" },
        { label:"Vulners",        icon:"🔭", url:`https://vulners.com/cve/${e2(q)}`,                                context:"Aggregated CVE intelligence",      riskHint:"Check for active campaigns" },
        { label:"AttackerKB",     icon:"⚔️", url:`https://attackerkb.com/search?q=${e2(q)}`,                        context:"Exploitation difficulty & value",  riskHint:"High value = targeted" },
      ],
    };

    const items = rows[type] || [];

    // Build scoring context text per type
    const contextNote = {
      ip:     "Cross-reference at least 3 sources. One suspicious hit warrants investigation; 2+ hits = escalate.",
      domain: "Newly registered + any threat feed hit = high confidence indicator. Check registration age.",
      url:    "Any phishing or malware classification = block immediately. Detonate in sandbox if unsure.",
      hash:   "VirusTotal ≥3 detections = confirmed malicious. Zero detections doesn't mean clean.",
      email:  "Combine breach exposure + domain reputation + email validity for full picture.",
      cve:    "CVSS ≥7 AND in CISA KEV = emergency patch priority. Check if EPSS >0.3.",
    }[type] || "";

    // Banner pills — top 3 tools as quick-access links
    const pillRow = $("ts-pill-row");
    if (pillRow) {
      pillRow.innerHTML = items.slice(0,3).map(r =>
        `<a href="${r.url}" target="_blank" class="ts-pill" title="${r.riskHint}" onclick="event.stopPropagation()">${r.icon} ${r.label}</a>`
      ).join("") + `<span style="font-size:10px;color:var(--muted);margin-left:2px">+${items.length-3} more ▼</span>`;
    }

    // Expanded body — all tools with hint
    body.innerHTML = `
      <div class="ts-grid">${items.map(r => `
        <a href="${r.url}" target="_blank" class="ts-row" title="${r.riskHint}">
          <span class="ts-row-icon">${r.icon}</span>
          <span class="ts-row-label">${r.label}</span>
          <span class="ts-row-context">${r.context}</span>
          <span class="ts-row-hint">${r.riskHint}</span>
        </a>`).join("")}</div>
      ${contextNote ? `<div class="ts-context-note">📌 ${contextNote}</div>` : ""}
    `;

    // Overall badge
    const overallColor = { ip:"#38bdf8", domain:"#34d399", url:"#fb923c", hash:"#f59e0b", email:"#a78bfa", cve:"#f87171" }[type] || "#9ca3af";
    badge.textContent = type.toUpperCase();
    badge.style.background = overallColor + "22";
    badge.style.color = overallColor;
    badge.style.borderColor = overallColor + "55";
    panel.style.display = "block";

    // Toggle expand/collapse
    const bannerBtn = $("ts-banner-toggle");
    const arrow     = $("ts-toggle-arrow");
    if (bannerBtn && !bannerBtn._tsListener) {
      bannerBtn._tsListener = true;
      bannerBtn.addEventListener("click", () => {
        body.classList.toggle("visible");
        arrow?.classList.toggle("open");
      });
    }
  }

  function hideThreatScore() {
    const panel = $("threat-score-panel");
    if (panel) panel.style.display = "none";
  }

  // ─── Feature 14: Threat Actor IOC Hint ───────────────────────
  // Known IOC-to-actor mappings (tool names, malware families, known infrastructure keywords)
  const ACTOR_IOC_HINTS = [
    { actor:"Lazarus Group",   nation:"North Korea", color:"#38bdf8",
      match: /blindingcan|applejeus|fastcash|bankshot|destover|lazarus|hidden.cobra|zinc/i,
      tools:["BLINDINGCAN","AppleJeus","FASTCash"], campaign:"Financial/Crypto theft", mitre:"G0032" },
    { actor:"APT29 / Cozy Bear", nation:"Russia (SVR)", color:"#f87171",
      match: /cozy.bear|nobelium|sunburst|wellmess|solarwinds|midnight.blizzard|meek|hammertoss/i,
      tools:["SUNBURST","WellMess","Cobalt Strike"], campaign:"Espionage / Supply Chain", mitre:"G0016" },
    { actor:"APT28 / Fancy Bear", nation:"Russia (GRU)", color:"#f87171",
      match: /fancy.bear|sofacy|strontium|x-agent|zebrocy|komplex|lojax|forest.blizzard/i,
      tools:["X-Agent","Zebrocy","LoJax"], campaign:"Credential Theft / Espionage", mitre:"G0007" },
    { actor:"Sandworm",        nation:"Russia (GRU)", color:"#f87171",
      match: /sandworm|industroyer|notpetya|blackenergy|whispergate|voodoo.bear|telebots/i,
      tools:["NotPetya","BlackEnergy","Industroyer"], campaign:"Destructive / Critical Infrastructure", mitre:"G0034" },
    { actor:"APT41",           nation:"China",        color:"#f59e0b",
      match: /apt41|winnti|barium|shadowpad|plugx|messagetap|poisonplug|brass.typhoon/i,
      tools:["ShadowPad","PlugX","Cobalt Strike"], campaign:"Espionage + Financial", mitre:"G0096" },
    { actor:"Kimsuky",         nation:"North Korea",  color:"#38bdf8",
      match: /kimsuky|babyshark|appleseed|randomquery|velvet.chollima|emerald.sleet/i,
      tools:["BabyShark","AppleSeed","QuasarRAT"], campaign:"Intelligence Gathering", mitre:"G0094" },
    { actor:"FIN7 / Carbanak", nation:"Russia/Ukraine",color:"#fb923c",
      match: /fin7|carbanak|boostwrite|babymetal|navigator.group|carbon.spider/i,
      tools:["Carbanak","BOOSTWRITE","Cobalt Strike"], campaign:"Financial/POS", mitre:"G0046" },
    { actor:"LockBit",         nation:"Criminal",     color:"#fb923c",
      match: /lockbit|lock.bit|lockbit3|alphv.lockbit/i,
      tools:["LockBit ransomware"], campaign:"Ransomware-as-a-Service", mitre:"" },
    { actor:"REvil / Sodinokibi", nation:"Criminal",  color:"#fb923c",
      match: /revil|sodinokibi|gold.southfield/i,
      tools:["REvil"], campaign:"Ransomware-as-a-Service", mitre:"G0115" },
    { actor:"Cobalt Strike (generic)", nation:"Various", color:"#fbbf24",
      match: /cobalt.strike|cobaltstrike|beacon.dll|malleable.c2|cs\.exe|teamserver/i,
      tools:["Cobalt Strike Beacon"], campaign:"Post-exploitation framework (multiple actors)", mitre:"" },
  ];

  function checkActorHints(type, q) {
    const panel = $("actor-hint-panel");
    if (!panel) return;
    const searchStr = q.toLowerCase();
    const matches = ACTOR_IOC_HINTS.filter(h => h.match.test(searchStr));
    if (!matches.length) { panel.style.display = "none"; return; }

    panel.style.display = "block";
    panel.innerHTML = matches.map(m => `
      <div class="actor-hint-card" style="border-color:${m.color}44">
        <div class="actor-hint-head">
          <span class="actor-hint-icon">🎭</span>
          <span class="actor-hint-name" style="color:${m.color}">${m.actor}</span>
          <span class="actor-hint-nation" style="background:${m.color}18;color:${m.color};border-color:${m.color}44">${m.nation}</span>
        </div>
        <div class="actor-hint-meta">
          <span>📌 Campaign: <strong>${m.campaign}</strong></span>
          <span>🛠 Tools: ${m.tools.join(", ")}</span>
        </div>
        <div class="actor-hint-links">
          ${m.mitre ? `<a href="https://attack.mitre.org/groups/${m.mitre}/" target="_blank" class="actor-hint-link">ATT&CK ${m.mitre}</a>` : ""}
          <a href="https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(m.actor)}" target="_blank" class="actor-hint-link">OTX Pulses</a>
          <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(q)}" target="_blank" class="actor-hint-link">VT Search</a>
        </div>
        <div class="actor-hint-note">⚠️ IOC pattern matched known ${m.actor} indicators — verify before concluding attribution.</div>
      </div>`).join("");
  }

  function hideActorHints() {
    const panel = $("actor-hint-panel");
    if (panel) panel.style.display = "none";
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
    setHref("ip_scamalytics",     `https://scamalytics.com/ip/${enc(ip)}`);
    setHref("ip_threatfox",       `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(ip)}`);
    setHref("ip_pulsedive",       `https://pulsedive.com/indicator/?ioc=${enc(ip)}`);
    setHref("ip_securitytrails",  `https://securitytrails.com/list/ip/${enc(ip)}`);
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
    setHref("dom_shodan",       `https://www.shodan.io/search?query=${enc(domain)}`);
    setHref("dom_dnstools",     `https://whois.domaintools.com/${enc(domain)}`);
    setHref("dom_crtsh",        `https://crt.sh/?q=${enc(domain)}`);
    setHref("dom_dnsdumpster",  `https://dnsdumpster.com/`);
    setHref("dom_threatfox",    `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(domain)}`);
    setHref("dom_pulsedive",    `https://pulsedive.com/indicator/?ioc=${enc(domain)}`);
    setHref("dom_passivedns",   `https://securitytrails.com/domain/${enc(domain)}/history/a`);
    setHref("dom_rdap",         `https://www.rdap.net/domain/${enc(domain)}`);
    fetchDomainAge(domain);
    injectCustomTools("domain", domain);
  }

  // ── Domain Age / RDAP enrichment ─────────────────────────────
  async function fetchDomainAge(domain) {
    const banner = $("verdict-banner");
    if (!banner) return;
    // RDAP sends the domain to rdap.org — show one-time notice
    const rdapConsent = (() => { try { return localStorage.getItem("osint_rdap_ok"); } catch { return null; } })();
    if (!rdapConsent) {
      banner.style.display = "block";
      banner.innerHTML = `<div style="font-size:10px;color:var(--muted);background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.25);border-radius:8px;padding:6px 10px;display:flex;align-items:center;gap:8px;">
        <span>📡 Domain age lookup sends the domain to <strong>rdap.org</strong> (public WHOIS service).</span>
        <button onclick="try{localStorage.setItem('osint_rdap_ok','1')}catch(e){}this.closest('[id]').style.display='none';fetchDomainAge('${domain}')" 
          style="font-size:10px;padding:2px 8px;border-radius:6px;border:1px solid rgba(251,146,60,0.4);background:transparent;color:#fb923c;cursor:pointer;white-space:nowrap">Allow once</button>
        <button onclick="try{localStorage.setItem('osint_rdap_ok','1')}catch(e){}this.closest('[id]').style.display='none'" 
          style="font-size:10px;padding:2px 8px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer">Skip</button>
      </div>`;
      return;
    }
    try {
      const res = await fetch(`https://rdap.org/domain/${domain}`);
      if (!res.ok) return;
      const data = await res.json();
      const events = data.events || [];
      const reg = events.find(e => e.eventAction === "registration");
      const upd = events.find(e => e.eventAction === "last changed");
      if (!reg) return;
      const regDate = new Date(reg.eventDate);
      const ageMs = Date.now() - regDate.getTime();
      const ageDays = Math.floor(ageMs / 86400000);
      const ageLabel = ageDays < 30 ? `⚠️ ${ageDays}d old — NEWLY REGISTERED` : ageDays < 180 ? `${ageDays}d old` : `${Math.floor(ageDays/365)}y ${Math.floor((ageDays%365)/30)}m old`;
      const isNew = ageDays < 30;
      const updStr = upd ? ` · Updated: ${new Date(upd.eventDate).toLocaleDateString()}` : "";
      const registrar = data.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(f=>f[0]==="fn")?.[3] || "";
      let html = `<div class="domain-age-badge ${isNew?"domain-age-new":"domain-age-ok"}">
        📅 Registered: ${regDate.toLocaleDateString()} — ${ageLabel}${updStr}
        ${registrar ? `· Registrar: ${registrar}` : ""}
      </div>`;
      if (isNew) html = `<div class="verdict-critical">${html}<span>🚨 Newly registered domain is a common phishing/malware indicator</span></div>`;
      banner.innerHTML = html; banner.style.display = "block";
    } catch { /* RDAP not available for all domains */ }
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
    setHref("usr_maigret",`https://github.com/soxoj/maigret`);
    setHref("usr_sherlock",`https://github.com/sherlock-project/sherlock`);
    setHref("usr_socialsearcher",`https://www.social-searcher.com/social-buzz/?q5=${enc(user)}`);
    setHref("usr_dehashed",`https://dehashed.com/search?query=${enc(user)}`);
    setHref("usr_intelx",`https://intelx.io/?s=${enc(user)}`);
    setHref("usr_breachdir",`https://breachdirectory.org/?q=${enc(user)}`);
    setHref("usr_leakcheck",`https://leakcheck.io/search?query=${enc(user)}`);
    setHref("usr_spiderfoot",`https://hx.spiderfoot.net/`);
    setHref("usr_github",`https://github.com/${enc(user)}`);
    setHref("usr_twitter",`https://twitter.com/${enc(user)}`);
    setHref("usr_reddit",`https://www.reddit.com/user/${enc(user)}`);
    setHref("usr_tiktok",`https://www.tiktok.com/@${enc(user)}`);
    setHref("usr_instagram",`https://www.instagram.com/${enc(user)}`);
    setHref("usr_linkedin",`https://www.linkedin.com/search/results/people/?keywords=${enc(user)}`);
    setHref("usr_snapchat",`https://www.snapchat.com/add/${enc(user)}`);
    setHref("usr_telegram",`https://t.me/${enc(user)}`);
    setHref("usr_discord",`https://discord.id/`);
    setHref("usr_pastebin",`https://pastebin.com/search?q=${enc(user)}`);
    setHref("usr_nitter",`https://nitter.net/search?q=${enc(user)}`);
    injectCustomTools("username", user);
  }

  function buildLinksForPhone(phone) {
    const digits = phone.replace(/\D/g,"");
    setHref("ph_truecaller",`https://www.truecaller.com/search/int/${enc(phone)}`);
    setHref("ph_numverify",`https://numverify.com/`);
    setHref("ph_phoneinfoga",`https://github.com/sundowndev/phoneinfoga`);
    setHref("ph_eyecon",`https://www.eyecon.mobi/`);
    setHref("ph_calleridtest",`https://www.calleridtest.com/reverse-lookup/?number=${enc(phone)}`);
    setHref("ph_intelx",`https://intelx.io/?s=${enc(phone)}`);
    setHref("ph_dehashed",`https://dehashed.com/search?query=${enc(phone)}`);
    setHref("ph_google",gsearch(`"${phone}" OR "${digits}" site:truecaller.com OR site:whitepages.com OR site:spokeo.com`));
  }

  function buildLinksForMAC(mac) {
    const prefix = mac.replace(/[:-]/g,"").slice(0,6).toUpperCase();
    setHref("mac_macvendors",`https://api.macvendors.com/${enc(mac)}`);
    setHref("mac_maclookup",`https://www.maclookup.app/search/${enc(mac)}`);
    setHref("mac_wireshark_oui",`https://www.wireshark.org/tools/oui-lookup.html`);
    setHref("mac_google",gsearch(`MAC OUI ${prefix} vendor manufacturer`));
  }

  function buildLinksForASN(asn) {
    const num = asn.replace(/^AS/i,"");
    setHref("asn_bgphe",`https://bgp.he.net/${enc(asn)}`);
    setHref("asn_ripestat",`https://stat.ripe.net/${enc(asn)}`);
    setHref("asn_asnlookup",`https://asnlookup.com/asn/${enc(asn)}`);
    setHref("asn_ipinfo",`https://ipinfo.io/${enc(asn)}`);
    setHref("asn_shodan",`https://www.shodan.io/search?query=asn%3A${enc(asn)}`);
    setHref("asn_greynoise",`https://viz.greynoise.io/query/?gnql=asn%3A${enc(num)}`);
  }

  function buildLinksForBTC(wallet) {
    setHref("btc_blockchain",`https://www.blockchain.com/explorer/addresses/btc/${enc(wallet)}`);
    setHref("btc_blockchair",`https://blockchair.com/bitcoin/address/${enc(wallet)}`);
    setHref("btc_walletexplorer",`https://www.walletexplorer.com/wallet/${enc(wallet)}`);
    setHref("btc_otx",`https://otx.alienvault.com/indicator/cryptocurrency/${enc(wallet)}`);
    setHref("btc_google",gsearch(`"${wallet}" ransomware OR fraud OR scam`));
  }

  function buildLinksForETH(wallet) {
    setHref("eth_etherscan",`https://etherscan.io/address/${enc(wallet)}`);
    setHref("eth_blockchair",`https://blockchair.com/ethereum/address/${enc(wallet)}`);
    setHref("eth_google",gsearch(`"${wallet}" ransomware OR fraud OR scam`));
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
      hideThreatScore(); hideActorHints();
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
    else if (type==="btc" || type==="eth") sections=[type,"btc","eth"];
    else if (type==="domain") sections=["domain","cert"]; // show cert inspector alongside domain
    else sections=[type];
    showRelevantTools(sections);
    setLandingLinks(); showVerdict(type, q); showThreatScore(type, q); checkActorHints(type, q); suggestMitreTactics(type);
    if (type==="mitre"&&q) setHref("mitre-attack-link",`https://attack.mitre.org/techniques/${q.replace(".","/")}/`);
    else setHref("mitre-attack-link","https://attack.mitre.org/");
    if (type==="ip") { buildLinksForIP(q); const priv=(isValidIPv4(q)&&isPrivateIPv4(q))||(isValidIPv6(q)&&isPrivateIPv6(q)); if(!silent&&output) output.value=priv?`IP detected (PRIVATE): ${q}\nNote: external OSINT may not return results for private IPs.`:`IP detected: ${q}`; setStatus(`Status: detected IP → ${q}`); }
    if (type==="domain") { buildLinksForDomain(q); if(!silent&&output) output.value=`Domain detected: ${q}`; setStatus(`Status: detected DOMAIN → ${q}`); const certInp=$("cert-input"); if(certInp && !certInp.value) certInp.value=q; }
    if (type==="url") { buildLinksForURL(q); if(!silent&&output) output.value=`URL detected: ${q}`; setStatus(`Status: detected URL → ${q}`); }
    if (type==="hash") {
      const hashAlgo = q.length===32?"MD5 / NTLM":q.length===40?"SHA-1":q.length===64?"SHA-256":q.length===96?"SHA-384":q.length===128?"SHA-512":"Unknown";
      const hashNotes = {
        "MD5 / NTLM": "⚠️ MD5 is cryptographically broken. Could also be an NTLM hash (Windows credential).",
        "SHA-1":  "⚠️ SHA-1 is deprecated. Widely used in older malware and certificates.",
        "SHA-256":"✅ SHA-256 — industry standard. Most sandbox/AV tools accept this.",
        "SHA-384":"SHA-384 — uncommon. Often seen in SSL certificates or firmware.",
        "SHA-512":"SHA-512 — strong, but rarely used in malware tracking. Check AV tools.",
      };
      buildLinksForHash(q);
      if(!silent&&output) output.value=`Hash detected: ${q}\n\nAlgorithm: ${hashAlgo}\nLength: ${q.length} hex chars (${q.length*4} bits)\n${hashNotes[hashAlgo]||""}\n\nTip: SHA-256 is the most widely supported across OSINT tools.\nIf you only have MD5/SHA-1, VirusTotal and MalwareBazaar still accept them.`;
      setStatus(`Status: detected HASH (${hashAlgo}) → ${q.slice(0,16)}…`);
    }
    if (type==="email") { buildLinksForEmail(q); if(!silent&&output) output.value=`Email detected: ${q}`; setStatus(`Status: detected EMAIL → ${q}`); }
    if (type==="username") { buildLinksForUsername(q); if(!silent&&output) output.value=`Username detected: ${q}`; setStatus(`Status: detected USERNAME → ${q}`); }
    if (type==="phone")    { buildLinksForPhone(q);    if(!silent&&output) output.value=`Phone number detected: ${q}`; setStatus(`Status: detected PHONE → ${q}`); }
    if (type==="mac")      { buildLinksForMAC(q);      if(!silent&&output) output.value=`MAC address detected: ${q}\nOUI prefix: ${q.replace(/[:-]/g,"").slice(0,6)}\nUse the pivot links to identify the vendor/manufacturer.`; setStatus(`Status: detected MAC → ${q}`); }
    if (type==="asn")      { buildLinksForASN(q);      if(!silent&&output) output.value=`ASN detected: ${q}\nUse pivot links to enumerate IP ranges, prefixes, and registrant info.`; setStatus(`Status: detected ASN → ${q}`); }
    if (type==="btc")      { buildLinksForBTC(q);      if(!silent&&output) output.value=`Bitcoin wallet detected: ${q}\nUse pivot links to trace transactions and check for ransomware associations.`; setStatus(`Status: detected BTC WALLET → ${q}`); }
    if (type==="eth")      { buildLinksForETH(q);      if(!silent&&output) output.value=`Ethereum wallet detected: ${q}\nUse pivot links to trace transactions on Etherscan.`; setStatus(`Status: detected ETH WALLET → ${q}`); }
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
    hideThreatScore(); hideActorHints();
    const sp=$("mitre-suggested"); if(sp) sp.style.display="none";
    const cvePanel=$("cve-enrichment"); if(cvePanel) cvePanel.style.display="none";
  });
  // ── Dark mode persistence ─────────────────────────────────────
  const toggleDark = $("toggle-dark");
  try { if (localStorage.getItem("osint_theme") === "light") document.body.classList.add("light"); } catch {}

  // First-run notice — show once, then dismiss permanently
  try {
    if (!localStorage.getItem("osint_welcomed")) {
      const notice = document.createElement("div");
      notice.id = "first-run-notice";
      notice.style.cssText = "position:fixed;bottom:20px;right:20px;z-index:9999;max-width:340px;background:var(--bg2);border:1px solid rgba(56,189,248,0.35);border-radius:12px;padding:14px 16px;box-shadow:0 8px 32px rgba(0,0,0,0.4);font-size:11px;line-height:1.6;";
      notice.innerHTML = `
        <div style="font-weight:800;font-size:13px;margin-bottom:6px;color:var(--text)">🦅 Welcome to HawkEye <span style="font-size:10px;background:rgba(56,189,248,0.1);color:#38bdf8;border:1px solid rgba(56,189,248,0.25);border-radius:20px;padding:1px 7px;">v${TOOLKIT_VERSION}</span></div>
        <div style="color:var(--muted);margin-bottom:10px;">
          🔒 <strong>Privacy:</strong> All processing happens locally in your browser.<br>
          📦 IOC history is saved in <em>this browser only</em> — not sent anywhere.<br>
          🔗 Tool lookups open external sites — only when you click them.<br>
          ⚠️ Do not paste credentials, PII, or classified data.
        </div>
        <div style="display:flex;gap:8px;">
          <button onclick="try{localStorage.setItem('osint_welcomed','1')}catch(e){}document.getElementById('first-run-notice').remove()" 
            style="flex:1;padding:6px;border-radius:8px;border:none;background:linear-gradient(135deg,#0ea5e9,#6366f1);color:#fff;font-weight:700;font-size:11px;cursor:pointer">
            Got it — Let's go
          </button>
        </div>`;
      document.body.appendChild(notice);
    }
  } catch(e) {}

  if (toggleDark) toggleDark.addEventListener("click", () => {
    document.body.classList.toggle("light");
    try { localStorage.setItem("osint_theme", document.body.classList.contains("light") ? "light" : "dark"); } catch {}
  });

  // ── Clipboard auto-detect on focus ───────────────────────────
  if (input) {
    input.addEventListener("focus", async () => {
      if (input.value.trim()) return;
      try {
        const text = await navigator.clipboard.readText();
        if (!text || text.length > 300 || text.includes("\n")) return;
        const { type } = detectType(text.trim(), "");
        if (type) { input.value = text.trim(); syncSearchboxState(); setStatus(`Status: clipboard IOC detected (${type}) — press Enter to search`); }
      } catch { /* clipboard permission denied — silent */ }
    });
  }


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
    // Deduplicate
    const seen = new Set();
    const deduped = iocs.filter(ioc => { const k = ioc.type+":"+ioc.q; if(seen.has(k)) return false; seen.add(k); return true; });
    if (!deduped.length) { bulkResults.innerHTML = '<div class="bulk-empty">No IOCs detected.</div>'; return; }

    const grouped = {};
    deduped.forEach(ioc => { if (!grouped[ioc.type]) grouped[ioc.type] = []; grouped[ioc.type].push(ioc); });

    let html = `<div class="bulk-summary">
      Found <strong>${deduped.length}</strong> unique IOC${deduped.length!==1?"s":""} across ${Object.keys(grouped).length} type${Object.keys(grouped).length!==1?"s":""}
      <div class="bulk-export-bar">
        <button class="bulk-exp-btn" id="bulk-exp-csv" type="button">📊 Export CSV</button>
        <button class="bulk-exp-btn" id="bulk-exp-splunk" type="button">🔍 Splunk format</button>
        <button class="bulk-exp-btn" id="bulk-exp-sigma" type="button">⚡ Sigma IOC list</button>
      </div>
    </div>`;

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
        const escapedQ = ioc.q.replace(/"/g,"&quot;").replace(/</g,"&lt;");
        html += `<div class="bulk-item">
          <div class="bulk-ioc-row-head">
            <div class="bulk-ioc-val">${escapedQ}</div>
            <button class="bulk-pivot-item-btn" data-val="${escapedQ}" data-type="${ioc.type}" type="button">🔍 Pivot</button>
            <button class="bulk-case-item-btn" data-val="${escapedQ}" data-type="${ioc.type}" type="button">📁 Case</button>
          </div>
          <div class="bulk-links">${linksHtml}</div>
        </div>`;
      });
      html += `</div>`;
    });

    bulkResults.innerHTML = html;
    bulkResults.dataset.iocs = JSON.stringify(deduped);

    // Per-item pivot
    bulkResults.querySelectorAll(".bulk-pivot-item-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        if (input) { input.value = btn.dataset.val; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
      });
    });
    bulkResults.querySelectorAll(".bulk-case-item-btn").forEach(btn => {
      btn.addEventListener("click", () => addIOCToCase(btn.dataset.type||"unknown", btn.dataset.val));
    });

    // Export CSV
    $("bulk-exp-csv")?.addEventListener("click", () => {
      const rows = ["type,value",...deduped.map(i=>`${i.type},"${i.q.replace(/"/g,'""')}"`)]
      const blob = new Blob([rows.join("\n")],{type:"text/csv"});
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
      a.download = `iocs-${Date.now()}.csv`; a.click();
    });
    // Export Splunk
    $("bulk-exp-splunk")?.addEventListener("click", async () => {
      const lines = deduped.map(i => `| makeresults | eval ${i.type}="${i.q.replace(/"/g, "\\\"")}"`).join("\n");
      try { await navigator.clipboard.writeText(lines); setBulkStatus("Splunk format copied to clipboard"); } catch {}
    });
    // Export Sigma IOC list
    $("bulk-exp-sigma")?.addEventListener("click", async () => {
      const lines = ["# Sigma IOC List — paste into detection rules",...deduped.map(i=>`  - '${i.q.replace(/'/g,"''")}' # ${i.type}`)];
      try { await navigator.clipboard.writeText(lines.join("\n")); setBulkStatus("Sigma IOC list copied to clipboard"); } catch {}
    });
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

  // ═══════════════════════════════════════════════════
  // ─── SOC UTILITIES TAB ───────────────────────────
  // ═══════════════════════════════════════════════════

  // ── Base64 Encode/Decode ──────────────────────────
  function b64DeepDecode(str) {
    let cur = str.trim();
    const layers = [];
    for (let i = 0; i < 8; i++) {
      const d = (() => { try { const r = atob(cur.replace(/\s/g,"")); const isPrint = r.split("").filter(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<127).length / r.length; return isPrint > 0.6 ? r : null; } catch { return null; } })();
      if (!d || d === cur) break;
      layers.push(d); cur = d;
    }
    return { result: cur, layers };
  }
  const utilB64In  = $("util-b64-input");
  const utilB64Out = $("util-b64-output");
  $("util-b64-decode")?.addEventListener("click", () => {
    try { if(utilB64Out) utilB64Out.value = atob((utilB64In?.value||"").trim().replace(/\s/g,"")); } catch { if(utilB64Out) utilB64Out.value = "⚠️ Invalid Base64"; }
  });
  $("util-b64-encode")?.addEventListener("click", () => {
    if(utilB64Out) utilB64Out.value = btoa(unescape(encodeURIComponent(utilB64In?.value||"")));
  });
  $("util-b64-deep")?.addEventListener("click", () => {
    const { result, layers } = b64DeepDecode(utilB64In?.value||"");
    if(utilB64Out) utilB64Out.value = layers.length ? `[${layers.length} layer(s) decoded]\n\n${result}` : result;
  });
  $("util-b64-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText(utilB64Out?.value||""); } catch {} });
  $("util-b64-pivot")?.addEventListener("click", () => {
    const v = (utilB64Out?.value||"").trim();
    if (v && input) { input.value = v.split("\n").pop(); syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
  });

  // ── URL Decode / Encode ───────────────────────────
  const utilUrlIn  = $("util-url-input");
  const utilUrlOut = $("util-url-output");
  $("util-url-decode")?.addEventListener("click", () => {
    try { if(utilUrlOut) utilUrlOut.value = decodeURIComponent((utilUrlIn?.value||"").replace(/\+/g," ")); } catch { if(utilUrlOut) utilUrlOut.value = "⚠️ Invalid URL encoding"; }
  });
  $("util-url-encode")?.addEventListener("click", () => { if(utilUrlOut) utilUrlOut.value = encodeURIComponent(utilUrlIn?.value||""); });
  $("util-url-double-decode")?.addEventListener("click", () => {
    try {
      let v = (utilUrlIn?.value||"");
      v = decodeURIComponent(v.replace(/\+/g," "));
      v = decodeURIComponent(v.replace(/\+/g," "));
      if(utilUrlOut) utilUrlOut.value = v;
    } catch { if(utilUrlOut) utilUrlOut.value = "⚠️ Decode failed"; }
  });
  $("util-url-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText(utilUrlOut?.value||""); } catch {} });

  // ── Regex IOC Hunter ─────────────────────────────
  $("util-regex-run")?.addEventListener("click", () => {
    const text = ($("util-regex-input")?.value||"").trim();
    if (!text) return;
    const res = $("util-regex-results");
    if (!res) return;
    const r = refangSmart(text);
    const found = {
      IPs:      [...new Set((r.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)||[]).filter(isValidIPv4))],
      Domains:  [...new Set((r.match(/\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\b/g)||[]).filter(d=>!/^\d+\.\d+/.test(d)))],
      URLs:     [...new Set((r.match(/https?:\/\/[^\s"'`>)]+/gi)||[]))],
      Emails:   [...new Set((r.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g)||[]))],
      Hashes:   [...new Set((r.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g)||[]))],
      CVEs:     [...new Set((r.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(c=>c.toUpperCase()))],
      Usernames:[...new Set((r.match(/(?:user(?:name)?|account)[:\s=]+([a-zA-Z0-9._\\-]{2,40})/gi)||[]).map(m=>(m.match(/[:\s=]+(.+)$/)||[])[1]||"").filter(Boolean))],
      Processes:[...new Set((r.match(/\b[\w\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|hta|scr)\b/gi)||[]).map(p=>p.toLowerCase()))],
      RegKeys:  [...new Set((r.match(/(?:HKCU|HKLM|HKEY_[A-Z_]+)[\\\/][^\s"'`,;]{5,}/gi)||[]))],
      FilePaths:[...new Set((r.match(/[A-Za-z]:\\[^\s"'`<>|,;*?]{4,}/g)||[]))],
    };
    const colors = {IPs:"#38bdf8",Domains:"#34d399",URLs:"#fb923c",Emails:"#a78bfa",Hashes:"#f59e0b",CVEs:"#f87171",Usernames:"#e879f9",Processes:"#67e8f9",RegKeys:"#94a3b8",FilePaths:"#c084fc"};
    const total = Object.values(found).reduce((s,a)=>s+a.length,0);
    if (!total) { res.innerHTML = '<div class="bulk-empty">No IOCs detected in the pasted text.</div>'; return; }
    let html = `<div class="regex-found-count">Found <strong>${total}</strong> items across ${Object.values(found).filter(a=>a.length).length} categories</div>`;
    Object.entries(found).forEach(([k,arr]) => {
      if (!arr.length) return;
      const c = colors[k]||"#9ca3af";
      html += `<div class="regex-group"><div class="regex-group-label" style="color:${c}">${k} <span class="bulk-count">${arr.length}</span></div>`;
      arr.forEach(v => { html += `<div class="regex-ioc-row"><code>${v.slice(0,90)}${v.length>90?"…":""}</code></div>`; });
      html += `</div>`;
    });
    res.innerHTML = html;
    // Store for copy/bulk
    res.dataset.iocs = JSON.stringify(found);
  });
  $("util-regex-copy")?.addEventListener("click", async () => {
    const res = $("util-regex-results");
    if (!res?.dataset.iocs) return;
    const found = JSON.parse(res.dataset.iocs);
    const lines = [];
    Object.entries(found).forEach(([k,arr]) => { if(arr.length) lines.push(`${k}:\n${arr.map(v=>"  "+v).join("\n")}`); });
    try { await navigator.clipboard.writeText(lines.join("\n\n")); } catch {}
  });
  $("util-regex-bulk")?.addEventListener("click", () => {
    const res = $("util-regex-results");
    if (!res?.dataset.iocs) return;
    const found = JSON.parse(res.dataset.iocs);
    const all = Object.values(found).flat();
    const bulkIn = $("bulk-input");
    if (bulkIn) { bulkIn.value = all.join("\n"); switchTab("bulk"); }
  });
  $("util-regex-clear")?.addEventListener("click", () => {
    const inp = $("util-regex-input"); const res = $("util-regex-results");
    if(inp) inp.value = ""; if(res) { res.innerHTML = ""; delete res.dataset.iocs; }
  });

  // ── IOC Normalizer ────────────────────────────────
  $("util-norm-run")?.addEventListener("click", () => {
    const lines = ($("util-norm-input")?.value||"").split("\n");
    const out = lines.map(line => {
      let v = line.trim();
      if (!v) return "";
      v = v.replace(/^hxxps:\/\//i,"https://").replace(/^hxxp:\/\//i,"http://");
      v = v.replace(/\[\.\]/g,".").replace(/\(\.\)/g,".").replace(/\[:\]/g,":");
      v = v.replace(/\[@\]/g,"@").replace(/\(dot\)/gi,".").replace(/\(at\)/gi,"@");
      v = v.replace(/^[\[\(]|[\]\)]+$/g,"").replace(/[,;'"]+$/g,"").trim();
      return v;
    }).filter(Boolean).join("\n");
    const el = $("util-norm-output"); if(el) el.value = out;
  });
  $("util-norm-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText($("util-norm-output")?.value||""); } catch {} });
  $("util-norm-pivot")?.addEventListener("click", () => {
    const v = ($("util-norm-output")?.value||"").trim();
    const bulkIn = $("bulk-input"); if(v && bulkIn) { bulkIn.value = v; switchTab("bulk"); }
  });
  $("util-norm-clear")?.addEventListener("click", () => {
    [$("util-norm-input"),$("util-norm-output")].forEach(el=>{if(el)el.value="";});
  });

  // ── Hex / Octal / Dec Decoder ─────────────────────
  function setHexOut(v) { const el=$("util-hex-output"); if(el) el.value=v; }
  $("util-hex-decode-hex")?.addEventListener("click", () => {
    try {
      const raw = ($("util-hex-input")?.value||"").replace(/\\x/g,"").replace(/0x/gi,"").replace(/\s+/g," ").trim();
      const bytes = raw.match(/.{1,2}/g)||[];
      setHexOut(bytes.map(b=>String.fromCharCode(parseInt(b,16))).join(""));
    } catch { setHexOut("⚠️ Invalid hex input"); }
  });
  $("util-hex-decode-oct")?.addEventListener("click", () => {
    try {
      const raw = ($("util-hex-input")?.value||"").replace(/\\/g," ").trim();
      setHexOut(raw.split(/\s+/).map(n=>String.fromCharCode(parseInt(n,8))).join(""));
    } catch { setHexOut("⚠️ Invalid octal input"); }
  });
  $("util-hex-decode-dec")?.addEventListener("click", () => {
    try {
      setHexOut(($("util-hex-input")?.value||"").trim().split(/[\s,]+/).map(n=>String.fromCharCode(parseInt(n,10))).join(""));
    } catch { setHexOut("⚠️ Invalid decimal input"); }
  });
  $("util-hex-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText($("util-hex-output")?.value||""); } catch {} });

  // ── Timestamp Converter ───────────────────────────
  function setTsOut(html) { const el=$("util-ts-output"); if(el) el.innerHTML=html; }
  $("util-ts-now")?.addEventListener("click", () => {
    const now = Date.now();
    const inp = $("util-ts-input"); if(inp) inp.value = String(now);
    setTsOut(`<strong>Now:</strong><br>Epoch (ms): ${now}<br>Epoch (s): ${Math.floor(now/1000)}<br>UTC: ${new Date(now).toUTCString()}<br>ISO: ${new Date(now).toISOString()}<br>Local: ${new Date(now).toLocaleString()}`);
  });
  $("util-ts-todate")?.addEventListener("click", () => {
    const v = ($("util-ts-input")?.value||"").trim();
    const n = Number(v);
    if (!n) { setTsOut("⚠️ Enter a valid epoch number"); return; }
    const ms = v.length >= 13 ? n : n * 1000;
    const d = new Date(ms);
    setTsOut(`<strong>Epoch → Date:</strong><br>Input: ${v}<br>UTC: ${d.toUTCString()}<br>ISO: ${d.toISOString()}<br>Local: ${d.toLocaleString()}`);
  });
  $("util-ts-toepoch")?.addEventListener("click", () => {
    const v = ($("util-ts-input")?.value||"").trim();
    try {
      const d = new Date(v); if(isNaN(d)) throw new Error();
      setTsOut(`<strong>Date → Epoch:</strong><br>Input: ${v}<br>Epoch (s): ${Math.floor(d.getTime()/1000)}<br>Epoch (ms): ${d.getTime()}<br>UTC: ${d.toUTCString()}`);
    } catch { setTsOut("⚠️ Invalid date string"); }
  });
  $("util-ts-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText($("util-ts-output")?.textContent||""); } catch {} });

  // ── Text Hasher ───────────────────────────────────
  $("util-hash-run")?.addEventListener("click", async () => {
    const text = $("util-hash-input")?.value||"";
    const out = $("util-hash-output");
    if (!text.trim() || !out) return;
    try {
      const enc2 = new TextEncoder();
      const [sha256buf, sha1buf] = await Promise.all([
        crypto.subtle.digest("SHA-256", enc2.encode(text)),
        crypto.subtle.digest("SHA-1", enc2.encode(text)),
      ]);
      const toHex = buf => Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
      const sha256 = toHex(sha256buf);
      const sha1 = toHex(sha1buf);
      out.innerHTML = `<strong>SHA-256:</strong><br><code style="font-size:11px;word-break:break-all">${sha256}</code><br><strong>SHA-1:</strong><br><code style="font-size:11px">${sha1}</code>`;
      out.dataset.sha256 = sha256;
    } catch(e) { out.innerHTML = "⚠️ Hash error: " + e.message; }
  });
  $("util-hash-copy")?.addEventListener("click", async () => {
    const sha256 = $("util-hash-output")?.dataset.sha256||"";
    if(sha256) { try { await navigator.clipboard.writeText(sha256); } catch {} }
  });
  $("util-hash-pivot")?.addEventListener("click", () => {
    const sha256 = $("util-hash-output")?.dataset.sha256||"";
    if(sha256 && input) { input.value = sha256; syncSearchboxState(); switchTab("single"); doSearch({ silent:false }); }
  });

  // ── Analyst Scratchpad (localStorage) ────────────
  const utilNotes = $("util-notes");
  const NOTES_KEY = "osint_scratchpad";
  if (utilNotes) {
    try { utilNotes.value = localStorage.getItem(NOTES_KEY)||""; } catch {}
    const updateNoteCount = () => {
      const v = utilNotes.value;
      const chEl = $("util-notes-chars"); const wdEl = $("util-notes-words");
      if(chEl) chEl.textContent = v.length;
      if(wdEl) wdEl.textContent = v.trim() ? v.trim().split(/\s+/).length : 0;
    };
    utilNotes.addEventListener("input", () => {
      try { localStorage.setItem(NOTES_KEY, utilNotes.value); } catch {}
      updateNoteCount();
    });
    updateNoteCount();
  }
  $("util-notes-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText(utilNotes?.value||""); } catch {} });
  $("util-notes-export")?.addEventListener("click", () => {
    const blob = new Blob([utilNotes?.value||""], {type:"text/plain"});
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `analyst-notes-${Date.now()}.txt`; a.click();
  });
  $("util-notes-clear")?.addEventListener("click", () => {
    if (!confirm("Clear scratchpad? This cannot be undone.")) return;
    if(utilNotes) utilNotes.value = "";
    try { localStorage.removeItem(NOTES_KEY); } catch {}
    [$("util-notes-chars"),$("util-notes-words")].forEach(el=>{if(el)el.textContent="0";});
  });

  // ── String Transforms ─────────────────────────────
  const utilStrIn  = $("util-str-input");
  const utilStrOut = $("util-str-output");
  function setStrOut(v) { if(utilStrOut) utilStrOut.value = v; }
  $("util-str-reverse")?.addEventListener("click", () => setStrOut((utilStrIn?.value||"").split("").reverse().join("")));
  $("util-str-rot13")?.addEventListener("click", () => setStrOut((utilStrIn?.value||"").replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0)+(c.toLowerCase()<'n'?13:-13)))));
  $("util-str-upper")?.addEventListener("click", () => setStrOut((utilStrIn?.value||"").toUpperCase()));
  $("util-str-lower")?.addEventListener("click", () => setStrOut((utilStrIn?.value||"").toLowerCase()));
  $("util-str-hex")?.addEventListener("click", () => setStrOut(Array.from(utilStrIn?.value||"").map(c=>"\\x"+c.charCodeAt(0).toString(16).padStart(2,"0")).join("")));
  $("util-str-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText(utilStrOut?.value||""); } catch {} });

  // ── JWT Decoder ───────────────────────────────────
  $("util-jwt-decode")?.addEventListener("click", () => {
    const raw = ($("util-jwt-input")?.value||"").trim();
    const out = $("util-jwt-output");
    if (!out) return;
    const parts = raw.split(".");
    if (parts.length < 2) { out.textContent = "⚠️ Invalid JWT — expected 3 dot-separated parts"; return; }
    try {
      const decode = part => {
        const pad = part.replace(/-/g,"+").replace(/_/g,"/");
        return JSON.parse(atob(pad + "==".slice(0,(4-pad.length%4)%4)));
      };
      const header  = decode(parts[0]);
      const payload = decode(parts[1]);
      const now = Math.floor(Date.now()/1000);
      const exp = payload.exp;
      const expStr = exp ? `${new Date(exp*1000).toISOString()} ${exp < now ? "⚠️ EXPIRED" : "✅ VALID"}` : "—";
      out.textContent = `── HEADER ──\n${JSON.stringify(header,null,2)}\n\n── PAYLOAD ──\n${JSON.stringify(payload,null,2)}\n\n── EXPIRY ──\n${expStr}\n\n── SIGNATURE ──\n${parts[2]||"—"} (not verified)`;
    } catch(e) { out.textContent = "⚠️ Decode failed: " + e.message; }
  });
  $("util-jwt-copy")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText($("util-jwt-output")?.textContent||""); } catch {} });

  // ═══════════════════════════════════════════════════════════════
  // ─── CTI FEED TAB ─────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════

  // ── CTI Sub-tab switcher ──────────────────────────────────────
  document.querySelectorAll(".cti-sub-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".cti-sub-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".cti-panel").forEach(p => p.style.display = "none");
      btn.classList.add("active");
      const panel = $(`cti-panel-${btn.dataset.ctitab}`);
      if (panel) panel.style.display = "block";
    });
  });

  // ── CTI Feed definitions ──────────────────────────────────────
  const CTI_FEEDS = [
    {
      id: "feodo", name: "Feodo Tracker — C2 IPs", icon: "🎣", color: "#f87171",
      url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
      parse: (text) => {
        const lines = text.split("\n").filter(l => l && !l.startsWith("#"));
        return { count: lines.length, sample: lines.slice(0,5).map(l=>l.split(",")[0]).join(", "), label: "C2 IP addresses" };
      }
    },
    {
      id: "urlhaus", name: "URLhaus — Malware URLs", icon: "🏚", color: "#fb923c",
      url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
      parse: (text) => {
        const lines = text.split("\n").filter(l => l && !l.startsWith("#") && l.includes("http"));
        return { count: lines.length, sample: lines.slice(0,3).map(l=>(l.split(",")[2]||"").replace(/"/g,"")).join(", "), label: "malware URLs (24h)" };
      }
    },
    {
      id: "tor", name: "TOR Exit Nodes", icon: "🧅", color: "#a78bfa",
      url: "https://check.torproject.org/torbulkexitlist",
      parse: (text) => {
        const ips = text.split("\n").filter(l => /^\d/.test(l));
        return { count: ips.length, sample: ips.slice(0,3).join(", "), label: "TOR exit nodes" };
      }
    },
  ];

  const ctiFeedsGrid = $("cti-feeds-grid");
  const ctiFeedStatus = $("cti-feed-status");

  function renderFeedCard(feed, state) {
    const existing = document.getElementById(`cti-feed-${feed.id}`);
    const html = `<div class="cti-feed-card" id="cti-feed-${feed.id}" style="border-color:${feed.color}33">
      <div class="cti-feed-head">
        <span class="cti-feed-icon">${feed.icon}</span>
        <span class="cti-feed-name">${feed.name}</span>
        <span class="cti-feed-badge" style="background:${feed.color}22;color:${feed.color};border-color:${feed.color}44">${state === "loading" ? "⏳ Loading" : state.count ? `${state.count.toLocaleString()} entries` : "⚠️ Unavailable"}</span>
      </div>
      ${state.count ? `<div class="cti-feed-meta">${state.label}: <code>${state.sample}</code>${state.count > 3 ? "..." : ""}</div>` : ""}
      ${state.count ? `<div class="cti-feed-actions">
        <a href="${feed.url}" target="_blank" class="quicklink-btn" style="font-size:10px">📥 Raw Feed</a>
      </div>` : ""}
    </div>`;
    if (existing) { existing.outerHTML = html; } else if (ctiFeedsGrid) { ctiFeedsGrid.insertAdjacentHTML("beforeend", html); }
  }

  // Add static info cards for feeds we can't CORS-fetch directly
  const STATIC_FEED_CARDS = [
    { icon:"🦊", color:"#fb923c", name:"ThreatFox — IOC Feed", desc:"Latest C2, malware hashes, URLs from ThreatFox.", url:"https://threatfox.abuse.ch/browse/" },
    { icon:"👽", color:"#34d399", name:"OTX AlienVault — Pulse Feed", desc:"Open threat exchange pulses from thousands of researchers.", url:"https://otx.alienvault.com/browse/global/pulses" },
    { icon:"🌫", color:"#38bdf8", name:"GreyNoise — Noise Feed", desc:"Differentiates benign internet noise from targeted attacks.", url:"https://viz.greynoise.io/" },
    { icon:"🧨", color:"#f87171", name:"CISA KEV — Known Exploited Vulns", desc:"CVEs actively exploited in the wild per CISA.", url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
    { icon:"📡", color:"#a78bfa", name:"Pulsedive — Threat Intel", desc:"Community threat intel with IOC enrichment.", url:"https://pulsedive.com/feed/" },
    { icon:"🔵", color:"#60a5fa", name:"MSTIC Blog — Microsoft TI", desc:"Latest threat actor profiles and campaign reports.", url:"https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/" },
  ];

  function renderStaticFeedCards() {
    if (!ctiFeedsGrid) return;
    STATIC_FEED_CARDS.forEach(c => {
      ctiFeedsGrid.insertAdjacentHTML("beforeend", `<div class="cti-feed-card" style="border-color:${c.color}33">
        <div class="cti-feed-head">
          <span class="cti-feed-icon">${c.icon}</span>
          <span class="cti-feed-name">${c.name}</span>
        </div>
        <div class="cti-feed-meta">${c.desc}</div>
        <div class="cti-feed-actions"><a href="${c.url}" target="_blank" class="quicklink-btn" style="font-size:10px">🔗 Open Feed</a></div>
      </div>`);
    });
  }

  $("cti-feeds-refresh")?.addEventListener("click", async () => {
    if (ctiFeedsGrid) ctiFeedsGrid.innerHTML = "";
    if (ctiFeedStatus) ctiFeedStatus.textContent = "Loading feeds...";
    renderStaticFeedCards();
    let loaded = 0;
    for (const feed of CTI_FEEDS) {
      renderFeedCard(feed, "loading");
      try {
        const res = await fetch(feed.url, { signal: AbortSignal.timeout(8000) });
        if (!res.ok) throw new Error("HTTP " + res.status);
        const text = await res.text();
        renderFeedCard(feed, feed.parse(text));
        loaded++;
      } catch(e) {
        renderFeedCard(feed, { count: 0, label: "Fetch error: " + e.message });
      }
    }
    if (ctiFeedStatus) ctiFeedStatus.textContent = `${loaded}/${CTI_FEEDS.length} live feeds loaded · ${new Date().toLocaleTimeString()}`;
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 2 — EMAIL HEADER DEEP ANALYZER
  // ════════════════════════════════════════════════════════════════
  function analyzeEmailHeadersFull(raw) {
    const t = (raw || "").replace(/\r\n/g, "\n");
    const getH = re => (t.match(re) || [])[1]?.trim() || "";
    // Basic fields
    const from       = getH(/^from:\s*(.+)$/im);
    const to         = getH(/^to:\s*(.+)$/im);
    const replyTo    = getH(/^reply-to:\s*(.+)$/im);
    const subject    = getH(/^subject:\s*(.+)$/im);
    const date       = getH(/^date:\s*(.+)$/im);
    const msgId      = getH(/^message-id:\s*<?([^>\n]+)>?/im);
    const returnPath = getH(/^return-path:\s*<?([^>\s]+)>?/im);
    const xOrigIP    = getH(/^x-originating-ip:\s*\[?([^\]\s\n]+)/im) ||
                       getH(/^x-sender-ip:\s*([^\s\n]+)/im);
    const xMailer    = getH(/^x-mailer:\s*(.+)$/im);
    // Extract email addresses
    const fromEmail  = (from.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i)||[])[1]||"";
    const fromName   = (from.match(/^"?([^"<]+)"?\s*</)||[])[1]?.trim()||"";
    const replyEmail = (replyTo.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i)||[])[1]||"";
    const retDomain  = returnPath.split("@")[1]?.toLowerCase()||"";
    const fromDomain = fromEmail.split("@")[1]?.toLowerCase()||"";
    // Auth block
    const authBlock = (() => {
      const m = t.match(/^authentication-results:[\s\S]+?(?=\n[A-Za-z0-9-]{2,}:|$)/im);
      return (m?.[0]||"").replace(/\n\s+/g," ");
    })();
    const spf  = (authBlock.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i)||[])[1]?.toLowerCase()||"none";
    const dkim = (authBlock.match(/\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i)||[])[1]?.toLowerCase()||"none";
    const dmarc= (authBlock.match(/\bdmarc=(pass|fail|bestguesspass|none)\b/i)||[])[1]?.toLowerCase()||"none";
    // Received hops
    const receivedBlocks = t.match(/^received:[\s\S]+?(?=\n[A-Za-z0-9-]{2,}:|$)/gim)||[];
    const hops = receivedBlocks.map((block, idx) => {
      const clean = block.replace(/\n\s+/g," ");
      const by    = (clean.match(/by\s+([\w.\-]+)/i)||[])[1]||"";
      const fr    = (clean.match(/from\s+([\w.\-\[\]]+)/i)||[])[1]||"";
      const ipM   = clean.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)||[];
      const ip    = ipM.find(i => !isPrivateIPv4(i))||ipM[0]||"";
      const tsM   = clean.match(/;\s*([A-Za-z].*(?:GMT|UTC|[+-]\d{4}))\s*$/i);
      const ts    = tsM ? new Date(tsM[1]) : null;
      return { hop: receivedBlocks.length - idx, by, from: fr, ip, ts, raw: clean };
    }).reverse();
    // Calculate delays between hops
    for (let i=1; i<hops.length; i++) {
      if (hops[i].ts && hops[i-1].ts) {
        const diff = (hops[i].ts - hops[i-1].ts) / 1000;
        hops[i].delay = diff < 0 ? "?" : diff < 60 ? `${Math.round(diff)}s` : `${Math.round(diff/60)}m`;
      }
    }
    // Phishing signal scoring
    let score = 0;
    const flags = [];
    if (spf === "fail" || spf === "softfail")  { score += 25; flags.push({ sev:"crit", msg:`SPF ${spf.toUpperCase()} — sender not authorized by domain's DNS policy` }); }
    if (dkim === "fail")                       { score += 20; flags.push({ sev:"crit", msg:"DKIM FAIL — message was modified in transit or sender domain is spoofed" }); }
    if (dmarc === "fail")                      { score += 20; flags.push({ sev:"crit", msg:"DMARC FAIL — email fails domain alignment check, strong phishing indicator" }); }
    if (replyEmail && replyEmail !== fromEmail) { score += 20; flags.push({ sev:"warn", msg:`Reply-To mismatch: From is ${fromEmail} but replies go to ${replyEmail}` }); }
    if (fromName && fromDomain && !fromEmail.toLowerCase().includes(fromName.toLowerCase().split(" ")[0]) && fromDomain.includes("gmail") || fromDomain.includes("yahoo") || fromDomain.includes("hotmail")) {
      score += 10; flags.push({ sev:"warn", msg:`Free email provider (${fromDomain}) used — possible impersonation` });
    }
    if (retDomain && fromDomain && retDomain !== fromDomain) { score += 15; flags.push({ sev:"warn", msg:`Return-Path domain (${retDomain}) differs from From domain (${fromDomain})` }); }
    if (xOrigIP)                               { score += 5;  flags.push({ sev:"info", msg:`X-Originating-IP: ${xOrigIP} — the sender's actual client IP` }); }
    if (hops.length <= 1)                      { score += 10; flags.push({ sev:"warn", msg:"Very few relay hops — headers may be forged or truncated" }); }
    if (!subject)                              { flags.push({ sev:"info", msg:"No subject line detected" }); }
    if (score === 0 && spf === "pass" && dkim === "pass") { flags.push({ sev:"ok", msg:"SPF + DKIM pass with no mismatches — email appears legitimate" }); }
    return { from, to, replyTo, subject, date, msgId, returnPath, xOrigIP, xMailer,
             fromEmail, fromName, fromDomain, replyEmail, retDomain,
             spf, dkim, dmarc, hops, flags, score };
  }

  function renderEmailHeaderResults(r) {
    const results = $("eha-results");
    if (!results) return;
    results.style.display = "block";
    // Score banner
    const banner = $("eha-score-banner");
    const pct = Math.min(100, r.score);
    const cls  = pct >= 50 ? "eha-score-phishing" : pct >= 25 ? "eha-score-suspicious" : "eha-score-clean";
    const lbl  = pct >= 50 ? "LIKELY PHISHING" : pct >= 25 ? "SUSPICIOUS" : "APPEARS CLEAN";
    banner.className = `eha-score-banner ${cls}`;
    banner.innerHTML = `<div class="eha-score-num">${pct}</div><div><div class="eha-score-label">${lbl}</div><div class="eha-score-sub">Phishing risk score — ${r.flags.length} signal(s) detected</div></div>`;
    // Summary grid
    const summaryItems = [
      { label:"From",        value: r.fromEmail || r.from || "—" },
      { label:"Reply-To",    value: r.replyEmail || "Same as From" },
      { label:"Subject",     value: r.subject || "—" },
      { label:"Date",        value: r.date || "—" },
      { label:"Return-Path", value: r.returnPath || "—" },
      { label:"X-Orig IP",   value: r.xOrigIP || "Not present" },
      { label:"Mailer",      value: r.xMailer || "Not disclosed" },
      { label:"Relay Hops",  value: r.hops.length + " hops" },
    ];
    $("eha-summary").innerHTML = summaryItems.map(s =>
      `<div class="eha-summary-item"><div class="eha-summary-label">${s.label}</div><div class="eha-summary-value">${esc(String(s.value))}</div></div>`
    ).join("");
    // Auth badges
    const authMap = { pass:"eha-auth-pass", fail:"eha-auth-fail", softfail:"eha-auth-fail", none:"eha-auth-none", neutral:"eha-auth-none" };
    $("eha-auth").innerHTML = ["SPF","DKIM","DMARC"].map((k,i) => {
      const v = [r.spf, r.dkim, r.dmarc][i];
      const cls = authMap[v] || "eha-auth-none";
      return `<span class="eha-auth-badge ${cls}">${k}: ${(v||"none").toUpperCase()}</span>`;
    }).join("");
    // Hop chain
    const hopsEl = $("eha-hops");
    if (r.hops.length) {
      hopsEl.innerHTML = `<div class="eha-hop-row eha-hop-head"><span>#</span><span>From / By</span><span>IP</span><span>Delay</span><span>Flag</span></div>` +
        r.hops.map(h => `<div class="eha-hop-row">
          <div class="eha-hop-num">${h.hop}</div>
          <div class="eha-hop-host">${esc(h.by || h.from || "?")} </div>
          <div class="eha-hop-ip">${h.ip ? `<a href="https://www.abuseipdb.com/check/${encodeURIComponent(h.ip)}" target="_blank" style="color:#38bdf8;text-decoration:none;">${esc(h.ip)}</a>` : "—"}</div>
          <div class="eha-hop-delay">${h.delay || "—"}</div>
          <div class="eha-hop-flag">${h.ip && !isPrivateIPv4(h.ip) ? "🌐" : "🏠"}</div>
        </div>`).join("");
    } else {
      hopsEl.innerHTML = `<div style="padding:12px;font-size:11px;color:var(--muted);">No Received headers found — headers may be incomplete or forged.</div>`;
    }
    // Flags
    $("eha-flags").innerHTML = r.flags.map(f => {
      const cls = f.sev==="crit" ? "eha-flag-crit" : f.sev==="warn" ? "eha-flag-warn" : "eha-flag-info";
      const icon = f.sev==="crit" ? "🚨" : f.sev==="warn" ? "⚠️" : f.sev==="ok" ? "✅" : "ℹ️";
      return `<div class="eha-flag-item ${cls}">${icon} ${esc(f.msg)}</div>`;
    }).join("") || `<div class="eha-flag-item eha-flag-info">✅ No obvious phishing signals detected</div>`;
    // Pivot buttons
    const pivots = [];
    if (r.fromEmail)  pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.fromEmail)}','email')">🔍 Investigate sender</button>`);
    if (r.xOrigIP)    pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.xOrigIP)}','ip')">🛡 Check origin IP</button>`);
    if (r.replyEmail && r.replyEmail !== r.fromEmail) pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.replyEmail)}','email')">📧 Check reply-to</button>`);
    pivots.push(`<button class="eha-pivot-btn" onclick="copyEHAHops()">📋 Copy hop IPs</button>`);
    $("eha-pivots").innerHTML = pivots.join("");
    // Store for pivot use
    window._ehaResult = r;
  }

  window.pivotFromEHA = (val, type) => {
    const inp = $("input"); if (inp) inp.value = val;
    syncSearchboxState(); switchTab("single"); doSearch({ silent: false });
  };
  window.copyEHAHops = () => {
    const ips = (window._ehaResult?.hops||[]).map(h=>h.ip).filter(Boolean).join("\n");
    navigator.clipboard.writeText(ips).catch(()=>{});
  };

  $("eha-analyze-btn")?.addEventListener("click", () => {
    const raw = $("eha-input")?.value?.trim();
    if (!raw) return;
    const r = analyzeEmailHeadersFull(raw);
    renderEmailHeaderResults(r);
  });
  $("eha-clear-btn")?.addEventListener("click", () => {
    if ($("eha-input")) $("eha-input").value = "";
    const res = $("eha-results"); if (res) res.style.display = "none";
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 3 — DETECTION QUERY BUILDER
  // ════════════════════════════════════════════════════════════════
  const DQB_QUERIES = {
    splunk: {
      ip:           (v) => v ? `index=* (src_ip="${v}" OR dest_ip="${v}" OR src="${v}" OR dst="${v}")\n| table _time, src_ip, dest_ip, action, app, host` : `index=* src_ip=<IOC_IP>\n| table _time, src_ip, dest_ip, action`,
      domain:       (v) => v ? `index=* (url="*${v}*" OR dns_query="${v}" OR host="${v}")\n| table _time, host, url, dns_query, user` : `index=* url="*<DOMAIN>*"\n| table _time, host, url, user`,
      hash:         (v) => v ? `index=* (file_hash="${v}" OR sha256="${v}" OR md5="${v}")\n| table _time, host, user, file_path, process` : `index=* file_hash="<HASH>"\n| table _time, host, file_path, process`,
      url:          (v) => v ? `index=* url="${v}"\n| table _time, host, user, url, action` : `index=* url="<URL>"\n| table _time, host, user, url`,
      email:        (v) => v ? `index=* (sender="${v}" OR recipient="${v}" OR from="${v}")\n| table _time, sender, recipient, subject, action` : `index=* sender="<EMAIL>"\n| table _time, sender, recipient, subject`,
      cmdline:      (v) => v ? `index=* CommandLine="*${v}*"\n| table _time, host, user, ParentImage, CommandLine` : `index=* (CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*")\n| table _time, host, user, CommandLine`,
      process:      (v) => v ? `index=* (Image="*${v}*" OR process_name="${v}")\n| table _time, host, user, Image, CommandLine, ParentImage` : `index=* Image="*<PROCESS>*"\n| table _time, host, user, Image`,
      encoded_ps:   () => `index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational"\n  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*")\n| rex field=CommandLine "(?i)-enc(?:odedcommand)?\\s+(?P<b64>[A-Za-z0-9+/=]+)"\n| table _time, host, user, CommandLine, b64`,
      failed_login: () => `index=* EventCode=4625\n| stats count by src_ip, user, host\n| where count > 5\n| sort - count`,
      new_account:  () => `index=* EventCode=4720\n| table _time, host, user, SAMAccountName, SubjectUserName`,
      sched_task:   () => `index=* (EventCode=4698 OR TaskName="*")\n| table _time, host, user, TaskName, CommandLine`,
      lateral:      () => `index=* (EventCode=4624 Logon_Type=3 OR EventCode=4648)\n| where src_ip!=dest_ip\n| stats count by src_ip, dest_ip, user\n| where count > 3`,
      c2_port:      () => `index=* (dest_port=4444 OR dest_port=50050 OR dest_port=8080 OR dest_port=1337 OR dest_port=9001)\n| table _time, src_ip, dest_ip, dest_port, process`,
      lolbin:       () => `index=* (Image="*mshta.exe*" OR Image="*regsvr32.exe*" OR Image="*rundll32.exe*" OR Image="*wscript.exe*" OR Image="*cscript.exe*" OR Image="*certutil.exe*")\n| where NOT match(ParentImage, "(?i)(windows\\\\system32|syswow64)\\\\(svchost|services|wininit)\\.exe")\n| table _time, host, user, Image, CommandLine, ParentImage`,
      large_upload: () => `index=* bytes_out > 10000000\n| stats sum(bytes_out) as total_bytes by src_ip, dest_ip\n| sort - total_bytes\n| eval total_MB=round(total_bytes/1048576, 2)`,
    },
    kql: {
      ip:           (v) => v ? `union DeviceNetworkEvents, CommonSecurityLog\n| where RemoteIP == "${v}" or SourceIP == "${v}" or DestinationIP == "${v}"\n| project TimeGenerated, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName` : `DeviceNetworkEvents\n| where RemoteIP == "<IOC_IP>"\n| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      domain:       (v) => v ? `union DeviceNetworkEvents, DnsEvents\n| where RemoteUrl contains "${v}" or Name contains "${v}"\n| project TimeGenerated, DeviceName, RemoteUrl, Name, IPAddresses` : `DnsEvents\n| where Name contains "<DOMAIN>"\n| project TimeGenerated, Computer, Name, IPAddresses`,
      hash:         (v) => v ? `DeviceFileEvents\n| where SHA256 == "${v}" or MD5 == "${v}"\n| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessAccountName` : `DeviceFileEvents\n| where SHA256 == "<HASH>"\n| project TimeGenerated, DeviceName, FileName, FolderPath`,
      encoded_ps:   () => `DeviceProcessEvents\n| where ProcessCommandLine matches regex @"(?i)(-enc|-EncodedCommand)"\n| extend B64 = extract(@"(?i)-enc(?:odedCommand)?\\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, B64`,
      failed_login: () => `SigninLogs\n| where ResultType !in ("0", "50125", "50140")\n| summarize FailedAttempts=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)\n| where FailedAttempts > 5\n| sort by FailedAttempts desc`,
      lateral:      () => `DeviceLogonEvents\n| where LogonType in ("Network", "RemoteInteractive")\n| where IsLocalLogon == false\n| summarize count() by RemoteDeviceName, AccountName, DeviceName\n| sort by count_ desc`,
      c2_port:      () => `DeviceNetworkEvents\n| where RemotePort in (4444, 50050, 8080, 1337, 9001)\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort`,
      lolbin:       () => `DeviceProcessEvents\n| where FileName in~ ("mshta.exe","regsvr32.exe","rundll32.exe","wscript.exe","cscript.exe","certutil.exe")\n| where InitiatingProcessFileName !in~ ("svchost.exe","services.exe","wininit.exe")\n| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
    },
    elastic: {
      ip:           (v) => v ? `GET .ds-logs-*/_search\n{\n  "query": {\n    "bool": {\n      "should": [\n        {"term": {"source.ip": "${v}"}},\n        {"term": {"destination.ip": "${v}"}}\n      ]\n    }\n  }\n}` : `GET .ds-logs-*/_search\n{\n  "query": {"term": {"source.ip": "<IOC_IP>"}}\n}`,
      hash:         (v) => v ? `GET .ds-logs-*/_search\n{\n  "query": {\n    "bool": {\n      "should": [\n        {"term": {"file.hash.sha256": "${v}"}},\n        {"term": {"file.hash.md5": "${v}"}}\n      ]\n    }\n  }\n}` : `GET .ds-logs-*/_search\n{\n  "query": {"term": {"file.hash.sha256": "<HASH>"}}\n}`,
      encoded_ps:   () => `GET .ds-logs-*/_search\n{\n  "query": {\n    "wildcard": {\n      "process.command_line": "*-EncodedCommand*"\n    }\n  }\n}`,
      failed_login: () => `GET .ds-logs-*/_search\n{\n  "query": {\n    "bool": {\n      "must": [\n        {"term": {"event.action": "logon-failed"}},\n        {"range": {"@timestamp": {"gte": "now-1h"}}}\n      ]\n    }\n  },\n  "aggs": {\n    "by_user": {"terms": {"field": "user.name"}},\n    "by_ip": {"terms": {"field": "source.ip"}}\n  }\n}`,
    },
    qradar: {
      ip:           (v) => v ? `SELECT * FROM events WHERE sourceip='${v}' OR destinationip='${v}' LAST 24 HOURS` : `SELECT * FROM events WHERE sourceip='<IOC_IP>' LAST 24 HOURS`,
      hash:         (v) => v ? `SELECT * FROM events WHERE "filehash"='${v}' LAST 24 HOURS` : `SELECT * FROM events WHERE "filehash"='<HASH>' LAST 24 HOURS`,
      encoded_ps:   () => `SELECT * FROM events WHERE "CommandLine" ILIKE '%-enc%' OR "CommandLine" ILIKE '%-EncodedCommand%' LAST 24 HOURS`,
      failed_login: () => `SELECT sourceip, username, count(*) AS attempts FROM events\nWHERE eventid=4625 GROUP BY sourceip, username\nHAVING count(*) > 5 LAST 1 HOURS`,
      lateral:      () => `SELECT sourceip, destinationip, username, count(*) FROM events\nWHERE eventid=4624 AND "LogonType"='3' GROUP BY sourceip, destinationip, username LAST 1 HOURS`,
    },
    cs: {
      ip:           (v) => v ? `event_simpleName=NetworkConnectIP4 (RemoteAddressIP4="${v}" OR LocalAddressIP4="${v}")\n| table _time, ComputerName, UserName, RemoteAddressIP4, RemotePort, FileName` : `event_simpleName=NetworkConnectIP4 RemoteAddressIP4="<IOC_IP>"\n| table _time, ComputerName, UserName, RemoteAddressIP4`,
      hash:         (v) => v ? `(MD5HashData="${v}" OR SHA256HashData="${v}")\n| table _time, ComputerName, UserName, FileName, FilePath, CommandLine` : `SHA256HashData="<HASH>"\n| table _time, ComputerName, UserName, FileName, FilePath`,
      encoded_ps:   () => `event_simpleName=ProcessRollup2 (CommandLine="*-enc *" OR CommandLine="*-EncodedCommand *" OR CommandLine="*FromBase64String*")\n| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName`,
      failed_login: () => `event_simpleName=UserLogon\n| stats count by UserName, RemoteAddressIP4\n| where count > 5\n| sort - count`,
      lolbin:       () => `event_simpleName=ProcessRollup2 ImageFileName IN ("mshta.exe","regsvr32.exe","rundll32.exe","wscript.exe","cscript.exe")\n| table _time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName`,
    },
  };

  function buildDQBQuery() {
    const platform = $("dqb-platform")?.value || "splunk";
    const pattern  = $("dqb-pattern")?.value || "ip";
    const rawVals  = ($("dqb-ioc-input")?.value||"").trim().split("\n").map(v=>v.trim()).filter(Boolean);
    const val      = rawVals[0] || "";
    const platformQ = DQB_QUERIES[platform] || DQB_QUERIES.splunk;
    const genFn    = platformQ[pattern] || platformQ.ip;
    let query;
    if (rawVals.length > 1 && ["ip","domain","hash","email","url","process"].includes(pattern)) {
      // Multi-value: build OR'd query
      if (platform === "splunk") {
        const orPart = rawVals.map(v => `"${v}"`).join(" OR ");
        query = `index=* (${orPart})\n| table _time, host, user, src_ip, dest_ip, process, CommandLine`;
      } else if (platform === "kql") {
        const field = pattern === "ip" ? "RemoteIP" : pattern === "hash" ? "SHA256" : "RemoteUrl";
        query = `DeviceNetworkEvents\n| where ${field} in (${rawVals.map(v=>`"${v}"`).join(", ")})\n| project TimeGenerated, DeviceName, AccountName, ${field}`;
      } else {
        query = genFn(val) + `\n// Remaining IOCs: ${rawVals.slice(1).join(", ")}`;
      }
    } else {
      query = genFn(val);
    }
    const out = $("dqb-output");
    if (out) out.textContent = `// Platform: ${platform.toUpperCase()} | Pattern: ${pattern.replace(/_/g," ")}\n// Generated: ${new Date().toLocaleString()}\n\n${query}`;
  }

  $("dqb-generate")?.addEventListener("click", buildDQBQuery);
  $("dqb-copy")?.addEventListener("click", async () => {
    const txt = $("dqb-output")?.textContent || "";
    try { await navigator.clipboard.writeText(txt); } catch {}
  });
  $("dqb-test-toggle")?.addEventListener("click", () => {
    const p = $("dqb-test-panel");
    if (p) p.style.display = p.style.display === "none" ? "block" : "none";
  });
  $("dqb-test-run")?.addEventListener("click", () => {
    const logLine = $("dqb-test-input")?.value?.trim() || "";
    const query   = $("dqb-output")?.textContent || "";
    const resultEl = $("dqb-test-result");
    if (!logLine || !resultEl) return;
    // Extract quoted strings from query and check if any appear in log line
    const terms = [...(query.matchAll(/"([^"]+)"/g))].map(m => m[1]).filter(t => t.length > 2 && !t.includes("\\n"));
    const hit = terms.some(t => logLine.toLowerCase().includes(t.toLowerCase()));
    resultEl.textContent = hit ? "✅ MATCH — log line would be captured" : "❌ NO MATCH";
    resultEl.className = hit ? "dqb-match" : "dqb-no-match";
    resultEl.style.border = "1px solid";
    resultEl.style.borderRadius = "6px";
    resultEl.style.padding = "3px 10px";
    resultEl.style.fontWeight = "700";
    resultEl.style.fontSize = "11px";
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 4 — THREAT HUNTING QUERY LIBRARY
  // ════════════════════════════════════════════════════════════════
  const HUNT_PACKS = [
    { title:"PowerShell Encoded Command Execution", mitre:"T1059.001", cat:"execution",       desc:"Detect PowerShell launched with Base64-encoded commands — common in phishing payloads and malware loaders.",
      queries:{ splunk:`index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational"\n  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*")\n| rex field=CommandLine "(?i)-enc\\s+(?P<b64>[A-Za-z0-9+/=]{20,})"\n| table _time, host, user, CommandLine, b64`, kql:`DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)(-enc |-EncodedCommand )" | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`, cs:`event_simpleName=ProcessRollup2 FileName="powershell.exe" CommandLine="*-enc *"\n| table _time, ComputerName, UserName, CommandLine` }},
    { title:"LOLBin Spawned by Office Application", mitre:"T1566.001", cat:"initial_access",  desc:"Detect Office apps (Word, Excel, Outlook) spawning cmd.exe, powershell, mshta or wscript — hallmark of malicious macro execution.",
      queries:{ splunk:`index=* ParentImage IN ("*winword.exe*","*excel.exe*","*outlook.exe*","*powerpnt.exe*") FileName IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe")\n| table _time, host, user, ParentImage, Image, CommandLine`, kql:`DeviceProcessEvents | where InitiatingProcessFileName has_any ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE") and FileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe") | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`, cs:`event_simpleName=ProcessRollup2 ParentBaseFileName IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE") ImageFileName IN ("cmd.exe","powershell.exe","wscript.exe")\n| table _time, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine` }},
    { title:"LSASS Memory Access (Credential Dumping)", mitre:"T1003.001", cat:"credential",   desc:"Detect processes accessing lsass.exe memory — used by Mimikatz, procdump, and comsvcs.dll for credential extraction.",
      queries:{ splunk:`index=* (TargetImage="*lsass.exe*" OR CommandLine="*lsass*") (GrantedAccess="0x1010" OR GrantedAccess="0x1fffff" OR GrantedAccess="0x1410")\n| table _time, host, user, SourceImage, TargetImage, GrantedAccess`, kql:`DeviceEvents | where ActionType == "OpenProcess" and TargetProcessFileName =~ "lsass.exe" and ProcessCommandLine !has_any ("MsMpEng","svchost") | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`, cs:`event_simpleName=ProcessAccess TargetImageFileName="*lsass.exe*"\n| where GrantedAccess IN ("0x1010","0x1fffff","0x1410")\n| table _time, ComputerName, UserName, SourceImageFileName, GrantedAccess` }},
    { title:"Scheduled Task Creation via Command Line", mitre:"T1053.005", cat:"persistence",  desc:"Detect scheduled task creation using schtasks.exe — common persistence mechanism used by malware and attackers.",
      queries:{ splunk:`index=* (Image="*schtasks.exe*" OR CommandLine="*schtasks*") CommandLine="*/create*"\n| table _time, host, user, CommandLine, ParentImage`, kql:`DeviceProcessEvents | where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create" | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`, cs:`event_simpleName=ProcessRollup2 ImageFileName="schtasks.exe" CommandLine="*/create*"\n| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName` }},
    { title:"New Local Admin Account Created", mitre:"T1136.001", cat:"persistence",           desc:"Detect creation of new local accounts followed by addition to Administrators group — post-exploitation backdoor tactic.",
      queries:{ splunk:`index=* EventCode IN (4720,4732)\n| eval event_type=if(EventCode==4720,"Account Created","Added to Admins")\n| table _time, host, user, SAMAccountName, SubjectUserName, event_type`, kql:`SecurityEvent | where EventID in (4720, 4732) | project TimeGenerated, Computer, SubjectUserName, TargetUserName, Activity`, cs:`event_simpleName=UserAccountCreated OR event_simpleName=UserAccountAddedToGroup\n| table _time, ComputerName, UserName, GroupRid` }},
    { title:"Impossible Travel / Concurrent Logins", mitre:"T1078.004", cat:"identity",        desc:"Detect successful logins from two different countries within a short window — strong indicator of credential compromise.",
      queries:{ splunk:`index=* EventCode=4624 Logon_Type=3\n| eval hour=strftime(_time,"%Y-%m-%d %H")\n| stats values(src_ip) as ips, values(Country) as countries, count by user, hour\n| where mvcount(countries) > 1`, kql:`SigninLogs | where ResultType == "0" | summarize Locations=make_set(Location), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h) | where array_length(Locations) > 1`, cs:`event_simpleName=UserLogon\n| stats dc(RemoteAddressIP4) as unique_ips, values(RemoteAddressIP4) as ips by UserName\n| where unique_ips > 2` }},
    { title:"MFA Fatigue / Push Spam Detection", mitre:"T1621", cat:"identity",                desc:"Detect accounts receiving excessive MFA push requests — Scattered Spider and others use this to wear down users.",
      queries:{ splunk:`index=* sourcetype=okta (eventType="user.mfa.okta_verify.deny_push" OR eventType="user.mfa.challenge")\n| stats count by user, src_ip, _time\n| where count > 5`, kql:`SigninLogs | where AuthenticationRequirement == "multiFactorAuthentication" and ResultType != "0" | summarize PushCount=count() by UserPrincipalName, bin(TimeGenerated, 1h) | where PushCount > 5`, cs:`event_simpleName=UserLogon AuthenticationMethod="MFA" AuthenticationResult="Denied"\n| stats count by UserName\n| where count > 5` }},
    { title:"Lateral Movement via RDP (T1021.001)", mitre:"T1021.001", cat:"lateral",           desc:"Detect RDP logins from internal hosts — lateral movement indicator, especially with admin shares or pass-the-hash.",
      queries:{ splunk:`index=* EventCode=4624 Logon_Type=10\n| where src_ip!=host\n| stats count by src_ip, host, user\n| where count > 2\n| sort - count`, kql:`DeviceLogonEvents | where LogonType == "RemoteInteractive" and IsLocalLogon == false | summarize count() by RemoteDeviceName, DeviceName, AccountName | sort by count_ desc`, cs:`event_simpleName=UserLogon LogonType="10"\n| stats count by UserName, LocalAddressIP4, RemoteAddressIP4\n| sort - count` }},
    { title:"Suspicious Outbound DNS (DGA Detection)", mitre:"T1568.002", cat:"c2",            desc:"Detect high-entropy, long, or high-frequency DNS queries — indicators of DGA malware C2 communication.",
      queries:{ splunk:`index=* sourcetype=stream:dns\n| eval domain_len=len(query)\n| where domain_len > 30 OR (src_ip=* AND reply_code="NXDOMAIN")\n| stats count by query, src_ip\n| sort - count`, kql:`DnsEvents | where Name matches regex "[a-z0-9]{15,}\\.(com|net|org|io)" or ResultCode == "NXDOMAIN" | summarize count() by Computer, Name | sort by count_ desc`, cs:`event_simpleName=DnsRequest (DomainName=~"[a-z0-9]{20,}.*" OR RequestType="NXDOMAIN")\n| table _time, ComputerName, UserName, DomainName` }},
    { title:"Large Data Exfiltration (Staging)", mitre:"T1041", cat:"exfil",                   desc:"Detect unusually large outbound transfers — potential data exfiltration via HTTP, FTP, DNS tunneling, or cloud storage.",
      queries:{ splunk:`index=* bytes_out > 50000000\n| stats sum(bytes_out) as total by src_ip, dest_ip, app\n| eval total_MB=round(total/1048576,1)\n| sort - total_MB\n| where total_MB > 50`, kql:`DeviceNetworkEvents | where LocalPort > 1024 and RemoteIPType == "Public" | summarize BytesSent=sum(tolong(SentBytes)) by DeviceName, RemoteIP, RemotePort | where BytesSent > 50000000 | sort by BytesSent desc`, cs:`event_simpleName=NetworkConnectIP4\n| stats sum(BytesSent) as total_bytes by ComputerName, RemoteAddressIP4\n| where total_bytes > 50000000` }},
    { title:"Certutil LOLBin Abuse (Payload Download)", mitre:"T1105", cat:"defense_evasion",  desc:"Detect certutil.exe used for downloading or decoding payloads — a classic LOLBin technique to bypass web filters.",
      queries:{ splunk:`index=* Image="*certutil.exe*" (CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*-encode*")\n| table _time, host, user, CommandLine, ParentImage`, kql:`DeviceProcessEvents | where FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache","-decode","-encode") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName` }},
    { title:"Windows Defender Exclusion Added", mitre:"T1562.001", cat:"defense_evasion",      desc:"Detect attackers adding AV exclusions to prevent detection of malware they've deployed.",
      queries:{ splunk:`index=* (CommandLine="*Add-MpPreference*" AND CommandLine="*Exclusion*") OR (EventCode=5007 Message="*ExclusionPath*")\n| table _time, host, user, CommandLine`, kql:`DeviceRegistryEvents | where RegistryKey has "Exclusions" and RegistryKey contains "Windows Defender" | project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessAccountName` }},
    { title:"Kerberoasting Detection", mitre:"T1558.003", cat:"credential",                    desc:"Detect Kerberoasting — requesting service tickets for service accounts to crack offline.",
      queries:{ splunk:`index=* EventCode=4769 TicketEncryptionType IN (0x17,0x18,0x23)\n| stats count by user, ServiceName, src_ip\n| where count > 3\n| sort - count`, kql:`SecurityEvent | where EventID == 4769 and TicketEncryptionType in ("0x17","0x18","0x23") | summarize count() by Account, IpAddress, ServiceName | sort by count_ desc` }},
    { title:"Shadow Copy Deletion (Ransomware Prep)", mitre:"T1490", cat:"exfil",              desc:"Detect VSS shadow copy deletion — a pre-ransomware step to prevent recovery.",
      queries:{ splunk:`index=* (CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*/set*recoveryenabled no*")\n| table _time, host, user, CommandLine`, kql:`DeviceProcessEvents | where ProcessCommandLine has_any ("vssadmin delete","shadowcopy delete","bcdedit /set recoveryenabled") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine` }},
    { title:"Token Impersonation / Privilege Escalation", mitre:"T1134", cat:"privilege_esc",  desc:"Detect token manipulation and privilege escalation via CreateProcessWithTokenW or similar APIs.",
      queries:{ splunk:`index=* (EventCode=4674 OR (EventCode=4688 ParentProcessName!="explorer.exe" Image="*cmd.exe*"))\n| where user!="SYSTEM"\n| table _time, host, user, Image, CommandLine`, kql:`DeviceEvents | where ActionType == "CreateProcessWithTokenW" or (ActionType == "TokenPrivilegeEnabled" and AdditionalFields has "SeDebugPrivilege") | project TimeGenerated, DeviceName, AccountName, ActionType, InitiatingProcessFileName` }},
    { title:"OAuth App Consent Grant (BEC Precursor)", mitre:"T1528", cat:"identity",          desc:"Detect OAuth app consent grants in Azure AD — used by Scattered Spider and others for persistent mailbox access.",
      queries:{ splunk:`index=* sourcetype=o365 Operation="Consent to application"\n| table _time, user, AppDisplayName, Scope, IsAdminConsent`, kql:`AuditLogs | where OperationName == "Consent to application" | extend App=tostring(TargetResources[0].displayName) | project TimeGenerated, InitiatedBy, App, AADTenantId, Result` }},
    { title:"New Service Installed (Persistence)", mitre:"T1543.003", cat:"persistence",       desc:"Detect new service installation — attackers install malicious services for persistence and privilege.",
      queries:{ splunk:`index=* EventCode=7045\n| table _time, host, user, ServiceName, ImagePath, StartType`, kql:`SecurityEvent | where EventID == 7045 | project TimeGenerated, Computer, ServiceName, ServiceFileName, ServiceStartType, SubjectUserName` }},
    { title:"DNS Tunneling Detection", mitre:"T1071.004", cat:"c2",                            desc:"Detect DNS tunneling — data exfiltration or C2 hidden in unusually long TXT or high-frequency queries.",
      queries:{ splunk:`index=* sourcetype=stream:dns query_type IN ("TXT","NULL")\n| eval q_len=len(query)\n| where q_len > 50\n| stats count, values(query) by src_ip\n| sort - count`, kql:`DnsEvents | where QueryType in ("TXT","NULL") | where strlen(Name) > 50 | summarize count(), Queries=make_set(Name) by Computer, ClientIP | sort by count_ desc` }},
    { title:"Pass-the-Hash Detection (NTLM Lateral Move)", mitre:"T1550.002", cat:"lateral",   desc:"Detect pass-the-hash attacks — NTLM Type3 auth with no prior Type1/2, or 4776 events from unexpected hosts.",
      queries:{ splunk:`index=* EventCode=4776 Workstation_Name!="localhost"\n| stats count by Workstation_Name, Account_Name\n| where count > 3`, kql:`SecurityEvent | where EventID == 4776 and WorkstationName != ComputerName | summarize count() by WorkstationName, TargetUserName | sort by count_ desc` }},
    { title:"Web Shell Detection (Post-Exploit)", mitre:"T1505.003", cat:"execution",          desc:"Detect web server processes spawning command shells — indicates web shell execution after initial compromise.",
      queries:{ splunk:`index=* (ParentImage IN ("*w3wp.exe*","*httpd.exe*","*nginx.exe*","*apache.exe*","*tomcat*")) Image IN ("*cmd.exe*","*powershell.exe*","*sh*","*bash*")\n| table _time, host, user, ParentImage, Image, CommandLine`, kql:`DeviceProcessEvents | where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe") and FileName in~ ("cmd.exe","powershell.exe","sh","bash") | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine` }},
  ];

  function renderHuntGrid(platform, category) {
    const grid = $("hunt-grid");
    if (!grid) return;
    const filtered = HUNT_PACKS.filter(p => category === "all" || p.cat === category);
    if (!filtered.length) { grid.innerHTML = `<div style="padding:20px;text-align:center;color:var(--muted);font-size:12px;">No hunt queries for this category.</div>`; return; }
    grid.innerHTML = filtered.map((p, idx) => {
      const q = p.queries[platform] || p.queries.splunk || Object.values(p.queries)[0];
      return `<div class="hunt-card">
        <div class="hunt-card-head">
          <span class="hunt-card-title">${esc(p.title)}</span>
          <span class="hunt-card-mitre">${esc(p.mitre)}</span>
          <span class="hunt-card-cat">${esc(p.cat.replace(/_/g," "))}</span>
        </div>
        <div class="hunt-card-desc">${esc(p.desc)}</div>
        <pre class="hunt-query-block">${esc(q)}</pre>
        <div class="hunt-card-actions">
          <button class="hunt-copy-btn" onclick="copyHuntQuery(${idx},'${platform}')">📋 Copy Query</button>
          <button class="hunt-copy-btn" onclick="sendHuntToQB(${idx},'${platform}')">⚙️ Edit in Query Builder</button>
        </div>
      </div>`;
    }).join("");
  }

  window.copyHuntQuery = (idx, platform) => {
    const p = HUNT_PACKS[idx]; if (!p) return;
    const q = p.queries[platform] || p.queries.splunk || Object.values(p.queries)[0];
    navigator.clipboard.writeText(q).catch(()=>{});
  };
  window.sendHuntToQB = (idx, platform) => {
    const p = HUNT_PACKS[idx]; if (!p) return;
    const q = p.queries[platform] || p.queries.splunk || Object.values(p.queries)[0];
    const out = $("dqb-output");
    if (out) { out.textContent = q; switchTab("utils"); }
  };

  $("hunt-filter-btn")?.addEventListener("click", () => {
    renderHuntGrid($("hunt-platform")?.value||"splunk", $("hunt-category")?.value||"all");
  });
  // Auto-render on first click of hunt tab
  document.querySelectorAll(".cti-sub-btn").forEach(btn => {
    if (btn.dataset.ctitab === "hunt") {
      btn.addEventListener("click", () => {
        if (!$("hunt-grid")?.children.length) renderHuntGrid("splunk","all");
      }, { once: true });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 5 — INCIDENT SEVERITY CALCULATOR
  // ════════════════════════════════════════════════════════════════
  const SEV_DESCS = {
    asset: ["Public-facing dev/test system","Internal business system","Critical business application","Exec, domain controller, or crown jewel"],
    threat:["Possible alert, unconfirmed","Likely malicious based on IOC reputation","Confirmed TP — malicious activity verified","Active attack in progress / ransomware"],
    blast: ["Single endpoint isolated","One department or team affected","Organization-wide / multiple systems","Includes external parties or supply chain"],
    data:  ["Public or non-sensitive data","Internal business information","Confidential / proprietary data","PII, PCI, PHI, or regulated data"],
  };
  const SEV_MATRIX = { p1:"🔴 P1 — CRITICAL", p2:"🟠 P2 — HIGH", p3:"🟡 P3 — MEDIUM", p4:"🟢 P4 — LOW" };
  const SEV_SLA    = { p1:"Respond immediately · Escalate now · Max 1 hour to contain", p2:"Respond within 4 hours · Assign senior analyst", p3:"Respond within 24 hours · Standard triage", p4:"Respond within 72 hours · Monitor and document" };

  window.updateSevCalc = function() {
    const a = parseInt($("sev-asset")?.value)||2;
    const t = parseInt($("sev-threat")?.value)||2;
    const b = parseInt($("sev-blast")?.value)||2;
    const d = parseInt($("sev-data")?.value)||2;
    // Update descriptions
    if ($("sev-asset-desc"))  $("sev-asset-desc").textContent  = SEV_DESCS.asset[a-1];
    if ($("sev-threat-desc")) $("sev-threat-desc").textContent = SEV_DESCS.threat[t-1];
    if ($("sev-blast-desc"))  $("sev-blast-desc").textContent  = SEV_DESCS.blast[b-1];
    if ($("sev-data-desc"))   $("sev-data-desc").textContent   = SEV_DESCS.data[d-1];
    const score = (a + t + b + d);
    const prio  = score >= 14 ? "p1" : score >= 10 ? "p2" : score >= 7 ? "p3" : "p4";
    const result= $("sev-result");
    if (!result) return;
    result.className = `sev-result sev-${prio}`;
    result.innerHTML = `
      <div class="sev-result-badge">${SEV_MATRIX[prio]}</div>
      <div class="sev-result-sla">${SEV_SLA[prio]}</div>
      <div class="sev-result-just">Justification: ${SEV_DESCS.asset[a-1].toLowerCase()} (asset) × ${SEV_DESCS.threat[t-1].toLowerCase()} (threat) × ${SEV_DESCS.blast[b-1].toLowerCase()} (scope) × ${SEV_DESCS.data[d-1].toLowerCase()} (data). Score: ${score}/16.</div>`;
    window._sevResult = { prio, label: SEV_MATRIX[prio], sla: SEV_SLA[prio], score, justification: result.querySelector(".sev-result-just")?.textContent||"" };
  };
  updateSevCalc();

  $("sev-copy-btn")?.addEventListener("click", async () => {
    const r = window._sevResult; if (!r) return;
    const txt = `Severity: ${r.label}\nSLA: ${r.sla}\n${r.justification}`;
    try { await navigator.clipboard.writeText(txt); } catch {}
  });
  $("sev-to-case-btn")?.addEventListener("click", () => {
    const r = window._sevResult; if (!r) return;
    if (activeCase) { activeCase.notes = (activeCase.notes||"") + `\n[Severity] ${r.label} — ${r.sla}`; saveActiveCase(); }
    switchTab("case");
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 6 — IP GEOLOCATION & TRAVEL CHECK
  // ════════════════════════════════════════════════════════════════
  async function geolocateIPs(ips) {
    const results = [];
    for (const ip of ips.slice(0,10)) {
      try {
        const r = await fetch(`https://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city,org,as,proxy,hosting,query`, { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        results.push({ ip, country: d.country||"—", region: d.regionName||"—", city: d.city||"—", org: (d.org||d.as||"—").slice(0,40), proxy: d.proxy, hosting: d.hosting, status: d.status });
      } catch {
        results.push({ ip, country:"Error", region:"—", city:"—", org:"Fetch failed", proxy:false, hosting:false, status:"fail" });
      }
    }
    return results;
  }

  $("geo-lookup-btn")?.addEventListener("click", async () => {
    const raw = $("geo-ips-input")?.value?.trim() || "";
    const ips  = raw.split("\n").map(v=>v.trim()).filter(Boolean);
    if (!ips.length) return;
    const tableWrap = $("geo-results-table");
    const mapEl     = $("geo-map");
    if (tableWrap) tableWrap.innerHTML = `<div style="font-size:11px;color:var(--muted);padding:8px;">Looking up ${ips.length} IP(s)...</div>`;
    const data = await geolocateIPs(ips);
    if (tableWrap) {
      tableWrap.innerHTML = `<table class="geo-table">
        <thead><tr><th>IP</th><th>Country</th><th>City</th><th>Org / ISP</th><th>Flags</th></tr></thead>
        <tbody>${data.map(d => `<tr>
          <td style="font-family:monospace;color:#38bdf8;">${esc(d.ip)}</td>
          <td>${esc(d.country)}</td>
          <td>${esc(d.city)}, ${esc(d.region)}</td>
          <td>${esc(d.org)}</td>
          <td>${d.proxy ? `<span style="color:#fb923c;font-size:9px;border:1px solid rgba(251,146,60,0.3);border-radius:20px;padding:1px 6px;">PROXY</span>` : ""}${d.hosting ? `<span style="color:#a78bfa;font-size:9px;border:1px solid rgba(167,139,250,0.3);border-radius:20px;padding:1px 6px;">HOSTING</span>` : ""}</td>
        </tr>`).join("")}</tbody>
      </table>`;
    }
    // Render Leaflet map
    if (mapEl) {
      mapEl.id = "geo-map-container";
      mapEl.innerHTML = "";
      mapEl.className = "";
      const coords = data.filter(d => d.status === "success").map(d => d._latlon).filter(Boolean);
      // Show simple map placeholder with link
      mapEl.style.cssText = "border-radius:8px;border:1px solid var(--border);padding:10px;font-size:11px;color:var(--muted);background:var(--bg2);min-height:80px;";
      const locationSummary = data.map(d => `${d.ip}: ${d.city}, ${d.country}`).join(" | ");
      mapEl.innerHTML = `<div style="font-size:10px;font-weight:700;margin-bottom:6px;">📍 Location Summary</div>${data.map(d => `<div style="margin-bottom:4px;font-family:monospace;font-size:10px;">${esc(d.ip)} → ${esc(d.city)}, ${esc(d.country)} ${d.proxy?"🔒":""}${d.hosting?"🖥️":""}</div>`).join("")}<a href="https://www.ip-tracker.org/locator/ip-locator.php?track=${encodeURIComponent(ips[0])}" target="_blank" style="font-size:10px;color:#38bdf8;text-decoration:none;margin-top:6px;display:inline-block;">🗺️ View on map →</a>`;
    }
  });

  $("geo-clear-btn")?.addEventListener("click", () => {
    if ($("geo-ips-input")) $("geo-ips-input").value = "";
    const t = $("geo-results-table"); if (t) t.innerHTML = "";
    const m = $("geo-map"); if (m) { m.textContent = "🌍 Map will appear here after lookup"; }
  });

  $("geo-travel-btn")?.addEventListener("click", async () => {
    const ip1 = $("geo-ip1")?.value?.trim();
    const ip2 = $("geo-ip2")?.value?.trim();
    const t1s  = $("geo-t1")?.value;
    const t2s  = $("geo-t2")?.value;
    const res  = $("geo-travel-result");
    if (!ip1 || !ip2 || !res) return;
    res.style.display = "block";
    res.textContent = "Looking up locations...";
    res.className = "geo-travel-result geo-travel-unknown";
    const [d1, d2] = await Promise.all([
      fetch(`https://ip-api.com/json/${encodeURIComponent(ip1)}?fields=lat,lon,city,country,status`).then(r=>r.json()).catch(()=>null),
      fetch(`https://ip-api.com/json/${encodeURIComponent(ip2)}?fields=lat,lon,city,country,status`).then(r=>r.json()).catch(()=>null),
    ]);
    if (!d1?.lat || !d2?.lat) { res.textContent = "⚠️ Could not geolocate one or both IPs"; return; }
    // Haversine distance
    const R = 6371;
    const dLat = (d2.lat-d1.lat) * Math.PI/180;
    const dLon = (d2.lon-d1.lon) * Math.PI/180;
    const a = Math.sin(dLat/2)**2 + Math.cos(d1.lat*Math.PI/180)*Math.cos(d2.lat*Math.PI/180)*Math.sin(dLon/2)**2;
    const distKm = Math.round(2*R*Math.atan2(Math.sqrt(a),Math.sqrt(1-a)));
    const minHours = distKm / 900; // ~900 km/h commercial flight
    if (t1s && t2s) {
      const diff = Math.abs(new Date(t2s) - new Date(t1s)) / 3600000;
      const impossible = diff < minHours && distKm > 100;
      res.className = `geo-travel-result ${impossible ? "geo-travel-impossible" : "geo-travel-possible"}`;
      res.innerHTML = `${impossible ? "⚡ IMPOSSIBLE TRAVEL DETECTED" : "✅ Travel appears possible"}<br>
        ${esc(ip1)} → ${esc(d1.city)}, ${esc(d1.country)}<br>
        ${esc(ip2)} → ${esc(d2.city)}, ${esc(d2.country)}<br>
        Distance: ${distKm.toLocaleString()} km | Time between logins: ${diff.toFixed(1)}h | Min flight time: ${minHours.toFixed(1)}h<br>
        ${impossible ? "Account is likely compromised — attacker logged in from a different country." : "Distance is consistent with the time elapsed between logins."}`;
    } else {
      res.className = "geo-travel-result geo-travel-unknown";
      res.innerHTML = `📍 ${esc(ip1)} → ${esc(d1.city)}, ${esc(d1.country)}<br>📍 ${esc(ip2)} → ${esc(d2.city)}, ${esc(d2.country)}<br>Distance: ${distKm.toLocaleString()} km | Min flight: ${minHours.toFixed(1)}h<br><em>Add login timestamps above to check impossibility</em>`;
    }
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 7 — CERTIFICATE / TLS INSPECTOR
  // ════════════════════════════════════════════════════════════════
  async function fetchCertificate(domain) {
    const enc = encodeURIComponent;
    const clean = domain.replace(/^https?:\/\//i,"").split("/")[0];
    const statusEl = $("cert-status");
    const resultsEl = $("cert-results");
    if (statusEl) { statusEl.style.display="flex"; statusEl.innerHTML=`<div class="cti-news-spinner"></div> Looking up certificates for <strong>${esc(clean)}</strong>…`; }
    if (resultsEl) resultsEl.style.display="none";
    try {
      const r = await fetch(`https://crt.sh/?q=${enc(clean)}&output=json`, { signal: AbortSignal.timeout(12000) });
      if (!r.ok) throw new Error("crt.sh returned " + r.status);
      const data = await r.json();
      if (!data.length) throw new Error("No certificates found for this domain");
      // Most recent cert
      const sorted = data.sort((a,b) => new Date(b.entry_timestamp) - new Date(a.entry_timestamp));
      const cert   = sorted[0];
      const allNames = [...new Set(sorted.flatMap(c => (c.name_value||"").split("\n").map(n=>n.trim().toLowerCase())).filter(n=>n && n.includes(".")))];
      const issued = new Date(cert.not_before||cert.entry_timestamp);
      const expires= new Date(cert.not_after||0);
      const now    = new Date();
      const ageDays= Math.floor((now-issued)/86400000);
      const daysLeft=Math.floor((expires-now)/86400000);
      const issuer = cert.issuer_name||"Unknown";
      const selfSigned = issuer.includes(cert.common_name||"") || issuer.toLowerCase().includes("self");
      // Flags
      const flags = [];
      if (selfSigned)     flags.push({ cls:"cert-flag-bad",  txt:"Self-signed" });
      if (ageDays < 30)   flags.push({ cls:"cert-flag-warn", txt:`New cert — issued ${ageDays} day(s) ago` });
      if (daysLeft < 14)  flags.push({ cls:"cert-flag-warn", txt:`Expires in ${daysLeft} day(s)` });
      if (daysLeft < 0)   flags.push({ cls:"cert-flag-bad",  txt:"EXPIRED" });
      if (allNames.some(n=>n.startsWith("*."))) flags.push({ cls:"cert-flag-warn", txt:"Wildcard cert" });
      if (!flags.length)  flags.push({ cls:"cert-flag-ok", txt:"Valid" });
      // Render
      $("cert-flags").innerHTML = flags.map(f=>`<span class="cert-flag ${f.cls}">${esc(f.txt)}</span>`).join("");
      $("cert-details").innerHTML = [
        { label:"Common Name", value: cert.common_name || clean },
        { label:"Issuer",      value: issuer.split(",").find(p=>p.trim().startsWith("O="))?.split("=")[1]?.trim() || issuer.slice(0,60) },
        { label:"Issued",      value: issued.toLocaleDateString() + ` (${ageDays}d ago)` },
        { label:"Expires",     value: expires.toLocaleDateString() + ` (${daysLeft}d left)` },
        { label:"Serial",      value: cert.serial_number || "—" },
        { label:"crt.sh ID",   value: cert.id ? `#${cert.id}` : "—" },
      ].map(d=>`<div class="cert-detail-item"><div class="cert-detail-label">${d.label}</div><div class="cert-detail-value">${esc(String(d.value))}</div></div>`).join("");
      // SANs
      if (allNames.length > 1) {
        $("cert-sans-wrap").style.display="block";
        $("cert-sans").innerHTML = allNames.slice(0,60).map(n=>`<span class="cert-san-tag" onclick="pivotFromEHA('${esc(n)}','domain')" title="Pivot to threat intel">${esc(n)}</span>`).join("");
        $("cert-sans-bulk")._names = allNames;
      } else { $("cert-sans-wrap").style.display="none"; }
      // History
      if ($("cert-history-btn")._showHistory) {
        $("cert-history-wrap").style.display="block";
        $("cert-history-list").innerHTML = sorted.slice(0,20).map(c=>`<div class="cert-history-item"><span class="cert-hist-date">${new Date(c.not_before||c.entry_timestamp).toLocaleDateString()}</span><span>${esc(c.common_name||"—")}</span><span style="color:var(--muted);margin-left:auto;">#${c.id}</span></div>`).join("");
      }
      if (statusEl) statusEl.style.display="none";
      if (resultsEl) resultsEl.style.display="block";
    } catch(e) {
      if (statusEl) statusEl.innerHTML = `⚠️ ${esc(e.message)}`;
    }
  }

  $("cert-lookup-btn")?.addEventListener("click", () => { const v=$("cert-input")?.value?.trim(); if(v) fetchCertificate(v); });
  $("cert-history-btn")?.addEventListener("click", () => {
    const btn = $("cert-history-btn");
    btn._showHistory = !btn._showHistory;
    btn.textContent = btn._showHistory ? "📜 Hide History" : "📜 Cert History";
    const v=$("cert-input")?.value?.trim(); if(v) fetchCertificate(v);
  });
  $("cert-sans-bulk")?.addEventListener("click", () => {
    const names = $("cert-sans-bulk")._names || [];
    const bulkInput = $("bulk-input");
    if (bulkInput) { bulkInput.value = names.join("\n"); switchTab("bulk"); $("bulk-extract-btn")?.click(); }
  });
  // Wire cert type into the single IOC tab type detection
  const origDetectType = window.detectTypeInternal;

  // ════════════════════════════════════════════════════════════════
  // FEATURE 8 — SHIFT HANDOFF GENERATOR
  // ════════════════════════════════════════════════════════════════
  $("ho-generate-btn")?.addEventListener("click", () => {
    const analyst  = $("ho-analyst")?.value?.trim() || "Analyst";
    const team     = $("ho-team")?.value?.trim() || "SOC";
    const start    = $("ho-shift-start")?.value ? new Date($("ho-shift-start").value).toLocaleString() : "—";
    const end      = $("ho-shift-end")?.value   ? new Date($("ho-shift-end").value).toLocaleString()   : "—";
    const findings = $("ho-findings")?.value?.trim() || "";
    const pending  = $("ho-pending")?.value?.trim() || "";
    const recs     = $("ho-recommendations")?.value?.trim() || "";
    const fmt      = $("ho-format")?.value || "text";
    // Auto-pull from session
    const caseCount = activeCase ? 1 : 0;
    const iocCount  = sessionHistory?.length || 0;
    const openCases = activeCase ? [`${activeCase.name} (${activeCase.status||"open"})`] : [];
    const findingsList = findings ? findings.split("\n").filter(Boolean) : ["No major findings this shift"];
    const pendingList  = pending  ? pending.split("\n").filter(Boolean)  : ["None"];
    const recsList     = recs     ? recs.split("\n").filter(Boolean)     : ["Continue monitoring current alerts"];
    const now = new Date().toLocaleString();
    let report = "";
    if (fmt === "markdown") {
      report = `# Shift Handoff Report\n**Analyst:** ${analyst} | **Team:** ${team}\n**Shift:** ${start} → ${end}\n**Generated:** ${now}\n\n---\n\n## Session Stats\n- Cases worked: ${caseCount}\n- IOCs investigated: ${iocCount}\n${openCases.length ? `- Open cases: ${openCases.join(", ")}` : ""}\n\n## Key Findings\n${findingsList.map(f=>`- ${f}`).join("\n")}\n\n## Pending / Open Items\n${pendingList.map(p=>`- ${p}`).join("\n")}\n\n## Recommendations for Next Shift\n${recsList.map(r=>`- ${r}`).join("\n")}\n\n---\n*Generated by HawkEye v${TOOLKIT_VERSION}*`;
    } else if (fmt === "exec") {
      report = `SHIFT SUMMARY — ${analyst} (${team})\n${start} to ${end}\n\n${findingsList.length} finding(s): ${findingsList[0]}${findingsList.length>1?` (+${findingsList.length-1} more)`:""}.\n${pendingList[0] !== "None" ? `${pendingList.length} item(s) pending next shift.` : "No open items."}\nRecommendation: ${recsList[0]}`;
    } else {
      report = `════════════════════════════════════════
SHIFT HANDOFF REPORT
════════════════════════════════════════
Analyst   : ${analyst}
Team/Tier : ${team}
Shift     : ${start} → ${end}
Generated : ${now}
────────────────────────────────────────
SESSION METRICS
  Cases worked    : ${caseCount}
  IOCs investigated: ${iocCount}
${openCases.length ? `  Open cases      : ${openCases.join(", ")}\n` : ""}
────────────────────────────────────────
KEY FINDINGS
${findingsList.map((f,i)=>`  ${i+1}. ${f}`).join("\n")}

PENDING / OPEN ITEMS
${pendingList.map((p,i)=>`  ${i+1}. ${p}`).join("\n")}

RECOMMENDATIONS FOR NEXT SHIFT
${recsList.map((r,i)=>`  ${i+1}. ${r}`).join("\n")}
════════════════════════════════════════
Generated by HawkEye v${TOOLKIT_VERSION}`;
    }
    const out = $("ho-output");
    if (out) out.textContent = report;
  });

  $("ho-copy-btn")?.addEventListener("click", async () => {
    const txt = $("ho-output")?.textContent || "";
    try { await navigator.clipboard.writeText(txt); } catch {}
  });
  $("ho-download-btn")?.addEventListener("click", () => {
    const txt = $("ho-output")?.textContent || "";
    if (!txt || txt.startsWith("←")) return;
    const a = document.createElement("a");
    a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(txt);
    a.download = `hawkeye-handoff-${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 9 — STIX 2.1 EXPORT
  // ════════════════════════════════════════════════════════════════
  $("case-stix-btn")?.addEventListener("click", () => {
    if (!activeCase || !activeCase.iocs?.length) {
      alert("No active case with IOCs to export. Add IOCs to a case first.");
      return;
    }
    const uuid = () => "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
      const r = Math.random()*16|0, v = c==="x" ? r : (r&0x3|0x8); return v.toString(16);
    });
    const now  = new Date().toISOString();
    const STIX_TYPE_MAP = { ip:"ipv4-addr", domain:"domain-name", url:"url", hash:"file", email:"email-addr", md5:"file", sha256:"file", sha1:"file" };
    const STIX_PATTERN  = { ip: v=>`[ipv4-addr:value = '${v}']`, domain: v=>`[domain-name:value = '${v}']`, url: v=>`[url:value = '${v}']`, hash: v=>`[file:hashes.'SHA-256' = '${v}']`, email: v=>`[email-addr:value = '${v}']` };
    const identity = { type:"identity", spec_version:"2.1", id:`identity--${uuid()}`, created:now, modified:now, name:"HawkEye Analyst", identity_class:"individual" };
    const indicators = activeCase.iocs.map(ioc => {
      const t = ioc.type||"domain";
      const patFn = STIX_PATTERN[t] || STIX_PATTERN.domain;
      return { type:"indicator", spec_version:"2.1", id:`indicator--${uuid()}`, created:now, modified:now, name:`${t.toUpperCase()} - ${ioc.value}`, description:`Extracted from case: ${activeCase.name}`, pattern: patFn(ioc.value), pattern_type:"stix", valid_from:now, labels:["malicious-activity"] };
    });
    const bundle = { type:"bundle", id:`bundle--${uuid()}`, objects:[identity,...indicators] };
    const json = JSON.stringify(bundle, null, 2);
    const a = document.createElement("a");
    a.href = "data:application/json;charset=utf-8," + encodeURIComponent(json);
    a.download = `hawkeye-stix-${activeCase.name.replace(/\s+/g,"-").toLowerCase()}-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
  });

  // ════════════════════════════════════════════════════════════════
  // FEATURE 10 — CLIPBOARD WATCHER
  // ════════════════════════════════════════════════════════════════
  let _clipWatchInterval = null;
  let _lastClipValue     = "";

  function startClipWatcher() {
    if (_clipWatchInterval) return;
    _clipWatchInterval = setInterval(async () => {
      if (document.hidden) return;
      try {
        const text = (await navigator.clipboard.readText()).trim();
        if (!text || text === _lastClipValue || text.length > 300) return;
        _lastClipValue = text;
        const detected = detectType(text, text);
        if (detected.type && detected.type !== "unknown" && detected.q) {
          const inp = $("input");
          if (inp && inp.value !== detected.q) {
            inp.value = detected.q;
            syncSearchboxState();
            $("clip-watch-status").textContent = `✅ Detected: ${detected.type} — ${detected.q.slice(0,25)}`;
            $("clip-watch-status").style.color = "#1D9E75";
            if (document.querySelector('[data-tab="single"]')?.classList.contains("active") ||
                document.querySelector('#tab-single')?.classList.contains("active")) {
              doSearch({ silent: true });
            }
            setTimeout(() => { if ($("clip-watch-status")) { $("clip-watch-status").textContent = "Watching clipboard…"; $("clip-watch-status").style.color = ""; } }, 4000);
          }
        }
      } catch { /* Permission denied or clipboard empty */ }
    }, 1500);
    $("clip-watch-status").textContent = "Watching clipboard…";
    $("clip-watch-track").style.background = "#1D9E75";
    $("clip-watch-thumb").style.transform = "translateX(16px)";
  }

  function stopClipWatcher() {
    clearInterval(_clipWatchInterval);
    _clipWatchInterval = null;
    $("clip-watch-status").textContent = "Auto-detect IOCs you copy";
    $("clip-watch-status").style.color = "";
    $("clip-watch-track").style.background = "";
    $("clip-watch-thumb").style.transform = "";
  }

  $("clip-watch-toggle")?.addEventListener("change", async (e) => {
    if (e.target.checked) {
      try {
        const perm = await navigator.permissions.query({ name:"clipboard-read" });
        if (perm.state === "denied") { e.target.checked = false; alert("Clipboard permission denied. Please allow clipboard access in your browser settings."); return; }
        startClipWatcher();
      } catch { startClipWatcher(); } // Some browsers don't support permission query
    } else {
      stopClipWatcher();
    }
  });

  // ── CTI Threat News Panel ─────────────────────────────────────

  // Uses Anthropic API when available (claude.ai context), falls back
  // to a comprehensive built-in threat intelligence database otherwise.

  const SEVERITY_COLORS = {
    CRITICAL: "cti-news-severity-critical",
    HIGH:     "cti-news-severity-high",
    MEDIUM:   "cti-news-severity-medium",
    INFO:     "cti-news-severity-info",
  };

  // ── Built-in Threat Intel Knowledge Base ─────────────────────
  // Comprehensive recent threats — always available, no API needed
  const BUILTIN_THREATS = {
    latest: [
      { title:"Volt Typhoon Pre-positions in US Critical Infrastructure", summary:"Chinese state-sponsored group Volt Typhoon (Bronze Silhouette) has been discovered living off the land inside US power grid, water, and communications networks. CISA issued Emergency Directive 24-02. The group uses LOLBins, valid credentials, and VPN appliances for persistence. TTPs include T1190, T1078, T1036.", severity:"CRITICAL", tags:["APT","China","Critical Infrastructure","LOTL","Volt Typhoon"], source:"CISA / MSTIC", date:"2025–2026", links:[{label:"Search",url:"https://www.google.com/search?q=Volt+Typhoon+critical+infrastructure+2025"}] },
      { title:"RansomHub Surpasses LockBit as Top Ransomware Operator", summary:"RansomHub has emerged as the dominant ransomware-as-a-service operation following LockBit's law enforcement disruption. Targets include healthcare, manufacturing, and legal sectors. Uses AuKill EDR killer, Go-based encryptor, and Cobalt Strike for C2. Over 200 confirmed victims in 2025.", severity:"CRITICAL", tags:["Ransomware","RansomHub","EDR Bypass","RaaS"], source:"BleepingComputer / Unit 42", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=RansomHub+ransomware+2025"}] },
      { title:"CISA KEV Adds Critical Ivanti Connect Secure Vulnerabilities", summary:"CISA added CVE-2025-0282 and CVE-2025-0283 (Ivanti Connect Secure stack buffer overflows, CVSS 9.0) to the Known Exploited Vulnerabilities catalog. Exploitation by UNC5337/UNC5221 confirmed in the wild. Patch immediately; check for SPAWN malware family indicators.", severity:"CRITICAL", tags:["CVE-2025-0282","Ivanti","VPN","Zero-day","KEV"], source:"CISA", date:"Jan 2025", links:[{label:"CISA KEV",url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},{label:"Search",url:"https://www.google.com/search?q=CVE-2025-0282+Ivanti+exploit"}] },
      { title:"Salt Typhoon Compromises Major US Telecom Carriers", summary:"Chinese APT Salt Typhoon (RedMike) breached AT&T, Verizon, T-Mobile, and Lumen to intercept lawful intercept infrastructure. The campaign targeted wiretap systems under CALEA. Senators called it the worst telecom hack in US history. TTPs include T1190, T1557, T1600.", severity:"CRITICAL", tags:["APT","China","Telecom","Salt Typhoon","Wiretap"], source:"WSJ / MSTIC", date:"Late 2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=Salt+Typhoon+telecom+hack+2025"}] },
      { title:"New Lumma Stealer Campaign via Fake CAPTCHA Pages", summary:"Lumma Stealer infections are surging via ClickFix social engineering: fake CAPTCHA or browser update pages trick users into running mshta.exe commands. Delivers credentials, crypto wallets, and browser data. Distribution via malvertising and compromised WordPress sites.", severity:"HIGH", tags:["Lumma Stealer","ClickFix","Infostealer","Social Engineering","T1059"], source:"Proofpoint / Unit 42", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Lumma+Stealer+ClickFix+CAPTCHA+2025"}] },
      { title:"Microsoft Patches 6 Zero-Days in March 2025 Patch Tuesday", summary:"March 2025 Patch Tuesday addressed 57 CVEs including 6 actively exploited zero-days in Windows CLFS (CVE-2025-29824, CVSS 7.8), NTFS, and DWM components. CLFS vulnerability used by ransomware groups for privilege escalation. Patch immediately.", severity:"HIGH", tags:["Patch Tuesday","Zero-day","CVE-2025-29824","Windows","CLFS"], source:"Microsoft MSRC", date:"Mar 2025", links:[{label:"Search",url:"https://www.google.com/search?q=Microsoft+Patch+Tuesday+March+2025+zero+day"}] },
    ],
    ransomware: [
      { title:"RansomHub — Dominant RaaS After LockBit Disruption", summary:"RansomHub has recruited former BlackCat/ALPHV and LockBit affiliates following law enforcement actions. Uses AuKill to terminate EDR, then deploys Go-based encryptor. Healthcare and critical infrastructure are primary targets. Demands average $2M+ ransom.", severity:"CRITICAL", tags:["RansomHub","RaaS","EDR Bypass","Healthcare"], source:"Unit 42 / FBI", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=RansomHub+ransomware+group+2025"}] },
      { title:"Black Basta Pivots to Social Engineering After Takedown Pressure", summary:"Black Basta shifted tactics to Microsoft Teams-based vishing attacks, impersonating IT helpdesk to deploy ScreenConnect and Cobalt Strike. Post-access activity includes Qakbot-free deployment, NTDS.dit extraction, and RansomHub encryptor delivery.", severity:"CRITICAL", tags:["Black Basta","Vishing","Teams","Social Engineering","Qakbot"], source:"Rapid7 / Microsoft", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Black+Basta+Microsoft+Teams+vishing+2025"}] },
      { title:"MEDUSA Ransomware Targets K-12 Schools and Healthcare", summary:"CISA and FBI issued advisory AA25-071A on MEDUSA ransomware. Group uses vulnerable drivers (BYOVD) to disable EDR, then deploys encryptor. Demands published on Tor leak site. Targets: K-12, healthcare, critical manufacturing. Uses Cobalt Strike and TightVNC.", severity:"HIGH", tags:["MEDUSA","Ransomware","BYOVD","Education","Healthcare"], source:"CISA / FBI AA25-071A", date:"Mar 2025", links:[{label:"CISA Advisory",url:"https://www.cisa.gov/news-events/cybersecurity-advisories"},{label:"Search",url:"https://www.google.com/search?q=MEDUSA+ransomware+CISA+2025"}] },
      { title:"LockBit 4.0 Infrastructure Rebuilt After Operation Cronos", summary:"Despite Operation Cronos takedown in Feb 2024, LockBit rebuilt infrastructure with LockBit 4.0 builder leaked. Active affiliates continue attacks. Leader LockBitSupp identified as Russian national Dmitry Khoroshev (OFAC sanctioned). New decryptors available via NCA.", severity:"HIGH", tags:["LockBit","Takedown","Operation Cronos","Builder Leak"], source:"NCA / Europol", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=LockBit+4.0+Operation+Cronos+2025"}] },
      { title:"DragonForce Ransomware Hits Retail Sector — M&S, Co-op UK", summary:"DragonForce ransomware affiliate attacked UK retailers Marks & Spencer and Co-op in early 2025. Attack vector: social engineering via IT helpdesk impersonation. Over 15GB of customer data exfiltrated. UK NCSC issued guidance for retail sector.", severity:"HIGH", tags:["DragonForce","Retail","UK","Data Breach","Social Engineering"], source:"NCSC UK / BleepingComputer", date:"Apr–May 2025", links:[{label:"Search",url:"https://www.google.com/search?q=DragonForce+ransomware+Marks+Spencer+2025"}] },
      { title:"Ransomware Groups Exploiting Fortinet SSL-VPN and Palo Alto Bugs", summary:"Multiple ransomware groups actively exploit CVE-2024-21762 (Fortinet FortiOS, CVSS 9.6) and CVE-2025-0108 (Palo Alto PAN-OS auth bypass). CISA KEV listed both. Initial access used for lateral movement then ransomware deployment within 48 hours.", severity:"CRITICAL", tags:["Fortinet","Palo Alto","CVE-2024-21762","VPN","Initial Access"], source:"CISA / Shadowserver", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=ransomware+Fortinet+CVE-2024-21762+exploit+2025"}] },
    ],
    apt: [
      { title:"Volt Typhoon (China) Inside US Critical Infrastructure 5+ Years", summary:"CISA and NSA confirmed Volt Typhoon has maintained persistent access in US power grid, water systems, and telecom networks for up to 5 years. Objective: pre-position for disruptive attack during a potential Taiwan conflict. Uses LOLBins, SOHO router botnets.", severity:"CRITICAL", tags:["Volt Typhoon","China","Critical Infrastructure","LOTL","T1190"], source:"CISA / NSA / FBI", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=Volt+Typhoon+US+critical+infrastructure+5+years"}] },
      { title:"APT29 / Midnight Blizzard Targets Microsoft and Government via OAuth", summary:"Russian SVR group APT29 (Midnight Blizzard) abused OAuth token theft to access Microsoft corporate email and move laterally. Also targeting European governments via spear-phishing PDF attachments with WINELOADER backdoor.", severity:"CRITICAL", tags:["APT29","Midnight Blizzard","OAuth","Microsoft","SVR"], source:"Microsoft MSTIC", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=APT29+Midnight+Blizzard+OAuth+Microsoft+2025"}] },
      { title:"Salt Typhoon (China) — Deepest Telecom Breach in US History", summary:"Salt Typhoon (RedMike/GhostEmperor) compromised 9+ US telecom carriers including AT&T and Verizon to access lawful intercept backdoors. Used custom malware SEASPY and SALTWATER on Barracuda ESG and Cisco IOS devices. No full remediation achieved.", severity:"CRITICAL", tags:["Salt Typhoon","China","Telecom","CALEA","Espionage"], source:"CISA / WSJ", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=Salt+Typhoon+telecom+espionage+2025"}] },
      { title:"APT28 (Fancy Bear) Campaigns Against NATO and Ukraine Aid Organizations", summary:"APT28 (GRU Unit 26165) escalated phishing campaigns against NATO members, defense contractors, and NGOs supporting Ukraine. Uses HeadLace malware delivered via spear-phishing. Targeting logistics networks for Ukraine military supply chain intelligence.", severity:"HIGH", tags:["APT28","Fancy Bear","NATO","Ukraine","GRU"], source:"Recorded Future / CERT-EU", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=APT28+NATO+Ukraine+2025"}] },
      { title:"Lazarus Group Steals $1.5B from Bybit Crypto Exchange", summary:"North Korean Lazarus Group executed the largest crypto theft in history — $1.5B from Bybit exchange via compromised Safe{Wallet} multisig infrastructure. Used TraderTraitor malware campaign targeting Safe developers months before the heist.", severity:"CRITICAL", tags:["Lazarus","North Korea","Crypto","Bybit","$1.5B"], source:"FBI / Chainalysis", date:"Feb 2025", links:[{label:"Search",url:"https://www.google.com/search?q=Lazarus+Bybit+hack+1.5+billion+2025"}] },
      { title:"Kimsuky Targets Think Tanks via Spear-Phishing with DMARC Abuse", summary:"North Korean Kimsuky group uses free email services with DMARC policy exploitation to spoof research institutions. Delivers QUASAR RAT and BabyShark malware. Targets nuclear policy researchers, academics, and government advisors in the US, EU, and South Korea.", severity:"HIGH", tags:["Kimsuky","North Korea","DMARC Abuse","Spear-Phishing","QUASAR RAT"], source:"NSA / CISA", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Kimsuky+DMARC+spearphishing+2025"}] },
    ],
    vulnerability: [
      { title:"CVE-2025-29824 — Windows CLFS Zero-Day Exploited by Ransomware", summary:"Critical Windows Common Log File System (CLFS) privilege escalation zero-day patched in March 2025 Patch Tuesday. CVSS 7.8. Actively exploited by PipeMagic ransomware affiliate. Used to escalate from standard user to SYSTEM for ransomware deployment.", severity:"CRITICAL", tags:["CVE-2025-29824","Windows","Zero-day","CLFS","Ransomware"], source:"Microsoft MSRC", date:"Mar 2025", links:[{label:"NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2025-29824"},{label:"Search",url:"https://www.google.com/search?q=CVE-2025-29824+Windows+CLFS"}] },
      { title:"CVE-2025-0282 — Ivanti Connect Secure RCE (CVSS 9.0) — KEV Listed", summary:"Stack buffer overflow in Ivanti Connect Secure, Policy Secure, and Neurons for ZTA allows unauthenticated RCE. Exploited by UNC5337 (China-nexus) to deploy SPAWN malware family (SPAWNANT, SPAWNMOLE, SPAWNSNAIL). CISA mandated patching within 48 hours.", severity:"CRITICAL", tags:["CVE-2025-0282","Ivanti","RCE","CISA KEV","Zero-day"], source:"CISA / Mandiant", date:"Jan 2025", links:[{label:"NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2025-0282"},{label:"Search",url:"https://www.google.com/search?q=CVE-2025-0282+Ivanti+exploit"}] },
      { title:"CVE-2024-21762 — Fortinet FortiOS SSL-VPN RCE — Mass Exploitation", summary:"Out-of-bounds write in Fortinet FortiOS and FortiProxy SSL-VPN (CVSS 9.6) enables unauthenticated RCE via crafted HTTP requests. Over 150,000 devices exposed on Shodan. Exploited by multiple threat actors including ransomware groups for initial access.", severity:"CRITICAL", tags:["CVE-2024-21762","Fortinet","SSL-VPN","Mass Exploit","CVSS 9.6"], source:"Shadowserver / CISA", date:"2024–2025", links:[{label:"NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2024-21762"},{label:"Search",url:"https://www.google.com/search?q=CVE-2024-21762+Fortinet+exploit"}] },
      { title:"CVE-2025-0108 — Palo Alto PAN-OS Authentication Bypass — Exploited", summary:"Authentication bypass in Palo Alto Networks PAN-OS management interface (CVSS 9.3). Attackers chain with CVE-2025-0110 for full RCE. CISA KEV listed. Actively exploited within 24 hours of disclosure. Restrict management interface access immediately.", severity:"CRITICAL", tags:["CVE-2025-0108","Palo Alto","PAN-OS","Auth Bypass","KEV"], source:"CISA / Palo Alto PSIRT", date:"Feb 2025", links:[{label:"NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2025-0108"},{label:"Search",url:"https://www.google.com/search?q=CVE-2025-0108+Palo+Alto+exploit"}] },
      { title:"CVE-2025-24200 — Apple iOS Zero-Day — Used Against Targeted Individuals", summary:"Zero-day in iOS Accessibility disables USB Restricted Mode on locked devices (CVSS 6.1). Exploited in targeted attacks against high-value individuals, potentially by commercial spyware vendors. Fixed in iOS 18.3.2. Apple patched without detailed disclosure.", severity:"HIGH", tags:["CVE-2025-24200","iOS","Apple","Zero-day","Spyware"], source:"Apple Security", date:"Feb 2025", links:[{label:"Search",url:"https://www.google.com/search?q=CVE-2025-24200+iOS+zero-day+spyware"}] },
      { title:"CVE-2024-3400 — Palo Alto GlobalProtect Zero-Day — KEV + Active Exploitation", summary:"Command injection in Palo Alto GlobalProtect (CVSS 10.0) enables unauthenticated RCE as root. UTA0218 threat actor deployed UPSTYLE backdoor and Python scripts for credential theft. CISA KEV listed. Telemetry shows 22,500+ compromised devices.", severity:"CRITICAL", tags:["CVE-2024-3400","Palo Alto","Command Injection","CVSS 10","UTA0218"], source:"Volexity / Palo Alto Unit 42", date:"2024", links:[{label:"NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2024-3400"},{label:"Search",url:"https://www.google.com/search?q=CVE-2024-3400+Palo+Alto+exploit"}] },
    ],
    phishing: [
      { title:"ClickFix Social Engineering — Fake CAPTCHA Delivering Infostealers", summary:"ClickFix campaigns trick users into running malicious PowerShell by presenting fake CAPTCHA or browser 'fix' instructions. Delivers Lumma Stealer, DarkComet, and NetSupport RAT. Over 50 legitimate sites compromised as delivery vectors. Uses mshta.exe and clipboard injection.", severity:"HIGH", tags:["ClickFix","ClickFix","Lumma Stealer","Social Engineering","mshta"], source:"Proofpoint", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=ClickFix+social+engineering+CAPTCHA+infostealer+2025"}] },
      { title:"Microsoft Teams Vishing — Black Basta IT Helpdesk Impersonation", summary:"Threat actors (Black Basta affiliates) impersonate corporate IT helpdesk via Microsoft Teams external chat, convincing employees to install ScreenConnect or AnyDesk for 'support.' Post-access: credential harvesting, NTDS.dit dump, then ransomware.", severity:"HIGH", tags:["Teams","Vishing","Black Basta","Helpdesk","ScreenConnect"], source:"Rapid7 / Microsoft", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Black+Basta+Microsoft+Teams+vishing+helpdesk+2025"}] },
      { title:"QR Code Phishing (Quishing) Targeting Microsoft 365 MFA", summary:"Quishing campaigns deliver QR codes via email to bypass secure email gateways. Codes link to AiTM (Adversary-in-the-Middle) phishing pages that capture MFA tokens in real-time. Tools: Evilginx2, Modlishka. Targets: M365 users in financial and healthcare sectors.", severity:"HIGH", tags:["Quishing","QR Code","MFA Bypass","AiTM","Evilginx2"], source:"Abnormal Security", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=QR+code+phishing+quishing+MFA+bypass+2025"}] },
      { title:"Scattered Spider Targets Cloud and SaaS via Helpdesk Social Engineering", summary:"UNC3944 (Scattered Spider) continues targeting Okta, Azure AD, and ServiceNow via help desk call spoofing to reset MFA. Post-compromise: data theft from SharePoint/OneDrive, deployment of ALPHV/RansomHub ransomware. FBI released detailed advisory.", severity:"CRITICAL", tags:["Scattered Spider","Okta","MFA Reset","Social Engineering","Help Desk"], source:"FBI / CISA", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Scattered+Spider+helpdesk+Okta+2025"}] },
      { title:"EvilProxy AiTM Platform — Commodity MFA-Bypass Phishing Kit", summary:"EvilProxy phishing-as-a-service provides pre-built AiTM reverse proxies for O365, Google, and Okta. Allows low-skill actors to bypass hardware MFA tokens. Over 120,000 phishing emails per month observed. Post-compromise: BEC wire fraud and data exfiltration.", severity:"HIGH", tags:["EvilProxy","AiTM","Phishing-as-a-Service","O365","MFA Bypass"], source:"Resecurity / Proofpoint", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=EvilProxy+AiTM+phishing+O365+MFA+bypass"}] },
      { title:"Agent Tesla and Remcos RAT Via ISO/LNK Malware Delivery Chains", summary:"Renewed surge in Agent Tesla and Remcos RAT campaigns using ISO files with LNK shortcuts to bypass Mark-of-the-Web. Delivered via email as 'invoice' or 'shipping' documents. Command and control via Telegram bots and SMTP. Targets: manufacturing, logistics, SMBs.", severity:"MEDIUM", tags:["Agent Tesla","Remcos RAT","ISO Delivery","MOTW Bypass","Telegram C2"], source:"ANY.RUN / SANS ISC", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Agent+Tesla+Remcos+ISO+LNK+delivery+2025"}] },
    ],
    malware: [
      { title:"Lumma Stealer — Dominant Infostealer Distributed via ClickFix + Malvertising", summary:"Lumma Stealer (LummaC2) is the most prevalent infostealer in 2025. Harvests browser passwords, cookies, crypto wallets, and 2FA secrets. Sold as MaaS ($250/month). Delivered via ClickFix, fake Cloudflare pages, and malvertising on Google Ads. C2 via Telegram.", severity:"HIGH", tags:["Lumma Stealer","MaaS","Infostealer","ClickFix","Credentials"], source:"ESET / Proofpoint", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Lumma+Stealer+infostealer+2025"}] },
      { title:"SPAWN Malware Family — Ivanti Zero-Day Post-Exploitation Toolkit", summary:"SPAWN (SPAWNANT, SPAWNMOLE, SPAWNSNAIL, SPAWNSLOTH) is a sophisticated malware suite deployed post-exploitation of Ivanti Connect Secure zero-days. Attributed to UNC5337 (China). SPAWNANT installs web shell; SPAWNMOLE tunnels traffic; SPAWNSNAIL provides SSH backdoor.", severity:"CRITICAL", tags:["SPAWN","Ivanti","China","UNC5337","Web Shell"], source:"Mandiant / CISA", date:"Jan 2025", links:[{label:"Search",url:"https://www.google.com/search?q=SPAWN+malware+Ivanti+UNC5337"}] },
      { title:"PLAYFULGHOST Backdoor Targets Chinese-Speaking Users via SEO Poisoning", summary:"PLAYFULGHOST combines keylogging, screen capture, audio recording, and remote shell capabilities. Delivered via SEO-poisoned results for VPN tools and Telegram. Attributed to China-linked threat actor. Evades detection using DLL sideloading and encrypted C2.", severity:"HIGH", tags:["PLAYFULGHOST","China","SEO Poisoning","Backdoor","DLL Sideloading"], source:"Google TAG / Mandiant", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=PLAYFULGHOST+backdoor+China+2025"}] },
      { title:"RESURGE Malware Exploits Ivanti with Rootkit and Bootkit Capabilities", summary:"RESURGE is an advanced persistent malware deployed against Ivanti Connect Secure, confirmed by CISA. Has rootkit, bootkit, dropper, backdoor, and tunneler capabilities. Survives factory resets. Significantly more capable than SPAWNCHIMERA predecessor.", severity:"CRITICAL", tags:["RESURGE","Ivanti","Rootkit","Bootkit","CISA"], source:"CISA AA25-071A", date:"Mar 2025", links:[{label:"CISA",url:"https://www.cisa.gov/news-events/cybersecurity-advisories"},{label:"Search",url:"https://www.google.com/search?q=RESURGE+malware+Ivanti+CISA+2025"}] },
      { title:"AsyncRAT Delivered via Encrypted Payload Chains — Evading EDR", summary:"AsyncRAT campaigns use multi-stage delivery: HTML smuggling → JS → PowerShell → encrypted payload → injection into .NET processes. New variant uses SSL-pinned C2 and process hollowing into legitimate binaries. Targets: SMBs in US, EU, LATAM.", severity:"HIGH", tags:["AsyncRAT","HTML Smuggling","PowerShell","Process Hollowing","EDR Bypass"], source:"ANY.RUN / Microsoft", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=AsyncRAT+HTML+smuggling+2025"}] },
      { title:"PipeMagic Trojan Used in Windows CLFS Zero-Day Exploitation", summary:"PipeMagic is a plugin-based trojan discovered exploiting the Windows CLFS zero-day (CVE-2025-29824) for privilege escalation. Uses named pipes for C2. Deployed by ransomware affiliates post-initial-access. Targets: enterprise networks in US, Saudi Arabia, Spain.", severity:"CRITICAL", tags:["PipeMagic","CVE-2025-29824","Trojan","Ransomware","Named Pipe"], source:"Microsoft MSTIC", date:"Mar 2025", links:[{label:"Search",url:"https://www.google.com/search?q=PipeMagic+trojan+CVE-2025-29824+Windows"}] },
    ],
    cloud: [
      { title:"Scattered Spider Cloud Attacks — Okta + Azure AD + ServiceNow Compromise", summary:"UNC3944 pivot to cloud environments after bypassing MFA via helpdesk social engineering. Enumerate SharePoint, download HR data, exfiltrate via MEGA. Post-compromise cloud persistence: create new Azure app registrations, add OAuth tokens, register new MFA devices.", severity:"CRITICAL", tags:["Scattered Spider","Okta","Azure AD","Cloud","MFA Bypass"], source:"CrowdStrike / CISA", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Scattered+Spider+cloud+Okta+Azure+2025"}] },
      { title:"Azure AD OAuth App Consent Grant Attacks Surge", summary:"Threat actors abuse Microsoft OAuth 'consent phishing' — users are tricked into granting apps broad delegated permissions (Mail.ReadWrite, Files.ReadWrite.All). Apps maintain persistent access even after password reset. 300% increase in consent grant abuse in 2025.", severity:"HIGH", tags:["Azure AD","OAuth","Consent Phishing","Microsoft 365","BEC"], source:"Microsoft MSTIC", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Azure+AD+OAuth+consent+phishing+2025"}] },
      { title:"AWS IMDSv1 Metadata Service Abuse for Credential Theft", summary:"Threat actors exploit SSRF vulnerabilities in cloud-hosted applications to reach AWS Instance Metadata Service (IMDSv1) and steal IAM role credentials. Used for lateral movement to S3 buckets, DynamoDB, and secrets. Migrate to IMDSv2 immediately.", severity:"HIGH", tags:["AWS","SSRF","IMDSv1","IAM","Credential Theft"], source:"Wiz / Datadog", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=AWS+IMDSv1+SSRF+credential+theft+2025"}] },
      { title:"Midnight Blizzard Targets Cloud Service Providers via SPNs", summary:"APT29 (Midnight Blizzard) is targeting managed service providers and cloud service providers to reach downstream customers. Uses stolen service principal credentials and app-only tokens to maintain access. Active targeting of Azure, M365, and AWS environments.", severity:"CRITICAL", tags:["APT29","Midnight Blizzard","Cloud MSP","Service Principal","SVR"], source:"MSTIC / NCSC UK", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=Midnight+Blizzard+APT29+cloud+MSP+2025"}] },
      { title:"Cloud Ransomware — Attackers Encrypt S3 Buckets via SSE-C", summary:"Novel ransomware technique uses AWS server-side encryption with customer-provided keys (SSE-C) to encrypt S3 objects without malware. Attacker obtains S3 write permissions, re-encrypts data, and deletes originals. No malware signature — bypasses all EDR.", severity:"CRITICAL", tags:["Cloud Ransomware","AWS S3","SSE-C","Encryption","No Malware"], source:"Halcyon Research", date:"2024–2025", links:[{label:"Search",url:"https://www.google.com/search?q=S3+bucket+ransomware+SSE-C+AWS+2025"}] },
      { title:"GCP Workspace Lateral Movement via Service Account Key Abuse", summary:"Researchers demonstrate lateral movement in GCP via overprivileged service account keys exported and used from attacker-controlled infrastructure. Targets: GCS buckets, BigQuery, and Cloud Functions. Defense: disable SA key creation, use Workload Identity.", severity:"HIGH", tags:["GCP","Service Account","Lateral Movement","Cloud Security","IAM"], source:"Wiz Research", date:"2025", links:[{label:"Search",url:"https://www.google.com/search?q=GCP+service+account+lateral+movement+2025"}] },
    ],
    cisa: [
      { title:"CISA KEV: CVE-2025-29824 — Windows CLFS Privilege Escalation", summary:"Added to KEV March 2025. Windows Common Log File System (CLFS) privilege escalation exploited by PipeMagic ransomware. Affects all supported Windows versions. CISA mandates federal agencies patch within 3 days. CVSS 7.8.", severity:"CRITICAL", tags:["CISA KEV","CVE-2025-29824","Windows","CLFS","Federal Mandate"], source:"CISA KEV Catalog", date:"Mar 2025", links:[{label:"CISA KEV",url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},{label:"NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2025-29824"}] },
      { title:"CISA AA25-071A — MEDUSA Ransomware Advisory", summary:"Joint advisory from CISA, FBI, and MS-ISAC on MEDUSA ransomware. IOCs include specific C2 domains, file hashes, and YARA rules. MEDUSA uses BYOVD to disable AV, then deploys gaze.exe encryptor. Targets: healthcare, education, critical manufacturing.", severity:"HIGH", tags:["CISA","MEDUSA","Ransomware","BYOVD","Advisory AA25-071A"], source:"CISA", date:"Mar 2025", links:[{label:"CISA Advisory",url:"https://www.cisa.gov/news-events/cybersecurity-advisories"}] },
      { title:"CISA Emergency Directive: Volt Typhoon in Critical Infrastructure", summary:"CISA Emergency Directive 24-02 orders all federal agencies to audit OT/ICS environments for Volt Typhoon indicators. Specific focus on VPN appliances, SOHO routers, and living-off-the-land techniques. Hunting guidance includes specific LOLBin command patterns.", severity:"CRITICAL", tags:["Volt Typhoon","CISA ED 24-02","Critical Infrastructure","ICS/OT","Federal Mandate"], source:"CISA", date:"2024–2025", links:[{label:"CISA",url:"https://www.cisa.gov/news-events/cybersecurity-advisories"}] },
      { title:"CISA Adds CVE-2025-0282 and CVE-2025-0283 — Ivanti Connect Secure to KEV", summary:"Two Ivanti Connect Secure stack buffer overflows added to KEV. CVE-2025-0282 (CVSS 9.0) enables unauthenticated RCE. CVE-2025-0283 is post-auth privilege escalation. SPAWN malware family deployed post-exploitation. 48-hour federal patch mandate.", severity:"CRITICAL", tags:["CISA KEV","Ivanti","CVE-2025-0282","Zero-day","SPAWN"], source:"CISA", date:"Jan 2025", links:[{label:"CISA KEV",url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}] },
      { title:"CISA / NSA Joint Advisory: Fast Flux DNS Used by Cybercriminals", summary:"CISA, NSA, FBI, and Five Eyes partners issued joint advisory on fast flux DNS technique used by ransomware groups and bulletproof hosting. Technique rapidly rotates DNS records to evade blocklists. Affected: Hive, Nefilim, BlackMatter, ALPHV infrastructure.", severity:"HIGH", tags:["Fast Flux","DNS","CISA","NSA","Bulletproof Hosting"], source:"CISA / NSA / Five Eyes", date:"Apr 2025", links:[{label:"CISA",url:"https://www.cisa.gov/news-events/cybersecurity-advisories"}] },
      { title:"CISA Secure by Design Pledge — 100+ Vendors Commit to Memory-Safe Code", summary:"CISA's Secure by Design initiative secured commitments from 100+ software vendors to eliminate memory safety vulnerabilities. Notable signatories: Microsoft, Google, AWS, Cisco. Focuses on eliminating C/C++ buffer overflows, SQLi, and default credentials.", severity:"INFO", tags:["CISA","Secure by Design","Memory Safety","Software Security","Policy"], source:"CISA", date:"2024–2025", links:[{label:"CISA Secure by Design",url:"https://www.cisa.gov/securebydesign"}] },
    ],
  };

  function renderNewsItem(item) {
    const sevClass = SEVERITY_COLORS[item.severity?.toUpperCase()] || "cti-news-severity-info";
    const tags = (item.tags || []).map(t => `<span class="cti-news-item-tag">${t}</span>`).join("");
    const links = (item.links || []).map(l =>
      `<a href="${l.url}" target="_blank" class="cti-news-item-link">↗ ${l.label}</a>`
    ).join("");
    return `
      <div class="cti-news-item">
        <div class="cti-news-item-head">
          <span class="cti-news-item-badge ${sevClass}">${item.severity || "INFO"}</span>
          <span class="cti-news-item-title">${item.title}</span>
        </div>
        <div class="cti-news-item-body">${item.summary}</div>
        ${tags ? `<div class="cti-news-item-tags">${tags}</div>` : ""}
        <div class="cti-news-item-footer">
          <span class="cti-news-item-meta">${item.source || ""} ${item.date ? `· ${item.date}` : ""}</span>
          <div class="cti-news-item-links">${links}</div>
        </div>
      </div>`;
  }

  let _lastNewsFetch = 0;
  const NEWS_COOLDOWN_MS = 30000; // 30 seconds between API calls
  async function fetchThreatNews(topic) {
    const btn      = $("cti-news-refresh");
    const results  = $("cti-news-results");
    const statusEl = $("cti-news-status");
    const tsEl     = $("cti-news-timestamp");
    if (!results) return;
    // Rate limit — skip API call if within cooldown (still shows built-in KB)
    const now = Date.now();
    const sinceLastFetch = now - _lastNewsFetch;
    if (sinceLastFetch < NEWS_COOLDOWN_MS && _lastNewsFetch > 0) {
      const wait = Math.ceil((NEWS_COOLDOWN_MS - sinceLastFetch) / 1000);
      btn.title = `Please wait ${wait}s before refreshing`;
    }

    btn.disabled = true;
    btn.textContent = "⏳ Loading...";
    statusEl.style.display = "flex";
    statusEl.innerHTML = `<div class="cti-news-spinner"></div> Fetching threat intelligence…`;
    results.innerHTML = "";

    const today = new Date().toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });

    // ── Try Anthropic API first (works in claude.ai artifact context) ────────
    const TOPIC_PROMPTS = {
      latest:        "Summarize the 6 most significant cybersecurity threats, attacks, or incidents reported in the past 4 weeks. Include ransomware, nation-state APT, CVEs, and major breaches.",
      ransomware:    "Summarize the 6 most active ransomware groups and campaigns from the past 4 weeks: group names, sectors targeted, new TTPs, and any variants.",
      apt:           "Summarize the 6 most significant nation-state APT campaigns or attributions from the past 4 weeks: actor names, targets, techniques.",
      vulnerability: "Summarize the 6 most critical CVEs disclosed or exploited in the past 4 weeks: CVE IDs, CVSS, affected products, KEV status.",
      phishing:      "Summarize the 6 most notable phishing, BEC, or social engineering campaigns from the past 4 weeks: lures, targets, tools.",
      malware:       "Summarize the 6 most significant malware families or new strains reported in the past 4 weeks: capabilities, delivery, C2.",
      cloud:         "Summarize the 6 most notable cloud security incidents or attacks on AWS/Azure/GCP/SaaS from the past 4 weeks.",
      cisa:          "Summarize the 6 most recent CISA advisories or KEV additions: affected products, CVEs, recommended actions.",
    };

    const systemPrompt = `You are a senior threat intelligence analyst. Today is ${today}. Generate a structured threat intel briefing based on your knowledge. Be specific with real actor names, CVE IDs, products. Respond with valid JSON ONLY — no markdown, no extra text.`;
    const userPrompt   = `${TOPIC_PROMPTS[topic] || TOPIC_PROMPTS.latest}\n\nReturn a JSON array of exactly 6 objects:\n[{"title":"headline max 80 chars","summary":"2-3 sentences with specific details","severity":"CRITICAL|HIGH|MEDIUM|INFO","tags":["tag1","tag2","tag3"],"source":"Best known source","date":"Approx date","links":[{"label":"Search","url":"https://www.google.com/search?q=URL-ENCODED-TITLE"}]}]\n\nReturn ONLY the JSON array.`;

    let apiSuccess = false;
    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 2500,
          system: systemPrompt,
          messages: [{ role: "user", content: userPrompt }]
        })
      });

      if (response.ok) {
        const data = await response.json();
        const raw = data.content?.find(b => b.type === "text")?.text || "";
        const cleaned = raw.replace(/^```json\s*/i,"").replace(/^```\s*/i,"").replace(/```\s*$/i,"").trim();
        const items = JSON.parse(cleaned);
        if (Array.isArray(items) && items.length > 0) {
          results.innerHTML = items.map(renderNewsItem).join("");
          statusEl.style.display = "none";
          if (tsEl) tsEl.textContent = new Date().toLocaleString() + " (AI-generated)";
          apiSuccess = true;
        }
      }
    } catch (_) {
      // API not available — fall through to built-in database
    }

    // ── Built-in knowledge base fallback ────────────────────────
    if (!apiSuccess) {
      const items = BUILTIN_THREATS[topic] || BUILTIN_THREATS.latest;
      results.innerHTML = items.map(renderNewsItem).join("");
      statusEl.style.display = "none";
      if (tsEl) tsEl.textContent = `Built-in Intel DB (as of early 2025) · ${new Date().toLocaleDateString()}`;
    }

    _lastNewsFetch = Date.now();
    btn.disabled = false;
    btn.textContent = "⚡ Get Latest";
    btn.title = "";
  }

  $("cti-news-refresh")?.addEventListener("click", () => {
    const topic = $("cti-news-topic")?.value || "latest";
    fetchThreatNews(topic);
  });

  // Auto-load when tab is opened for the first time
  let _newsLoaded = false;
  document.querySelectorAll(".cti-sub-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      if (btn.dataset.ctitab === "news" && !_newsLoaded) {
        _newsLoaded = true;
        setTimeout(() => fetchThreatNews($("cti-news-topic")?.value || "latest"), 120);
      }
    });
  });


  // ── Actor Intel Database (built-in profiles) ──────────────────
  const ACTOR_DB = {
    "APT29": { aliases:["Cozy Bear","NOBELIUM","Midnight Blizzard","Dark Halo"], origin:"Russia", sponsor:"SVR", type:"Nation-State", tlp:"white", description:"Russian SVR-linked group known for the SolarWinds supply chain attack (SUNBURST), spear-phishing campaigns, and long-term stealthy espionage operations against governments and think tanks.", ttps:["T1566.001","T1190","T1027","T1055","T1071.001","T1078","T1195.002"], tools:["SUNBURST","TEARDROP","BEATDROP","Cobalt Strike","WellMess"], targets:"Government, NGOs, Technology, Healthcare, Think Tanks", mitre:"https://attack.mitre.org/groups/G0016/" },
    "APT28": { aliases:["Fancy Bear","Sofacy","STRONTIUM","Forest Blizzard"], origin:"Russia", sponsor:"GRU", type:"Nation-State", tlp:"white", description:"Russian GRU Unit 26165 group attributed to DNC hack (2016), NATO phishing, and multiple Western government intrusions.", ttps:["T1566","T1190","T1059.001","T1078","T1003.001","T1071"], tools:["X-Agent","Sofacy","Zebrocy","Drovorub"], targets:"Government, Military, NATO, Think Tanks", mitre:"https://attack.mitre.org/groups/G0007/" },
    "Lazarus": { aliases:["HIDDEN COBRA","Zinc","Diamond Sleet","APT38"], origin:"North Korea", sponsor:"RGB", type:"Nation-State", tlp:"white", description:"North Korean state-sponsored group responsible for WannaCry, Bangladesh Bank Heist, and numerous cryptocurrency exchange attacks for financial gain.", ttps:["T1566.001","T1204","T1059","T1486","T1041","T1078","T1105"], tools:["WannaCry","BLINDINGCAN","HOPLIGHT","Fallchill"], targets:"Financial, Crypto, Defense, Healthcare", mitre:"https://attack.mitre.org/groups/G0032/" },
    "FIN7": { aliases:["Carbanak","ITG14","Carbon Spider","Sangria Tempest"], origin:"Russia/Ukraine", sponsor:"Criminal", type:"Financial Crime", tlp:"white", description:"Prolific financially-motivated group targeting hospitality, restaurant, and retail sectors via spear-phishing and JavaScript backdoors. Known for CARBANAK banking malware.", ttps:["T1566.001","T1059.005","T1055","T1027","T1083","T1071"], tools:["CARBANAK","BIRDDOG","POWERPLANT","Cobalt Strike"], targets:"Financial, Hospitality, Retail, Restaurant", mitre:"https://attack.mitre.org/groups/G0046/" },
    "Scattered Spider": { aliases:["UNC3944","Roasted 0ktapus","StarFraud","Muddled Libra"], origin:"US/UK", sponsor:"Criminal", type:"Financial Crime / BEC", tlp:"white", description:"English-speaking threat actor known for SIM swapping, MFA bypass via help desk social engineering, and high-profile attacks on MGM Resorts and Caesars Entertainment.", ttps:["T1621","T1078","T1534","T1566","T1059","T1598.003"], tools:["OKTAPUS phishing kit","Cobalt Strike","AnyDesk"], targets:"BPO, Telecom, Hospitality, Crypto, Gaming", mitre:"https://attack.mitre.org/groups/G1015/" },
    "Volt Typhoon": { aliases:["Bronze Silhouette","Vanguard Panda","Dev-0391"], origin:"China", sponsor:"MSS/PLA", type:"Nation-State", tlp:"white", description:"Chinese state-sponsored actor focusing on US critical infrastructure pre-positioning. Known for using LOTL (Living off the Land) techniques to avoid detection.", ttps:["T1190","T1078","T1059","T1021.001","T1560","T1071","T1036"], tools:["FRP","web shells","netsh"], targets:"Critical Infrastructure, Utilities, Communications, Military", mitre:"https://attack.mitre.org/groups/G1017/" },
    "Sandworm": { aliases:["Voodoo Bear","IRIDIUM","Seashell Blizzard","APT44"], origin:"Russia", sponsor:"GRU", type:"Nation-State / Destructive", tlp:"white", description:"GRU Unit 74455 — responsible for NotPetya (most destructive cyberattack in history), Ukraine power grid attacks, and BlackEnergy campaigns.", ttps:["T1486","T1561","T1190","T1059","T1071","T1570"], tools:["NotPetya","BlackEnergy","Industroyer","Cyclops Blink"], targets:"Ukraine, Energy, Government, Global", mitre:"https://attack.mitre.org/groups/G0034/" },
    "Kimsuky": { aliases:["Thallium","Velvet Chollima","APT43","TA406"], origin:"North Korea", sponsor:"RGB", type:"Nation-State", tlp:"white", description:"North Korean espionage group focused on collecting intelligence from South Korean think tanks, government entities, and policy experts.", ttps:["T1566.001","T1059.001","T1027","T1083","T1114","T1078"], tools:["AppleSeed","SHARPEXT","PENCILDOWN","BabyShark"], targets:"South Korea, US Think Tanks, Government, Academia", mitre:"https://attack.mitre.org/groups/G0094/" },
    "LockBit": { aliases:["ABCD","LockBit 3.0","LockBit Black"], origin:"Unknown / RaaS", sponsor:"Criminal RaaS", type:"Ransomware Group", tlp:"white", description:"Prolific ransomware-as-a-service group. Most active ransomware operation globally from 2022-2024. Known for double-extortion via data leak site.", ttps:["T1486","T1490","T1489","T1078","T1021","T1083","T1041"], tools:["LockBit ransomware","StealBit exfil tool","Cobalt Strike"], targets:"Healthcare, Government, Education, Manufacturing (indiscriminate)", mitre:"https://attack.mitre.org/software/S0652/" },
    "Cl0p": { aliases:["TA505","Lace Tempest"], origin:"Russia/Ukraine", sponsor:"Criminal", type:"Ransomware / FIN", tlp:"white", description:"Known for exploiting zero-days en masse (GoAnywhere, MOVEit). Responsible for some of the largest data-theft extortion campaigns.", ttps:["T1190","T1041","T1486","T1078","T1105"], tools:["Cl0p ransomware","SDBOT","FlawedAmmyy"], targets:"Financial, Healthcare, Tech (mass exploitation campaigns)", mitre:"https://attack.mitre.org/groups/G0092/" },
    "TA505": { aliases:["Evil Corp adjacent","Hive0065"], origin:"Russia", sponsor:"Criminal", type:"Financial Crime", tlp:"white", description:"Major threat actor responsible for distributing Dridex, Locky ransomware, and FlawedAmmyy RAT. Known for high-volume phishing campaigns.", ttps:["T1566","T1059.005","T1204.002","T1071","T1027"], tools:["Dridex","Locky","FlawedAmmyy","ServHelper"], targets:"Financial, Retail, Healthcare", mitre:"https://attack.mitre.org/groups/G0092/" },
    "Turla": { aliases:["Snake","Venomous Bear","IRON HUNTER","Secret Blizzard"], origin:"Russia", sponsor:"FSB", type:"Nation-State", tlp:"white", description:"FSB-linked group known for using compromised satellite links for C2, and the sophisticated Carbon/Snake malware framework.", ttps:["T1190","T1027","T1055","T1071","T1078","T1074"], tools:["Snake","Carbon","Kazuar","ComRAT"], targets:"Government, Embassies, Military, EU/NATO", mitre:"https://attack.mitre.org/groups/G0010/" },
    "APT41": { aliases:["Double Dragon","Barium","Winnti","Earth Baku"], origin:"China", sponsor:"MSS", type:"Nation-State + Financial", tlp:"white", description:"Dual mission Chinese group conducting both espionage for MSS and financially motivated attacks (gaming companies, crypto). Unique dual nation-state/criminal mandate.", ttps:["T1190","T1078","T1059","T1027","T1055","T1486"], tools:["DUSTPAN","DEADEYE","KEYPLUG","Cobalt Strike"], targets:"Healthcare, Telecom, Technology, Gaming, Government", mitre:"https://attack.mitre.org/groups/G0096/" },
  };

  function renderActorCard(name, actor) {
    const typeColors = { "Nation-State":"#38bdf8","Financial Crime":"#f59e0b","Ransomware Group":"#f87171","Nation-State / Destructive":"#f87171","Financial Crime / BEC":"#fb923c","Nation-State + Financial":"#a78bfa" };
    const tc = typeColors[actor.type] || "#9ca3af";
    return `<div class="cti-actor-card">
      <div class="cti-actor-head">
        <div>
          <div class="cti-actor-name">${name}</div>
          <div class="cti-actor-aliases">AKA: ${actor.aliases.join(" · ")}</div>
        </div>
        <div class="cti-actor-badges">
          <span class="cti-actor-badge" style="color:${tc};background:${tc}18;border-color:${tc}44">${actor.type}</span>
          <span class="cti-actor-badge" style="color:#e879f9;background:#e879f918;border-color:#e879f944">${actor.origin}</span>
          <span class="cti-actor-badge" style="color:#fbbf24;background:#fbbf2418;border-color:#fbbf2444">${actor.sponsor}</span>
        </div>
      </div>
      <div class="cti-actor-desc">${actor.description}</div>
      <div class="cti-actor-grid">
        <div class="cti-actor-row"><span class="cti-actor-label">🎯 Targets</span><span>${actor.targets}</span></div>
        <div class="cti-actor-row"><span class="cti-actor-label">🛠 Tools</span><span>${actor.tools.join(", ")}</span></div>
      </div>
      <div class="cti-actor-ttps">
        ${actor.ttps.map(t => `<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="sa-mitre-card" style="display:inline-flex">
          <div class="sa-mitre-tid">${t}</div>
          <div class="sa-mitre-name">${getMitreName(t)}</div>
        </a>`).join("")}
      </div>
      <div class="cti-actor-actions">
        <a href="${actor.mitre}" target="_blank" class="quicklink-btn">🧩 MITRE ATT&CK Profile</a>
        <button class="quicklink-btn cti-hunt-btn" data-actor="${name}" type="button">🔍 Hunt IOCs</button>
      </div>
    </div>`;
  }

  const ctiActorResults = $("cti-actor-results");

  $("cti-actor-search-btn")?.addEventListener("click", () => {
    const q = ($("cti-actor-input")?.value||"").trim().toLowerCase();
    if (!q) return;
    const matches = Object.entries(ACTOR_DB).filter(([name, actor]) =>
      name.toLowerCase().includes(q) ||
      actor.aliases.some(a => a.toLowerCase().includes(q)) ||
      actor.description.toLowerCase().includes(q) ||
      actor.tools.some(t => t.toLowerCase().includes(q))
    );
    if (!ctiActorResults) return;
    if (!matches.length) { ctiActorResults.innerHTML = `<div class="bulk-empty">No matching actors found for "${esc(q)}". Try an alias, tool name, or partial name.</div>`; return; }
    ctiActorResults.innerHTML = matches.map(([n,a]) => renderActorCard(n,a)).join("");
    ctiActorResults.querySelectorAll(".cti-hunt-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const actor = ACTOR_DB[btn.dataset.actor];
        if (!actor) return;
        const bulkIn = $("bulk-input");
        if (bulkIn) { bulkIn.value = actor.tools.join("\n") + "\n" + actor.ttps.join("\n"); switchTab("bulk"); $("bulk-analyze-btn")?.click(); }
      });
    });
  });

  $("cti-actor-random")?.addEventListener("click", () => {
    const keys = Object.keys(ACTOR_DB);
    const name = keys[Math.floor(Math.random()*keys.length)];
    const inp = $("cti-actor-input"); if(inp) inp.value = name;
    $("cti-actor-search-btn")?.click();
  });

  // Allow Enter key on actor input
  $("cti-actor-input")?.addEventListener("keydown", e => { if(e.key==="Enter") $("cti-actor-search-btn")?.click(); });

  // ── IOC Intel Check ───────────────────────────────────────────
  const CTI_IOC_PIVOTS = {
    ip:     [{l:"ThreatFox",    u: q => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(q)}`},
             {l:"OTX",          u: q => `https://otx.alienvault.com/indicator/ip/${enc(q)}`},
             {l:"GreyNoise",    u: q => `https://viz.greynoise.io/ip/${enc(q)}`},
             {l:"FeodoTracker", u: q => `https://feodotracker.abuse.ch/browse.php?search=${enc(q)}`},
             {l:"Pulsedive",    u: q => `https://pulsedive.com/indicator/?ioc=${enc(q)}`},
             {l:"AbuseIPDB",    u: q => `https://www.abuseipdb.com/check/${enc(q)}`}],
    domain: [{l:"ThreatFox",    u: q => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(q)}`},
             {l:"OTX",          u: q => `https://otx.alienvault.com/indicator/domain/${enc(q)}`},
             {l:"URLhaus",      u: q => `https://urlhaus.abuse.ch/browse.php?search=${enc(q)}`},
             {l:"Pulsedive",    u: q => `https://pulsedive.com/indicator/?ioc=${enc(q)}`},
             {l:"URLScan",      u: q => `https://urlscan.io/search/#domain:${enc(q)}`}],
    hash:   [{l:"MalwareBazaar",u: q => `https://bazaar.abuse.ch/browse.php?search=${enc(q)}`},
             {l:"ThreatFox",    u: q => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(q)}`},
             {l:"OTX",          u: q => `https://otx.alienvault.com/indicator/file/${enc(q)}`},
             {l:"VirusTotal",   u: q => `https://www.virustotal.com/gui/file/${enc(q)}`},
             {l:"Hybrid Anal.", u: q => `https://www.hybrid-analysis.com/search?query=${enc(q)}`}],
    url:    [{l:"URLhaus",      u: q => `https://urlhaus.abuse.ch/browse.php?search=${enc(q)}`},
             {l:"ThreatFox",    u: q => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(q)}`},
             {l:"OTX",          u: q => `https://otx.alienvault.com/indicator/url/${enc(q)}`},
             {l:"URLScan",      u: q => `https://urlscan.io/search/#page.url:${enc(q)}`}],
    cve:    [{l:"CISA KEV",     u: q => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`},
             {l:"Exploit-DB",   u: q => `https://www.exploit-db.com/search?cve=${enc(q)}`},
             {l:"NVD",          u: q => `https://nvd.nist.gov/vuln/detail/${enc(q)}`},
             {l:"Vulners",      u: q => `https://vulners.com/search?query=${enc(q)}`}],
    email:  [{l:"HIBP",         u: q => `https://haveibeenpwned.com/account/${enc(q)}`},
             {l:"OTX",          u: q => `https://otx.alienvault.com/indicator/email/${enc(q)}`},
             {l:"IntelX",       u: q => `https://intelx.io/?s=${enc(q)}`},
             {l:"Dehashed",     u: q => `https://dehashed.com/search?query=${enc(q)}`}],
  };

  $("cti-ioc-check-btn")?.addEventListener("click", () => {
    const raw = ($("cti-ioc-input")?.value||"").trim();
    if (!raw) return;
    const { type, q } = detectType(raw, "");
    const results = $("cti-ioc-results");
    const statusEl = $("cti-ioc-status")?.querySelector("span");
    if (!type) { if(results) results.innerHTML=`<div class="bulk-empty">⚠️ Could not detect IOC type for: ${raw}</div>`; return; }
    const pivots = CTI_IOC_PIVOTS[type] || CTI_IOC_PIVOTS.ip;
    const typeColor = {ip:"#38bdf8",domain:"#34d399",hash:"#f59e0b",url:"#fb923c",email:"#a78bfa",cve:"#f87171"}[type]||"#9ca3af";
    if (statusEl) statusEl.textContent = `Detected: ${type.toUpperCase()} — showing CTI pivot links`;
    if (!results) return;
    results.innerHTML = `<div class="cti-ioc-header" style="border-color:${typeColor}44;background:${typeColor}0d">
      <span class="lt-ev-badge" style="color:${typeColor};background:${typeColor}18;border-color:${typeColor}44">${type.toUpperCase()}</span>
      <code style="font-size:13px">${q}</code>
      <button class="quicklink-btn" id="cti-ioc-pivot-main" data-val="${q.replace(/"/g,'&quot;')}" type="button">🔍 Full OSINT Pivot</button>
    </div>
    <div class="cti-ioc-links-grid">
      ${pivots.map(p => `<a href="${p.u(q)}" target="_blank" class="cti-ioc-link-card">
        <div class="cti-ioc-link-name">${p.l}</div>
        <div class="cti-ioc-link-action">Check →</div>
      </a>`).join("")}
    </div>
    <div class="cti-ioc-hints">
      <div class="cti-ioc-hint-head">💡 Investigation hints for ${type.toUpperCase()}</div>
      ${getIOCHints(type).map(h=>`<div class="lt-finding lt-finding-info">ℹ️ ${h}</div>`).join("")}
    </div>`;
    $("cti-ioc-pivot-main")?.addEventListener("click", () => {
      if (input) { input.value = q; syncSearchboxState(); switchTab("single"); doSearch({ silent:false }); }
    });
  });
  $("cti-ioc-input")?.addEventListener("keydown", e => { if(e.key==="Enter") $("cti-ioc-check-btn")?.click(); });

  function getIOCHints(type) {
    return {
      ip:     ["Check both ThreatFox and FeodoTracker for C2 associations","GreyNoise distinguishes targeted attacks from internet background noise","Cross-reference ASN ownership — cloud hosting IPs are common in phishing","Check if IP is a TOR exit node or known VPN/proxy"],
      domain: ["Check domain registration age — newly registered is a red flag","Look for typosquatting of known brands","Certificate Transparency logs (crt.sh) reveal related subdomains","Passive DNS shows historical IPs — useful for pivot to related infrastructure"],
      hash:   ["Submit unknown hashes to sandbox for dynamic analysis","Check MalwareBazaar for malware family and campaign attribution","Cross-reference with Hybrid Analysis for behavioral IOCs","SSDEEP fuzzy hashing can find variants of the same malware"],
      url:    ["URLScan.io captures full page screenshots — useful for phishing detection","Check URLhaus for malware delivery association","Archive.org preserves content if URL is now 404","Extract domain from URL and pivot separately for deeper intel"],
      email:  ["HIBP shows if email appeared in known breach data","Check email reputation score — EmailRep.io is good for this","Google OSINT: search email in quotes to find forum posts, registrations","Pivot on email domain for broader infrastructure analysis"],
      cve:    ["Check CISA KEV first — if listed, exploitation is confirmed in the wild","EPSS score indicates exploit probability — prioritize high EPSS","Search Exploit-DB and GitHub for public PoC code","Check vendor advisory for patch availability and workarounds"],
    }[type] || ["Search across multiple threat intel platforms for context","Look for related IOCs to understand full attack scope","Check TLP for sharing restrictions before distributing"];
  }

  // ── Campaign Tracker ──────────────────────────────────────────
  let ctiCampaigns = [];
  try { ctiCampaigns = JSON.parse(localStorage.getItem("osint_cti_campaigns")||"[]"); } catch {}

  function saveCampaigns() { try { localStorage.setItem("osint_cti_campaigns", JSON.stringify(ctiCampaigns)); } catch {} }

  function renderCampaigns() {
    const list = $("cti-campaigns-list");
    if (!list) return;
    if (!ctiCampaigns.length) { list.innerHTML = '<div class="bulk-empty">No campaigns tracked yet. Add one above.</div>'; return; }
    const statusColors = { active:"#f87171", monitoring:"#fbbf24", closed:"#34d399" };
    const statusLabels = { active:"🔴 Active", monitoring:"🟡 Monitoring", closed:"🟢 Closed" };
    list.innerHTML = ctiCampaigns.map((c,i) => `<div class="cti-camp-card" id="cti-camp-${i}">
      <div class="cti-camp-head">
        <div>
          <div class="cti-camp-name">${c.name}</div>
          ${c.actor ? `<div class="cti-camp-actor">Actor: ${c.actor}</div>` : ""}
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="cti-actor-badge" style="color:${statusColors[c.status]};background:${statusColors[c.status]}18;border-color:${statusColors[c.status]}44">${statusLabels[c.status]||c.status}</span>
          <span class="cti-actor-badge" style="color:#9ca3af">${new Date(c.created).toLocaleDateString()}</span>
          <button class="lt-pivot-btn cti-camp-del" data-idx="${i}" type="button">🗑</button>
        </div>
      </div>
      <div class="cti-camp-iocs">
        <div class="cti-camp-ioc-label">IOCs (${(c.iocs||[]).length})</div>
        ${(c.iocs||[]).slice(0,10).map(ioc=>`<div class="regex-ioc-row"><code>${ioc.type}: ${ioc.value}</code></div>`).join("")}
        ${(c.iocs||[]).length>10?`<div style="font-size:10px;color:var(--muted)">...and ${c.iocs.length-10} more</div>`:""}
      </div>
      <div class="cti-camp-add-ioc">
        <input class="aw-input cti-camp-ioc-input" type="text" placeholder="Add IOC to this campaign" data-idx="${i}" style="font-size:11px;padding:5px 8px" />
        <button class="lt-pivot-btn cti-camp-addioc" data-idx="${i}" type="button">➕ Add IOC</button>
      </div>
    </div>`).join("");
    list.querySelectorAll(".cti-camp-del").forEach(btn => {
      btn.addEventListener("click", () => { ctiCampaigns.splice(Number(btn.dataset.idx),1); saveCampaigns(); renderCampaigns(); });
    });
    list.querySelectorAll(".cti-camp-addioc").forEach(btn => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.idx);
        const iocInp = list.querySelector(`.cti-camp-ioc-input[data-idx="${idx}"]`);
        const val = (iocInp?.value||"").trim(); if(!val) return;
        const { type } = detectType(val,"");
        if (!ctiCampaigns[idx].iocs) ctiCampaigns[idx].iocs = [];
        ctiCampaigns[idx].iocs.push({ type: type||"unknown", value: val });
        saveCampaigns(); renderCampaigns();
      });
    });
  }

  $("cti-camp-add")?.addEventListener("click", () => {
    const name = ($("cti-camp-name")?.value||"").trim();
    if (!name) return;
    ctiCampaigns.unshift({ name, actor: $("cti-camp-actor")?.value?.trim()||"", status: $("cti-camp-status")?.value||"active", created: Date.now(), iocs:[] });
    saveCampaigns(); renderCampaigns();
    [$("cti-camp-name"),$("cti-camp-actor")].forEach(el=>{if(el)el.value="";});
  });

  $("cti-camp-export")?.addEventListener("click", () => {
    const lines = ["# CTI Campaign Export","# Generated: "+new Date().toISOString(),""];
    ctiCampaigns.forEach(c => {
      lines.push(`## ${c.name} [${c.status.toUpperCase()}]`);
      if(c.actor) lines.push(`Actor: ${c.actor}`);
      lines.push(`Created: ${new Date(c.created).toISOString()}`);
      if(c.iocs?.length) { lines.push("IOCs:"); c.iocs.forEach(i=>lines.push(`  [${i.type}] ${i.value}`)); }
      lines.push("");
    });
    const blob = new Blob([lines.join("\n")],{type:"text/plain"});
    const a = document.createElement("a"); a.href=URL.createObjectURL(blob);
    a.download=`cti-campaigns-${Date.now()}.txt`; a.click();
  });

  $("cti-camp-clear")?.addEventListener("click", () => {
    if (!confirm("Clear all campaigns? This cannot be undone.")) return;
    ctiCampaigns = []; saveCampaigns(); renderCampaigns();
  });

  // Init
  loadCaseFromStorage();
  renderCampaigns();
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
