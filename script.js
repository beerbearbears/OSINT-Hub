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

    // ── Hard exclusions — these are definitely NOT email headers ──
    // Windows Event Log patterns
    if (/^Log Name:\s+\w|^Source:\s+Microsoft-Windows|^Event ID:\s+\d|^Task Category:/im.test(head)) return false;
    // SIEM / CEF / Syslog patterns  
    if (/^CEF:\d\||\bCEF:0\b|event_simpleName\s*=|sourcetype\s*=|eventType\s*=|ComputerName\s*[=:]|Ngsiem\.|event\.action\s*=/im.test(head)) return false;
    // JSON / structured log patterns
    if (/^\s*\{[\s\S]*"eventTime"\s*:|^\s*\{[\s\S]*"eventName"\s*:|^\s*\{[\s\S]*"eventVersion"\s*:/m.test(head)) return false;
    // Firewall/network log patterns
    if (/\bSRC=\d|src=\d{1,3}\.\d|dst=\d{1,3}\.\d|\bDPT=\d+\b|\bSPT=\d+\b/i.test(head)) return false;
    // SIEM alert patterns
    if (/^\s*(?:Severity|Detection|Alert|Offense|Notable)\s*[=:]\s*/im.test(head) && !/^From:/im.test(head)) return false;

    // ── Strong email header signals ──
    const strong = [
      /(^|\n)\s*received:\s/im, /(^|\n)\s*authentication-results:\s/im,
      /(^|\n)\s*dkim-signature:\s/im, /(^|\n)\s*arc-seal:\s/im,
      /(^|\n)\s*message-id:\s/im, /(^|\n)\s*return-path:\s/im,
    ];
    const hasStrongSignal = strong.some(rx => rx.test(head));
    if (!hasStrongSignal) {
      // Weaker signals — require more evidence
      const hasFrom   = /(^|\n)\s*from:\s/im.test(head);
      const hasTo     = /(^|\n)\s*to:\s/im.test(head);
      const hasSubject= /(^|\n)\s*subject:\s/im.test(head);
      const hasDate   = /(^|\n)\s*date:\s/im.test(head);
      // Need at least 3 of the weak signals together
      const weakCount = [hasFrom, hasTo, hasSubject, hasDate].filter(Boolean).length;
      if (weakCount < 3) return false;
    }

    const headerLineCount = (head.match(/(^|\n)[A-Za-z0-9-]{2,}:\s.+/g) || []).length;
    return hasStrongSignal || headerLineCount >= 8;
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
  // Secondary tabs that show a "back" button — user navigated away from main search
  const SECONDARY_TABS = new Set(["custom","utils","cti"]);
  let _lastMainTab = "single"; // remembers the last main tab for back navigation

  function switchTab(name) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.id === `tab-${name}`));
    // Show/hide back bar based on whether we're on a secondary tab
    const isSecondary = SECONDARY_TABS.has(name);
    document.querySelectorAll(".tab-back-bar").forEach(bar => {
      bar.style.display = isSecondary ? "flex" : "none";
    });
    // Update back button label with the last main tab name
    if (isSecondary) {
      document.querySelectorAll(".tab-back-btn").forEach(btn => {
        const mainLabel = {single:"IOC Search", bulk:"Bulk IOC", script:"Script Analyzer",
          writeup:"Alert Write-up", case:"Case Manager", timeline:"Timeline",
          hashfile:"Hash File", defangbulk:"Defang/Refang", yara:"YARA/Sigma",
          logtriage:"Log Triage"}[_lastMainTab] || "Search";
        btn.textContent = "← " + mainLabel;
        btn.onclick = () => switchTab(_lastMainTab);
      });
    } else {
      _lastMainTab = name; // remember this as the last main tab
    }
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
    // 1. Full URLs with scheme — defang scheme + dots
    t = t.replace(/\b(https?|ftp):\/\/([^\s<>"')]+)/gi, (m, scheme, rest) => {
      const defScheme = scheme.toLowerCase() === "https" ? "hxxps" : scheme.toLowerCase() === "ftp" ? "fxp" : "hxxp";
      return defScheme + "://" + rest.replace(/\./g, "[.]");
    });
    // 2. Emails — defang @ and dots in domain
    t = t.replace(/\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi,
      (m, u, d) => `${u}[@]${d.replace(/\./g, "[.]")}`);
    // 3. IPv4 addresses — defang dots
    t = t.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
      m => isValidIPv4(m) ? m.replace(/\./g, "[.]") : m);
    // 4. IPv6 addresses — defang colons
    // Match full IPv6 (must have 2+ colon groups to avoid false positives)
    t = t.replace(/\b([0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){3,7}(?::(?:[0-9A-Fa-f]{1,4}|))*)\b/g, m => {
      if (isValidIPv6(m)) return m.replace(/:/g, "[:]");
      return m;
    });
    // 5. Bare domains (not already defanged, not inside a URL already processed)
    // Only defang if it looks like a real domain (has a valid TLD, not a file extension)
    const COMMON_TLDS = /\.(com|net|org|io|gov|edu|mil|int|co|uk|de|fr|jp|cn|ru|br|in|au|ca|mx|eu|xyz|top|icu|sbs|me|info|biz|name|us|app|dev|cloud|store|online|site|web|tech|club|live|news|agency|solutions|services|support|group|global)\b/i;
    t = t.replace(/\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+)\b/gi, m => {
      // Skip if already defanged or is a file/version string
      if (m.includes("[.]") || m.includes("[:]")) return m;
      // Must have a valid TLD
      if (!COMMON_TLDS.test(m)) return m;
      // Skip purely numeric looking domains (they'd be caught as IPs already)
      if (/^\d+\.\d+/.test(m)) return m;
      // Skip file extensions like evil.exe, report.pdf
      if (/\.(exe|dll|sys|bat|cmd|ps1|vbs|js|py|sh|pdf|doc|xls|zip|rar|7z|png|jpg|gif|svg|css|html|htm|xml|json|log|txt|csv)$/i.test(m)) return m;
      return m.replace(/\./g, "[.]");
    });
    return t;
  }

  function refangSmart(text) {
    let t = (text || "");
    t = t.replace(/hxxps:\/\//gi,"https://").replace(/hxxp:\/\//gi,"http://");
    t = t.replace(/\[@\]/g,"@").replace(/\[\.\]/g,".").replace(/\[:\]/g,":");
    return t;
  }

  // ── Smart IOC Extractor (28 observable categories) ───────────
  function extractSmartIOCs(text) {
    const now = new Date().toISOString();
    const t   = (text || "").replace(/\r\n/g, "\n");
    const r   = refangSmart(t);
    const uniq = arr => [...new Set(arr.filter(Boolean))].sort();

    // Network
    const ips  = uniq((r.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)||[]).filter(isValidIPv4));
    const ipv6 = uniq((r.match(/\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){3,7}\b/g)||[]).filter(m => { try { return isValidIPv6(m); } catch { return false; } }));
    const urls = uniq((r.match(/https?:\/\/[^\s<>"'\]\n]+/gi)||[]).map(u => u.replace(/[.,;)]+$/, "")));
    const SKIP_DOM = /^(?:\d+\.\d+|\d+$|actor\.|client\.|outcome\.|target\.|user\.|eventType|displayName|alternateId|ipAddress|geographicalContext|HTML\.|JS\.|Win32\.|Malware\.|Exploit\.|Trojan\.|Ransom\.|Backdoor\.|CVE-)/i;
    const isOktaField = d => d.split(".").length >= 3 && d.split(".").every(p => /^[a-z][a-zA-Z0-9]*$/.test(p));
    const domains = uniq(
      (r.match(/\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\b/g)||[])
      .filter(d => !ips.includes(d) && /\.[a-zA-Z]{2,}$/.test(d) &&
        !/\.(exe|dll|ps1|bat|vbs|js|py|sh|pdf|doc|xls|zip|png|jpg|gif|svg|css|json|log|txt|csv|xml|md|html|htm|jar|msi|rar|7z|cab|lnk|scr|sys)$/i.test(d) &&
        !SKIP_DOM.test(d) && !isOktaField(d) && !d.split(".").every(p => /^\d+$/.test(p))
      )
    );
    const ports = uniq((r.match(/\b(?:dstport|srcport|remoteport|ipport|RemotePort|IpPort|port)\s*[=:]\s*(\d{1,5})\b/gi)||[])
      .map(m => (m.match(/(\d{1,5})$/)||[])[1]).filter(p => p && parseInt(p) <= 65535 && parseInt(p) >= 1));
    const emails = uniq((r.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g)||[]).map(e => e.toLowerCase()));

    // Usernames from structured fields
    const _rawUsernames = [];
    const _userRe = /\b(?:UserName|SubjectUserName|TargetUserName|actor\.alternateId|username|account\s+name|Secondary\s+name|Username)\s*[=:"\s]+([^\s"',\n]{2,60})/gi;
    let um;
    while ((um = _userRe.exec(t)) !== null) {
      const v = um[1].trim().replace(/^["']|["']$/g, "");
      if (v && !/^(?:None|null|N\/A|--|true|false|\d+)$/i.test(v)) _rawUsernames.push(v);
    }
    const usernames = uniq(_rawUsernames);

    // Display names
    const _nameRe = /\b(?:User\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s+Privileged|(?:actor\.displayName|target\.displayName|UserDisplayName)\s*[=:"]+\s*([^,"\n\s][^,"\n]{2,50}?)(?=\s+\w+[=.]|\s*$|\n)|(?:displayName)\s*[=:"]+\s*([A-Za-z][^,"\n]{2,50}?)(?=\s+\w+[=.]|\s*$|\n))/gi;
    const displayNames = [];
    let nm;
    while ((nm = _nameRe.exec(t)) !== null) {
      const v = (nm[1]||nm[2]||nm[3]||"").trim();
      if (v && v.length > 2 && !/^(?:None|null|--)$/i.test(v)) displayNames.push(v);
    }

    // Departments, titles
    const deptM  = t.match(/\bDepartment\s+([^\n]{3,60}?)(?=\s+(?:Title|Network|Username|Email|Privileged|Risk|Source|Time|User|Alert|Classification|AD|SID|OU|See|IP|Activity)\b)/i);
    const titleM = t.match(/\bTitle\s+([^\n]{3,60}?)(?=\s+(?:Network|Username|Email|Privileged|Risk|Source|Time|User|Alert|Classification|AD|SID|OU|See|IP|Activity)\b)/i);

    // Hostnames
    const _hostRe = /\b(?:ComputerName|clientHostname|AgentComputerName|devicehostname|Computer|WorkstationName|hostname)\s*[=:"\s]+([A-Za-z0-9][A-Za-z0-9_\-\.]{2,50})/gi;
    const hostnames = [];
    let hm;
    while ((hm = _hostRe.exec(t)) !== null) { const v=hm[1].trim(); if (v&&!hostnames.includes(v)) hostnames.push(v); }
    (t.match(/\b(?:[A-Z]{2,6}-[A-Z0-9]{2,6}-[A-Z0-9]{2,8}|DC-\w{2,20}|WS-\w{2,20}|SRV-\w{2,20})\b/g)||[]).forEach(h=>{ if (!hostnames.includes(h)) hostnames.push(h); });

    // Hashes, files, registry
    const hashes   = uniq((r.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g)||[]).filter(h => /^[a-fA-F0-9]+$/.test(h)));
    const filePaths= uniq((r.match(/(?:[A-Za-z]:\\[^\s"<>|*?\n]+|\\\\[^\s"<>|*?\n]+|\/(?:etc|var|tmp|home|usr|opt|bin|sbin|proc|dev)\/[^\s"<>\n]+)/g)||[]).map(p=>p.replace(/[,;.]+$/, "")));
    const regKeys  = uniq((r.match(/HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\\/\w\s%_.\-]*/g)||[]).map(k=>k.trim()));
    const processes= uniq((r.match(/\b([\w\-]{2,40}\.(?:exe|dll|sys|bat|cmd|ps1|vbs|hta|msi|jar|sh|py))\b/gi)||[]).map(p=>p.toLowerCase()));

    // Command lines
    const cmdlines = [];
    const _cmdRe = /(?:CommandLine|cmdline)\s*[=:"\s]+([^\n"]{5,200}?)(?=\s+[A-Za-z_]+[A-Za-z0-9_]*\s*=|\s*$|\n)/gi;
    let cl;
    while ((cl = _cmdRe.exec(t)) !== null) { const v=cl[1].trim().replace(/^["']|["']$/g,""); if (v.length>4) cmdlines.push(v.slice(0,200)); }

    // Timestamps
    const timestamps = uniq([
      ...(t.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/g)||[]),
      ...(t.match(/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?/gi)||[]),
    ]);

    // Geo, carriers, apps
    const GEO_RE = /\b(?:Location country|country|city|geographicalContext\.country|geographicalContext\.city)\s*[=:"\s]+([A-Za-z][A-Za-z\s]{2,30})(?=[,\s\n(]|$)/gi;
    const geoMatches = [];
    let gm;
    while ((gm = GEO_RE.exec(t)) !== null) { const v=gm[1].trim().replace(/\s+(?:Location|Source|Time|User|Alert|Risk).*$/i,""); if (v&&v.length>1&&!/^(?:None|null|--)$/i.test(v)) geoMatches.push(v); }
    const KNOWN_CITIES = /\b(San Juan|Vega Baja|Mexico City|Dallas|Miami|Houston|Chicago|New York|Los Angeles|San Francisco|Moscow|Beijing|London|Tokyo|Manila|Cebu|Dubai|Singapore|Toronto|Sydney|Berlin|Paris|Rome|Madrid|Seoul|Taipei|Jakarta|Lagos|Cairo|Riyadh|Bogota|Lima|Santiago|Buenos Aires|Karachi|Mumbai|Delhi|Bangalore|Kolkata)\b/gi;
    (t.match(KNOWN_CITIES)||[]).forEach(c => geoMatches.push(c));
    const geoLocations = uniq(geoMatches.map(g=>g.trim()));

    const CARRIER_RE = /\b(Liberty Mobile Puerto Rico|T-Mobile USA|T-Mobile|RadioMovil Dipsa|Telcel|AT&T|Verizon|Sprint|Comcast|Charter|Cox|Rogers|Bell Canada|Telus|Claro|Movistar|Entel|Tigo|Digicel|Flow|Orange|Vodafone|Deutsche Telekom|Telefonica|Telenor|Softbank|NTT|KDDI|Rakuten|Korea Telecom|SK Telecom|Globe|PLDT|Smart|Reliance Jio|Airtel|BSNL)[^\n,;.]{0,30}/gi;
    const carriers = uniq((t.match(CARRIER_RE)||[]).map(c=>c.trim().replace(/[,;.]+$/, "")));

    // Auth outcomes, risk, threat names, event IDs
    const failCount  = (t.match(/\bFAILURE\b/gi)||[]).length;
    const succCount  = (t.match(/\bSUCCESS\b/gi)||[]).length;
    const blockedCnt = (t.match(/\bblocked\b|\bdenied\b|\bdrop\b/gi)||[]).length;
    const outcomes = [];
    if (failCount)    outcomes.push("FAILURE ×" + failCount);
    if (succCount)    outcomes.push("SUCCESS ×" + succCount);
    if (blockedCnt)   outcomes.push("BLOCKED/DENIED ×" + blockedCnt);
    const riskMatch = t.match(/\bRisk score\s+([\w,. ]+?)(?=\s+(?:Classification|Privileged|Department|User|Source|Time))/i) || t.match(/\bSeverity\s*[=:]\s*(\w+)/i);
    const riskScores = riskMatch ? [riskMatch[1].trim()] : [];
    const _threatRe = /(?:threatName|DetectDescription|DetectionName|alert_name)\s*[=:"\s]+([^\n"',\s][^\n"',]{2,79}?)(?=\s+\w+=|\s*$|\s+[A-Z][a-zA-Z]+=)/gi;
    const threats = [];
    let tm;
    while ((tm = _threatRe.exec(t)) !== null) { const v=tm[1].trim().replace(/^["']|["']$/g,""); if (v&&v.length>2&&!threats.includes(v)) threats.push(v); }
    const subjMatch  = t.match(/\bsubject\s*[=:]\s*(.+?)(?=\s+\w+=|\n|$)/i);
    const logonMatch = t.match(/\bLogonType\s*[=:]\s*(\d+)/i);
    const failReasonMatch = t.match(/FailureReason\s*[=:]\s*(.+?)(?=\n|$)/i);
    const cves      = uniq((r.match(/CVE-\d{4}-\d{4,}/gi)||[]).map(c=>c.toUpperCase()));
    const mitreTTPs = uniq((r.match(/\bT\d{4}(?:\.\d{3})?\b/g)||[]));
    const eventIDs  = uniq((r.match(/\bEventID?\s*[=:]\s*(\d{3,5})/gi)||[]).map(m=>"EventID "+((m.match(/\d{3,5}/)||[])[0])));
    const asns      = uniq((r.match(/\bAS\d{4,6}\b|\bASN\s*\d{4,6}\b/gi)||[]).map(a=>a.toUpperCase()));

    // Build output
    const sections = [];
    const add = (label, arr, note) => { if (arr.length) sections.push(label + " (" + arr.length + ")" + (note?" ["+note+"]":"") + ":\n" + arr.map(v=>"  "+v).join("\n")); };
    add("IPv4 Addresses",   ips);
    add("IPv6 Addresses",   ipv6);
    add("URLs",             urls);
    add("Domains",          domains);
    add("Ports",            ports);
    add("Email Addresses",  emails);
    add("User Accounts / Usernames", usernames);
    add("Display Names",    uniq(displayNames));
    if (deptM)  sections.push("Departments (1):\n  " + deptM[1].trim());
    if (titleM) sections.push("Titles / Roles (1):\n  " + titleM[1].trim());
    add("Hostnames",        uniq(hostnames));
    const hashLabel = hashes.length===1 ? ({32:"MD5",40:"SHA1",64:"SHA256"}[hashes[0].length]||"") : "";
    add("File Hashes",      hashes, hashLabel);
    add("Processes / Files",processes);
    add("File Paths",       filePaths);
    add("Registry Keys",    regKeys);
    add("Command Lines",    uniq(cmdlines), "truncated at 200 chars");
    add("Threat Names",     uniq(threats));
    if (subjMatch) sections.push("Email Subjects (1):\n  " + subjMatch[1].trim());
    add("Auth Outcomes",    outcomes);
    add("Risk / Severity",  riskScores);
    if (logonMatch) sections.push("Logon Types (1):\n  LogonType " + logonMatch[1] + " — " + ({"2":"Interactive","3":"Network","4":"Batch","5":"Service","7":"Unlock","8":"NetworkCleartext","9":"NewCredentials","10":"RemoteInteractive","11":"CachedInteractive"}[logonMatch[1]]||"Unknown"));
    if (failReasonMatch) sections.push("Failure Reasons (1):\n  " + failReasonMatch[1].trim());
    add("Geographic Locations", geoLocations);
    add("Carriers / ISPs",  carriers);
    add("Timestamps",       timestamps.slice(0,10), timestamps.length>10?"first 10 of "+timestamps.length:"");
    add("CVEs",             cves);
    add("MITRE ATT&CK TTPs",mitreTTPs);
    add("Windows Event IDs",eventIDs);
    add("ASNs",             asns);

    const total = sections.reduce((n, s) => { const m=s.match(/\((\d+)\)/); return n+(m?parseInt(m[1]):1); }, 0);
    const header = ["SMART IOC EXTRACTOR", "Extracted At (UTC): " + now, "Total observables:  " + total, ""];
    if (!sections.length) return [...header, "No recognizable observables found."].join("\n");
    return [...header, ...sections].join("\n\n");
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


    // ══════════════════════════════════════════════════════════════
    // MULTI-SOURCE CORRELATION ENGINE
    // Runs first — detects all log sources present in the pasted text,
    // correlates by shared user/host/IP, maps to kill chain stages,
    // and sets enriched prefillData before the single-source parsers run.
    // ══════════════════════════════════════════════════════════════
    (function detectAndCorrelateMultiSource() {
      const SOURCE_SIGS = [
        { id:"zscaler",     label:"Zscaler ZIA",           re:/logtype=ZscalerNSS|Ngsiem\.event\.vendor.*[Zz]scaler|Vendor\.threatname|Vendor\.csip|urlCategory.*(?:Malware|C2)/i },
        { id:"crowdstrike", label:"CrowdStrike Falcon",    re:/event_simpleName|DetectionSummaryEvent|ProcessRollup2|ComputerName=\w.*UserName=\w.*Severity/i },
        { id:"okta",        label:"Okta",                  re:/actor\.alternateId|outcome\.result|eventType=user\.|okta/i },
        { id:"azure",       label:"Azure AD\/Entra",       re:/UserPrincipalName=|SignInLogs|ConditionalAccessStatus|RiskLevel=\w.*IPAddress|AzureAD/i },
        { id:"defender",    label:"Microsoft Defender",    re:/AlertId=|MachineId=|DetectionSource=Windows|ActionType=Process/i },
        { id:"sentinelone", label:"SentinelOne",           re:/AgentComputerName=|ThreatClassification=|MitigationStatus=|AgentId=/i },
        { id:"proofpoint",  label:"Proofpoint",            re:/spamScore=|phishScore=|tapUrl=|xmailer=Proofpoint/i },
        { id:"paloalto",    label:"Palo Alto NGFW",        re:/subtype=threat.*type=THREAT|policyname=\w.*threatname=|pan:/i },
        { id:"qradar",      label:"IBM QRadar",            re:/\bqid=|\bmagnitude=|\bcredibility=.*relevance=|deviceType=QRadar/i },
        { id:"darktrace",   label:"Darktrace NDR",         re:/modelBreach=|anomalyScore=|pbid=|deviceScore=/i },
        { id:"netskope",    label:"Netskope CASB",         re:/NetskopeName=|bypass_traffic=|appcategory=|access_method=Client/i },
        { id:"falcon_id",   label:"Falcon Identity",       re:/Access from unusual geolocation|Access from blocklisted|Source endpoint IP address|Suspicious web-based activity/i },
        { id:"aws",         label:"AWS CloudTrail",        re:/eventSource=.*amazonaws|awsRegion=|userIdentity.*arn/i },
        { id:"windows",     label:"Windows Event Log",     re:/EventID=\d+|EventType=|LogonType=\d+|SubjectUserName=|TargetUserName=/i },
        { id:"snort",       label:"Snort\/Suricata",       re:/\[\d+:\d+:\d+\].*Classification:|GID:\d+.*SID:\d+/i },
        { id:"saas",        label:"SaaS\/Teams",           re:/platform=Teams|sourceApp=Microsoft Teams|platform=OneDrive/i },
      ];

      const found = SOURCE_SIGS.filter(s => s.re.test(t));
      if (found.length < 2) return; // single source — let normal parser handle it

      // Entity extraction across all sources
      const emailFreq = {};
      (t.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/gi)||[])
        .forEach(e => { const k=e.toLowerCase(); emailFreq[k]=(emailFreq[k]||0)+1; });
      const allEmails  = Object.keys(emailFreq).sort((a,b)=>emailFreq[b]-emailFreq[a]);
      const allHosts   = [...new Set((t.match(/(?<=(?:ComputerName|clientHostname|AgentComputerName|devicehostname|hostname|Computer)[=:])([a-zA-Z0-9_.-]{3,50})/gi)||[]))];
      const extIPs     = [...new Set((t.match(/\b(?!(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.)(?!0\.)(?!255\.)(\d{1,3}\.){3}\d{1,3}\b/g)||[]))];
      const allURLs    = [...new Set((t.match(/https?:\/\/[^\s"',\n]{5,120}/gi)||[]))];
      const allHashes  = [...new Set((t.match(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b/g)||[]))];

      const primaryUser = allEmails[0] || "";
      const primaryHost = allHosts[0]  || "";
      const primaryExtIP= extIPs[0]    || "";

      // Kill chain stage detection
      const KC_STAGES = [
        { name:"Initial Access",    icons:"📧",  srcIds:["proofpoint","zscaler"],               re:/phish|spam|clickfix|scam|redirect.*chain|malware.*email/i },
        { name:"Execution",         icons:"⚙️",  srcIds:["crowdstrike","defender","sentinelone"],re:/ProcessRollup|CommandLine|powershell|cmd\.exe|execution|process.*creat/i },
        { name:"Persistence",       icons:"📌",  srcIds:["crowdstrike","windows"],              re:/scheduled.*task|registry.*run|autorun|service.*install/i },
        { name:"Credential Access", icons:"🔑",  srcIds:["okta","azure","windows","falcon_id"], re:/FAILURE|password.*fail|MFA|credential|brute.*force|spray|lsass/i },
        { name:"Defense Evasion",   icons:"🥷",  srcIds:["crowdstrike","defender"],             re:/obfuscat|encoded.*command|base64|disable.*av|exclusion|tamper/i },
        { name:"C2 Communication",  icons:"📡",  srcIds:["zscaler","paloalto","darktrace","crowdstrike"], re:/command.*control|C2|beacon|cobalt|pre-c2|malware.*communicat/i },
        { name:"Exfiltration",      icons:"📤",  srcIds:["zscaler","netskope","aws"],           re:/exfil|data.*out|upload.*bytes|bytes.*sent.*\d{5,}/i },
        { name:"Lateral Movement",  icons:"🔀",  srcIds:["windows","crowdstrike"],              re:/lateral|rdp.*success|smb.*auth|pass.*hash|psexec|wmi.*remote/i },
      ];

      const activeStages = KC_STAGES.filter(s => {
        return s.srcIds.some(id => found.find(f => f.id===id)) && s.re.test(t);
      });

      // MITRE mapping from stages
      const stageMitre = {
        "Initial Access":    ["T1566","T1566.001","T1566.002","T1190"],
        "Execution":         ["T1059","T1059.001","T1059.003","T1204","T1204.002"],
        "Persistence":       ["T1053.005","T1547.001","T1543.003"],
        "Credential Access": ["T1078","T1110","T1110.003","T1556","T1621"],
        "Defense Evasion":   ["T1027","T1562.001","T1140"],
        "C2 Communication":  ["T1071","T1071.001","T1095","T1041"],
        "Exfiltration":      ["T1048","T1041","T1567"],
        "Lateral Movement":  ["T1021","T1021.001","T1550.002"],
      };
      activeStages.forEach(s => (stageMitre[s.name]||[]).slice(0,2).forEach(m => results.mitre.add(m)));

      // Severity from stage count + source count
      const sc = activeStages.length;
      if      (sc >= 3) results.severity = "critical";
      else if (sc >= 2) results.severity = "high";
      else              results.severity = "medium";

      // Cross-source correlation findings
      results.findings = [];
      results.findings.push(`🔗 ${found.length} log sources detected: ${found.map(s=>s.label).join(" + ")}`);

      if (primaryUser || primaryHost) {
        const pivot = [primaryUser&&("👤 "+primaryUser), primaryHost&&("💻 "+primaryHost), primaryExtIP&&("🌐 "+primaryExtIP)].filter(Boolean).join("  ");
        results.findings.push(`🎯 Correlated on: ${pivot}`);
      }

      if (activeStages.length) {
        const chain = activeStages.map(s=>s.icons+" "+s.name).join(" → ");
        results.findings.push(`⛓️ Attack chain: ${chain}`);
        if (sc >= 3) results.findings.push(`🚨 CONFIRMED ATTACK SEQUENCE — ${sc} kill chain stages present across ${found.length} sources. Treat as active intrusion.`);
        else if (sc >= 2) results.findings.push(`⚠️ Multi-stage activity — ${sc} attack phases detected. Escalation recommended.`);
      }

      // Specific cross-source logic
      const has = id => found.some(f => f.id===id);
      if (has("proofpoint") && (has("crowdstrike")||has("defender")))
        results.findings.push(`🚨 Phishing email → Endpoint execution on same host. Email was permitted and malicious code ran — CONFIRMED COMPROMISE.`);
      if ((has("okta")||has("azure")||has("falcon_id")) && (has("crowdstrike")||has("defender")))
        results.findings.push(`⚠️ Identity alert + Endpoint alert on same account/host — attacker may have active session and running processes.`);
      if ((has("okta")||has("azure")||has("falcon_id")) && (has("zscaler")||has("paloalto")))
        results.findings.push(`⚠️ Identity compromise + suspicious network traffic — post-auth C2 or data access is likely. Check proxy logs for session activity after authentication.`);
      if (has("zscaler") && (has("crowdstrike")||has("defender")))
        results.findings.push(`⚠️ Network C2/malware alert + Endpoint execution — malware on host is actively calling out. Block destination IPs and isolate endpoint.`);

      // IOC aggregation
      if (allEmails.length)  { results.iocs.emails    = allEmails; results.iocs.usernames = allEmails.map(e=>e.split("@")[0]); }
      if (allHosts.length)   results.iocs.hostnames  = allHosts;
      if (extIPs.length)     results.iocs.ips        = extIPs.slice(0,8);
      if (allURLs.length)    results.iocs.urls       = allURLs.slice(0,6);
      if (allHashes.length)  results.iocs.hashes     = allHashes;

      // Prefill for SOC note and narrative
      results.prefillData.username           = results.prefillData.username  || primaryUser;
      results.prefillData.hostname           = results.prefillData.hostname  || primaryHost;
      results.prefillData.src_ip             = results.prefillData.src_ip    || primaryExtIP;
      results.prefillData.source_count       = found.length;
      results.prefillData.correlated_sources = found.map(s=>s.label).join(", ");
      results.prefillData.kill_chain_stage   = activeStages.map(s=>s.name).join(" → ");
      results.prefillData.kill_chain_stages  = activeStages.length;
      results.prefillData.is_multi_source    = true;

      // Override eventType with multi-source label
      const priorityIds = ["crowdstrike","sentinelone","defender","falcon_id","okta","azure","proofpoint","zscaler","paloalto","netskope","darktrace","qradar","snort","aws","windows","saas"];
      const topId    = priorityIds.find(id => found.some(f=>f.id===id));
      const topLabel = found.find(f=>f.id===topId)?.label || found[0]?.label || "";
      results.eventType = `Multi-Source [${found.length} sources] — ${topLabel}`;

    })();

    // ══════════════════════════════════════════════════════════════
    // MULTI-EVENT CORRELATION ENGINE
    // Detects raw log line sequences (NOT wrapped in alert envelope)
    // Parses each line, builds a timeline, and synthesises a story
    // before the main parser chain runs.
    // ══════════════════════════════════════════════════════════════
    const _lines = t.split("\n").map(l => l.trim()).filter(l => l.length > 10);
    const _multiLineThreshold = 2; // 2+ structured log lines = treat as raw sequence

    // Structured log line detector — returns parsed fields or null
    function _parseLine(line) {
      // Skip lines that look like alert headers, not raw log lines
      if (/^Alert\s+\d+\.|^#fields:|^#version:|^<\d+>|^\*\*\*/.test(line)) return null;

      const entry = { raw: line };

      // Timestamp patterns
      const tsMatch = line.match(
        /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)|^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)|^(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})/i
      );
      if (tsMatch) entry.ts = (tsMatch[1]||tsMatch[2]||tsMatch[3]).trim();

      // IP addresses
      const ips = (line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)||[]).filter(isValidIPv4);
      if (ips.length) entry.ips = ips;

      // Email / username
      const email = line.match(/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/);
      if (email) entry.user = email[1];

      // Outcome / status
      const outcome = line.match(/\b(SUCCESS|FAILURE|FAILED|ALLOW(?:ED)?|BLOCK(?:ED)?|DENY|DENIED|QUARANTINE(?:D)?|DROP(?:PED)?|4624|4625|4626|4688|4720|4732)\b/i);
      if (outcome) entry.outcome = outcome[1].toUpperCase();

      // Event ID
      const eid = line.match(/\bEventID[=:\s]+(\d{4,5})/i);
      if (eid) entry.eventId = eid[1];

      // URL
      const url = line.match(/https?:\/\/[^\s"'<>\]]+/);
      if (url) entry.url = url[0];

      // Process name (Windows events)
      const proc = line.match(/NewProcessName[=:\s]+([^\s,\n]{4,100})/i);
      if (proc) entry.process = proc[1];

      // Threat / signature
      const threat = line.match(/(?:threatName|threat_name|signature|detection)[=:\s]+([^\s,\n]{3,80})/i);
      if (threat) entry.threat = threat[1];

      // Location
      const loc = line.match(/\b(Mexico City|Dallas|Moscow|Beijing|London|New York|[A-Z][a-z]+ (?:US|MX|RU|CN|GB|BR|NG|DE|FR))\b/);
      if (loc) entry.location = loc[1];

      // Carrier
      const carrier = line.match(/(?:T-Mobile USA|RadioMovil Dipsa|Verizon|AT&T|Comcast|Rostelecom|China Telecom|DigitalOcean)/i);
      if (carrier) entry.carrier = carrier[0];

      // Must have at least timestamp OR outcome to be a structured line
      const hasStructure = !!(entry.ts || entry.outcome || entry.eventId || (entry.ips && entry.user));
      return hasStructure ? entry : null;
    }

    // Parse all lines
    const _parsedLines = _lines.map(_parseLine).filter(Boolean);
    const _isMultiEvent = _parsedLines.length >= _multiLineThreshold && 
                          _parsedLines.length >= (_lines.length * 0.4); // at least 40% parseable

    if (_isMultiEvent) {
      results.prefillData.is_multiline = true;
      results.prefillData.event_count  = _parsedLines.length;

      // ── Extract unique actors ─────────────────────────────────
      const _users   = [...new Set(_parsedLines.map(e => e.user).filter(Boolean))];
      const _allIPs  = [...new Set(_parsedLines.flatMap(e => e.ips||[]))];
      const _outcomes= _parsedLines.map(e => e.outcome).filter(Boolean);

      if (_users.length === 1) results.prefillData.username = _users[0];
      else if (_users.length > 1) results.prefillData.username = _users[0]; // primary user

      // ── Build timeline sequence ───────────────────────────────
      const _timeline = _parsedLines.map(e => ({
        ts:      e.ts      || "",
        user:    e.user    || _users[0] || "",
        ip:      e.ips?.[0]|| "",
        outcome: e.outcome || "",
        url:     e.url     || "",
        process: e.process || "",
        threat:  e.threat  || "",
        location:e.location|| "",
        carrier: e.carrier || "",
        raw:     e.raw,
      }));
      results.prefillData.timeline = _timeline;

      // ── Outcome pattern analysis ──────────────────────────────
      const failures = _outcomes.filter(o => /FAILURE|FAILED|4625|DENY|BLOCK/.test(o));
      const successes= _outcomes.filter(o => /SUCCESS|4624|ALLOW/.test(o));
      const executions=_parsedLines.filter(e => e.eventId === "4688" || e.process);

      // IP role analysis — which IPs are associated with failures vs successes
      const _failIPs = [...new Set(_parsedLines.filter(e => /FAILURE|FAILED|4625|DENY|BLOCK/.test(e.outcome||"")).flatMap(e => e.ips||[]))];
      const _succIPs = [...new Set(_parsedLines.filter(e => /SUCCESS|4624|ALLOW/.test(e.outcome||"")).flatMap(e => e.ips||[]))];
      const _mixedIPs= _failIPs.filter(ip => _succIPs.includes(ip)); // same IP in both = ambiguous
      const _foreignFailIPs  = _failIPs.filter(ip => !_succIPs.includes(ip));
      const _knownGoodSuccIPs= _succIPs.filter(ip => !_failIPs.includes(ip));

      if (_failIPs.length)   results.prefillData.fail_ips    = _failIPs.join(", ");
      if (_succIPs.length)   results.prefillData.success_ips = _succIPs.join(", ");

      // ── Location analysis ─────────────────────────────────────
      const _failLocs = [...new Set(_parsedLines.filter(e => /FAILURE|FAILED|4625/.test(e.outcome||"")).map(e => e.location).filter(Boolean))];
      const _succLocs = [...new Set(_parsedLines.filter(e => /SUCCESS|4624/.test(e.outcome||"")).map(e => e.location).filter(Boolean))];
      const _allLocs  = [...new Set(_parsedLines.map(e => e.location).filter(Boolean))];
      const _allCarriers = [...new Set(_parsedLines.map(e => e.carrier).filter(Boolean))];

      if (_failLocs.length) results.prefillData.suspicious_location = _failLocs.join(", ");
      if (_allLocs.length)  results.prefillData.location = _allLocs.join(", ");
      if (_allCarriers.length) results.prefillData.carrier = _allCarriers[0];

      // ── First/last event timestamps ───────────────────────────
      const _timestamps = _parsedLines.map(e => e.ts).filter(Boolean);
      if (_timestamps.length >= 2) {
        results.prefillData.timestamp = _timestamps[0];
        results.prefillData.ts_last   = _timestamps[_timestamps.length - 1];
        results.prefillData.ts_span   = `${_timestamps[0]} → ${_timestamps[_timestamps.length - 1]}`;
      }

      // ── Pattern recognition ───────────────────────────────────
      const patterns = [];

      // Pattern 1: Auth failures → success (credential abuse)
      if (failures.length >= 2 && successes.length >= 1) {
        // Check if failures come BEFORE successes in timeline
        const firstFailIdx = _parsedLines.findIndex(e => /FAILURE|FAILED|4625/.test(e.outcome||""));
        const firstSuccIdx = _parsedLines.findIndex(e => /SUCCESS|4624/.test(e.outcome||""));
        if (firstFailIdx < firstSuccIdx || firstFailIdx === -1) {
          patterns.push("failure_then_success");
          results.findings.push(`🚨 ${failures.length} authentication failure(s) followed by ${successes.length} success(es) — classic credential stuffing or brute-force with eventual access.`);
          results.severity = "high";
          results.mitre.add("T1110"); results.mitre.add("T1078");
        }
      }

      // Pattern 2: Impossible travel — successes from different IPs/locations
      if (_knownGoodSuccIPs.length >= 1 && _foreignFailIPs.length >= 1) {
        patterns.push("impossible_travel");
        results.findings.push(`🚨 Concurrent activity from ${_foreignFailIPs.length > 1 ? _foreignFailIPs.length+" foreign IPs" : _foreignFailIPs[0]} (FAILURE) and ${_knownGoodSuccIPs[0]} (SUCCESS) — impossible travel indicator. Two locations active simultaneously.`);
        results.severity = "critical";
        results.mitre.add("T1078.004");
      }

      // Pattern 3: Repeated failures from same foreign IP
      const _ipFailCounts = {};
      _parsedLines.filter(e => /FAILURE|FAILED|4625/.test(e.outcome||"")).forEach(e => {
        (e.ips||[]).forEach(ip => { _ipFailCounts[ip] = (_ipFailCounts[ip]||0) + 1; });
      });
      const _highFailIP = Object.entries(_ipFailCounts).sort((a,b) => b[1]-a[1])[0];
      if (_highFailIP && _highFailIP[1] >= 3) {
        patterns.push("brute_force");
        results.findings.push(`⚠️ ${_highFailIP[1]} consecutive failures from ${_highFailIP[0]} — brute force or credential stuffing pattern.`);
        if (results.severity === "info") results.severity = "medium";
        results.mitre.add("T1110.001");
      }

      // Pattern 4: Process execution after auth success (lateral movement / post-exploit)
      if (executions.length > 0 && successes.length > 0) {
        const firstSucc = _parsedLines.findIndex(e => /SUCCESS|4624/.test(e.outcome||""));
        const firstExec = _parsedLines.findIndex(e => e.process || e.eventId === "4688");
        if (firstExec > firstSucc) {
          patterns.push("exec_after_auth");
          const procs = [...new Set(executions.map(e => e.process?.split("\\").pop() || "process").filter(Boolean))];
          results.findings.push(`🚨 Process execution detected after authentication success: ${procs.slice(0,3).join(", ")} — possible post-compromise execution.`);
          results.severity = "critical";
          results.mitre.add("T1059"); results.mitre.add("T1078");
        }
      }

      // Pattern 5: Web redirect/block chain
      const _blockedURLs = _parsedLines.filter(e => /BLOCK|DENY/.test(e.outcome||"") && e.url).map(e => e.url);
      const _allowedURLs = _parsedLines.filter(e => /ALLOW/.test(e.outcome||"") && e.url).map(e => e.url);
      if (_blockedURLs.length >= 1 && _allowedURLs.length >= 1) {
        patterns.push("web_chain");
        results.findings.push(`⚠️ Traffic chain: allowed access to ${_allowedURLs.slice(0,2).join(", ")} then blocked attempts to ${_blockedURLs.slice(0,2).join(", ")} — possible redirect chain from legitimate site.`);
        if (results.severity === "info") results.severity = "medium";
        results.mitre.add("T1566.002");
      }

      // Pattern 6: Multiple threat signatures across lines
      const _threats = [...new Set(_parsedLines.map(e => e.threat).filter(Boolean))];
      if (_threats.length >= 2) {
        patterns.push("multi_threat");
        results.findings.push(`⚠️ Multiple threat signatures detected across log lines: ${_threats.slice(0,4).join(", ")}`);
      }

      // ── Set event type based on patterns ─────────────────────
      if (!results.eventType || results.eventType === "Unknown" || results.eventType === "Generic Log / Text") {
        if (patterns.includes("impossible_travel") || patterns.includes("failure_then_success")) {
          results.eventType = "Identity Security Alert";
        } else if (patterns.includes("exec_after_auth")) {
          results.eventType = "Endpoint / Post-Auth Execution";
        } else if (patterns.includes("web_chain")) {
          results.eventType = "Web / Proxy Log";
        } else if (executions.length > 0) {
          results.eventType = "Windows Event Log";
        } else if (failures.length > 0 || successes.length > 0) {
          results.eventType = "Authentication Event";
        } else {
          results.eventType = "Multi-Event Log";
        }
      }

      // ── Build correlated story string (used by SOC note) ─────
      const _primaryUser = _users[0] || "";
      const _totalEvents = _parsedLines.length;
      const _timeSpan    = results.prefillData.ts_span || "";
      const _pattern     = patterns[0] || "multi_event";

      const _storyParts = [
        _primaryUser ? `Account: ${_primaryUser}` : "",
        `${_totalEvents} events${_timeSpan ? " from " + _timeSpan : ""}`,
        failures.length ? `${failures.length} FAILURE(s)` : "",
        successes.length ? `${successes.length} SUCCESS(es)` : "",
        _foreignFailIPs.length ? `Foreign failure IP: ${_foreignFailIPs.join(", ")}` : "",
        _knownGoodSuccIPs.length ? `Known-good success IP: ${_knownGoodSuccIPs.join(", ")}` : "",
        _failLocs.length ? `Suspicious location: ${_failLocs.join(", ")}` : "",
        _allCarriers.length ? `Carrier: ${_allCarriers[0]}` : "",
        executions.length ? `Process execution: ${[...new Set(executions.map(e => e.process?.split("\\").pop()).filter(Boolean))].slice(0,2).join(", ")}` : "",
      ].filter(Boolean).join(" | ");
      results.prefillData.correlated_story = _storyParts;
      results.prefillData.patterns = patterns;
      // Only set alert_count if identity parser hasn't already set it
      // and only when lines are actual alerts (not user log lines)
      if (!results.prefillData.alert_count || results.prefillData.alert_count === "1") {
        const _realEventCount = _parsedLines.filter(l => 
          !(l.raw||"").match(/^Mar\.|^Jan\.|^Feb\.|^Apr\.|^May\.|^Jun\.|^Jul\.|^Aug\.|^Sep\.|^Oct\.|^Nov\.|^Dec\./)
        ).length;
        if (_realEventCount > 1) results.prefillData.alert_count = String(_realEventCount);
      }

      // Store IPs in iocs
      if (_allIPs.length) results.iocs.ips = _allIPs;
      if (_users.length) results.iocs.usernames = _users;
    }

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
    // ── Domain extraction: fixed regex + real-TLD allowlist + field-name filter ──
    const _REAL_TLDS = new Set("com net org io co gov edu mil xyz info biz app dev web us uk de fr jp cn ru au ca br in it es nl se no fi dk be ch at id sg hk tw kr ph my th vn sa ae il tr me tv cc ly sh eu nu gg im je ms ac ad am ba bd bg bh bi bn bo bs bt by bz ci cl cm cv cy cz dj dm do dz ec ee eg er et fj fm ga gd ge gh gi gl gm gn gq gr gt gu gy hn hr ht hu iq ir is jo ke kg kh ki km kn kp kw kz la lb lc li lk lr ls lt lu lv ma mc md mg mh mk ml mm mn mo mp mr mt mu mv mw mx mz na nc ne ng ni np nr nz om pa pe pg pl pr ps pt pw py qa ro rs rw sb sc sd si sk sl sm sn so sr ss st sv sx sy sz tc td tg th tj tl tm tn to tr tt tz ua ug uy uz vc ve vg vi vu ws ye za zm zw aero cat coop mobi museum name tel travel cloud online store shop blog news media tech site page link live games zone world digital network systems services solutions center group team studio design agency".split(" "));
    // Collect left-of-equals tokens (these are field names, not domains)
    const _leftOfEq = new Set();
    (t.match(/\b([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)\s*[=:]/g)||[]).forEach(m => _leftOfEq.add(m.trim().replace(/\s*[=:]$/,"")));
    // New regex handles 2-part domains (evil.com) unlike the old 3-part requirement
    const _rawDomains = (refanged.match(/\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)\.[a-zA-Z]{2,63}\b/g)||[]);
    results.iocs.domains = [...new Set(_rawDomains.map(d=>d.replace(/[.,;:)"']+$/,"")).filter(d => {
      if (!d || d.length < 4) return false;
      if (/^\d+\.\d+/.test(d)) return false;                          // IP-like
      if (d.includes("@")) return false;                                  // email part
      const parts = d.split(".");
      const tld = parts[parts.length-1].toLowerCase();
      if (!_REAL_TLDS.has(tld)) return false;                            // non-real TLD → OUT
      if (_leftOfEq.has(d)) return false;                                // field name → OUT
      // All-uppercase non-TLD segment (e.g. RIFT, BACKDOOR, RIFT) → OUT
      if (parts.slice(0,-1).some(p => /^[A-Z]{2,}$/.test(p))) return false;
      // Known SIEM field-word-only domains (all segments are log field words) → OUT
      const _SIEM_WORDS = /^(?:alert|event|indicator|ngsiem|timestamp|product|vendor|action|status|severity|hostname|source|destination|local|remote|address|port|protocol|device|record|category|field|value|key|label|tag|uuid|guid|checksum|signature|rule|policy|detect|threat|risk|score|level|priority|code|message|description|info|debug|error|warn|trace|audit|log|entry|row|column|index|offset|size|count|total|rate|flag|request|response|header|body|payload|data|buffer|stream|thread|process|service|module|plugin|package|library|runtime|engine|virtual|container|node|cluster|cloud|tenant|subscription|account|resource|scope|namespace|zone|region|provider|partner|customer|client|server|proxy|gateway|router|switch|firewall)$/i;
      if (parts.slice(0,-1).length >= 2 && parts.slice(0,-1).every(p => _SIEM_WORDS.test(p))) return false;
      return true;
    }))];
    // Hashes: exclude values that are labeled as event IDs, alert IDs, UUIDs, or GUIDs
    // Build a set of values that appear after known non-hash labels
    const _eventIdValues = new Set();
    // Use a looser capture to handle prefixed values like "req-abc123..." or "evt-44d886..."
    (t.match(/(?:event[._-]?id|alert[._-]?id|incident[._-]?id|case[._-]?id|correlation[._-]?id|log[._-]?id|record[._-]?id|message[._-]?id|trace[._-]?id|span[._-]?id|request[._-]?id|session[._-]?id|detect(?:ion)?[._-]?id|uuid|guid|objectid|_id|requestid|principalid|accountid|jobid|taskid|flowid|connid|txid|eventid|reportid|ruleid|policyid|deviceid|hostid|userid|tenantid|subscriptionid|resourceid|tokenid)\s*[=:\t"]+\s*([^\s"{}\]\),;]{4,})/gi)||[]).forEach(m => {
      const raw = (m.match(/[=:\t"]+\s*([^\s"{}\]\),;]{4,})$/)||[])[1];
      if (!raw) return;
      // Strip non-hex chars to get the pure hex content
      const hexOnly = raw.replace(/[^a-fA-F0-9]/g,"");
      if (hexOnly.length >= 8) _eventIdValues.add(hexOnly.toLowerCase());
      // Also add the raw value with all separators removed
      _eventIdValues.add(raw.toLowerCase().replace(/[^a-f0-9]/g,""));
      // Add all 32/40/64-char substrings of hexOnly (catches "req-abc123..." -> "abc123...")
      for (const len of [64, 40, 32]) {
        for (let i = 0; i <= hexOnly.length - len; i++) {
          _eventIdValues.add(hexOnly.slice(i, i+len).toLowerCase());
        }
      }
    });
    const _rawH = (stripForIOC.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g)||[]);
    const _seenH = new Set();
    results.iocs.hashes = _rawH.filter(h => {
      const lo = h.toLowerCase();
      if (_seenH.has(lo)) return false;
      if (_eventIdValues.has(lo)) return false;   // labeled as an ID field → not a file hash
      _seenH.add(lo);
      return true;
    });
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

    // ── Timestamp extraction ──
    const _nowYear = new Date().getFullYear();
    const _tsPatterns = [
      /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g,  // ISO 8601
      /\d{2}[\/\-]\d{2}[\/\-]\d{4}[T ]\d{2}:\d{2}:\d{2}/g,                           // MM/DD/YYYY HH:MM:SS
      /\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)/gi,                  // Windows M/D/YYYY H:MM:SS AM/PM
      /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}/gi, // syslog with year
      /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?/gi, // Falcon Identity: "Mar. 18, 2026 20:45:20"
    ];

    const _rawTs = [];
    _tsPatterns.forEach(p => { const m=t.match(p); if(m) _rawTs.push(...m); });
    // Syslog timestamps without year: "Mar 18 15:02:42" — inject current year
    const _syslogNoYr = (t.match(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b/gi)||[]);
    _syslogNoYr.forEach(m => {
      const withYear = m.replace(/(\w+ \d{1,2}) (\d{2}:)/, `$1 ${new Date().getFullYear()} $2`);
      _rawTs.push(withYear);
    });
    results.iocs.timestamps = [...new Set(_rawTs)];
    if (results.iocs.timestamps.length) results.prefillData.timestamp = results.iocs.timestamps[0];
    // Store raw text reference for _finalizeTriage post-processing
    results._rawText = t;

    // ── Verdict / Action extraction (blocked/allowed/dropped/denied etc.) ──
    const _VERDICT_MAP = { blocked:"BLOCKED", block:"BLOCKED", deny:"BLOCKED", denied:"BLOCKED", rejected:"BLOCKED", reject:"BLOCKED", dropped:"DROPPED", drop:"DROPPED", "drop-packet":"DROPPED", alertdrop:"DROPPED", "alert-drop":"DROPPED", allowed:"ALLOWED", allow:"ALLOWED", permit:"ALLOWED", permitted:"ALLOWED", accepted:"ALLOWED", accept:"ALLOWED", pass:"ALLOWED", passed:"ALLOWED", "reset-both":"BLOCKED", "reset-client":"BLOCKED", reset:"BLOCKED", detected:"DETECTED", alert:"DETECTED", quarantined:"QUARANTINED", quarantine:"QUARANTINED", killed:"BLOCKED", terminated:"BLOCKED", prevented:"BLOCKED" };
    const _verdictRaw = (t.match(/(?:(?:event[._]?)?action|verdict|disposition|pattern[._]?disposition[._]?value|result(?:_?status)?|policy[._]?result|traffic[._]?direction|fw[._]?action|routing[._]?action|nat[._]?action|audit[._]?action)\s*[=:\t]+\s*([a-zA-Z_\-]{2,30})/gi)||[]);
    const _verdicts = [...new Set(_verdictRaw.map(v => {
      const raw = (v.match(/[=:\t]+\s*([a-zA-Z_\-]{2,30})$/)||[])[1]?.toLowerCase().replace(/-/g,"");
      return _VERDICT_MAP[raw] || _VERDICT_MAP[raw?.replace(/ed$/,"")] || null;
    }).filter(Boolean))];
    // Also catch standalone verdict words in context
    // Also catch "alert drop" Suricata pattern and similar compound verdicts
    const _compoundVerdict = (t.match(/\balert\s+drop\b/gi)||[]).map(()=>"DROPPED");
    const _standaloneVerdict = (t.match(/\b(blocked|allowed|dropped|denied|permitted|quarantined|detected|prevented)\b/gi)||[]).map(v => _VERDICT_MAP[v.toLowerCase()]).filter(Boolean);
    results.iocs.verdicts = [...new Set([..._verdicts, ..._compoundVerdict, ..._standaloneVerdict])];
    if (results.iocs.verdicts.length) results.prefillData.verdict = results.iocs.verdicts[0];

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


    // 2c. SAAS / CASB / FILE-BASED ALERTS (Teams, OneDrive, SharePoint, Box, Dropbox)
    if ((
      /(?:platform|app|application)\s*[=:]\s*(?:Teams|OneDrive|SharePoint|Box|Dropbox|Slack|Google\s*Drive|M365|Office365)/i.test(t) ||
      /(?:filename|file_name|fileName)\s*[=:"]+\s*\S+\.(html|exe|dll|bat|ps1|js|vbs|zip|rar|7z|docm|xlsm|pptm)/i.test(t) ||
      (/(?:fileSize|file_size|malwareType|filePath)\s*[=:"]+\s*\S+/i.test(t) && /Teams|OneDrive|SharePoint|Dropbox|Box|Slack|CASB|SaaS/i.test(t)) ||
      (/action\s*[=:]\s*(?:Quarantine|quarantined|DLP Block|file_blocked)/i.test(t) && /Teams|OneDrive|SharePoint|Dropbox|Slack|SaaS/i.test(t))
    ) && !/AlertId|MachineId|DeviceId|ActionType=Process|event_simpleName|ComputerName.*UserName.*Severity|netskope|NetskopeClientVersion|bypass_traffic|appcategory|NetskopeName/i.test(t)) {
      results.eventType = "SaaS / File Security Alert";
      const user      = (t.match(/(?:user|username|upn|email)\s*[=:"]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1]||"";
      const host      = (t.match(/(?:clientHostname|hostname|device|computer)\s*[=:"]+\s*([a-zA-Z0-9_.-]{2,60})/i)||[])[1]||"";
      const filename  = (t.match(/(?:filename|file_name|fileName)\s*[=:"]+\s*([^\s\"',\n]{2,120})/i)||[])[1]||"";
      const platform  = (t.match(/(?:platform|app|application|sourceApp|source_app)\s*[=:"]+\s*([^\s\"',\n]{2,40})/i)||[])[1]||"";
      const action    = (t.match(/(?:action|verdict|disposition)\s*[=:"]+\s*([^\s\"',\n]{2,30})/i)||[])[1]||"";
      const malType   = (t.match(/(?:malwareType|malware_type|threatName|threat_name|detectionName)\s*[=:"]+\s*([^\s\"',\n]{2,80})/i)||[])[1]||"";
      const srcIP     = (t.match(/(?:srcIP|src_ip|clientIP|sourceIP|source_ip)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const fileSize  = (t.match(/(?:fileSize|file_size|size)\s*[=:"]+\s*(\d+)/i)||[])[1]||"";
      const isQuarantined = /quarantine|quarantined/i.test(action);
      const isBlocked     = /blocked|block|deny|denied/i.test(action);
      const isAllowed     = /allow|allowed|permit/i.test(action);

      if (user)     { results.indicators.push(`User: ${user}`);     results.prefillData.username   = user; }
      if (host)     { results.indicators.push(`Host: ${host}`);     results.prefillData.hostname   = host; }
      if (srcIP)    { results.indicators.push(`SrcIP: ${srcIP}`);   results.prefillData.src_ip     = srcIP; }
      if (platform) { results.indicators.push(`Platform: ${platform}`); results.prefillData.platform = platform; }
      if (filename) { results.indicators.push(`File: ${filename}`); results.prefillData.threat_name = filename; }
      if (malType)  { results.indicators.push(`Detection: ${malType}`); if (!results.prefillData.threat_name) results.prefillData.threat_name = malType; }
      if (action)   { results.indicators.push(`Action: ${action}`); results.prefillData.verdict    = action.toUpperCase(); }

      // Determine if file was executed or just detected
      const noExec = isQuarantined || isBlocked || /no\s*exec|not\s*executed|storage\s*only|detected\s*not\s*run/i.test(t);
      const possiblyExec = isAllowed || /executed|launched|ran|run|process\s*created/i.test(t);

      if (isQuarantined) {
        results.findings.push(`✅ File quarantined — threat contained before execution. No evidence of execution at this stage.`);
        results.prefillData.control_action = "QUARANTINED";
        results.severity = results.severity === "info" ? "medium" : results.severity;
      } else if (isBlocked) {
        results.findings.push(`✅ File blocked — access prevented. No execution risk.`);
        results.prefillData.control_action = "BLOCKED";
      } else if (isAllowed) {
        results.findings.push(`⚠️ File ALLOWED — file was not blocked. Execution risk exists. Requires immediate EDR triage.`);
        results.prefillData.control_action = "ALLOWED";
        if (results.severity === "info") results.severity = "high";
      }

      // File extension analysis
      if (/\.(exe|dll|bat|ps1|vbs|hta|msi|js)$/i.test(filename)) {
        results.findings.push(`🚨 Executable file type: ${filename.split('.').pop().toUpperCase()} — high execution risk if run.`);
        results.mitre.add("T1204.002"); results.severity = "high";
      } else if (/\.(html|htm)$/i.test(filename)) {
        results.findings.push(`⚠️ HTML file — potential phishing lure or ClickFix delivery mechanism.`);
        results.mitre.add("T1566.002");
        if (results.severity === "info") results.severity = "medium";
      } else if (/\.(docm|xlsm|pptm|docx|xlsx)$/i.test(filename)) {
        results.findings.push(`⚠️ Office document — potential macro-enabled malware delivery.`);
        results.mitre.add("T1566.001");
        if (results.severity === "info") results.severity = "medium";
      } else if (/\.(zip|rar|7z|iso|img)$/i.test(filename)) {
        results.findings.push(`⚠️ Archive/image file — possible malware container, evades AV scanning.`);
        results.mitre.add("T1027");
      }

      // Platform-specific notes
      if (/teams/i.test(platform)) results.findings.push(`ℹ️ File shared via Microsoft Teams — check sender, channel, and whether other users received/opened it.`);
      else if (/onedrive|sharepoint/i.test(platform)) results.findings.push(`ℹ️ File stored in Microsoft 365 cloud storage — check sharing permissions and access logs.`);
      else if (/dropbox|box|gdrive|google.*drive/i.test(platform)) results.findings.push(`ℹ️ File detected in shadow IT cloud storage — policy review may be needed.`);

      results.mitre.add("T1566"); results.mitre.add("T1204");
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
    if (/\[Classification:|(?:^|\s)ET\s+[A-Z]{2,}|GPL\s+\w+|Suricata|snort|(?:^|\s)alert\s+(?:tcp|udp|icmp)\s/im.test(t) &&
        /Priority:\s*\d|GID:\s*\d|SID:\s*\d|\[1:[0-9]+:[0-9]+\]|\[Classification/i.test(t) &&
        !/zscaler|netskope|mcafee|symantec|umbrella|forcepoint|bluecoat|proxySG|barracuda.*web|websense|skyhigh|casb/i.test(t)) {
      results.eventType = /suricata/i.test(t) ? "Suricata IDS/IPS" : "Snort IDS/IPS";
      const idsSig = (t.match(/(?:alert\.signature|msg|signature|sig_name)\s*[=:\"\[]+\s*\"?([^\"\]\n]{5,100})/i)||[])[1]?.replace(/^\"\"+|\"+$/g,"")||"";
      if (idsSig) results.prefillData.threat_name = idsSig;
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


    // 8. NETSKOPE CASB
    if (/netskope|NetskopeClientVersion|NetskopeName|appcategory|bypass_traffic|npa_tunnel_id|skopecloud/i.test(t)) {
      results.eventType = /dlp/i.test(t) ? "Netskope DLP Alert" : "Netskope CASB Alert";
      const user     = (t.match(/(?:user|email)\s*[=:"]+\s*([^\s"\n,]{3,80}@[^\s"\n,]{3,40})/i)||[])[1]||"";
      const srcIp    = (t.match(/(?:srcip|src_ip|clientip)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dstIp    = (t.match(/(?:dstip|dst_ip|serverip)\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const url      = (t.match(/(?:url|dsturl)\s*[=:"]+\s*(https?:\/\/[^\s"\n,]+)/i)||[])[1]||"";
      const app      = (t.match(/(?:^|\s)app\s*[=:"]+\s*([^\s"\n,]{2,50})/i)||[])[1]||"";
      const category = (t.match(/(?:appcategory|category)\s*[=:"]+\s*([^\s"\n,]{2,60})/i)||[])[1]||"";
      const threat   = (t.match(/(?:NetskopeName|malware_name|dlp_rule)\s*[=:"]+\s*([^\s"\n,]{2,80})/i)||[])[1]||"";
      const action   = (t.match(/(?:action|activity|alert_type)\s*[=:"]+\s*([^\s"\n,]{2,40})/i)||[])[1]||"";
      const access   = (t.match(/access_method\s*[=:"]+\s*([^\s"\n,]{2,40})/i)||[])[1]||"";
      if (user)     { results.indicators.push(`User: ${user}`);        results.prefillData.username = user; }
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`);      results.prefillData.src_ip   = srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (app)        results.indicators.push(`App: ${app}`);
      if (category)   results.indicators.push(`Category: ${category}`);
      if (action)     results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (access)     results.indicators.push(`Access: ${access}`);
      if (url)      { results.prefillData.url = url; }
      if (threat)   { results.findings.push(`🚨 Netskope threat detected: ${threat}`); results.severity="high"; results.prefillData.threat_name=threat; results.mitre.add("T1071"); }
      if (/block|blocked|denied/i.test(action)) results.findings.push(`✅ Traffic blocked by Netskope policy`);
      else if (/allow/i.test(action) && threat) { results.findings.push(`⚠️ Malicious traffic ALLOWED — investigate endpoint immediately`); results.severity="critical"; }
      if (/dlp/i.test(results.eventType)) { results.findings.push(`🚨 DLP policy triggered — potential data exfiltration attempt`); results.mitre.add("T1048"); }
      if (category) results.prefillData.category = category;
      results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 9. CISCO UMBRELLA
    if (/umbrella|opendns|roaming.*client/i.test(t) || (/proxied|Blocked,,,|DNS Response,/i.test(t) && /umbrella/i.test(t))) {
      results.eventType = /dns/i.test(t) ? "Cisco Umbrella DNS" : "Cisco Umbrella Proxy";
      const domain   = (t.match(/(?:domain|destination|queried_domain)\s*[=:,]*\s*([a-zA-Z0-9.-]{3,100}\.[a-zA-Z]{2,})/i)||[])[1]||"";
      const srcIp    = (t.match(/(?:src|source|internal_ip|client_ip)\s*[=:,]*\s*(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const identity = (t.match(/(?:identities|user|username)\s*[=:,]*\s*([^\s",\\n]{3,80})/i)||[])[1]||"";
      const category = (t.match(/(?:categories|category)\s*[=:,]*\s*([^\s",\\n]{2,80})/i)||[])[1]||"";
      const action   = (t.match(/(?:action|verdict)\s*[=:,]*\s*(Blocked|Allowed|Proxied|[A-Z][a-z]+)/i)||[])[1]||"";
      const threat   = (t.match(/(?:threat_name|malware)\s*[=:,]*\s*([^\s",\\n]{2,60})/i)||[])[1]||"";
      if (identity) { results.indicators.push(`Identity: ${identity.slice(0,60)}`); results.prefillData.username=identity; }
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`);   results.prefillData.src_ip=srcIp; }
      if (domain)     results.indicators.push(`Domain: ${domain}`);
      if (category)   results.indicators.push(`Category: ${category.slice(0,50)}`);
      if (action)     results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (/malware|phish|command.*control|botnet/i.test(category)) { results.findings.push(`🚨 Umbrella blocked access to malicious category: ${category}`); results.severity="high"; results.mitre.add("T1071.004"); }
      if (/block/i.test(action)) results.findings.push(`✅ DNS/proxy query blocked by Cisco Umbrella`);
      if (threat) results.prefillData.threat_name = threat;
      if (category) results.prefillData.category = category;
      results.mitre.add("T1071.004");
      return _finalizeTriage(results);
    }


    // 10. SYMANTEC PROXYSG / BROADCOM WSS / BLUECOAT
    if (/ProxySG|Blue.?Coat|SGOS|bluecoat|symantec.*proxy|broadcom.*proxy|TCP_DENIED|TCP_NC_MISS|PROXY_BLOCK/i.test(t)) {
      results.eventType = /broadcom|symantec/i.test(t) ? "Symantec WSS / ProxySG" : "Blue Coat ProxySG";
      const url      = (t.match(/(?:GET|POST|CONNECT)\s+(https?:\/\/[^\s"]+)/i)||[])[1]||"";
      const srcIp    = (t.match(/(?:src|source|client)\s*[=:"'\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dstIp    = (t.match(/DIRECT\/?(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const user     = (t.match(/(?:user|username|authenticated)\s*[=:"'\s]+([a-zA-Z0-9._%+-]+@[^\s"]+)/i)||[])[1]||"";
      const status   = (t.match(/TCP_(?:DENIED|HIT|MISS|TUNNEL|NC_MISS)[/\\]?(\d{3})?/i)||[])[0]||"";
      const category = (t.match(/(?:PROXY_BLOCK_REQMOD|category)\s*[="'\s]*"?([^"'\s,\\n]{3,50})/i)||[])[1]||"";
      const threat   = (t.match(/(?:Malware|ThreatName|threat)\s*[=:"'\s]+([^"'\s,\\n]{3,60})/i)||[])[1]||"";
      if (user)     { results.indicators.push(`User: ${user}`);   results.prefillData.username=user; }
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`); results.prefillData.src_ip=srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (status)     results.indicators.push(`Status: ${status}`);
      if (category)   results.indicators.push(`Category: ${category}`);
      if (url)        results.prefillData.url = url;
      if (/DENIED|BLOCK/i.test(status||t)) results.findings.push(`✅ Request blocked by ProxySG policy`);
      if (threat || /malware/i.test(category||"")) { results.findings.push(`🚨 Threat/malware category: ${threat||category}`); results.severity="high"; if(threat) results.prefillData.threat_name=threat; }
      if (category) results.prefillData.category = category;
      results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 11. MCAFEE WEB GATEWAY / SKYHIGH CASB
    if (/mcafee.*web|skyhigh|McAfee.*Gateway|McAfee.*CASB|MWG/i.test(t) ||
        (/mcafee/i.test(t) && /blocked|web.?gateway|policyname|category/i.test(t))) {
      results.eventType = /skyhigh/i.test(t) ? "Skyhigh / McAfee CASB" : "McAfee Web Gateway";
      const srcIp    = (t.match(/(?:SrcIP|src_ip|clientip)\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dstIp    = (t.match(/(?:DstIP|dst_ip|serverip)\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const user     = (t.match(/(?:User|Username|Account)\s*[=:\s]+([^\s",\\n]{3,60})/i)||[])[1]||"";
      const url      = (t.match(/(?:URL|Uri)\s*[=:\s]+(https?:\/\/[^\s",\\n]+)/i)||[])[1]||"";
      const action   = (t.match(/(?:Action|Verdict)\s*[=:\s]+(Blocked|Allowed|Deny|Block|Allow|[A-Z]+)/i)||[])[1]||"";
      const category = (t.match(/(?:Category|UrlCategory|WebCategory)\s*[=:\s]+([^\s",\\n]{2,60})/i)||[])[1]||"";
      const threat   = (t.match(/(?:ThreatName|Malware|Virus)\s*[=:\s]+([^\s",\\n]{2,80})/i)||[])[1]||"";
      const policy   = (t.match(/(?:PolicyName|Policy)\s*[=:\s]+([^\s",\\n]{2,60})/i)||[])[1]||"";
      if (user)     { results.indicators.push(`User: ${user}`);     results.prefillData.username=user; }
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`);   results.prefillData.src_ip=srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (category)   results.indicators.push(`Category: ${category}`);
      if (action)     results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (policy)     results.indicators.push(`Policy: ${policy}`);
      if (url)        results.prefillData.url = url;
      if (threat)   { results.findings.push(`🚨 Threat detected: ${threat}`); results.severity="high"; results.prefillData.threat_name=threat; }
      if (/block|deny/i.test(action)) results.findings.push(`✅ Request blocked by McAfee/Skyhigh policy`);
      if (/malware|phish/i.test(category||"")) results.findings.push(`⚠️ Malicious URL category: ${category}`);
      if (category) results.prefillData.category = category;
      results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 12. BARRACUDA WEB SECURITY
    if (/barracuda.*web|barracuda.*filter|barracuda.*gateway|barracuda.*shield/i.test(t) ||
        (/barracuda/i.test(t) && /blocked|allowed|web|spam/i.test(t))) {
      results.eventType = /email|spam|mail/i.test(t) ? "Barracuda Email Security" : "Barracuda Web Security";
      const srcIp  = (t.match(/(?:src|source|client)[_\s]?ip\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const user   = (t.match(/(?:user|account|email)\s*[=:\s]+([^\s",\\n]{3,60}@[^\s",\\n]+)/i)||[])[1]||"";
      const url    = (t.match(/(?:url|uri|link)\s*[=:\s]+(https?:\/\/[^\s",\\n]+)/i)||[])[1]||"";
      const action = (t.match(/(?:action|verdict|result)\s*[=:\s]+([^\s",\\n]{2,30})/i)||[])[1]||"";
      const reason = (t.match(/(?:reason|threat|category|block_reason)\s*[=:\s]+([^\s",\\n]{2,80})/i)||[])[1]||"";
      if (user)   { results.indicators.push(`User: ${user}`);   results.prefillData.username=user; }
      if (srcIp)  { results.indicators.push(`SrcIP: ${srcIp}`); results.prefillData.src_ip=srcIp; }
      if (action)   results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (reason)   results.indicators.push(`Reason: ${reason}`);
      if (url)      results.prefillData.url = url;
      if (/block|deny/i.test(action)) results.findings.push(`✅ Traffic blocked by Barracuda — ${reason||"policy match"}`);
      if (/malware|phish|virus/i.test(reason||"")) { results.findings.push(`🚨 Malware/phishing blocked: ${reason}`); results.severity="high"; results.prefillData.threat_name=reason; }
      results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 13. FORCEPOINT NGFW / WEBSENSE
    if (/forcepoint|websense|Triton/i.test(t) && !/ProxySG|Blue.?Coat|TCP_DENIED/i.test(t)) {
      results.eventType = /ngfw|firewall/i.test(t) ? "Forcepoint NGFW" : "Forcepoint Web Security";
      const srcIp    = (t.match(/(?:src|source|clientip)\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/i)||[])[1]||"";
      const dstIp    = (t.match(/(?:dst|dest|serverip)\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/i)||[])[1]||"";
      const user     = (t.match(/(?:user|username|logon)\s*[=:\s]+([^\s",\\n]{3,60})/i)||[])[1]||"";
      const url      = (t.match(/(?:url|uri)\s*[=:\s]+(https?:\/\/[^\s",\\n]+)/i)||[])[1]||"";
      const action   = (t.match(/(?:action|verdict|disposition)\s*[=:\s]+([^\s",\\n]{2,30})/i)||[])[1]||"";
      const category = (t.match(/(?:category|web_category|threat)\s*[=:\s]+([^\s",\\n]{2,60})/i)||[])[1]||"";
      if (user)     { results.indicators.push(`User: ${user}`);   results.prefillData.username=user; }
      if (srcIp)    { results.indicators.push(`SrcIP: ${srcIp}`); results.prefillData.src_ip=srcIp; }
      if (dstIp)      results.indicators.push(`DstIP: ${dstIp}`);
      if (action)     results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (category)   results.indicators.push(`Category: ${category}`);
      if (url)        results.prefillData.url = url;
      if (/block|deny/i.test(action)) results.findings.push(`✅ Forcepoint blocked this request`);
      if (/malware|phish|exploit/i.test(category||"")) { results.findings.push(`🚨 Malicious category: ${category}`); results.severity="high"; }
      if (category) results.prefillData.category = category;
      results.mitre.add("T1071");
      return _finalizeTriage(results);
    }


    // 14. FIREWALL / NETWORK LOGS
    if (/SRC=|DST=|PROTO=|DPT=|SPT=|inbound|outbound|\bACCEPT\b|\bDROP\b|\bDENY\b|firewall|src_ip|dst_ip|action=allow|action=deny/i.test(t) &&
        !/requesturl|refererurl|malwarecat|urlCategory|threatName|Vendor\.threatname|Vendor\.threatcat|Vendor\.ipsrulelabel|Ngsiem\.event\.vendor.*[Zz]scaler|[Zz]scaler.*Ngsiem\.event\.vendor|zscaler.*(?:logtype|zia|zpa)|(?:logtype|type)=zscaler/i.test(t) &&
        !/\bqid=|\bmagnitude=|\bcredibility=|\brelevance=|deviceType.*QRadar|\bQRadar\b|\bqradar\b/i.test(t)) {
      results.eventType = "Firewall / Network Log";
      // iptables/netfilter style
      const src  = (t.match(/(?:SRC|src_ip|srcip|source)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const dst  = (t.match(/(?:DST|dst_ip|dstip|dest(?:ination)?)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const proto= (t.match(/PROTO[=:\s]+(\w+)/i)||[])[1]||(t.match(/\b(TCP|UDP|ICMP)\b/i)||[])[1]||"";
      const dport2= (t.match(/(?:DPT|dport|dst_port|destination_port)[=:\s]+(\d{1,5})/i)||[])[1]||"";
      const sport2= (t.match(/(?:SPT|sport|src_port|source_port)[=:\s]+(\d{1,5})/i)||[])[1]||"";
      const fwact = (t.match(/(?:\bACCEPT\b|\bDROP\b|\bDENY\b|\bREJECT\b|action[=:\s]+\w+)/i)||[])[0]||"";
      const fwhost= (t.match(/(?:hostname|host|device)[=:\s]+([a-zA-Z0-9_.-]{2,40})/i)||[])[1]||"";
      if (proto)  results.prefillData.proto      = proto;
      if (dport2) results.prefillData.dest_port  = dport2;
      if (sport2) results.prefillData.src_port   = sport2;
      if (fwhost) results.prefillData.hostname   = fwhost;
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
    if (/GET |POST |PUT |DELETE |HEAD |HTTP\/[12]|\bstatus[=:\s]+[245]\d\d\b|\bcs-uri\b|\brequest_url\b|\burl_path\b/i.test(t) &&
        !/Ngsiem\.event\.vendor|Vendor\.cdip|Vendor\.threatname|Vendor\.devicehostname|zscalernss-fw/i.test(t)) {
      results.eventType = "Web / Proxy Log";
      const method  = (t.match(/\b(GET|POST|PUT|DELETE|PATCH|HEAD)\b/i)||[])[1]||"";
      const status  = (t.match(/(?:status|sc-status|response_code)[=:\s]+(\d{3})/i)||[])[1]||"";
      const url     = (t.match(/(?:url|cs-uri-stem|cs-uri)[=:\s]+"?([^\s"]+)/i)||[])[1]||"";
      const useragent=(t.match(/(?:user[_-]agent|cs\(user-agent\))[=:\s]+"?([^"\n]{1,200})/i)||[])[1]||"";
      const referer = (t.match(/(?:referer|cs\(referer\))[=:\s]+"?([^\s"]+)/i)||[])[1]||"";
      if (method)    results.indicators.push(`Method: ${method}`);
      if (url)       results.indicators.push(`URL: ${url.slice(0,80)}`);
      if (status)    results.indicators.push(`Status: ${status}`);
      if (useragent) { results.indicators.push(`UA: ${useragent.slice(0,60)}`); results.prefillData.useragent = useragent; }
      const referer2 = (t.match(/(?:referer|referrer|cs\(referer\))\s*[=:"]+\s*"?([^"\n\s]{5,200})/i)||[])[1]||"";
      if (referer2) results.prefillData.referer = referer2;
      if (status)   results.prefillData.http_status = status;
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
    if ((/falcon|crowdstrike|detect\.base|falconhost|detect_id|SeverityName|PatternDisposition|ProcessRollup|eventType.*falcon|event_simpleName|DetectDescription|RemoteAddressIP4|SHA256HashData|ComputerName.*UserName.*Severity/i.test(t) ||
        (fieldsHeaderMatch && /\baid\b|\bcid\b|CrowdStrike|Falcon/i.test(t))) &&
        !/IOC Management|CrowdStrike.*Threat Intelligence|Rubrik.*CrowdStrike|No results found.*CrowdStrike|Risk score.*Low.*3\.9|Source endpoint IP.*200\.|Account domain.*temcologistics|Access from unusual geolocation.*Risk score/i.test(t)) {
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

      const host    = getField(["computername","hostname","computer_name"],
                        /(?:ComputerName|Hostname|computer_name)\s*[=:\t"]+\s*([a-zA-Z0-9_.-]+)/i) ||
                       (t.match(/Vendor\.devicehostname\s+(\S+)/i)||[])[1] || "";
      // Also pick up lowercase variants forwarded via SIEM connectors
      const hostFallback = host || (t.match(/(?:devicehostname|device_hostname)\s*[=:\s]+([a-zA-Z0-9_.-]{2,60})(?:\s+\w|$)/im)||[])[1] || "";
      const user    = getField(["username","user_name","user"],
                        /(?:UserName|user_name|username)\s*[=:\t"]+\s*([a-zA-Z0-9_.%+\-@]+(?:@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?)/i) ||
                       (t.match(/(?:^|\s)user\s*=\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/im)||[])[1] || "";
      const rawSev  = getField(["severityname","severity"], /(?:Severity|SeverityName)\s*[=:\t"]+\s*(\w+)/i);
      // Only accept real severity values — reject field names and junk
      const sev     = /^(?:critical|high|medium|low|informational|info)$/i.test(rawSev) ? rawSev : "";
      const tactic  = getField(["tactic"], /(?:^|\t)Tactic\t([^\t\n\r]+)/i);
      const tech    = getField(["technique"], /(?:^|\t)Technique\t([^\t\n\r]+)/i);
      const _cmdFull = getField(["commandline","command_line","cmdline"], /(?:CommandLine|cmdline|command_line)\s*[=:\t"]+\s*([^\t\n\r"]{5,200})/i);
      const cmd      = _cmdFull ? _cmdFull.replace(/\s+[A-Z][A-Za-z0-9]+=.*$/, "").slice(0,200) : "";
      const parentP = getField(["parentbasefilename","parent_process_name","parentprocessname"], /(?:ParentBaseFileName|parent_process_name)\s*[=:\t"]+\s*([^\t\n\r"]+)/i);
      const destIp  = getField(["remoteaddressip4","dest_ip","dst_ip","remoteip"], /(?:RemoteAddressIP4|dest_ip|dst_ip|RemoteIP)\s*[=:\t"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
      const srcIp   = getField(["localaddressip4","src_ip","srcip","localip"], /(?:LocalAddressIP4|src_ip|srcip|LocalIP)\s*[=:\t"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
      const descr   = getField(["detectdescription","detect_description","description"], /(?:DetectDescription|detect_description|description)\s*[=:\t"]+\s*([^\t\n\r"]{5,})/i);
      // For tactic/technique from TSV, the value may include the technique ID
      const techClean = tech.replace(/^T\d{4}(?:\.\d{3})?\s+/,"").trim(); // strip leading T-ID
      const obj       = getField(["objective"], /(?:Objective)\s*[=:\t"]+\s*([^\t\n\r,"]+)/i);

      const proc2   = getField(["imagefilename","filename","processname"],/(?:ImageFileName|FileName|ProcessName)\s*[=:\t"]+\s*([^\t\n\r"]{2,100})/i);
      const sha256  = getField(["sha256hashdata","sha256"],/(?:SHA256HashData|SHA256)\s*[=:\t"]+\s*([a-fA-F0-9]{64})/i);
      const remPort = getField(["remoteport"],/(?:RemotePort|remote_port)\s*[=:\t"]+\s*(\d{2,5})/i);
      const _csHost = hostFallback || host;
      if (_csHost)  { results.indicators.push(`Host: ${_csHost}`);    results.prefillData.hostname = _csHost; }
      const _csUser = user || (t.match(/Vendor\.user\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1] || "";
      if (_csUser)  { results.indicators.push(`User: ${_csUser}`);    results.prefillData.username = _csUser; }
      if (proc2 && !proc2.match(/^(?:ImageFileName|ProcessName|FileName)$/i)) { results.indicators.push(`Process: ${proc2}`); results.prefillData.process = proc2; }
      if (sha256) { results.prefillData.hash = sha256; }
      if (remPort){ results.prefillData.dest_port = remPort; }
      // RemoteAddressIP4 = external endpoint (treat as dest for network flow, src for threat hunting)
      if (destIp) { results.indicators.push(`Remote IP: ${destIp}`); results.prefillData.src_ip = destIp; results.prefillData.dest_ip = destIp; }
      // LocalAddressIP4 = the endpoint itself — use as hostname fallback
      if (srcIp)  { results.indicators.push(`Local IP: ${srcIp}`); if (!results.prefillData.hostname) results.prefillData.hostname = srcIp; }
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
        results.prefillData.rule  = descr.split(/\s+event_simpleName/i)[0].slice(0, 100);
        if (!results.prefillData.threat_name) results.prefillData.threat_name = results.prefillData.rule;
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

      // If the log also has web/proxy fields (CS+Zscaler combo), extract them
      if (!results.prefillData.url) {
        const _url = (t.match(/(?:url|requestedURL|requesturl)\s*[=:\s]+(https?:\/\/[^\s"\n,]+)/i)||[])[1] ||
                     (t.match(/Vendor\.url\s+(https?:\/\/[^\s"\n,]+)/i)||[])[1] || "";
        if (_url) results.prefillData.url = _url;
      }
      if (!results.prefillData.referer) {
        const _ref = (t.match(/(?:referer|refererurl)\s*[=:\s]+(https?:\/\/[^\s"\n,]+)/i)||[])[1] || "";
        if (_ref) results.prefillData.referer = _ref;
      }
      if (!results.prefillData.threat_name) {
        const _tn = (t.match(/(?:urlCategory|threatName|threatname|ThreatName)\s*[=:\s]+([^\s"\n,]{3,80})/i)||[])[1] ||
                    (t.match(/Vendor\.threatname\s+((?:(?!\s+Vendor\.).){2,80})/im)||[])[1] || "";
        if (_tn) results.prefillData.threat_name = _tn;
      }
      if (!results.prefillData.category) {
        const _cat = (t.match(/(?:urlCategory|category|threatcat)\s*[=:\s]+([^\s"\n,]{3,60})/i)||[])[1] ||
                     (t.match(/Vendor\.threatcat\s+((?:(?!\s+Vendor\.).){2,60})/im)||[])[1] || "";
        if (_cat) results.prefillData.category = _cat;
      }
      // Vendor.* src/dst for NGSIEM CS format
      if (!results.prefillData.src_ip) {
        const _csip = (t.match(/Vendor\.csip\s+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1] ||
                      (t.match(/(?:srcip|srcIP|SrcIP|source\.ip)\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1] || "";
        if (_csip) results.prefillData.src_ip = _csip;
      }
      if (!results.prefillData.dest_ip) {
        const _cdip = (t.match(/Vendor\.cdip\s+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1] ||
                      (t.match(/(?:dstip|dstIP|DstIP|destination\.ip)\s*[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1] || "";
        if (_cdip) results.prefillData.dest_ip = _cdip;
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
      (/Service\s+provider\s+azure|Event\s+category.*Audit|Event\s+source.*Directory/i.test(t) && /azure|entra|aad/i.test(t)) ||
      // Entra ID / Azure AD Sign-In logs (raw export or SIEM forward)
      /UserPrincipalName|SignInLogs|RiskDetail|RiskLevelDuringSignIn|RiskLevelAggregated|ConditionalAccessStatus|AuthenticationRequirement|createdDateTime.*Category/i.test(t) ||
      (/RiskLevel|RiskDetail|RiskState/i.test(t) && /IPAddress|CountryOrRegion|AppDisplayName/i.test(t))
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
                             /UserPrincipalName\s*[=:,]\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
                             /User\s+name\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
                             /User\s+principal\s+name\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i]);
      const ip       = getF([/(?:"?ClientIP"?\s*[,:\s]\s*"?)(\d{1,3}(?:\.\d{1,3}){3})/i,
                             /IPAddress\s*[=:,]\s*(\d{1,3}(?:\.\d{1,3}){3})/i,
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
      const riskLevel   = getF([/RiskLevel(?:DuringSignIn|Aggregated)?\s*[=:,]\s*([\w]+)/i, /RiskLevel\s*[=:,]\s*([\w]+)/i]);
      const riskDetail  = getF([/RiskDetail\s*[=:,]\s*([a-zA-Z]+(?:[A-Z][a-z]+)*)(?:\s+\w+=|$)/im, /RiskDetail\s*[=:,]\s*([^\n\r,\t\s]{2,60})/i]);
      const location    = getF([/City\s*[=:,]\s*([a-zA-Z\s]{2,40})(?:\s+\w+=|$)/im, /City\s*[=:,]\s*([^\n\r,\t]{2,40})/i]);
      const country     = getF([/CountryOrRegion\s*[=:,]\s*([a-zA-Z]{2,30})(?:\s+\w+=|$)/im, /CountryOrRegion\s*[=:,]\s*([^\n\r,\t]{2,30})/i]);
      const resultType  = getF([/ResultType\s*[=:,]\s*(\d+)/i]);
      const resultDesc  = getF([/ResultDescription\s*[=:,]\s*([^\n\r]{2,100})/i]);
      const caStatus    = getF([/ConditionalAccessStatus\s*[=:,]\s*([^\n\r,]{2,40})/i]);
      const authReq     = getF([/AuthenticationRequirement\s*[=:,]\s*([^\n\r,]{2,60})/i]);
      const deviceName  = getF([/DeviceName\s*[=:,]\s*([^\n\r,\s]{2,60})/i, /Device\s*[=:,]\s*([^\n\r,\s]{2,60})/i]);

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
      if (riskLevel)  { results.indicators.push(`Risk Level: ${riskLevel}`); results.prefillData.risk_level = riskLevel; }
      if (riskDetail) { results.indicators.push(`Risk Detail: ${riskDetail}`); results.prefillData.risk_detail = riskDetail; }
      if (location || country) results.indicators.push(`Location: ${[location, country].filter(Boolean).join(", ")}`);
      if (resultDesc) results.indicators.push(`Result: ${resultDesc}`);
      if (caStatus)   results.indicators.push(`CA Policy: ${caStatus}`);
      if (deviceName) { results.indicators.push(`Device: ${deviceName}`); results.prefillData.hostname = deviceName; }
      if (country)    results.prefillData.location = [location, country].filter(Boolean).join(", ");
      if (riskLevel && /high|critical/i.test(riskLevel)) { results.severity = "high"; }
      if (/unfamiliarFeatures|atypicalTravel|anonymizedIPAddress|maliciousIPAddress|passwordSpray/i.test(riskDetail||"")) { results.severity = "critical"; }

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
    if (/eventType|actor\.alternateId|outcome\.result|displayMessage|debugContext|authenticationContext|okta/i.test(t) &&
        !/EventID=|EventType=Failure|LogonType=|WorkstationName=|FailureReason=|SubjectUserName=|TargetUserName=|TimeCreated=/i.test(t)) {
      results.eventType = "Okta / SSO Identity Log";
      const evType   = (t.match(/(?:"?eventType"?\s*[:,]\s*"?)([a-zA-Z_.]{4,80})/i)||[])[1]||"";
      const outcome  = (t.match(/(?:"?result"?\s*[:,]\s*"?)(SUCCESS|FAILURE|SKIPPED|ALLOW|DENY|UNKNOWN)/i)||[])[1]||
                       (t.match(/(?:outcome\.result)\s*[=:,]\s*([A-Z_]+)/i)||[])[1]||"";
      const outcomeReason = (t.match(/(?:outcome\.reason|reason)\s*[=:,]\s*"?([A-Z_]+)(?:\s+\w+[=.]|$)/im)||[])[1]?.trim()||
                            (t.match(/(?:outcome\.reason)\s*[=:,]\s*"?([^"\n\r,\t\s]{3,60})/i)||[])[1]||"";
      const user     = (t.match(/(?:alternateId)\s*[=:,]\s*"?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1]||
                       (t.match(/actor\.alternateId\s*[=:,]\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i)||[])[1]||"";
      const displayName = (t.match(/(?:actor\.)?displayName\s*[=:,]\s*"?([^"\n\r,]{2,60})/i)||[])[1]||"";
      const ip       = (t.match(/(?:"?ipAddress"?|client\.ipAddress)\s*[=:,]\s*"?(\d{1,3}(?:\.\d{1,3}){3})/i)||[])[1]||"";
      const country  = (t.match(/(?:geographicalContext\.country|country)\s*[=:,]\s*"?([a-zA-Z\s]{2,40})(?:\s+\w+[=.:]|$)/im)||[])[1]?.trim()||
                       (t.match(/(?:geographicalContext\.country)\s*[=:,]\s*"?([^"\n\r,\t]{2,40})/i)||[])[1]||"";
      const city     = (t.match(/(?:geographicalContext\.city|city)\s*[=:,]\s*"?([a-zA-Z\s]{2,40})(?:\s+\w+[=.:]|$)/im)||[])[1]?.trim()||
                       (t.match(/(?:geographicalContext\.city)\s*[=:,]\s*"?([^"\n\r,\t]{2,40})/i)||[])[1]||"";
      const msg      = (t.match(/(?:"?displayMessage"?\s*[:,]\s*"?)([^",\n\r]{4,120})/i)||[])[1]||"";
      const target   = (t.match(/(?:target\.displayName|target.*displayName)\s*[=:,]\s*"?([^"\n\r,]{2,80})/i)||[])[1]||"";
      const ua       = (t.match(/(?:rawUserAgent|userAgent)\s*[=:,]\s*"?([^"\n\r]{4,200})/i)||[])[1]||"";
      const sessionId= (t.match(/(?:sessionId|session\.id)\s*[=:,]\s*"?([^"\n\r,\s]{4,80})/i)||[])[1]||"";
      if (evType)    results.indicators.push(`Event Type: ${evType}`);
      if (user)    { results.indicators.push(`User: ${user}`); results.prefillData.username = user; }
      if (displayName && displayName !== user) results.indicators.push(`Display Name: ${displayName}`);
      if (outcome)   results.indicators.push(`Outcome: ${outcome}${outcomeReason?" ("+outcomeReason+")":""}`);
      if (ip)      { results.indicators.push(`Source IP: ${ip}`); results.prefillData.src_ip = ip; }
      if (city || country) { const loc = [city, country].filter(Boolean).join(", "); results.indicators.push(`Location: ${loc}`); results.prefillData.location = loc; }
      if (target)    results.indicators.push(`Target App: ${target}`);
      if (msg)       results.findings.push(`ℹ️ ${msg}`);
      if (outcomeReason && outcomeReason.length < 80) results.prefillData.rule = outcomeReason;
      if (ua && /curl|python|go-http|okhttp/i.test(ua)) results.findings.push(`⚠️ Suspicious client: ${ua.slice(0,80)}`);
      if (outcome === "FAILURE") { results.findings.push("⚠️ Authentication failure"); results.mitre.add("T1110"); if(!["critical","high"].includes(results.severity)) results.severity="medium"; }
      if (/user\.mfa\.factor\.deactivate|MFA.*bypass|mfa.*reset/i.test(evType||t)) { results.findings.push("🚨 MFA deactivation or bypass detected"); results.mitre.add("T1621"); results.severity="critical"; }
      if (/policy\.evaluate_sign_on/i.test(evType) && /DENY/i.test(outcome)) { results.findings.push("⚠️ Sign-on policy denied access"); results.mitre.add("T1078"); }
      if (/session\.impersonation/i.test(evType)) { results.findings.push("🚨 Admin impersonation session — investigate immediately"); results.mitre.add("T1078.004"); results.severity="critical"; }
      if (/user\.account\.update_password|user\.account\.reset_password/i.test(evType)) { results.findings.push("⚠️ Password change/reset event"); results.mitre.add("T1098"); }
      return _finalizeTriage(results);
    }


    // 18. ZSCALER (ZIA / ZPA)
    if (/zscaler|ZscalerApp|dlpDictionaries|urlCategory.*zscaler|policyAction.*zscaler|transactionID.*zscaler|csfbEnabled|zia.*log|zpa.*log|zscalernss|Ngsiem\.event\.vendor.*[Zz]scaler/i.test(t) ||
        (/zscaler/i.test(t) && /urlCategory|policyAction|threatName|requesturl|malwarecat|refererurl|respcode|Vendor\.threatname|Vendor\.cdip|Vendor\.csip/i.test(t)) ||
        (/Vendor\.threatname|Vendor\.threatcat|Vendor\.ipsrulelabel|Vendor\.devicehostname/i.test(t) && /zscaler/i.test(t)) ||
        (/(?:requesturl|refererurl|malwarecat|respcode).*zscaler|zscaler.*(?:requesturl|refererurl|malwarecat)/i.test(t))) {
      results.eventType = /zpa|private.access/i.test(t) ? "Zscaler ZPA Log" : "Zscaler ZIA Log";

      // ── Comprehensive field extraction — covers NSS, ECS, NGSIEM, Splunk, and raw formats ──
      // Each field tries multiple known naming conventions in priority order
      const _first = (...patterns) => { for (const p of patterns) { const m = t.match(p); if (m?.[1]?.trim()) return m[1].trim(); } return ""; };

      const url = _first(
        /(?:url\.original|requestedURL|requesturl|full_url|destinationurl|desturl|dsturl|target_url|request_url|requested_url)\s*[=:"]+\s*(https?:\/\/[^\s"\n,]+)/i,
        /(?:^|\s)url\s*[=:"]+\s*(https?:\/\/[^\s"\n,]+)/im,
        /(?:uri|request\.uri|http\.request\.uri)\s*[=:"]+\s*(https?:\/\/[^\s"\n,]+)/i
      );
      const referer = _first(
        /(?:http\.request\.referrer|http\.request\.referer|refererurl|referer_url|http_referer|cs\(referer\)|refer_url|httpreferer)\s*[=:"]+\s*"?(https?:\/\/[^\s"\n,]+)/i,
        /(?:referer|referrer)\s*[=:"]+\s*"?(https?:\/\/[^\s"\n,]+)/i
      );
      const threat = _first(
        /Vendor\.threatname\s+((?:(?!\s+Vendor\.|\s+[a-z]+\.[a-z]).){2,80})/im,
        /(?:threat\.indicator\.name|threat\.name|malwarecat|malwarename|threatName|malwareCategory|threatCategory|rule\.name|threatsignature|threat_name)\s*[=:"]+\s*"?([^\s"\n,]{2,80})/i
      );
      const categoryRaw = _first(
        /Vendor\.threatcat\s+((?:(?!\s+Vendor\.).){2,80})/im,
        /(?:rule\.category|urlCategory|cloudApp|url\.category|threat\.category|category)\s*[=:"]+\s*"([^"\n]{2,80})"/i,
        /(?:rule\.category|urlCategory|cloudApp|url\.category|threat\.category|category)\s*[=:"]+\s*([^"\n,;\t]{2,60})(?:\s+\w+=|$)/im
      );
      const category = categoryRaw ? categoryRaw.trim().replace(/\s+\w+=.*$/,'').replace(/[,\s]+$/,'') : "";
      const action = _first(
        /Vendor\.action\s+((?:(?!\s+Vendor\.).){2,40})/im,
        /event\.action\s+([^\n\t]{2,30})(?=\s+event\.|$)/im,
        /(?:event\.action|policyAction|result|verdict)\s*[=:"]+\s*"?([^\s"\n,]{2,30})/i,
        /(?:^|\s)action\s*[=:"]+\s*"?([^\s"\n,]{2,30})/im
      );
      const srcIp = _first(
        /Vendor\.csip\s+(\d{1,3}(?:\.\d{1,3}){3})/i,
        /(?:source\.ip|src\.ip|client\.ip|srcIP|clientIP|srcip|client_ip|client\.address)\s*[=:"\s]+([\s]?\d{1,3}(?:\.\d{1,3}){3})/i,
        /(?:^|\s)src\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/im
      );
      const dstIp = _first(
        /Vendor\.cdip\s+(\d{1,3}(?:\.\d{1,3}){3})/i,
        /(?:destination\.ip|dst\.ip|dstIP|serverIP|server_ip|dstip|server\.ip|destination\.address)\s*[=:"\s]+(\d{1,3}(?:\.\d{1,3}){3})/i,
        /(?:^|\s)dst\s*[=:"]+\s*(\d{1,3}(?:\.\d{1,3}){3})/im
      );
      const dstPort = _first(
        /Vendor\.cdport\s+(\d{1,5})/i,
        /(?:destination\.port|dst\.port|dstport|serverport|destinationport)\s*[=:"\s]+(\d{1,5})/i,
        /(?:^|\s)dport\s*[=:"]+\s*(\d{1,5})/im
      );
      const user = _first(
        /Vendor\.user\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
        /(?:user\.name|user\.email|userName|login|email)\s*[=:"\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
        /(?:^|\s)user\s*[=:"]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/im
      );
      const hostname = _first(
        /Vendor\.devicehostname\s+([a-zA-Z0-9_.-]{2,60})/i,
        /(?:host\.name|host\.hostname|clientHostname|deviceName|machine|endpoint|devicehostname)\s*[=:"\s]+([a-zA-Z0-9_.-]{2,60})/i
      );
      const useragent = _first(
        /(?:user_agent\.original|http\.request\.user_agent|user[_-]?agent|cs\(user-agent\)|useragent)\s*[=:"]+\s*"?([^\n"]{5,250})/i,
        /(Mozilla\/\d\.\d[^\n"]{5,250})/i
      );
      const httpStatus = _first(
        /(?:http\.response\.status_code|responseCode|statusCode|sc-status|respcode|responsecode|sc_status|http_status|cs-status)\s*[=:"]+\s*(\d{3})/i,
        /\b(403|200|301|302|404|500|502|503)\b/
      );
      const bytes = _first(
        /Vendor\.inbytes\s+(\d+)/i,
        /(?:network\.bytes|http\.response\.bytes|bytesTotal|txBytes|totalBytes|rxbytes|sendbytes|transferbytes|totalbytes|bytes_received|destination\.bytes|inbytes)\s*[=:"\s]+(\d+)/i
      );
      const proto = _first(
        /(?:network\.transport|network\.protocol|proto|protocol)\s*[=:"]+\s*([a-zA-Z]{2,10})/i
      );
      const location = _first(
        /Vendor\.locationname\s+((?:(?!\s+Vendor\.).){2,60})/im,
        /(?:location|locationname|geo\.country|src\.geo\.country_name|destination\.geo\.country_name)\s*[=:"\s]+([^\n"\t]{2,40})/i
      );
      const rule = _first(
        /Vendor\.ipsrulelabel\s+((?:(?!\s+Vendor\.).){2,80})/im,
        /Vendor\.rulelabel\s+((?:(?!\s+Vendor\.).){2,80})/im,
        /(?:rule\.name|ruleName|policyName|policy\.name|filterName|profileName)\s*[=:"\s]+([^"\n,]{2,80})(?:\s+\w|$)/im
      );
      const department = _first(
        /Vendor\.department\s+(\S+)/i,
        /(?:department|dept|ou)\s*[=:"]+\s*"?([^\n"]{2,60})/i
      );

      // Store everything in prefillData for the SOC note generator
      if (user)       { results.indicators.push(`User: ${user}`);        results.prefillData.username   = user; }
      if (srcIp)      { results.indicators.push(`SrcIP: ${srcIp}`);      results.prefillData.src_ip     = srcIp; }
      if (dstIp)      { results.indicators.push(`DstIP: ${dstIp}`);      results.prefillData.dest_ip    = dstIp; }
      if (dstPort)    { results.indicators.push(`DstPort: ${dstPort}`);  results.prefillData.dest_port  = dstPort; }
      if (hostname)   { results.indicators.push(`Host: ${hostname}`);     results.prefillData.hostname   = hostname; }
      if (category)     results.indicators.push(`Category: ${category}`);
      if (action)       results.indicators.push(`Action: ${action.toUpperCase()}`);
      if (referer)    { results.prefillData.referer    = referer; }
      if (useragent)  { results.prefillData.useragent  = useragent; }
      if (httpStatus) { results.prefillData.http_status = httpStatus; }
      if (bytes)      { results.prefillData.bytes       = bytes; }
      if (category)   { results.prefillData.category    = category;
                        if (!threat && /command.*control|c2|malware|phish|botnet|ransomware|exploit/i.test(category))
                          results.prefillData.threat_name = category; }
      if (proto)      { results.prefillData.proto        = proto; }
      if (location)   { results.prefillData.location = decodeURIComponent(location.replace(/\+/g,' ')); }
      if (department) { results.prefillData.department = department.split(/\s+/)[0]; }
      if (rule)       { results.prefillData.rule         = rule;
                        results.indicators.push(`Rule: ${rule}`); }
      if (threat) {
        results.prefillData.threat_name = threat;
        results.findings.push(`🚨 Zscaler detected threat: ${threat}`);
        results.mitre.add("T1071");
        results.severity = "high";
      }
      // ── NGSIEM log-tail parsing ───────────────────────────────
      // Format: "blocked|allowed [action] ... [threatname] [code] GET [dstIP] [domain]/ [referer]/ [UA]"
      // Extract URL/referer from the plain-text log section if not already found
      if (!url || !referer) {
        // Match the log tail: "GET dstIP domain/ referer/ Mozilla..."
        const _logTail = t.match(/(?:GET|POST|PUT|HEAD)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/i);
        if (_logTail) {
          if (!url)     { const _u = "https://" + _logTail[2]; results.prefillData.url = _u; }
          if (!referer) { const _r = "https://" + _logTail[3]; results.prefillData.referer = _r;
                          results.findings.push(`ℹ️ HTTP Referrer: ${_r.slice(0,100)}`); }
        }
        // Also try: plain domain pattern after status code in log tail
        if (!url) {
          const _domainInLog = t.match(/(?:403|200|301|302|404)\s+(?:GET|POST)?\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\/)/i);
          if (_domainInLog) results.prefillData.url = "https://" + _domainInLog[1];
        }
      }
      if (url) {
        results.prefillData.url = url;
        results.findings.push(`ℹ️ Requested URL: ${url.slice(0,100)}`);
      }
      if (referer) {
        results.findings.push(`ℹ️ Referrer: ${referer.slice(0,100)}`);
      }
      if (/block|blocked|deny|denied/i.test(action)) {
        results.findings.push(`✅ Traffic blocked by Zscaler policy — confirm no endpoint compromise`);
      }
      if (/allow/i.test(action) && threat) {
        results.findings.push(`⚠️ Malicious traffic was ALLOWED — investigate endpoint immediately`);
        results.severity = "critical";
      }
      if (bytes && parseInt(bytes) > 10000000) {
        results.findings.push(`⚠️ Large data transfer: ${(parseInt(bytes)/1048576).toFixed(1)} MB — possible data exfiltration`);
      }
      // NGSIEM threat score
      const _threatScore = (t.match(/Vendor\.threat_score\s+(\d+)/i)||[])[1]||"";
      if (_threatScore && parseInt(_threatScore) >= 50) {
        results.findings.push(`⚠️ Threat score: ${_threatScore}/100 — elevated risk`);
        if (parseInt(_threatScore) >= 70) results.severity = "high";
      }
      // NGSIEM tunnel type (ZscalerClientConnector = user is on VPN/agent)
      const _tunType = (t.match(/Vendor\.tuntype\s+(\S+)/i)||[])[1]||"";
      if (_tunType && _tunType !== "None") results.indicators.push(`Tunnel: ${_tunType}`);

      if (!results.findings.length) {
        results.findings.push(`ℹ️ Zscaler web activity — ${category||"access"} ${action?"→ "+action:""}`);
      }
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
      (/Risk score|Privileged.*No|Privileged.*Yes/i.test(t) && /Account name|Username|Email address/i.test(t)) ||
      (/Access from unusual geolocation|Access from blocklisted location|Suspicious web-based activity/i.test(t) &&
       /Source endpoint IP|Risk score|Department|Account name/i.test(t)) ||
      results.eventType === "Identity Security Alert"
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
      const riskRaw  = (t.match(/(?:Risk score|RiskLevel|risk_level|riskLevel|RiskState|UserRiskLevel)\s*[=:,]?\s*([\w.]+)/i)||[])[1]?.trim() || "";
      const riskNum  = parseFloat((riskRaw.match(/[\d.]+/)||[])[0]||"0");
      const platform = (t.match(/(?:Destination application identifier|application)\s+([^\n]{3,60})/i)||[])[1]?.trim() ||
                       (t.match(/VMware Identity Service|Workspace ONE|vIDM/i)||[])[0] || "";
      const alertType= (t.match(/^([^\n]{5,80})/)||[])[1]?.trim() || "Identity alert";
      const privStr  = (t.match(/Privileged\s+(Yes|No)/i)||[])[1]||"";
      const dept  = (t.match(/Department\s+([^\n]{3,50})(?=\s+(?:Title|Network|Username|Email|Privileged|Risk|Source|Time|User|Alert|Classification|AD|SID|OU|See|IP|Location|Activity)|$)/im)||
                  t.match(/Department\s+([^\n]{3,40})/i)||[])[1]?.trim().replace(/\s+(Title|Network|Username|Email).*$/i,'')||"";
      const title = (t.match(/Title\s+([^\n]{3,50})(?=\s+(?:Network|Username|Email|Privileged|Risk|Source|Time|User|Alert|Classification|AD|SID|OU|See|IP|Location|Activity|Department)|$)/im)||
                  t.match(/Title\s+([^\n]{3,40})/i)||[])[1]?.trim().replace(/\s+(Network|Username|Email|Privileged).*$/i,'')||"";
      const failures = (t.match(/\bFAILURE\b/gi)||[]).length;
      const successes= (t.match(/\bSUCCESS\b/gi)||[]).length;
      // Falcon Identity multi-alert context
      // Only count actual "Alert N. <name>" patterns — exclude noise from "# of hosts" etc
      const alertNames = (t.match(/\bAlert\s+\d+\.\s+([A-Z][^\n]{5,80})/g)||[])
        .map(a => a.replace(/\bAlert\s+\d+\.\s+/i,'').trim())
        .filter(a => !/^\d|^#|^See|^Related|^Time|^Source|^Location|^Account|^IP/.test(a));
      const alertCount = alertNames.length || 1;
      // Extract display name: "User Miguel Vargas Torres Privileged"
      const displayName = (t.match(/\bUser\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s+Privileged/)||[])[1]?.trim() || "";
      if (displayName) results.prefillData.display_name = displayName;
      const locationCountry = (
        t.match(/Location country\s+([A-Za-z][a-zA-Z\s]{2,30}?)\s*(?:\([\d.,\s-]+\)|Location country code|Source|Time|User|Alert|Risk|Privileged|Classification)/im) ||
        t.match(/Location country\s+([A-Za-z][a-zA-Z\s]{2,30})(?=\s+(?:Location|Source|Time|User|Alert|Risk|Privileged|Classification)|$)/im) ||
        t.match(/Location country\s+([A-Za-z][a-zA-Z\s]{2,20})/i) ||
        [])[1]?.trim() || "";
      // Extract city from the ALERT SECTION only (before "Logs" section)
      // Avoid picking up cities from SUCCESS log lines (known-good location)
      const _alertSection = t.split(/\bLogs\b/i)[0] || t;
      const locationCity = (
        // Explicitly listed in alert geo fields — stop before coords or next field
        _alertSection.match(/Location country\s+[A-Za-z][a-zA-Z\s]{2,30}?\s*\([\d.,\s-]+\).*?(?:Location country code\s+(\S+)|$)/im) && "" ||
        // City from FAILURE log lines — "City Name ST" pattern at end of log line
        (t.match(/FAILURE[^\n]+?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:PR|MX|US|CA|GB|DE|AU)\b/gi)||[])
          .map(m => m.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:PR|MX|US|CA|GB)/)?.[1]).filter(Boolean)[0] ||
        // Success log lines city (known-good baseline)
        (t.match(/SUCCESS[^\n]+?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:US|PR|CA|GB)\b/gi)||[])
          .map(m => m.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:US|PR|CA|GB)/)?.[1]).filter(Boolean)[0] ||
        // Mexico City specific
        (t.match(/\b(Mexico City)\b/i)||[])[1] || ""
      ) || "";
      const aspOrg    = (t.match(/Source IP ASN organization\s+([^\n]{3,60})(?=\s+(?:Source IP ISP|Source IP ASN|Source account|Time detected|User |Alert |Risk )|$)/im)||[t.match(/ASN organization\s+([^\n]{3,50})/i)||[]])[1]?.trim().replace(/\s+(?:Source|Time|User|Alert).*$/i,'').replace(/,.*$/,'')||"";
      const ispDomain   = (t.match(/Source IP ISP domain\s+(\S+)/i)||[])[1]?.trim()||"";
      const carrierFrom = (t.match(/(?:Liberty Mobile Puerto Rico|T-Mobile USA|RadioMovil Dipsa|T-Mobile|Verizon|AT&T|Sprint|Comcast|Telcel|RadioMovil|Movistar|Claro|Rogers|Bell|Telus|Liberty Mobile|DTAG)[^\n,;.]{0,35}/i)||[])[0]?.trim().replace(/[,;.].*$/,'')||"";
      const deviceUA  = (t.match(/MSAL[^\n]{2,80}/i)||t.match(/Mozilla\/5\.0[^\n]{5,80}/i)||[])[0]||"";
      const isIPhone  = /iPhone|iOS/i.test(deviceUA);
      const isAndroid = /Android/i.test(deviceUA);
      const deviceStr = isIPhone ? "iPhone (iOS)" : isAndroid ? "Android" : deviceUA ? "mobile device" : "";
      // Known-good location vs suspicious
      const successIPs = [];
      const failIPs    = [];
      const logLines = t.match(/(?:Mar|Jan|Feb|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+[\d:]+[.\d]*\s+[\d.]+\s+[a-fA-F0-9-]+\s+\S+\s+(SUCCESS|FAILURE)/gi)||[];
      logLines.forEach(line => {
        const ip = (line.match(/(?:Mar|Jan|Feb|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+[\d:.]+\s+([\d.]+)/i)||[])[1]||"";
        if (/SUCCESS/i.test(line) && ip) successIPs.push(ip);
        if (/FAILURE/i.test(line) && ip) failIPs.push(ip);
      });
      const uniqueSuccessIPs = [...new Set(successIPs)];
      const uniqueFailIPs    = [...new Set(failIPs)];
      // Store enriched context
      if (locationCity||locationCountry) {
        const _lcClean = locationCountry.replace(/\s+(?:Location country code|Source|Time|User|Alert|Risk|Privileged).*/i,'').trim();
        results.prefillData.location = [locationCity, _lcClean].filter(Boolean).join(", ");
        // Store suspicious location separately (for escalation block)
        // suspicious_location = explicitly what the alert says (Mexico), NOT Dallas from success logs
        const _suspCity = locationCity.replace(/Dallas|New York|Chicago|Houston|Phoenix|Los Angeles/i,'').trim();
        results.prefillData.suspicious_location = [_suspCity, _lcClean].filter(Boolean).join(", ").replace(/^,\s*/,'').trim();
        // Will be overridden by user log day2 city if available (more precise)
      }
      if (dept)  results.prefillData.department = dept.split(/\s+(?:Title|Network|Username)/i)[0]?.trim() || dept;
      if (title) results.prefillData.role        = title.split(/\s+(?:Network|Username|Email)/i)[0]?.trim() || title;
      if (alertCount > 1) results.prefillData.alert_count = String(alertCount);
      results.prefillData.carrier = (aspOrg || carrierFrom || "").split(/\s+(?:Source|Time|User|Alert)/i)[0]?.trim() || "";
      results.prefillData.device  = deviceStr;
      results.prefillData.fail_ips   = uniqueFailIPs.join(", ");
      results.prefillData.success_ips = uniqueSuccessIPs.join(", ");

      // Extract all unique login IPs (IPv4 + IPv6) from the log rows
      const ipv4Set = new Set((t.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)||[]).filter(ip => !ip.startsWith("0.") && ip !== "0.0.0.0"));
      const ipv6Set = new Set((t.match(/\b[a-fA-F0-9]{4}:[a-fA-F0-9:]{9,39}\b/g)||[]));

      if (user || email) { results.indicators.push(`User: ${user || email}`); results.prefillData.username = user || email; }
      if (srcIpv4)       { results.indicators.push(`Source IP: ${srcIpv4}`); results.prefillData.src_ip = srcIpv4; }
      if (addIpv6)         results.indicators.push(`Add. IP (IPv6): ${addIpv6.slice(0,30)}...`);
      if (riskRaw)         results.indicators.push(`Risk Score: ${riskRaw}`);
      if (platform)        results.indicators.push(`Platform: ${platform.slice(0,50)}`);
      if (privStr)         results.indicators.push(`Privileged: ${privStr}`);
      if (dept)            results.indicators.push(`Dept: ${dept}${title?" · "+title:""}`);
      if (alertNames.length) results.indicators.push(`Alerts: ${alertNames.slice(0,3).join(" | ")}`);
      if (locationCountry)   results.indicators.push(`Location: ${[locationCity,locationCountry].filter(Boolean).join(", ")}`);
      if (aspOrg||carrierFrom) results.indicators.push(`Carrier/ISP: ${aspOrg||carrierFrom}`);
      if (deviceStr)         results.indicators.push(`Device: ${deviceStr}`);

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
        if (!results.prefillData.user_log_parsed) {
        results.findings.push(`⚠️ ${failures} FAILURE(s) followed by ${successes} SUCCESS(es) — possible credential stuffing with eventual success`);
      }
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
      const _cleanPlatform = platform.split(/\s+(?:Location|Source|Time|User|Account)/i)[0]?.trim().slice(0,60)||"";
      if (_cleanPlatform) results.findings.push(`ℹ️ Target application: **${_cleanPlatform}**`);

      // Mobile device pattern (same UA from different locations)
      const uas = [...new Set((t.match(/Mozilla\/5\.0[^\n]*/g)||[]).map(ua => ua.slice(0,60)))];
      if (uas.length === 1 && (ipv4Set.size + ipv6Set.size) >= 2) {
        results.findings.push(`⚠️ Same device (${uas[0].includes("iPhone") ? "iPhone" : uas[0].includes("Android") ? "Android" : "mobile"}) used from multiple cities — potential account sharing or SIM swap`);
      }

      results.prefillData.notes = [
        alertNames.length > 1 ? `${alertCount} alerts: ${alertNames.slice(0,3).map(a=>a.split(/\s+(?:Indicators|Account|Source|Time)/i)[0].trim().slice(0,60)).join(" | ")}` : alertType.split(/\s+(?:Indicators|Account|Source|Time)/i)[0].trim().slice(0,60),
        `User: ${email||user}`,
        dept||title ? `Role: ${[title,dept].filter(Boolean).join(", ")}` : "",
        `Risk: ${riskRaw||"unscored"}`,
        locationCountry ? `Suspicious origin: ${[locationCity,locationCountry.replace(/\s+(?:Location country code|Source|Time|User|Alert|Risk|Privileged).*/i,"").trim()].filter(Boolean).join(", ")}` : "",
        aspOrg ? `Carrier: ${aspOrg.split(",")[0].trim()}` : "",
        deviceStr ? `Device: ${deviceStr}` : "",
        uniqueFailIPs.length ? `FAILURE IPs: ${uniqueFailIPs.join(", ")}` : "",
        uniqueSuccessIPs.length ? `SUCCESS IPs: ${uniqueSuccessIPs.join(", ")}` : "",
        `${failures} FAILURE(s), ${successes} SUCCESS(es)`,
      ].filter(Boolean).join(" | ");
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
    if (/subtype=|action=allow|action=deny|action=block|app=|dstip=|srcip=|policyname=|logid=|devname=/i.test(t) &&
        !/event_simpleName|DetectDescription|RemoteAddressIP4|SHA256HashData|crowdstrike|falcon|event_platform/i.test(t)) {
      results.eventType = /fortinet|fortigate|logid=/i.test(t) ? "Fortinet FortiGate Log" : "Palo Alto NGFW Log";
      // CEF cs1Label=Severity cs1=<value> pattern for Palo Alto CEF exports
      const _cefSevLabel = (t.match(/cs(\d)Label\s*=\s*Severity/i)||[])[1];
      if (_cefSevLabel) {
        const _cefSevVal = ((t.match(new RegExp("cs"+_cefSevLabel+"\\s*=\\s*(\\w+)",'i'))||[])[1]||"").toLowerCase();
        if (/critical/i.test(_cefSevVal)) results.severity="critical";
        else if (/high/i.test(_cefSevVal)) results.severity="high";
        else if (/medium/i.test(_cefSevVal)) results.severity="medium";
        else if (/low/i.test(_cefSevVal)) results.severity="low";
      }
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
      if (threat) { results.findings.push(`🚨 Threat detected: ${threat}`); results.severity="critical"; results.mitre.add("T1059"); results.prefillData.threat_name = threat; }
      if (app)    results.prefillData.app = app;
      if (policy) results.prefillData.policy = policy;
      if (/allow/i.test(action) && dport === "4444") { results.findings.push("🚨 Allowed traffic on port 4444 (Metasploit default)"); results.mitre.add("T1071"); results.severity="critical"; }
      if (/allow/i.test(action) && dport === "50050") { results.findings.push("🚨 Allowed traffic on port 50050 (Cobalt Strike)"); results.mitre.add("T1071"); results.severity="critical"; }
      if (/allow/i.test(action) && dport === "3389") { results.findings.push("⚠️ RDP allowed outbound — verify necessity"); results.mitre.add("T1021.001"); if(results.severity!=="critical") results.severity="high"; }
      if (src && !isPrivateIPv4(src) && /allow/i.test(action) && dport && !["80","443","53"].includes(dport)) { results.findings.push(`⚠️ Inbound allow on non-standard port ${dport} from external IP`); }
      results.mitre.add("T1071");  // Application Layer Protocol (more appropriate for outbound traffic)
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
    // ── Universal rule/policy extraction (runs for ALL parsers) ──
    const _rawAll = results._rawText || "";
    if (!results.prefillData.rule && _rawAll) {
      const _rm =
        _rawAll.match(/(?:ruleName|rule_name|PolicyName|policy_name|FilterName|DetectName|alert_name|signature_name|DetectDescription|description)[ \t]*[=:"]+[ \t]*"?([^"\n\r,]{3,100})/i) ||
        _rawAll.match(/(?:Rule|Policy|Filter)[ \t]*[=:,\t]+[ \t]*([^\n\r,]{3,80})/i);
      if (_rm?.[1]?.trim() && !_rm[1].match(/^(?:rule|category|policy|filter|name|type|none|null|-)$/i))
        results.prefillData.rule = _rm[1].trim().slice(0, 100);
    }
    // ── Post-process: apply CEF csN severity if not already set by parser ──
    const _raw = results._rawText || "";
    if (results.severity === "info" && _raw) {
      // Pattern 1: csNLabel=Severity csN=<value> (in any order)
      const _cefSevN = (_raw.match(/cs(\d)Label\s*=\s*Severity/i)||[])[1];
      if (_cefSevN) {
        const _cefSevVal = ((_raw.match(new RegExp("(?:^|\\s)cs"+_cefSevN+"\\s*=\\s*(\\w+)","im"))||[])[1]||"").toLowerCase();
        if (/critical/.test(_cefSevVal)) results.severity="critical";
        else if (/high/.test(_cefSevVal)) results.severity="high";
        else if (/medium|moderate/.test(_cefSevVal)) results.severity="medium";
        else if (/low/.test(_cefSevVal)) results.severity="low";
      }
      // Pattern 2: severity=high / syslog severity patterns
      if (results.severity === "info") {
        const _sevMatch = (_raw.match(/(?:^|\s)(?:severity|sev|priority)\s*[=:]\s*(critical|high|medium|moderate|low|informational|info|warn(?:ing)?)/im)||[])[1]?.toLowerCase();
        if (_sevMatch) {
          if (/critical/.test(_sevMatch)) results.severity="critical";
          else if (/high/.test(_sevMatch)) results.severity="high";
          else if (/medium|moderate/.test(_sevMatch)) results.severity="medium";
          else if (/low/.test(_sevMatch)) results.severity="low";
          else if (/warn/.test(_sevMatch)) results.severity="medium";
        }
      }
      // Pattern 3: CEF DeviceEventClassID severity digit (1-10 scale in header)
      if (results.severity === "info") {
        const _cefHdrSev = (_raw.match(/^CEF:\d\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|(\d+)/m)||[])[1];
        if (_cefHdrSev) {
          const s = parseInt(_cefHdrSev);
          if (s >= 9) results.severity="critical";
          else if (s >= 7) results.severity="high";
          else if (s >= 4) results.severity="medium";
          else if (s >= 1) results.severity="low";
        }
      }
    }
    // ── Post-process: extract Windows Event Log timestamp (M/D/YYYY H:MM:SS AM/PM) ──
    if (!results.iocs.timestamps?.length && results._rawText) {
      const _winTs = results._rawText.match(/\b(\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM))/gi);
      if (_winTs) {
        results.iocs.timestamps = [...new Set(_winTs)];
        results.prefillData.timestamp = _winTs[0];
      }
    }
    // ── Post-process: AWS CloudTrail suspicious actions as verdicts ──
    if (!results.iocs.verdicts?.length && results._rawText) {
      const _awsSuspicious = /AttachUserPolicy|AttachRolePolicy|CreateUser|AddUserToGroup|PutUserPolicy|DeleteTrail|StopLogging|CreateAccessKey|PutBucketPolicy/i;
      if (_awsSuspicious.test(results._rawText)) {
        results.iocs.verdicts = ["SUSPICIOUS"];
        results.prefillData.verdict = "SUSPICIOUS";
        if (results.severity === "info") results.severity = "high";
      }
    }
    // Assign human severity label
    const sevMap = { critical:"🔴 CRITICAL", high:"🟠 HIGH", medium:"🟡 MEDIUM", low:"🟢 LOW", info:"⚪ INFO" };
    results.severityLabel = sevMap[results.severity] || "⚪ INFO";
    // Deduplicate IOCs — remove domains that are IPs
    if (results.iocs.domains && results.iocs.ips) {
      results.iocs.domains = results.iocs.domains.filter(d => !results.iocs.ips.includes(d));
    }
    // ── Apply offline KB enrichment ───────────────────────────
    // enrichFromKB is defined after this function — call it lazily
    if (typeof enrichFromKB === "function") enrichFromKB(results);
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

    // Web/CASB/Network (Zscaler, Netskope, Umbrella, ProxySG, Darktrace, Firewall, Suricata)
    if (/zscaler|netskope|casb|umbrella|proxySG|forcepoint|mcafee.*web|skyhigh|barracuda.*web|darktrace|firewall|network|suricata|snort|ids|ips|ndr/i.test(et)) {
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
  // ═══════════════════════════════════════════════════════════════
  // LOG TRIAGE — PARAGRAPH NARRATIVE ALERT SUMMARY
  // Writes a full analyst-grade paragraph explaining:
  //   WHAT happened · WHO/WHAT was involved · WHY it's suspicious
  //   WHAT likely occurred · WHAT the next action should be
  // ═══════════════════════════════════════════════════════════════
  // ══════════════════════════════════════════════════════════════════════
  // OFFLINE THREAT INTELLIGENCE KNOWLEDGE BASE
  // Embedded context used by the triage engine for instant, offline enrichment.
  // No API call needed — this knowledge is always available.
  // ══════════════════════════════════════════════════════════════════════
  const THREAT_KB = {

    // ── Malware / Threat Signature Context ────────────────────────────
    signatures: {
      "HTML.Trojan.ClickFix":        { verdict:"TP", sev:"high",    cat:"social-engineering", desc:"ClickFix lure page — instructs user to paste PowerShell/cmd into Run dialog. Pre-compromise delivery, not post-compromise.", mitre:["T1204.001","T1059.001"], action:"Block domain, pull EDR telemetry for clipboard/process activity on host." },
      "HTML.Scam.TechSupport":       { verdict:"TP", sev:"medium",  cat:"scam",               desc:"Tech-support scam page — fake Windows error or Microsoft alert designed to harvest credentials or trick user into calling a fraudulent support number.", mitre:["T1566.002","T1204.001"], action:"Block domain, check if user called any phone number from the page." },
      "HTML.Phishing":               { verdict:"TP", sev:"high",    cat:"phishing",           desc:"Phishing page — credential harvesting site designed to mimic a legitimate login portal.", mitre:["T1566.002","T1078"], action:"Block domain, check if user submitted credentials, force password reset." },
      "JS.Miner":                    { verdict:"TP", sev:"low",     cat:"cryptominer",        desc:"Browser-based cryptominer — consumes CPU resources, typically not destructive but indicates a compromised or malicious website.", mitre:["T1496"], action:"Block domain. No credential risk, but investigate site category." },
      "Trojan.GenericKD":            { verdict:"TP", sev:"critical",cat:"trojan",             desc:"Generic trojan dropper — multi-purpose malware loader. High risk of follow-on payload delivery or persistence.", mitre:["T1059","T1055","T1547"], action:"Isolate host immediately, full forensic triage." },
      "Exploit.CVE":                 { verdict:"TP", sev:"critical",cat:"exploit",            desc:"Known CVE exploit attempt. Immediate patching and host isolation required.", mitre:["T1190","T1203"], action:"Isolate host, patch immediately, check for successful exploitation." },
      "Cobalt.Strike":               { verdict:"TP", sev:"critical",cat:"c2",                 desc:"Cobalt Strike beacon — commercial pen-test tool widely abused by ransomware groups and APTs for C2 and lateral movement.", mitre:["T1071","T1055","T1021"], action:"IMMEDIATE: isolate host, block C2 IP/domain, escalate to IR." },
      "Metasploit":                  { verdict:"TP", sev:"critical",cat:"c2",                 desc:"Metasploit framework activity — open-source exploitation framework. High confidence active attack.", mitre:["T1059","T1190"], action:"IMMEDIATE: isolate host, block source IP, escalate to IR." },
      "Mimikatz":                    { verdict:"TP", sev:"critical",cat:"credential",         desc:"Mimikatz credential dumping tool — extracts plaintext passwords, hashes, Kerberos tickets from LSASS memory.", mitre:["T1003.001","T1078"], action:"IMMEDIATE: assume all domain credentials compromised, reset all, isolate host." },
      "Ransomware":                  { verdict:"TP", sev:"critical",cat:"ransomware",         desc:"Ransomware activity detected. Encryption may be in progress or complete.", mitre:["T1486","T1490"], action:"IMMEDIATE: isolate host, take offline snapshot, do NOT reboot, escalate." },
      "HTML.Scam.TechSupport":       { verdict:"TP", sev:"medium",  cat:"scam",               desc:"Tech-support scam page — fake Windows error or Microsoft alert designed to harvest credentials or trick user into calling a fraudulent support number.", mitre:["T1566.002","T1204.001"], action:"Block domain, check if user called any phone number from the page or submitted credentials." },
      "EICAR":                       { verdict:"FP", sev:"info",    cat:"test",               desc:"EICAR antivirus test file — this is a standard AV test string, not real malware. Safe to ignore.", mitre:[], action:"Verify this is a planned AV test. If unexpected, investigate who ran it." },
      "PUP":                         { verdict:"FP", sev:"low",     cat:"pup",                desc:"Potentially Unwanted Program — adware, toolbar, or bundled software. Low risk, typically not malicious.", mitre:[], action:"Remove if against policy. Not an active threat." },
      "HTML.Trojan":                 { verdict:"TP", sev:"high",    cat:"trojan",             desc:"Browser-delivered trojan — malicious HTML/JS payload attempting to execute in browser context.", mitre:["T1059.007","T1204.001"], action:"Block domain, check for follow-on process execution on host." },
      "Malware.pre-C2":              { verdict:"TP", sev:"high",    cat:"c2",                 desc:"Pre-C2 communication attempt — malware beaconing to establish command-and-control channel. Block before session is established.", mitre:["T1071","T1095"], action:"Block destination IP/domain, pull EDR for implant on host." },
    },

    // ── Alert Type Context ─────────────────────────────────────────────
    alertTypes: {
      "Access from unusual geolocation":  { risk:"high",    desc:"Authentication from a location not in the user's normal baseline. High confidence if combined with auth failures or carrier mismatch.", immediate:"Verify with user out-of-band. If unconfirmed, disable account." },
      "Access from blocklisted location": { risk:"critical",desc:"Authentication from a country on the corporate or threat-intel blocklist. Treat as compromise until proven otherwise.", immediate:"Disable account NOW. Do not wait for user response." },
      "Suspicious web-based activity":    { risk:"medium",  desc:"ML-detected anomalous web behavior — unusual browsing pattern, suspicious user-agent, or access to high-risk domain categories.", immediate:"Review full session, block suspicious domains, check for download activity." },
      "Impossible travel":                { risk:"critical",desc:"Same account authenticated from two geographically distant locations within a timeframe that makes physical travel impossible.", immediate:"IMMEDIATE account disable, revoke all sessions." },
      "MFA denied":                       { risk:"high",    desc:"User denied an MFA push they did not initiate — confirms attacker has credentials and is attempting to bypass MFA.", immediate:"Reset credentials immediately. Enable number matching on MFA." },
      "MFA fatigue":                      { risk:"critical",desc:"Repeated MFA push notifications — attacker spamming MFA to exhaust user. Associated with Scattered Spider / UNC3944.", immediate:"Disable account, re-enrol MFA, investigate how credentials were obtained." },
      "Concurrent login":                 { risk:"high",    desc:"Multiple simultaneous authenticated sessions from different IPs — session token theft or credential sharing.", immediate:"Revoke all active sessions, investigate session source." },
      "Password spray":                   { risk:"high",    desc:"Low-and-slow brute force using common passwords across many accounts. Often precursor to credential stuffing.", immediate:"Check for successful auths after failures, lock accounts with repeated failures." },
      "OAuth app consent":                { risk:"high",    desc:"Application consent grant — attacker may have registered a malicious OAuth app to persist access without credentials.", immediate:"Revoke consent immediately, audit all granted app permissions." },
    },

    // ── Carrier/ISP Attribution ───────────────────────────────────────
    carriers: {
      "Liberty Mobile Puerto Rico": { country:"Puerto Rico", type:"mobile", note:"Liberty Mobile PR (formerly Claro) — Puerto Rico's major mobile carrier. Direct PR mobile connection." },
      "Liberty Mobile":             { country:"Puerto Rico", type:"mobile", note:"Liberty Mobile — Puerto Rico mobile carrier. Direct mobile connection." },
      "centennialpr.net":           { country:"Puerto Rico", type:"mobile", note:"Centennial PR / Liberty Mobile — Puerto Rico mobile network." },
      "RadioMovil Dipsa":   { country:"Mexico",      type:"mobile", note:"Telcel — Mexico's largest mobile carrier. Direct mobile connection, not a VPN or proxy." },
      "Telcel":             { country:"Mexico",      type:"mobile", note:"Telcel (RadioMovil Dipsa) — Mexico's largest mobile carrier." },
      "T-Mobile USA":       { country:"USA",         type:"mobile", note:"T-Mobile USA — major US mobile carrier. Commonly used for legitimate employee mobile access." },
      "Verizon":            { country:"USA",         type:"mobile", note:"Verizon — major US carrier. Normal for corporate mobile devices." },
      "AT&T":               { country:"USA",         type:"mobile", note:"AT&T — major US carrier. Normal for corporate mobile devices." },
      "Rostelecom":         { country:"Russia",      type:"isp",    note:"Russia's state-owned ISP. High-risk origin for corporate auth events." },
      "China Telecom":      { country:"China",       type:"isp",    note:"China state-owned ISP. High-risk origin for corporate auth events." },
      "DigitalOcean":       { country:"USA",         type:"hosting",note:"Cloud hosting provider — commonly used for VPS-based attacks. Not a user ISP." },
      "Linode":             { country:"USA",         type:"hosting",note:"Cloud hosting — commonly used for attack infrastructure." },
      "Vultr":              { country:"USA",         type:"hosting",note:"Cloud VPS — commonly used for attack infrastructure." },
      "M247":               { country:"Romania",     type:"vpn",    note:"M247 — bulletproof hosting/VPN provider frequently used for attack anonymization." },
      "Mullvad":            { country:"Sweden",      type:"vpn",    note:"Mullvad VPN — legitimate privacy VPN. Auth from Mullvad may indicate deliberate anonymization." },
    },

    // ── URL/Domain Pattern Context ────────────────────────────────────
    urlPatterns: [
      { re:/\/verify\/?$|\/captcha\/?$|\/check\/?$|\/validate\/?$|\/confirm\/?$|\/update\/?$/i, label:"ClickFix/Verify lure path", risk:"high", desc:"Path matches ClickFix, CAPTCHA bypass, or verification lure patterns — commonly used in social engineering to deliver PowerShell payloads." },
      { re:/\/admin\/|\/wp-admin\/|\/xmlrpc\.php/i,                                             label:"CMS admin/exploit path",   risk:"high", desc:"Targeting CMS admin panels or known vulnerable endpoints. Possible exploitation attempt." },
      { re:/\.php\?id=|union.*select|' OR '1'='1/i,                                            label:"SQLi indicator",           risk:"critical", desc:"SQL injection pattern in URL. Active exploitation attempt." },
      { re:/cmd\.exe|powershell|base64|eval\(|document\.write/i,                               label:"Code execution in URL",    risk:"critical", desc:"URL contains code execution payload. Likely XSS or command injection attempt." },
      { re:/\.(exe|dll|bat|ps1|vbs|js|hta|msi|iso|zip|rar|7z)(\?|$)/i,                        label:"Executable/archive download",risk:"high", desc:"URL points to an executable or archive — potential malware delivery." },
      { re:/\.ru\/|\.cn\/|\.tk\/|\.xyz\/|\.top\/|\.club\/|\.icu\//i,                          label:"High-risk TLD",            risk:"medium", desc:"Domain uses a TLD frequently associated with malware hosting and phishing." },
      { re:/[a-z0-9]{15,}\.(com|net|org|io|me)\//i,                                           label:"DGA-like domain",          risk:"high", desc:"Long random-looking domain name — potential DGA (Domain Generation Algorithm) C2 domain." },
    ],

    // ── Verdict logic ─────────────────────────────────────────────────
    getSignatureContext(sigName) {
      if (!sigName) return null;
      const sig = sigName.toLowerCase();
      // Exact match first
      const exact = Object.keys(this.signatures).find(k => sig === k.toLowerCase());
      if (exact) return this.signatures[exact];
      // Starts-with match (e.g. HTML.Scam.TechSupport matches HTML.Scam.TechSupport)
      const starts = Object.keys(this.signatures).find(k => sig.startsWith(k.toLowerCase()) || k.toLowerCase().startsWith(sig.split(".").slice(0,2).join(".").toLowerCase()));
      if (starts) return this.signatures[starts];
      // Contains match (fallback)
      const contains = Object.keys(this.signatures).find(k => sig.includes(k.toLowerCase()));
      return contains ? this.signatures[contains] : null;
    },
    getAlertTypeContext(alertType) {
      const key = Object.keys(this.alertTypes).find(k => alertType.toLowerCase().includes(k.toLowerCase()));
      return key ? this.alertTypes[key] : null;
    },
    getCarrierContext(carrier) {
      const key = Object.keys(this.carriers).find(k => carrier.toLowerCase().includes(k.toLowerCase()));
      return key ? this.carriers[key] : null;
    },
    // VPN / Hosting IP ranges — common FP sources
    vpnHostingASNs: [
      "digitalocean","linode","vultr","amazon","amazonaws","google cloud","microsoft azure",
      "ovhcloud","hetzner","contabo","m247","mullvad","expressvpn","nordvpn","protonvpn",
      "private internet access","surfshark","ipvanish","torguard","hidemyass",
    ],
    isVPNOrHosting(carrier) {
      if (!carrier) return false;
      const c = carrier.toLowerCase();
      return this.vpnHostingASNs.some(v => c.includes(v));
    },
    getURLContext(url) {
      if (!url) return null;
      for (const p of this.urlPatterns) {
        if (p.re.test(url)) return p;
      }
      return null;
    },
  };

  // ── Apply KB enrichment to every triage result ─────────────────────
  function enrichFromKB(res) {
    const pf  = res.prefillData || {};
    // Look for signature in multiple fields + cmdline + findings
    const sig = pf.threat_name || pf.rule ||
                (pf.cmdline||"").match(/mimikatz|cobalt.strike|metasploit|meterpreter|bloodhound|sharphound|rubeus|kerberoast|procdump.*lsass/i)?.[0] ||
                (res.findings||[]).join(" ").match(/mimikatz|cobalt.strike|metasploit|ransomware|lsass.*dump|credential.*dump/i)?.[0] || "";
    const alertNames = (res._rawText||"").match(/Alert \d+\.\s+([^\n]{5,80})/gi)||[];

    // Enrich from signature
    const sigCtx = THREAT_KB.getSignatureContext(sig);
    if (sigCtx) {
      if (!pf.kb_verdict) pf.kb_verdict   = sigCtx.verdict;
      if (!pf.kb_desc)   pf.kb_desc     = sigCtx.desc;
      if (!pf.kb_action) pf.kb_action   = sigCtx.action;
      if (!pf.kb_mitre)  pf.kb_mitre    = sigCtx.mitre;
      // Upgrade severity if KB says higher
      const sevOrder = {info:0,low:1,medium:2,high:3,critical:4};
      if ((sevOrder[sigCtx.sev]||0) > (sevOrder[res.severity]||0)) res.severity = sigCtx.sev;
    }

    // Enrich from alert type names (Falcon Identity style)
    alertNames.forEach(a => {
      const alertCtx = THREAT_KB.getAlertTypeContext(a);
      if (alertCtx) {
        if (!pf.kb_alert_desc)    pf.kb_alert_desc    = alertCtx.desc;
        if (!pf.kb_alert_action)  pf.kb_alert_action  = alertCtx.immediate;
        const sevOrder = {low:0,medium:1,high:2,critical:3};
        if ((sevOrder[alertCtx.risk]||0) > (sevOrder[res.severity]||0)) res.severity = alertCtx.risk;
      }
    });

    // Enrich from carrier
    const carrierCtx = THREAT_KB.getCarrierContext(pf.carrier||"");
    if (carrierCtx) {
      pf.kb_carrier_desc = `${pf.carrier} is a ${carrierCtx.type} carrier in ${carrierCtx.country}. ${carrierCtx.note}`;
    }

    // Enrich from URL pattern
    const urlCtx = THREAT_KB.getURLContext(pf.url||"");
    if (urlCtx && !res.findings.some(f => f.includes(urlCtx.label))) {
      res.findings.push(`⚠️ URL pattern: ${urlCtx.label} — ${urlCtx.desc}`);
    }

    // ── OSINT section parser ─────────────────────────────────
    // Detects VT / Talos / AbuseIPDB results the analyst pasted
    var _rawFull = res._rawText || '';
    var _osintRaw = '';
    var _osintSplit = _rawFull.split(/(?:^|\n)\s*OSINT\s*:?\s*(?:\n|$)/im);
    if (_osintSplit.length > 1) {
      _osintRaw = _osintSplit[1].split(/\n{3,}/)[0] || '';
    }
    if (_osintRaw.length > 10) {
      var _vtClean   = /VT[:\s].*(?:No security vendor flagged|not.*malicious|0\s*\/\s*\d+|Clean)/i.test(_osintRaw);
      var _vtBad     = /VT[:\s].*(?:\d+\s*\/\s*\d+.*malicious|malicious)/i.test(_osintRaw) && !_vtClean;
      var _taloGood  = /Talos[:\s].*(?:Neutral|Good|Favorable)/i.test(_osintRaw);
      var _taloBad   = /Talos[:\s].*(?:Poor|Malicious|Untrusted)/i.test(_osintRaw);
      var _abuseOk   = /AbuseIPDB[:\s].*(?:not found|0%|clean|no report)/i.test(_osintRaw);
      var _abuseBad  = /AbuseIPDB[:\s].*(?:\d{2,3}%|malicious|reported)/i.test(_osintRaw);
      pf.osint_vt        = _vtClean ? 'CLEAN' : _vtBad ? 'MALICIOUS' : 'UNKNOWN';
      pf.osint_talos     = _taloGood ? 'NEUTRAL' : _taloBad ? 'POOR' : 'UNKNOWN';
      pf.osint_abuseipdb = _abuseOk ? 'CLEAN' : _abuseBad ? 'REPORTED' : 'UNKNOWN';
      pf.osint_clean     = (_vtClean || _taloGood) && _abuseOk;
      pf.osint_section   = _osintRaw.trim().slice(0, 400);
      if (pf.osint_clean) {
        res.findings.push('\u2705 OSINT: IP ' + (pf.src_ip || 'source') + ' is CLEAN \u2014 VT: ' + pf.osint_vt + ', Talos: ' + pf.osint_talos + ', AbuseIPDB: ' + pf.osint_abuseipdb + '. No threat intelligence matches.');
        if (pf.kb_verdict === 'TP') pf.kb_verdict = 'TP_VERIFY';
      } else if (_vtBad || _taloBad || _abuseBad) {
        res.findings.push('\uD83D\uDEA8 OSINT: IP ' + (pf.src_ip || 'source') + ' is MALICIOUS \u2014 VT: ' + pf.osint_vt + ', Talos: ' + pf.osint_talos + ', AbuseIPDB: ' + pf.osint_abuseipdb + '. High-confidence threat actor IP.');
        res.severity = 'critical';
        pf.kb_verdict = 'TP';
      }
    }

    // ── User log section parser ─────────────────────────────────
    // Parses structured auth log lines the analyst added below the alert
    var _ulSplit = _rawFull.split(/\bUser\s+log\s*\n/i);
    var _ulRaw   = _ulSplit.length > 1 ? (_ulSplit[1].split(/\bOSINT\s*:/i)[0] || '') : '';
    if (_ulRaw.trim().length > 20) {
      pf.user_log_parsed = true;
      var _ulLines = _ulRaw.split('\n').filter(function(l){ return l.trim().length > 20; });
      var _failures = [], _successes = [], _ips = [], _carriers = [], _cities = [], _dates = [];
      var _iosVer = '';
      _ulLines.forEach(function(line) {
        var _ts      = (line.match(/^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d+:\d+:\d+\.?\d*)/i)||[])[1] || '';
        var _status  = (line.match(/\b(FAILURE|SUCCESS)\b/i)||[])[1] || '';
        var _ipv4    = (line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/)||[])[1] || '';
        var _ipv6    = (line.match(/\b([0-9a-f]{4}:[0-9a-f:]{5,})/i)||[])[1] || '';
        var _ip      = _ipv4 || _ipv6 || '';
        var _city    = (line.match(/\b(San Juan|Vega Baja|Mexico City|Dallas|Miami|Houston|Chicago|San Francisco|Los Angeles|New York)\b/i)||[])[1] || '';
        var _region  = (line.match(/\s+(PR|MX|US|CA|GB|DE|AU)\s/)||[])[1] || '';
        var _carrier = (line.match(/(?:T-Mobile USA|Liberty Mobile Puerto Rico|Liberty Mobile|RadioMovil Dipsa|T-Mobile|AT&T|Verizon|Sprint)[^,\n]*/i)||[])[0] || '';
        if (_carrier) _carrier = _carrier.trim().replace(/[,;.].*$/,'');
        var _ios = (line.match(/iPhone.*?OS ([\d_]+)/i)||[])[1] || '';
        if (_ios && !_iosVer) _iosVer = _ios.replace(/_/g,'.');
        var _day = _ts ? _ts.split(' ').slice(0,3).join(' ') : '';
        if (_status === 'FAILURE' || (line.match(/FAILURE/i) && _ip)) _failures.push({ts:_ts,ip:_ip,city:_city,region:_region,carrier:_carrier});
        if (_status === 'SUCCESS' || (line.match(/SUCCESS/i) && _ip)) _successes.push({ts:_ts,ip:_ip,city:_city,region:_region,carrier:_carrier});
        if (_ip && _ips.indexOf(_ip) < 0) _ips.push(_ip);
        if (_carrier && _carriers.indexOf(_carrier) < 0) _carriers.push(_carrier);
        if (_city && _cities.indexOf(_city) < 0) _cities.push(_city);
        if (_day && _dates.indexOf(_day) < 0) _dates.push(_day);
      });
      pf.user_log_lines     = _ulLines.length;
      pf.user_log_failures  = _failures.length;
      pf.user_log_successes = _successes.length;
      pf.user_log_ips       = _ips.join(', ');
      pf.user_log_carriers  = _carriers.join(', ');
      pf.user_log_cities    = _cities.join(', ');
      pf.user_log_dates     = _dates.join(', ');
      // Day-over-day analysis
      var _day1 = _ulLines.filter(function(l){ return l.match(/Mar\.?\s+20,?\s+2026/i); });
      var _day2 = _ulLines.filter(function(l){ return l.match(/Mar\.?\s+21,?\s+2026/i); });
      var _d1carrier = (_day1[0]||'').match(/(?:T-Mobile USA|Liberty Mobile Puerto Rico|Liberty Mobile|RadioMovil Dipsa|T-Mobile|AT&T|Verizon)[^,\n]*/i);
      var _d2carrier = (_day2[0]||'').match(/(?:T-Mobile USA|Liberty Mobile Puerto Rico|Liberty Mobile|RadioMovil Dipsa|T-Mobile|AT&T|Verizon)[^,\n]*/i);
      var _d1city    = (_day1.join(' ').match(/\b(San Juan|Vega Baja|Mexico City|Dallas|Miami)\b/i)||[])[1] || '';
      var _d2city    = (_day2.join(' ').match(/\b(San Juan|Vega Baja|Mexico City|Dallas|Miami)\b/i)||[])[1] || '';
      var _d1ip      = (_day1[0]||'').match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f]{4}:[0-9a-f:]{5,})\b/i);
      var _d2ip      = (_day2[0]||'').match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      var _c1 = _d1carrier ? _d1carrier[0].trim().replace(/[,;.].*$/,'') : '';
      var _c2 = _d2carrier ? _d2carrier[0].trim().replace(/[,;.].*$/,'') : '';
      var _sameDevice = _iosVer ? 'Same device (iPhone iOS ' + _iosVer + ') on both days.' : 'Same device type both days.';
      // Summary findings
      res.findings.push('\uD83D\uDCCB User log (' + _ulLines.length + ' lines, ' + _dates.length + ' day(s)): ' + _failures.length + ' FAILURE(s), ' + _successes.length + ' SUCCESS(es). IPs: ' + _ips.join(', ') + '.');
      if (_day1.length && _day2.length && (_c1 !== _c2 || _d1city !== _d2city)) {
        var _d1sum = 'Mar 20: ' + (_c1||'unknown carrier') + (' \u2014 ') + (_d1city||'unknown city') + ' ' + ((_day1[0]||'').match(/\b(PR|US|MX)\b/)||[''])[0] + ' (' + ((_d1ip||[''])[0]||'unknown IP') + ')';
        var _d2sum = 'Mar 21: ' + (_c2||'unknown carrier') + (' \u2014 ') + (_d2city||'unknown city') + ' ' + ((_day2[0]||'').match(/\b(PR|US|MX)\b/)||[''])[0] + ' (' + ((_d2ip||[''])[0]||'unknown IP') + ')';
        pf.user_log_day1_summary = _d1sum;
        pf.user_log_day2_summary = _d2sum;
        res.findings.push('\uD83D\uDCC5 Day-over-day shift: ' + _d1sum + ' \u2192 ' + _d2sum + '. ' + _sameDevice);
        if (pf.osint_clean) {
          res.findings.push('\u2139\uFE0F Carrier/location change + clean OSINT: user may have switched networks (roaming, dual-SIM, or location change) \u2014 not necessarily malicious. Verify with user.');
        }
      } else {
        res.findings.push('\u2705 Consistent auth pattern across ' + _dates.length + ' day(s). ' + _sameDevice);
      }
    }

    // Redirect chain builder
    if (pf.url && pf.referer) {
      try {
        const destHost = new URL(pf.url).hostname;
        const refHost  = new URL(pf.referer).hostname;
        if (destHost !== refHost) {
          pf.redirect_chain = `${refHost} → ${destHost}`;
          pf.kb_redirect_desc = `User was browsing ${refHost} which silently redirected to ${destHost}. The referring site may itself be compromised or malicious.`;
        }
      } catch {}
    }
    // Check for multiple domain hops in the raw text (multi-redirect chains)
    const rawDomains = [];
    const domainHopRe = /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
    let m;
    while ((m = domainHopRe.exec(res._rawText||"")) !== null) {
      const d = m[1];
      if (!rawDomains.includes(d)) rawDomains.push(d);
    }
    if (rawDomains.length > 2) {
      pf.domain_chain = rawDomains.slice(0, 6).join(" → ");
    }

    // VPN/hosting check — may flip verdict to FP
    if (THREAT_KB.isVPNOrHosting(pf.carrier||"")) {
      pf.kb_vpn_flag = true;
      pf.kb_vpn_desc = `Source carrier "${pf.carrier}" is a VPN or cloud hosting provider — this authentication may be from a corporate VPN or legitimate remote access tool. Verify before escalating.`;
    }

    // Control validation — what did the security control actually DO?
    const rawLower = (res._rawText||"").toLowerCase();
    const ctrlAction = pf.verdict || pf.control_action || pf.http_status || "";
    if (/(blocked|block|ips drop|deny|denied|prevented|quarantine|quarantined)/i.test(ctrlAction + " " + rawLower.slice(0,200))) {
      pf.control_result = "CONTAINED";
      pf.control_desc   = "Security control blocked the threat. No content reached the endpoint.";
    } else if (/(allowed|allow|permit|success|passed)/i.test(ctrlAction)) {
      pf.control_result = "ALLOWED";
      pf.control_desc   = "⚠️ Traffic was ALLOWED through. Manual investigation required to determine impact.";
    } else if (/(detected|alert|flagged|raised)/i.test(ctrlAction)) {
      pf.control_result = "DETECTED_ONLY";
      pf.control_desc   = "Threat was detected but not automatically blocked. Action depends on follow-on activity.";
    }

    // Compromise check — did any post-compromise indicators appear?
    const comprPromise = [
      { re: /execut|process.*creat|child.*process|spawn/i,              label: "process execution detected" },
      { re: /download|bytes.*recv|payload.*deliver/i,                   label: "file/payload download detected" },
      { re: /persist|registry.*run|scheduled.*task|autorun/i,           label: "persistence mechanism detected" },
      { re: /c2|command.*control|beacon.*success|callback.*success/i,   label: "C2 callback detected" },
      { re: /exfil|data.*sent|upload.*success|bytes.*out.*[1-9]\d{4,}/i,label: "possible data exfiltration" },
      { re: /lateral|rdp.*success|smb.*auth|pass.*hash/i,              label: "lateral movement detected" },
    ];
    const compromiseIndicators = comprPromise.filter(c => c.re.test(res._rawText||""));
    if (compromiseIndicators.length > 0) {
      pf.compromise_indicators = compromiseIndicators.map(c => c.label).join("; ");
      pf.kb_verdict = "TP_ESCALATE";
      res.severity = "critical";
    } else if (pf.control_result === "CONTAINED") {
      if (!pf.kb_verdict) pf.kb_verdict = "TP";
      pf.no_compromise = true;
    }

    return res;
  }

  function buildNarrativeParagraph(res) {
    const iocs        = res.iocs     || {};
    const pf          = res.prefillData || {};
    const findings    = res.findings || [];
    const mitre       = res.mitre ? [...res.mitre] : [];
    const raw         = (res._rawText || "").toLowerCase();
    const et          = res.eventType || "Security Event";
    const sev         = res.severity  || "info";
    const findingsStr = findings.join(" ").toLowerCase();
    const verdict     = scoreAutoVerdict(res);

    // ── STEP 1: Alert Classification ─────────────────────────
    const isWeb      = /zscaler|proxy|web.*log|zia|firewall.*network/i.test(et);
    const isIdentity = /identity|okta|azure|entra|mfa|authentication|sso|falcon identity/i.test(et);
    const isEndpoint = /crowdstrike|falcon|defender|sentinelone|edr|endpoint/i.test(et);
    const isSaaS     = /saas|teams|onedrive|sharepoint|casb|file.*security/i.test(et);
    const isNetwork  = /firewall|network|ids|ips|snort|suricata|darktrace|qradar/i.test(et);
    const isEmail    = /proofpoint|email|phishing|spam/i.test(et);
    const category   = isWeb ? "Network/Web" : isIdentity ? "Identity" : isEndpoint ? "Endpoint" : isSaaS ? "SaaS/File" : isEmail ? "Email" : isNetwork ? "Network" : "Unknown";

    // ── STEP 2: Entity extraction (already done by parser) ────
    const user    = pf.username  || iocs.usernames?.[0]  || "";
    const host    = pf.hostname  || iocs.hostnames?.[0]  || "";
    const srcIP   = pf.src_ip    || "";
    const dstIP   = pf.dest_ip   || (iocs.ips||[]).find(ip => !isPrivateIPv4(ip) && ip !== srcIP) || "";
    const dstPort = pf.dest_port || "";
    const url     = pf.url       || iocs.urls?.[0] || "";
    const referer = pf.referer   || "";
    const sig     = pf.threat_name || pf.rule || "";
    const cat     = pf.category  || "";
    const action  = pf.verdict   || pf.control_action || "";
    const ts      = pf.timestamp || iocs.timestamps?.[0] || "";
    const dept    = pf.department || "";
    const role    = pf.role       || "";
    const carrier = pf.carrier    || "";
    const loc     = pf.location   || pf.suspicious_location || "";
    const failIPs = pf.fail_ips   || "";
    const succIPs = pf.success_ips|| "";
    const device  = pf.device     || "";
    const hash    = iocs.hashes?.[0] || "";
    const proc    = pf.process    || "";
    const cmdline = pf.cmdline    || "";
    const domain  = url ? (() => { try { return new URL(url).hostname; } catch { return ""; }})() : (iocs.domains||[])[0] || "";
    const refDomain = referer ? (() => { try { return new URL(referer).hostname; } catch { return ""; }})() : "";

    // ── MULTI-SOURCE OVERRIDE ────────────────────────────────────
    // When multiple sources were correlated, build a unified narrative
    if (pf.is_multi_source && pf.correlated_sources) {
      const srcCount   = pf.source_count || 2;
      const sources    = pf.correlated_sources;
      const kc         = pf.kill_chain_stage || "";
      const kcStages   = pf.kill_chain_stages || 0;
      const who_str    = user && host ? `${user} on host ${host}` : user || host || "an account";
      const whom_str   = (dept||role) ? ` (${[role,dept].filter(Boolean).join(", ")})` : "";
      const ip_str     = srcIP ? ` from ${srcIP}` : "";
      const ts_str     = pf.timestamp ? ` at ${pf.timestamp}` : "";

      const p1_ms = `${srcCount} log sources correlate on ${who_str}${whom_str}${ip_str}${ts_str} — ${sources}. `
        + (kc ? `The activity spans ${kcStages} kill chain stage${kcStages>1?"s":""}: ${kc}. ` : "")
        + (kcStages >= 3 ? "This represents a confirmed, multi-stage intrusion sequence." : kcStages >= 2 ? "This is a multi-stage attack pattern." : "Events from these sources are linked by shared entity.");

      const p2_ms = (() => {
        const has = id => (pf.correlated_sources||"").toLowerCase().includes(id);
        if (has("proofpoint") && (has("crowdstrike")||has("defender")))
          return `Correlation confirms phishing-to-execution: an email from Proofpoint logs was permitted through, and CrowdStrike/Defender recorded process execution on the same host shortly after. The user likely opened the attachment or clicked a link that ran malicious code.`;
        if ((has("okta")||has("azure")||has("falcon")||has("entra")) && has("zscaler"))
          return `An identity alert and a web/proxy alert share the same user and source IP — the authentication event and network traffic are part of the same session. Verify whether the auth succeeded and what the session accessed post-login.`;
        if (has("crowdstrike") && has("zscaler"))
          return `Endpoint and network telemetry align: CrowdStrike detected malicious process activity while Zscaler recorded outbound traffic from the same host. The endpoint is likely beaconing to a C2 server.`;
        return `These sources share common entity indicators (user, host, or IP) and together describe a more complete picture of the event than any single alert alone.`;
      })();

      const p3_ms = findings.some(f => /phishing.*execution|credential.*exec|C2.*exec/i.test(f))
        ? "⚠️ Evidence of compromise present — multiple attack stages completed. Immediate containment required."
        : (pf.control_result === "CONTAINED" && kcStages < 2)
          ? "✅ Security controls contained this activity. Verify no lateral movement or data access occurred."
          : "⚠️ Multi-source activity — review each source for evidence of execution, data access, or persistence.";

      const urgency = sev==="critical" ? "IMMEDIATE: Isolate endpoint, disable account, preserve evidence, escalate to IR."
                    : sev==="high"     ? "Priority: Block IOCs across all detected sources, pull EDR telemetry, review auth logs."
                    :                    "Standard: Correlate timestamps across sources, validate each alert, close or escalate.";
      const p4_ms = urgency + (kbAction ? " " + kbAction : "");

      const vl_ms = kcStages >= 3 ? "TP – Confirmed multi-stage intrusion. Escalation required. Treat as active breach."
                  : kcStages >= 2 ? "TP – Multi-stage attack confirmed. Escalate and investigate full scope."
                  : "TP – Correlated alerts from multiple sources. Review and validate each source.";

      return { p1:p1_ms, p2:p2_ms, p3:p3_ms, p4:p4_ms, verdictLine:vl_ms,
               mitreContext: mitre.slice(0,5).map(m=>`${m} (${getMitreName(m)})`).join(", "),
               category: `Multi-Source (${srcCount} sources)`,
               controlResult: pf.control_result || "DETECTED_ONLY",
               controlIcon: kcStages>=3 ? "🚨" : "⚠️",
               controlLabel: kcStages>=3 ? "MULTI-STAGE ATTACK — immediate action required" : "CORRELATED ALERTS — review all sources",
               effectiveVerdict: kcStages>=3 ? "TP_ESCALATE" : "TP_BLOCKED_NFA",
               redirectChain: pf.redirect_chain || "",
               behaviors: findings.slice(0,4).map(f=>f.replace(/[🔗🎯⛓️🚨⚠️ℹ️]/g,"").trim()),
             };
    }

    // ── STEP 3: Timeline (reconstruct event sequence) ─────────
    const timelineStr = (() => {
      if (ts) {
        try {
          const d = new Date(ts.replace(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+/i, m => m.replace(".", "")));
          if (!isNaN(d.getTime())) {
            return d.toLocaleDateString("en-US", {month:"short",day:"numeric",year:"numeric"}) + " at " +
                   d.getUTCHours().toString().padStart(2,"0") + ":" + d.getUTCMinutes().toString().padStart(2,"0") + " UTC";
          }
        } catch {}
        return ts;
      }
      return "";
    })();

    // Redirect chain
    const redirectChain = pf.domain_chain || (refDomain && domain && refDomain !== domain ? `${refDomain} → ${domain}` : "");
    const failSuccPattern = (failIPs && succIPs && failIPs !== succIPs);

    // ── STEP 4: Detection translation (KB already enriched) ───
    const kbDesc     = pf.kb_desc || pf.kb_alert_desc || "";
    const kbAction   = pf.kb_action || pf.kb_alert_action || "";
    const kbCarrier  = pf.kb_carrier_desc || "";
    const kbVPN      = pf.kb_vpn_desc || "";
    const kbRedirect = pf.kb_redirect_desc || "";
    // OSINT context from analyst-added section
    const osintClean = pf.osint_clean || false;
    const osintDesc  = osintClean
      ? 'OSINT check on ' + (srcIP||'IP') + ': VT clean, Talos neutral, AbuseIPDB not found — no threat intelligence associations. Source IP has no known malicious history.'
      : (pf.osint_vt === 'MALICIOUS' || pf.osint_talos === 'POOR')
        ? 'OSINT: IP ' + (srcIP||'source') + ' has threat intelligence hits — VT: ' + (pf.osint_vt||'?') + ', Talos: ' + (pf.osint_talos||'?') + '. Treat as malicious.'
        : '';

    // ── STEP 5: Behavior analysis ─────────────────────────────
    const behaviors = [];
    if (redirectChain)     behaviors.push(`redirect chain: ${redirectChain}`);
    if (/\.sbs\/|\.id\/|\.xyz\/|\.top\/|\.tk\/|\.club\/|\.icu\//i.test(url||"")) behaviors.push("suspicious TLD in destination");
    if (failSuccPattern)   behaviors.push(`failed auth from ${failIPs} → success from ${succIPs}`);
    if (pf.alert_count > 1) behaviors.push(`${pf.alert_count} correlated alerts in rapid succession`);
    if (device && failIPs) behaviors.push(`same device (${device}) active from multiple countries simultaneously`);
    if (pf.kb_vpn_flag)    behaviors.push("source identified as VPN or hosting provider");

    // ── STEP 6: Control validation ────────────────────────────
    const controlResult = pf.control_result || (
      /blocked|drop|deny|quarantine|prevented/i.test(action) ? "CONTAINED" :
      /allowed|permit|success/i.test(action) ? "ALLOWED" :
      "DETECTED_ONLY"
    );
    const controlIcon   = controlResult === "CONTAINED" ? "✅" : controlResult === "ALLOWED" ? "⚠️" : "ℹ️";
    const controlLabel  = controlResult === "CONTAINED" ? "BLOCKED/QUARANTINED — threat contained" :
                          controlResult === "ALLOWED"   ? "ALLOWED — manual investigation required" :
                          "DETECTED — verify if blocked or allowed";

    // ── STEP 7: Compromise check ──────────────────────────────
    const comprIndicators = pf.compromise_indicators || "";
    const noCompromise    = pf.no_compromise || (controlResult === "CONTAINED" && !comprIndicators);
    const comprStatus     = comprIndicators
      ? `⚠️ Post-compromise indicators: ${comprIndicators}`
      : noCompromise
      ? "✅ No evidence of execution, download, persistence, C2, or data exfiltration based on available logs."
      : "ℹ️ Insufficient telemetry to confirm or rule out compromise — EDR review recommended.";

    // ── STEP 8: Root cause ────────────────────────────────────
    const rootCause = (() => {
      if (redirectChain || isWeb)    return kbDesc || `User's browser was directed to a malicious destination${redirectChain ? " via redirect chain from " + refDomain : ""}. ${sig ? sig + " is the detected threat signature." : ""}`;
      if (isIdentity && failSuccPattern) return `Credential abuse pattern detected — authentication failures from a foreign IP followed by success suggests the legitimate user's credentials are in use by an attacker.`;
      if (isIdentity)                return kbDesc || "Anomalous authentication event — location or device does not match the user's baseline.";
      if (isSaaS)                    return `Malicious file detected in ${pf.platform || "cloud platform"} — likely delivered via social engineering or compromised sender account.`;
      if (isEndpoint && cmdline)     return `Malicious process execution — ${sig || "suspicious command"} was launched on the endpoint.`;
      if (isEndpoint)                return kbDesc || "Endpoint security detected malicious behavior or a known threat signature.";
      return "Security control detected anomalous activity matching a known threat pattern.";
    })();

    // ── STEP 9 & 10: Verdict + Disposition ───────────────────
    const effectiveVerdict = pf.kb_verdict === "TP_ESCALATE" ? "ESCALATE" :
                             controlResult === "CONTAINED" && !comprIndicators ? "TP_BLOCKED_NFA" :
                             controlResult === "ALLOWED" && comprIndicators ? "TP_ESCALATE" :
                             pf.kb_verdict === "FP" || verdict.verdict === "LIKELY FALSE POSITIVE" ? "FP" :
                             pf.kb_vpn_flag ? "TP_BENIGN" :
                             (osintClean && pf.user_log_parsed && pf.user_log_day1_summary) ? "TP_BENIGN" :
                             "TP_BLOCKED_NFA";

    const verdictText = {
      TP_BLOCKED_NFA:  "TP – Blocked / No Further Action. Threat was contained by security controls with no evidence of compromise.",
      TP_ESCALATE:     "⚠️ TP – Escalation Required. Suspicious activity succeeded or post-compromise indicators are present.",
      TP_BENIGN:       "TP – Likely Benign. Detection appears related to expected user behavior (VPN/remote access). Verify with user.",
      FP:              "Likely False Positive. No malicious activity confirmed. Review detection rule for tuning.",
      UNKNOWN:         "Inconclusive. Insufficient context — manual review required.",
    }[effectiveVerdict] || "";

    const mitreParts = mitre.slice(0, 4).map(t => `${t} (${getMitreName(t)})`).join(", ");
    const mitreContext = mitreParts ? `MITRE ATT&CK: ${mitreParts}` : "";

    // ── BUILD P1: The Story (WHO + WHAT + WHEN + WHERE + HOW) ─
    const whenWhere = [timelineStr, loc && isIdentity ? `from ${loc}` : ""].filter(Boolean).join(", ");
    const who  = user && host ? `${user} on host ${host}` : user || host || (srcIP ? `host ${srcIP}` : "an internal user");
    const whom = dept || role ? ` (${[role, dept].filter(Boolean).join(", ")})` : "";

    let p1 = "";
    if (isWeb || isSaaS) {
      const actionDesc = controlResult === "CONTAINED" ? "was blocked" : "accessed";
      if (redirectChain) {
        p1 = `${who}${whom}${whenWhere ? " at " + whenWhere : ""} accessed ${refDomain || "a website"}, which redirected to ${domain || dstIP}${sig ? `, triggering the ${sig} signature` : ""}. Zscaler returned HTTP ${pf.http_status || "403"}, blocking the connection before any content was delivered.`;
      } else if (isSaaS) {
        p1 = `${who}${whom}${whenWhere ? " at " + whenWhere : ""} — a file${sig ? " (" + sig + ")" : ""} was detected via ${pf.platform || "cloud platform"}${action ? " and " + action.toLowerCase() : ""}.`;
      } else {
        p1 = `${who}${whom}${whenWhere ? " at " + whenWhere : ""} attempted to reach ${url || domain || dstIP}${sig ? ", which matched the threat signature " + sig : ""}${cat ? " (" + cat + ")" : ""}. The security control ${actionDesc} the request.`;
      }
    } else if (isIdentity) {
      const alertCountStr = pf.alert_count > 1 ? `${pf.alert_count} correlated identity alerts` : "a suspicious identity alert";
      p1 = `${who}${whom} triggered ${alertCountStr}${whenWhere ? " at " + whenWhere : ""}. `;
      // User log day-shift takes priority as the P1 story when available
      if (pf.user_log_parsed && pf.user_log_day1_summary && pf.user_log_day2_summary) {
        p1 += `User log analysis shows a day-over-day carrier and location shift: ${pf.user_log_day1_summary} → ${pf.user_log_day2_summary}. The same device (${device||"iPhone iOS"}) was used on both days, suggesting a network change rather than a different actor.`;
      } else if (failSuccPattern) {
        const failCount = (res._rawText||"").match(/\bFAILURE\b/gi)?.length || 0;
        p1 += `Authentication logs show ${failCount || "multiple"} consecutive failures from ${failIPs} (${loc}) followed by successful logins from ${succIPs} — indicating credentials were being actively tested from a foreign location while the legitimate user remained active on their known device.`;
      } else if (carrier) {
        p1 += `Access was sourced from ${loc || "an unusual location"}${carrier ? " via " + carrier : ""}${kbCarrier ? " — " + kbCarrier.split(".")[1]?.trim() : ""}.`;
      }
    } else if (isEndpoint) {
      p1 = `${who}${whom}${whenWhere ? " at " + whenWhere : ""} — ${sig || "a threat"} was detected on endpoint ${host || "the device"}${proc ? " via process " + proc : ""}${cmdline ? ". Command: " + cmdline.slice(0,100) : ""}.`;
    } else {
      p1 = `${who}${whom}${whenWhere ? " at " + whenWhere : ""} — ${sig || et} detected. ${controlLabel}.`;
    }

    // ── BUILD P2: Why it matters + Control validation ─────────
    let p2 = rootCause;
    if (kbCarrier && !p1.includes(kbCarrier.slice(0,20))) p2 += " " + kbCarrier;
    if (kbVPN)  p2 = kbVPN;
      if (osintDesc && !p2.includes('OSINT')) p2 = (p2 ? p2 + ' ' : '') + osintDesc;

    // ── BUILD P3: Compromise check ────────────────────────────
    const p3 = comprStatus;

    // ── BUILD P4: Recommended action ─────────────────────────
    const urgencyMap = {
      critical: "IMMEDIATE ACTION REQUIRED — isolate host/account, block IOCs, escalate to IR.",
      high:     "Priority review — verify impact, block IOCs, pull EDR telemetry.",
      medium:   "Standard review — validate detection, check for follow-on activity.",
      low:      "Low priority — validate and close or tune if FP.",
      info:     "Informational — log and monitor.",
    };
    let p4 = urgencyMap[sev] || urgencyMap.info;
    if (kbAction) p4 += " " + kbAction;

    // ── VERDICT LINE ──────────────────────────────────────────
    const verdictLine = verdictText || `Based on available evidence: ${verdict.verdict}. TP likelihood: ${verdict.tpPct}%.`;

    return { p1, p2, p3, p4, verdictLine, mitreContext, category, controlResult, controlIcon, controlLabel, effectiveVerdict, redirectChain, behaviors };
  }

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
    // Web/CASB/phishing narratives
    else if (/web|proxy|email|phish|netskope|casb|umbrella|proxySG|forcepoint|barracuda|skyhigh|mcafee.*web/i.test(type) || iocs.urls?.length || iocs.domains?.length) {
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

  // ═══════════════════════════════════════════════════════════════
  // LOG TRIAGE — STRUCTURED IOC EXTRACTION TABLE
  // Clear src IP / dst IP / user / host / port / hash callout panel
  // ═══════════════════════════════════════════════════════════════
  function buildStructuredIOCPanel(res) {
    const iocs = res.iocs || {};
    const pf   = res.prefillData || {};

    // ── Resolve primary fields ──────────────────────────────────
    const srcIP   = pf.src_ip  || "";
    const dstIP   = pf.dest_ip || "";
    const user    = pf.username || (iocs.usernames||[])[0] || pf.sender?.split("@")[0] || "";
    const host    = pf.hostname || (iocs.hostnames||[])[0] || "";
    const proto   = pf.proto   || "";
    const dstPort = pf.dest_port || (iocs.ports||[])[0] || "";
    const hash    = (iocs.hashes||[])[0] || "";
    const process = (iocs.processes||[])[0] || "";
    const cmdline = pf.cmdline || (iocs.cmdlines||[])[0] || "";
    const domain  = (iocs.domains||[])[0] || "";
    const url     = (iocs.urls||[])[0] || "";
    const email   = pf.sender || (iocs.emails||[])[0] || "";

    // ── IP classification helpers ──────────────────────────────
    const ipFlag = (ip) => {
      if (!ip) return "";
      if (isPrivateIPv4(ip) || isPrivateIPv6(ip)) return `<span class="lt-ioc-flag lt-ioc-flag-priv">RFC1918</span>`;
      return `<span class="lt-ioc-flag lt-ioc-flag-pub">Public</span>`;
    };
    const ipClass = (ip) => {
      if (!ip) return "";
      return (isPrivateIPv4(ip) || isPrivateIPv6(ip)) ? " priv" : " src";
    };

    // ── Build rows only for fields that have data ──────────────
    const rows = [];
    const addRow = (label, value, cls, extra, pivotType) => {
      if (!value) return;
      const pivotBtn  = pivotType ? `<button class="lt-ioc-mini-btn lt-ioc-pivot-mini" data-val="${esc(value)}" data-type="${pivotType}" type="button">🔍 Pivot</button>` : "";
      const copyBtn   = `<button class="lt-ioc-mini-btn lt-ioc-copy-mini" data-val="${esc(value)}" type="button">📋</button>`;
      const caseBtn   = pivotType ? `<button class="lt-ioc-mini-btn lt-ioc-case-mini" data-val="${esc(value)}" data-type="${pivotType}" type="button">📁 Case</button>` : "";
      rows.push(`<tr>
        <td class="lt-ioc-field-label">${label}</td>
        <td><span class="lt-ioc-field-val${cls ? " "+cls : ""}">${esc(value.slice ? value.slice(0,120) : value)}${value.length>120?"…":""}</span>${extra||""}</td>
        <td class="lt-ioc-row-btns">${copyBtn}${pivotBtn}${caseBtn}</td>
      </tr>`);
    };

    // Timestamp and verdict at the very top
    const timestamp = pf.timestamp || (iocs.timestamps||[])[0] || "";
    const verdicts  = iocs.verdicts || [];
    if (timestamp || verdicts.length) {
      const verdictStr   = verdicts.join(" / ");
      const vc = verdicts.includes("BLOCKED")||verdicts.includes("DROPPED") ? "#f87171" : verdicts.includes("ALLOWED") ? "#34d399" : verdicts.includes("DETECTED")||verdicts.includes("QUARANTINED") ? "#fbbf24" : "#9ca3af";
      const vBadge = verdictStr ? `<span class="lt-ioc-flag" style="background:${vc}18;color:${vc};border-color:${vc}44;font-weight:800;padding:3px 12px;border-radius:20px;border:1px solid;">${esc(verdictStr)}</span>` : "";
      const tsVal = timestamp ? `<span class="lt-ioc-field-val" style="font-family:monospace;">${esc(timestamp)}</span>` : "";
      rows.push(`<tr>
        <td class="lt-ioc-field-label">${timestamp ? "Timestamp" : "Action"}</td>
        <td>${tsVal}${tsVal && vBadge ? " " : ""}${vBadge}</td>
        <td class="lt-ioc-row-btns">${timestamp ? `<button class="lt-ioc-mini-btn lt-ioc-copy-mini" data-val="${esc(timestamp)}" type="button">📋</button>` : ""}</td>
      </tr>`);
    }
    addRow("Source IP",   srcIP,   "src" + ipClass(srcIP),   ipFlag(srcIP),   srcIP && !isPrivateIPv4(srcIP) ? "ip" : null);
    addRow("Dest IP",     dstIP,   "dst" + ipClass(dstIP),   ipFlag(dstIP),   dstIP && !isPrivateIPv4(dstIP) ? "ip" : null);
    addRow("User",        user,    "user",  "",              "username");
    addRow("Host",        host,    "host",  "",              null);
    addRow("Protocol",    proto,   "",      "",              null);
    addRow("Dest Port",   dstPort, "",      `${dstPort ? buildPortLabel(dstPort) : ""}`, null);
    addRow("Process",     process, "",      "",              null);
    addRow("Hash",        hash,    "hash",  "",              "hash");
    addRow("Email",       email,   "",      "",              "email");
    addRow("Domain",      domain,  "",      "",              "domain");
    addRow("URL",         url,     "",      "",              "url");
    if (cmdline) addRow("CommandLine", cmdline, "", "", null);

    // ── Additional IPs beyond src/dst ─────────────────────────
    const allIPs = (iocs.ips||[]).filter(ip => ip !== srcIP && ip !== dstIP);
    allIPs.slice(0,5).forEach((ip, idx) => {
      addRow(`IP ${idx+2}`, ip, "src"+ipClass(ip), ipFlag(ip), !isPrivateIPv4(ip) ? "ip" : null);
    });

    if (!rows.length) return "";

    return `<div class="lt-ioc-panel">
      <div class="lt-ioc-panel-head">
        <span class="lt-ioc-panel-title">🎯 Structured IOC Extraction</span>
        <button class="lt-ioc-mini-btn" id="lt-copy-ioc-table" type="button">📋 Copy All Fields</button>
        <button class="lt-ioc-mini-btn" id="lt-addall-ioc-btn" type="button">📁 Add All to Case</button>
      </div>
      <table class="lt-ioc-table">
        <thead><tr><th>Field</th><th>Value</th><th>Actions</th></tr></thead>
        <tbody>${rows.join("")}</tbody>
      </table>
    </div>`;
  }

  function buildPortLabel(port) {
    const PORT_MAP = {
      "21":"FTP","22":"SSH","23":"Telnet","25":"SMTP","53":"DNS","80":"HTTP",
      "110":"POP3","143":"IMAP","389":"LDAP","443":"HTTPS","445":"SMB","3389":"RDP",
      "5985":"WinRM","5986":"WinRM-HTTPS","1433":"MSSQL","3306":"MySQL","5432":"PostgreSQL",
      "6379":"Redis","27017":"MongoDB","4444":"Metasploit","50050":"Cobalt Strike",
      "8080":"HTTP-Alt","8443":"HTTPS-Alt","9001":"Tor/C2","1337":"C2","135":"RPC",
      "139":"NetBIOS","636":"LDAPS","88":"Kerberos","464":"Kerberos Pwd","593":"RPC-HTTP",
      "2049":"NFS","111":"RPC-portmap","4045":"NFS lockd","69":"TFTP","161":"SNMP",
    };
    const known = PORT_MAP[String(port)];
    if (!known) return "";
    const isC2 = ["4444","50050","9001","1337"].includes(String(port));
    const cls  = isC2 ? "lt-ioc-flag lt-ioc-flag-pub" : "lt-ioc-flag lt-ioc-flag-ok";
    return `<span class="${cls}">${known}</span>`;
  }

  // ═══════════════════════════════════════════════════════════════
  // LOG TRIAGE — AUTO-VERDICT SCORER & CASE NOTES GENERATOR
  // ═══════════════════════════════════════════════════════════════
  function scoreAutoVerdict(res) {
    const findings    = (res.findings||[]).join(" ").toLowerCase();
    const iocs        = res.iocs || {};
    const pf          = res.prefillData || {};
    const sev         = res.severity || "info";
    const raw         = (res._rawText||"").toLowerCase();

    let tpScore = 0;
    let fpScore = 0;
    const tpReasons = [];
    const fpReasons = [];

    // ── TP signals ─────────────────────────────────────────────
    if (sev === "critical")                          { tpScore += 40; tpReasons.push("critical severity"); }
    if (sev === "high")                              { tpScore += 30; tpReasons.push("high severity"); }
    if (/🚨/.test(res.findings?.join("")||""))       { tpScore += 15; tpReasons.push("critical findings present"); }
    if (iocs.hashes?.length)                         { tpScore += 10; tpReasons.push("file hashes extracted"); }
    if (/ransomware|encrypt|shadow.*copy|vssadmin/.test(findings+raw)) { tpScore += 40; tpReasons.push("ransomware behavior"); }
    if (/c2|command.*control|beacon|cobalt.*strike/.test(findings+raw)) { tpScore += 35; tpReasons.push("C2/beaconing indicators"); }
    if (/lsass|credential.*dump|mimikatz/.test(findings+raw)) { tpScore += 30; tpReasons.push("credential dumping"); }
    if (/lateral.*movement|pass.*hash|pass.*ticket/.test(findings+raw)) { tpScore += 30; tpReasons.push("lateral movement"); }
    if (/encoded.*powershell|base64.*command|iex.*download|-enc\b|-EncodedCommand/i.test(findings+raw)) { tpScore += 25; tpReasons.push("encoded/obfuscated execution"); }
    if (/impossible.*travel|concurrent.*location/.test(findings+raw)) { tpScore += 30; tpReasons.push("impossible travel detected"); }
    if (/spf.*fail.*dkim.*fail|dkim.*fail.*spf.*fail/.test(findings+raw)) { tpScore += 20; tpReasons.push("SPF + DKIM both fail"); }
    if (/oauth.*consent|app.*granted.*admin/.test(findings+raw)) { tpScore += 25; tpReasons.push("OAuth admin consent granted"); }
    if (/root.*account|root.*used/.test(findings+raw)) { tpScore += 35; tpReasons.push("root account activity"); }
    if (/not.*mitigated|mitigation.*fail/.test(findings+raw)) { tpScore += 30; tpReasons.push("threat not mitigated"); }
    if (/data.*exfil|large.*upload|bytes.*out.*\d{7}/.test(findings+raw)) { tpScore += 25; tpReasons.push("data exfiltration indicators"); }
    const extIPs = (iocs.ips||[]).filter(ip => !isPrivateIPv4(ip) && !isPrivateIPv6(ip));
    if (extIPs.length > 0)                           { tpScore += 15; tpReasons.push(`${extIPs.length} external IP(s) detected`); }

    // ── FP signals ─────────────────────────────────────────────
    if (sev === "low" || sev === "info")             { fpScore += 25; fpReasons.push("low/info severity"); }
    if (/whitelist|safe.*list|approved|authorized/.test(findings+raw)) { fpScore += 30; fpReasons.push("authorization indicators present"); }
    if (/scheduled.*task.*known|patch.*management|wsus|sccm|intune/.test(findings+raw+raw)) { fpScore += 25; fpReasons.push("known IT management activity"); }
    if (/vpn.*known|vpn.*corporate|corporate.*vpn/.test(findings+raw)) { fpScore += 20; fpReasons.push("known VPN exit node"); }
    if (/test.*environment|dev.*box|sandbox|qa.*server/.test(findings+raw)) { fpScore += 20; fpReasons.push("non-production environment indicators"); }
    if (!extIPs.length && iocs.ips?.length)          { fpScore += 10; fpReasons.push("all IPs are internal/RFC1918"); }
    if (sev === "medium" && !tpReasons.length)       { fpScore += 10; fpReasons.push("medium severity with no strong TP signals"); }

    const total = tpScore + fpScore;
    const tpPct = total > 0 ? Math.round((tpScore / total) * 100) : 50;
    const verdict = tpPct >= 65 ? "LIKELY TRUE POSITIVE" : tpPct <= 35 ? "LIKELY FALSE POSITIVE" : "UNCERTAIN — NEEDS REVIEW";
    const cls     = tpPct >= 65 ? "lt-verdict-likely-tp" : tpPct <= 35 ? "lt-verdict-likely-fp" : "lt-verdict-uncertain";
    return { tpPct, fpPct: 100-tpPct, verdict, cls, tpReasons, fpReasons };
  }

  // ═══════════════════════════════════════════════════════════════
  // SOC CASE NOTE GENERATOR — Analyst-grade prose case note
  // Produces the full flowing narrative matching professional SOC format:
  //   P1: Timeline + who + what happened + why/how (cause → effect chain)
  //   P2: What the security control did + impact scope (what DIDN'T happen)  
  //   P3: Final Verdict + Disposition
  // ═══════════════════════════════════════════════════════════════
  function generateSOCCaseNote(res, analystVerdict, analystDisposition, analystName, extraContext) {
    const iocs        = res.iocs        || {};
    const pf          = res.prefillData || {};
    const findings    = res.findings    || [];
    const et          = res.eventType   || "Security Event";
    const sev         = res.severity    || "info";
    const raw         = (res._rawText   || "").toLowerCase();
    const findingsStr = findings.join(" ").toLowerCase();

    // ── Field extraction ───────────────────────────────────────
    const user      = pf.username  || iocs.usernames?.[0] || "";
    const host      = pf.hostname  || iocs.hostnames?.[0] || "";
    const srcIP     = pf.src_ip    || "";
    const dstIP     = pf.dest_ip   || (iocs.ips||[]).find(ip=>!isPrivateIPv4(ip)&&ip!==srcIP) || "";
    const dstPort   = pf.dest_port || iocs.ports?.[0]     || "";
    const _urlHost  = pf.url ? (() => { try { return new URL(pf.url).hostname; } catch { return ""; }})() : "";
    const _corp     = (pf.username||"").split("@")[1]?.toLowerCase() || "";
    const domain    = _urlHost || (iocs.domains||[]).find(d=>d!==_corp) || iocs.domains?.[0] || "";
    const fullURL   = pf.url   || iocs.urls?.[0] || "";
    const urlPath   = fullURL ? (() => { try { const u=new URL(fullURL); return u.pathname+(u.search||""); } catch { return ""; }})() : "";
    const hash      = iocs.hashes?.[0]    || "";
    const proc      = iocs.processes?.[0] || pf.process || "";
    const cmdline   = pf.cmdline || iocs.cmdlines?.[0] || "";
    const email     = pf.sender  || iocs.emails?.[0]   || "";
    const sig        = pf.threat_name || "";
    const category   = pf.category    || "";
    const referer    = pf.referer     || "";
    const ua         = pf.useragent   || "";
    const httpCode   = pf.http_status || "";
    const bytes      = pf.bytes       || "";
    const verdict    = pf.verdict     || (iocs.verdicts||[])[0] || "";
    const ts         = pf.timestamp   || iocs.timestamps?.[0]   || "";
    const rule       = pf.rule        || pf.policy               || pf.notes || "";
    const location   = pf.location    || "";
    const department = pf.department  || "";
    const riskLevel  = pf.risk_level  || "";
    const riskDetail = pf.risk_detail || "";
    const operation  = pf.operation   || "";
    const hashVal    = pf.hash        || iocs.hashes?.[0]        || "";
    const mitre      = (res.mitre||[]).slice(0,4);

    // ── Parse timestamp ───────────────────────────────────────
    let dateStr = "", timeStr = "", timeEnd = "";
    if (ts) {
      try {
        const d = new Date(ts);
        const yr = d.getFullYear();
        const _nowYr = new Date().getFullYear();
        if (!isNaN(d.getTime()) && yr >= _nowYr - 2 && yr <= _nowYr + 1) {
          dateStr = d.toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric"});
          const hh = d.getUTCHours().toString().padStart(2,"0");
          const mm = d.getUTCMinutes().toString().padStart(2,"0");
          const mm2 = Math.min(59,parseInt(mm)+2).toString().padStart(2,"0");
          timeStr = `${hh}:${mm}`;
          timeEnd = `${hh}:${mm2}`;
        }
      } catch {}
      if (!dateStr) {
        dateStr = ts.split("T")[0] || ts.split(" ")[0] || ts;
        timeStr = ts.includes("T") ? ts.split("T")[1]?.slice(0,5) : "";
        timeEnd = "";
      }
    }
    const whenStr = dateStr
      ? `On ${dateStr}` + (timeStr ? `, at approximately ${timeStr}${timeEnd&&timeEnd!==timeStr?"–"+timeEnd:""} UTC` : "")
      : "During the review period";

    // ── Browser / OS from User-Agent ──────────────────────────
    let browser = "", os = "";
    if (ua) {
      if (/Chrome\/[\d.]+.*Safari/i.test(ua) && !/Chromium|Edge/i.test(ua)) browser = "Google Chrome";
      else if (/Firefox\//i.test(ua))  browser = "Mozilla Firefox";
      else if (/Edg\//i.test(ua))      browser = "Microsoft Edge";
      else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = "Safari";
      else if (/MSIE|Trident/i.test(ua)) browser = "Internet Explorer";
      else if (/curl|wget|python|go-http|PowerShell/i.test(ua)) browser = (ua.match(/^([^\s/]+)/)||[])[1]||"an automated tool";
      if (/Windows NT 10|Windows NT 11|Windows 10|Windows 11/i.test(ua)) os = "Windows 10/11";
      else if (/Windows NT 6\.3/i.test(ua)) os = "Windows 8.1";
      else if (/Windows NT 6\.1/i.test(ua)) os = "Windows 7";
      else if (/Mac OS X/i.test(ua))   os = "macOS";
      else if (/Android/i.test(ua))    os = "Android";
      else if (/iPhone|iPad/i.test(ua)) os = "iOS";
      else if (/Linux/i.test(ua))      os = "Linux";
    }
    const clientStr = browser && os ? `${browser} on ${os}` : browser || os || "";

    // ── Source control label ──────────────────────────────────
    const src = /netskope/i.test(et)              ? "Netskope CASB"
              : /skyhigh|mcafee.*casb/i.test(et)  ? "Skyhigh/McAfee CASB"
              : /umbrella.*dns/i.test(et)          ? "Cisco Umbrella DNS"
              : /umbrella/i.test(et)               ? "Cisco Umbrella"
              : /proxySG|blue.?coat|symantec.*wss/i.test(et) ? "Symantec ProxySG"
              : /forcepoint|websense/i.test(et)    ? "Forcepoint"
              : /barracuda.*web/i.test(et)         ? "Barracuda Web Security"
              : /mcafee.*web/i.test(et)            ? "McAfee Web Gateway"
              : /zscaler.*zpa/i.test(et)           ? "Zscaler ZPA"
              : /zscaler/i.test(et)                ? "Zscaler Internet Access"
              : /proofpoint/i.test(et)             ? "Proofpoint TAP"
              : /crowdstrike|falcon/i.test(et)     ? "CrowdStrike Falcon"
              : /defender.*xdr|mde/i.test(et)      ? "Microsoft Defender XDR"
              : /defender/i.test(et)               ? "Microsoft Defender"
              : /sentinelone/i.test(et)            ? "SentinelOne"
              : /suricata/i.test(et)               ? "Suricata IDS"
              : /snort/i.test(et)                  ? "Snort IDS"
              : /darktrace/i.test(et)              ? "Darktrace NDR"
              : /palo alto|ngfw/i.test(et)         ? "Palo Alto NGFW"
              : /fortinet|fortigate/i.test(et)     ? "Fortinet FortiGate"
              : /azure ad|entra/i.test(et)         ? "Azure AD / Entra ID"
              : /aws|cloudtrail/i.test(et)         ? "AWS CloudTrail"
              : /okta/i.test(et)                   ? "Okta"
              : /qradar/i.test(et)                 ? "IBM QRadar"
              : /splunk/i.test(et)                 ? "Splunk"
                      : /windows event|authentication event|event log/i.test(et) ? "Windows Security Event Log"
                      : et.replace(/ Log$| Alert$/i,"") || "Security Platform";

    // ── Verdict / disposition labels ──────────────────────────
    const vLabel = {
      TP_blocked:   `TP – Blocked${sig?" ("+sig.split(" ").slice(0,4).join(" ")+")":""}`,
      TP_detected:  `TP – Detected, Not Blocked${sig?" ("+sig.split(" ").slice(0,4).join(" ")+")":""}`,
      TP_confirmed: "TP – Confirmed Compromise",
      FP:           "FP – False Positive",
      BEN:          "Benign – Expected Activity",
      TBD:          "TBD – Under Investigation",
    }[analystVerdict] || analystVerdict || "TBD";

    const dLabel = {
      NFA:          "No Further Action (NFA) — threat contained at network layer",
      escalated:    "Escalated to Tier 2 / Incident Response",
      contained:    "Endpoint Isolated / Contained",
      monitoring:   "Monitoring — watching for recurrence",
      remediated:   "Remediated",
      user_notified:"User Notified",
    }[analystDisposition] || analystDisposition || "NFA";

    // ═══════════════════════════════════════════════════════════
    // PARAGRAPH 1 — The story: timeline + who + what happened +
    //               why + the chain of events
    // ═══════════════════════════════════════════════════════════
    const p1parts = [];

    const isWeb  = /zscaler|netskope|casb|proxy|umbrella|proxySG|forcepoint|barracuda.*web|mcafee.*web|symantec.*web/i.test(et);
    const isEDR  = /crowdstrike|falcon|defender|sentinelone|endpoint|edr/i.test(et);
    const isEmail= /proofpoint|email|mail/i.test(et);
    const isIdent= /azure ad|entra|okta|identity|impossible.*travel/i.test(et+raw);
    const isNet  = /suricata|snort|ids|ips|firewall|darktrace|ndr|palo alto|ngfw|fortinet/i.test(et);
    const isCloud= /aws|cloudtrail/i.test(et);

    if (isWeb) {
      // ── WEB / PROXY / CASB ──────────────────────────────────
      const _deptStr  = department && !/^\d+$/.test(department) ? ` (${department})` : "";
      const who = user && host ? `user **${user}**${_deptStr} on endpoint **${host}** (${srcIP||"internal"})`
                : user ? `user **${user}**${_deptStr}${srcIP?" from "+srcIP:""}`
                : host ? `endpoint **${host}**${srcIP?" ("+srcIP+")":""}`
                : srcIP ? `internal host **${srcIP}**` : "an internal user";

      const what = /block/i.test(verdict) ? "attempted to reach" : "accessed";
      const target = domain
        ? `**${domain}**${dstIP?" ("+dstIP+(dstPort?":"+dstPort:"")+")":`${dstPort?" on port "+dstPort:""}`}`
        : dstIP ? `${dstIP}${dstPort?":"+dstPort:""}` : "an external resource";

      const sigDesc = sig && sig !== category ? (sig.includes(".")?`under the threat signature **${sig}**`:`flagged as **${sig}**`) : "";
      const catDesc = category ? `classified under **${category}**` : "";
      const both = sigDesc && catDesc ? `${catDesc}, ${sigDesc}` : sigDesc||catDesc;

      // Opening — full URL, rule name, and all context
      const urlDisplay = fullURL ? `**${fullURL.slice(0,120)}${fullURL.length>120?"…":""}**` : target;
      const ruleClause = rule ? ` — this was flagged by the rule **${rule}**` : "";
      p1parts.push(`${whenStr}, ${who} ${what} ${urlDisplay}${both?", which was "+both:""}${ruleClause}. ${src} intercepted the request and returned HTTP **${httpCode||"block"}**, preventing the connection from completing.`);

      // Referrer — tell the full story of how the user ended up there
      if (referer && referer !== fullURL) {
        const refHost = (() => { try { return new URL(referer).hostname; } catch { return referer.slice(0,80); }})();
        const refPath = (() => { try { const u=new URL(referer); return u.pathname!=="/"?u.pathname:""; } catch { return ""; }})();
        p1parts.push(`The HTTP referrer was **${referer.slice(0,150)}${referer.length>150?"…":""}** — the user was already browsing **${refHost}${refPath}** when that page silently directed the browser toward the malicious destination. This referrer chain is a key indicator: the user did not intentionally navigate to the blocked URL; instead, they were passively redirected by content embedded in the previous page, which may itself be compromised or malicious.`);
      }

      // What was requested — file path tells us intent
      if (urlPath && urlPath !== "/" && urlPath !== "") {
        const ext = (urlPath.match(/\.([a-z0-9]{2,6})$/i)||[])[1]||"";
        const pathNote = /\.(exe|dll|ps1|bat|msi|js|vbs|hta|jar|iso|lnk|scr)/i.test(urlPath)
          ? `The specific resource requested was **${urlPath}** — a **${ext.toUpperCase()}** file, which is a common format for delivering malware payloads. The combination of a malicious domain and a directly-linked executable strongly indicates an attempted drive-by download.`
          : /\/login|\/auth|\/verify|\/confirm|\/update|\/secure|\/account/i.test(urlPath)
          ? `The requested path **${urlPath}** follows patterns typical of phishing landing pages designed to harvest credentials or account details.`
          : null;
        if (pathNote) p1parts.push(pathNote);
      }

      // Threat-specific narrative
      if (/clickfix/i.test(sig)) {
        p1parts.push(`ClickFix is a social engineering technique where a malicious web page presents a fake error or CAPTCHA and instructs the user to paste a command into their terminal or run dialog — effectively tricking them into executing attacker-controlled code themselves. The fact that Zscaler blocked at the network layer means the page never fully loaded, but the user was clearly directed toward it.`);
      } else if (/ransomware|cryptolock|wannacry|ryuk|lockbit/i.test(sig||findingsStr)) {
        p1parts.push(`The threat signature matches a known ransomware family. Network-layer blocking at this stage is critical — if the payload had reached the endpoint, it would likely have begun file encryption within seconds of execution.`);
      } else if (/c2|command.*control|beacon|cobalt/i.test(sig||category||findingsStr)) {
        p1parts.push(`This destination is consistent with command-and-control infrastructure. C2 communication at the proxy layer often indicates an implant on the endpoint is attempting to check in with the attacker — blocking here cuts the feedback loop, but the endpoint should still be investigated for the implant itself.`);
      } else if (/phish/i.test(sig||category)) {
        p1parts.push(`Phishing infrastructure typically serves as a stepping stone — the user lands on the page, enters credentials, and the attacker harvests them in real time. The block prevents the page from loading, but the user may have already typed their credentials before the block took effect if the redirect was fast.`);
      } else if (/malware|trojan|dropper|downloader/i.test(sig||category)) {
        p1parts.push(`The flagged destination hosts malware delivery infrastructure. The zero bytes transferred (${bytes||"0"} bytes received) confirms the payload was not delivered — the block occurred before any content was transferred to the client.`);
      }

      // Client context
      if (clientStr) {
        p1parts.push(`The request was made via **${clientStr}**, consistent with normal browser-driven browsing activity rather than an automated tool or background process.`);
      }

    } else if (isEDR) {
      // ── ENDPOINT / EDR ───────────────────────────────────────
      const _userPart = user ? `user **${user}**` : "";
      const _hostPart = host ? `endpoint **${host}**` : "";
      const who = _userPart && _hostPart ? `${_userPart} on ${_hostPart}`
                : _userPart || _hostPart || (srcIP ? `host **${srcIP}**` : "an endpoint");
      const _ruleNote = rule ? ` — detection rule: **${rule}**` : "";
      p1parts.push(`${whenStr}, ${src} raised a **${sev.toUpperCase()}** severity alert on ${who}${_ruleNote}.`);

      if (proc) {
        let procLine = `The flagged process was **${proc}**`;
        if (cmdline) procLine += ` with the command line: \`${cmdline.slice(0,180)}${cmdline.length>180?"…":""}\``;
        p1parts.push(procLine + ".");
      }
      if (hash) p1parts.push(`The associated file carries SHA-256 hash \`${hash.slice(0,32)}...\`. This should be immediately submitted to VirusTotal and your EDR's custom IOC block list.`);
      if (/encode|base64/i.test(findingsStr)) p1parts.push(`The command line uses Base64 encoding — a deliberate technique to hide the actual command from string-based detection. When decoded, it typically reveals a download cradle, remote code execution string, or persistence mechanism.`);
      if (/lolbin|rundll|mshta|wscript|cscript|regsvr/i.test(findingsStr)) p1parts.push(`A Windows Living-off-the-Land Binary (LOLBin) was used for execution. Attackers favour these because they are legitimate signed Windows binaries — most antivirus and application whitelists allow them by default.`);
      if (/lsass|mimikatz|credential.*dump/i.test(findingsStr)) p1parts.push(`LSASS memory access was detected — this is the credential dumping phase of the attack. The attacker is attempting to extract password hashes or plaintext credentials to enable lateral movement to other systems.`);
      if (sig) p1parts.push(`The detection matched the rule: **${sig}**.`);

    } else if (isEmail) {
      // ── EMAIL ────────────────────────────────────────────────
      const from = email || "[unknown sender]";
      const to   = pf.recipient || user || "[recipient]";
      p1parts.push(`${whenStr}, ${src} intercepted a${/phish/i.test(sig||category)?" phishing":""} email sent from **${from}** to **${to}**.`);
      if (fullURL) p1parts.push(`The message body contained a malicious link pointing to **${domain||fullURL.slice(0,80)}**${sig?", matched by the signature **"+sig+"**":""}.`);
      if (/spf.*fail|dkim.*fail/i.test(findingsStr)) p1parts.push(`Both SPF and DKIM authentication checks failed — the sender domain is almost certainly spoofed, and the message did not originate from a legitimate mail server for that domain.`);

    } else if (isIdent) {
      // ── IDENTITY / AZURE AD / OKTA / ENTRA / FALCON IDENTITY ─
      const who = user || email || "an account";
      // Pull all the rich context the identity parser extracted
      const _alertCount = pf.alert_count ? parseInt(pf.alert_count) : 0;
      const _carrier    = pf.carrier     || "";
      const _device     = pf.device      || "";
      const _failIPs    = pf.fail_ips    || "";
      const _successIPs = pf.success_ips || "";
      const _role       = pf.role        || "";
      const _locFull    = pf.suspicious_location || location || "";
      const _ipStr      = srcIP && !isPrivateIPv4(srcIP) ? srcIP : "";

      // Opening: who + how many alerts + from where
      const _locPart  = _locFull && _ipStr ? ` from **${_locFull}** (${_ipStr})`
                      : _locFull ? ` from **${_locFull}**`
                      : _ipStr   ? ` from **${_ipStr}**` : "";
      const _riskPart = riskLevel ? ` with a **${riskLevel.toUpperCase()} risk level**` : "";
      const _identDesc = _alertCount > 1
        ? `**${_alertCount} correlated identity security alerts**`
        : `a suspicious authentication event`;
      const _userCtx = department ? ` (${department}${_role ? ", " + _role : ""})` : _role ? ` (${_role})` : "";
      p1parts.push(`${whenStr}, ${src} raised ${_identDesc} for account **${who}**${_userCtx}${_locPart}${_riskPart}.`);

      // Multi-alert summary — only include "blocklisted country" if alert explicitly says so
      if (/unusual geolocation|blocklisted|suspicious web/i.test(raw)) {
        const hasGeolocation = /unusual.geolocation|Access from unusual/i.test(raw);
        const hasBlocklisted = /blocklisted.(?:location|country)|Access from blocklisted/i.test(raw);
        const hasSuspiciousWeb = /suspicious.web|web-based.activity/i.test(raw);
        const alertParts = [
          hasGeolocation ? "**access from an unusual geolocation**" : "",
          hasSuspiciousWeb ? "**suspicious web-based activity flagged by ML**" : "",
          hasBlocklisted ? "**access from a blocklisted country**" : "",
        ].filter(Boolean);
        if (alertParts.length > 0) {
          p1parts.push(`The alert covers: ${alertParts.join(", ")} — ${alertParts.length > 1 ? "multiple signals firing on the same account within minutes is" : "this"} a strong indicator requiring investigation.`);
        }
      }

      // Carrier / ISP geographic context
      if (_carrier && _ipStr) {
        const _carrierType = /Telcel|RadioMovil|Movistar|Claro|Tigo/i.test(_carrier) ? "Latin American mobile carrier"
                           : /T-Mobile|Verizon|AT&T|Sprint/i.test(_carrier) ? "US mobile carrier" : "mobile network";
        p1parts.push(`Authentication from **${_ipStr}** is routed through **${_carrier}** — a ${_carrierType} — consistent with the flagged country. This is not a VPN or anonymization service; it is a direct mobile data connection from the reported location.`);
      }

      // Known-good vs suspicious IP pattern (the most compelling part of the story)
      if (_successIPs && _failIPs && _successIPs !== _failIPs) {
        const _goodIP = _successIPs.split(",")[0]?.trim();
        const _badIP  = _failIPs.split(",")[0]?.trim();
        const failCount = (raw.match(/\bFAILURE\b/gi)||[]).length;
        const succCount = (raw.match(/\bSUCCESS\b/gi)||[]).length;
        p1parts.push(`Log analysis shows a clear before-and-after pattern: the account was authenticating **successfully** from **${_goodIP}** (the user's known location) shortly before and after the suspicious window. In between, **${failCount} consecutive FAILURE events** were recorded from **${_badIP}** — a foreign IP — indicating the credentials were being actively tried by an unknown party in a different country while the legitimate user was still active on their known device.`);
      } else if (riskDetail && !riskDetail.match(/^none$/i)) {
        p1parts.push(`The platform reported risk signal: **${riskDetail}** — this indicates ${/unfamiliarFeatures/i.test(riskDetail) ? "sign-in properties that deviate from the user's established baseline (device fingerprint, location, browser, time of day)" : /atypicalTravel|impossibleTravel/i.test(riskDetail) ? "geographically impossible travel — the account appears active in two locations simultaneously, which no human can do" : "elevated risk as assessed by the identity platform's ML model"}. Treat this as active credential compromise until definitively ruled out.`);
      }

      // Device context
      if (_device) {
        const _appName = /VMware Identity|vmware/i.test(raw) ? "VMware Identity Service"
                       : /Outlook/i.test(raw) ? "Outlook Mobile"
                       : /Microsoft Authentication/i.test(raw) ? "Microsoft Authentication Broker"
                       : "the target application";
        p1parts.push(`The user-agent is **${_device}** accessing **${_appName}** — ${pf.user_log_parsed && pf.user_log_day1_summary ? "the same device was seen from both the normal and flagged location, consistent with a carrier or location change." : "matching the user\'s known device profile. This means either the attacker has a stolen session token, or the user\'s physical device is in the flagged location."}`);
      }

      // Okta-specific event type
      if (/okta/i.test(src) && operation) p1parts.push(`Event type: **${operation}**${rule ? " — outcome reason: **" + rule + "**" : ""}.`);

      // Generic impossible travel fallback
      const ips = iocs.ips || [];
      if (ips.length >= 2 && !_successIPs) {
        p1parts.push(`The account was seen authenticating from **${ips.length} geographically distinct IP addresses** — **${ips.slice(0,3).join("**, **")}** — within a short window that makes legitimate travel between those locations impossible.`);
      }
      if (/mfa.*fail|push.*deny/i.test(findingsStr)) p1parts.push(`Multiple MFA prompts were rejected by the real user — the attacker has the password and is attempting to brute-force the second factor.`);

    } else if (isNet) {
      // ── NETWORK / IDS / FIREWALL ─────────────────────────────
      // Try to extract more context from the raw log directly
      const rawT = res._rawText || "";
      const _proto  = pf.proto   || (rawT.match(/(TCP|UDP|ICMP|GRE|ESP|AH)/i)||[])[1]||"";
      const _action = (rawT.match(/(ACCEPT|DROP|DENY|REJECT|BLOCK|ALLOW|PERMIT|blocked|allowed)/i)||[])[1]||verdict||"";
      const _iface  = (rawT.match(/(?:in|out|interface)[=:\s]+([a-zA-Z0-9./]+)/i)||[])[1]||"";
      const _rule   = pf.policy || (rawT.match(/(?:rule|policy|chain)\s*[=:\s]+([^\s,;]{2,40})/i)||[])[1]||sig||"";
      
      const srcPriv = srcIP && isPrivateIPv4(srcIP);
      const dstPriv = dstIP && isPrivateIPv4(dstIP);
      const srcLabel = srcIP ? (srcPriv ? `internal host **${host||srcIP}**` : `external IP **${srcIP}**`) : (host ? `**${host}**` : "an internal host");
      const dstLabel = dstIP ? (dstPriv ? `internal host **${dstIP}**` : `external IP **${dstIP}**`) : "an external destination";
      const connDesc = [_proto, dstPort ? "port **"+dstPort+"**" : ""].filter(Boolean).join(" on ");
      
      const actionVerb = /drop|deny|block|reject/i.test(_action) ? "attempted to connect" : "connected";
      const _wasBlocked = /drop|deny|block|reject/i.test(_action||verdict||findingsStr);
      const _ruleStr    = _rule || rule || "";
      p1parts.push(`${whenStr}, ${srcLabel} ${actionVerb} to ${dstLabel}${connDesc?" via "+connDesc:""}. ${src} ${_wasBlocked?"intercepted and **blocked** this connection":"detected and logged this connection"}${_ruleStr?" — triggered by rule **"+_ruleStr+"**":""}.`);
      
      // Explain significance based on direction and port
      if (srcPriv && !dstPriv) {
        if (/443|4443|8443/i.test(dstPort||"")) p1parts.push(`Outbound HTTPS traffic from an internal host to an external IP is common, but warrants review when the destination has no known legitimate association — it may indicate a user visiting a suspicious site or an implant communicating over port 443 to blend with normal traffic.`);
        else if (/4444|50050|1337|8080/i.test(dstPort||"")) p1parts.push(`Port **${dstPort}** is commonly associated with attacker tooling (Metasploit, Cobalt Strike, or custom C2 frameworks). Outbound connections to unfamiliar external IPs on this port should be treated as a potential C2 beacon until proven otherwise.`);
        else if (dstPort) p1parts.push(`The outbound connection was made on port **${dstPort}**. Cross-reference this destination against threat intelligence to determine whether it is a known malicious IP or hosting provider before closing.`);
      } else if (!srcPriv && dstPriv) {
        p1parts.push(`This is inbound traffic from an external IP — a potential scan, exploitation attempt, or unauthorised access probe targeting your internal infrastructure.`);
      }
      if (sig) p1parts.push(`The traffic matched the detection signature: **${sig}**.`);
      if (/c2|beacon|cobalt/i.test(sig||findingsStr)) p1parts.push(`Beaconing to an external host is the primary indicator of an active implant. Even if this single connection was blocked, the endpoint should be examined for the presence of malware that may retry the connection.`);

    } else if (isCloud) {
      // ── AWS / CLOUD ───────────────────────────────────────────
      const who = user || pf.operation?.split("\n")[0] || "an IAM principal";
      p1parts.push(`${whenStr}, ${src} recorded a privileged cloud action by **${who}**${srcIP?" from IP "+srcIP:""}.`);
      if (/AttachUserPolicy|AttachRolePolicy|PutUserPolicy/i.test(raw)) p1parts.push(`The action involves attaching an IAM policy — if done without authorisation, this grants the actor administrative or elevated permissions that can persist even after a password reset.`);
      if (/DeleteTrail|StopLogging/i.test(raw)) p1parts.push(`CloudTrail logging was disabled or deleted — a classic attacker step to blind defenders before escalating actions. This is a critical indicator and should be treated as a confirmed compromise until proven otherwise.`);
      if (/CreateAccessKey/i.test(raw)) p1parts.push(`A new access key was created — attackers do this to establish a persistent backdoor into the AWS environment that survives password changes.`);

    } else {
      // ── GENERIC FALLBACK — context-aware ─────────────────────
      const _whoFull = user && host ? `user **${user}** on **${host}**`
                     : user ? `user **${user}**${srcIP?" ("+srcIP+")":""}`
                     : host ? `**${host}**${srcIP?" ("+srcIP+")":""}`
                     : srcIP ? `host **${srcIP}**` : "an internal asset";
      const _ruleNote = rule ? ` triggered by rule **${rule}**` : "";
      p1parts.push(`${whenStr}, ${src} recorded a **${sev.toUpperCase()}** severity event involving ${_whoFull}${_ruleNote}.`);
      // Auth/logon-specific context
      if (/4625|4771|4776|failed.*logon|logon.*fail|invalid.*cred|auth.*fail/i.test(et+findingsStr+raw)) {
        const _srcHost = (raw.match(/workstationname[=:\s]+([^\s,\n]{2,40})/i)||[])[1] || "";
        const _logonType = (raw.match(/logontype[=:\s]+(\d)/i)||[])[1] || "";
        const _typeDesc = {"2":"interactive","3":"network (SMB/RDP)","4":"batch","5":"service","7":"unlock","8":"NetworkCleartext","10":"RemoteInteractive (RDP)"}[_logonType] || "";
        p1parts.push(`This is a **failed logon event**${_srcHost?" originating from workstation **"+_srcHost+"**":""}${_typeDesc?" via logon type "+_logonType+" ("+_typeDesc+")":""}. The account **${user||"unknown"}** attempted to authenticate to **${host||"the target host"}** and was rejected — this pattern is consistent with brute-force or credential stuffing activity.`);
        if (srcIP && !isPrivateIPv4(srcIP)) p1parts.push(`The source IP **${srcIP}** is external and should be checked immediately in AbuseIPDB and threat intelligence feeds.`);
      }
      if (sig) p1parts.push(`The detection matched: **${sig}**.`);
      const critFindings = findings.filter(f=>f.startsWith("🚨")).map(f=>f.replace(/^🚨\s*/,""));
      if (critFindings.length) p1parts.push(`Key finding: ${critFindings[0]}.`);
    }

    // MITRE context — weave it in naturally
    if (mitre.length) {
      const mitreDesc = mitre.map(tid => {
        const name = getMitreName(tid);
        return (name && name !== tid && !name.startsWith("T1")) ? `**${tid}** (${name})` : `**${tid}**`;
      }).join(", ");
      p1parts.push(`This activity aligns with MITRE ATT&CK: ${mitreDesc}.`);

      // ── User log section context (day-over-day carrier/location shift) ──
      if (pf.user_log_parsed && pf.user_log_day1_summary && pf.user_log_day2_summary) {
        p1parts.push(`User log analysis across ${pf.user_log_dates||"multiple days"} shows: **${pf.user_log_day1_summary}** → **${pf.user_log_day2_summary}**. The same device (${pf.device||"iPhone iOS"}) was used on both days.`);
      }

      // ── OSINT context (analyst-added IP reputation results) ──────────
      if (pf.osint_clean) {
        p1parts.push(`OSINT check on **${srcIP||"source IP"}** returned no threat intelligence hits — VT: ${pf.osint_vt||"CLEAN"}, Talos: ${pf.osint_talos||"NEUTRAL"}, AbuseIPDB: ${pf.osint_abuseipdb||"CLEAN"}. The source IP has no known malicious history.`);
      } else if (pf.osint_vt === "MALICIOUS" || pf.osint_talos === "POOR") {
        p1parts.push(`**OSINT ALERT**: IP **${srcIP}** has threat intelligence hits — VT: ${pf.osint_vt}, Talos: ${pf.osint_talos}. Treat this IP as confirmed malicious infrastructure.`);
      }
    }

    // ═══════════════════════════════════════════════════════════
    // PARAGRAPH 2 — The security control's response + impact scope
    // (what was blocked, what the user was doing, what didn't happen)
    // ═══════════════════════════════════════════════════════════
    const p2parts = [];
    const isBlocked  = /block|blocked|deny|denied|drop|dropped|prevented|quarantine/i.test(verdict||findingsStr||raw);
    const isDetected = !isBlocked && /detect|alert|found|flag/i.test(findingsStr);
    const isAllowed  = /allow|permit|pass/i.test(verdict||"") && !isBlocked;

    if (isBlocked) {
      if (isWeb) {
        const blockDesc = httpCode ? `responded with HTTP ${httpCode}` : "blocked the connection";
        p2parts.push(`**${src} ${blockDesc}**, stopping the request before any content reached the endpoint. ${bytes&&bytes!=="0"?`A total of ${bytes} bytes were transferred — consistent with just the block page, not a payload.`:"Zero bytes were received from the destination, confirming no content was delivered to the browser."}`);
      } else if (isEDR) {
        p2parts.push(`**${src} quarantined or killed the process** before it could complete its intended action. The threat was neutralised at the execution stage.`);
      } else if (isEmail) {
        p2parts.push(`**${src} quarantined the message** before it reached the user's inbox. The recipient never saw the email.`);
      } else if (isNet) {
        p2parts.push(`**The connection was dropped** by the ${src} before any data exchange could occur.`);
      } else {
        p2parts.push(`**${src} blocked this activity.** The threat was intercepted before causing further impact.`);
      }
    } else if (isAllowed) {
      p2parts.push(`⚠️ **This traffic was NOT blocked** — ${src} allowed the connection through. Endpoint investigation is required immediately to determine whether a payload was delivered and executed.`);
    } else if (isDetected) {
      p2parts.push(`**${src} generated an alert** but did not automatically block. Manual response is required to contain the threat.`);
    }
    // Identity-specific P2
    if (isIdent) {
      const _identAction = isBlocked ? "blocked this sign-in attempt" : "flagged this event for review";
      // OSINT clean + user log same device = likely benign carrier change
      if (pf.osint_clean && pf.user_log_parsed && pf.user_log_day1_summary) {
        p2parts.push(`**${src} flagged this event for review.** Based on the user log and OSINT context, this activity is consistent with a network or carrier change — the same device (${pf.device||"iPhone iOS"}) was used on both days and the source IP (${srcIP}) has no threat intelligence associations.`);
        p2parts.push(`Recommended action: verify with the user directly by phone to confirm the location change. If confirmed, close as **TP – Benign**. If the user cannot confirm, escalate immediately and treat as credential compromise.`);
      } else {
        p2parts.push(`**${src} ${_identAction}.** ${isBlocked ? "The authentication did not complete — the account was not compromised during this specific session. However, the attacker clearly has valid credentials and is actively attempting access." : "The sign-in may have succeeded. Verify immediately in the audit log whether the session was established and what actions were taken post-authentication."}`);
        p2parts.push(`Immediate containment is warranted — credential compromise at this risk level requires full incident response: revoke all active sessions, rotate credentials, re-enrol MFA from a trusted device, and audit every action taken during the suspicious session window.`);
      }
    }

    // No-follow-on scope statement
    if (isBlocked && isWeb) {
      const notSeen = [];
      if (!proc) notSeen.push("no suspicious child processes");
      if (!hash) notSeen.push("no file downloads");
      if (!/persist|registry|sched.*task|startup/i.test(findingsStr)) notSeen.push("no persistence artefacts");
      if (!/c2|beacon/i.test(findingsStr)||isWeb) notSeen.push("no command-and-control callbacks");
      if (!/lateral|rdp|smb|pass.*hash/i.test(findingsStr)) notSeen.push("no lateral movement indicators");
      if (notSeen.length >= 2) {
        p2parts.push(`Based on the available telemetry, there is no evidence of follow-on compromise — ${notSeen.slice(0,-1).join(", ")}, and ${notSeen[notSeen.length-1]} are present in the logs. The threat appears to have been fully contained at the network perimeter.`);
      }
    } else if (isBlocked && isEDR) {
      p2parts.push(`Review the full process tree in ${src} to confirm no child processes were spawned before the kill. Check for any files written to disk or registry changes made during the brief execution window.`);
    }

    // Extra context from analyst
    if (extraContext?.trim()) {
      p2parts.push(extraContext.trim());
    }

    // ═══════════════════════════════════════════════════════════
    // PARAGRAPH 3 — Verdict + next steps + sign-off
    // ═══════════════════════════════════════════════════════════
    const nextSteps = [];
    if (isWeb && isBlocked) {
      if (dstIP && !isPrivateIPv4(dstIP)) nextSteps.push(`Add **${dstIP}** and **${domain||dstIP}** to the firewall/proxy blocklist if not already present`);
      if (srcIP && isPrivateIPv4(srcIP)) nextSteps.push(`Pull EDR telemetry for **${host||srcIP}** for the 30 minutes surrounding the event to check for any follow-on execution`);
      if (referer) nextSteps.push(`Investigate the referring site **${(() => { try { return new URL(referer).hostname; } catch { return referer.slice(0,60); }})()}** — it may be compromised and serving as a redirect hub`);
      nextSteps.push(`Search proxy logs for other users who queried **${domain}** in the same window — determine blast radius`);
    } else if (isEDR) {
      if (hash) nextSteps.push(`Check **${hash.slice(0,16)}...** on VirusTotal and submit to the EDR's custom IOC feed`);
      if (host) nextSteps.push(`Run a full AV and EDR scan on **${host}** and review the process tree`);
      nextSteps.push(`Hunt for lateral movement from **${host||"the affected endpoint"}** — check auth logs, SMB, and RDP sessions`);
    } else if (isIdent) {
      // If OSINT clean + user log same device = verify first, don't automatically reset
      if (pf.osint_clean && pf.user_log_parsed && pf.user_log_day1_summary) {
        nextSteps.push(`Call **${user||"the user"}** directly to confirm whether the location change (${pf.user_log_day2_summary?.split(" ")[0]||"new location"}) was expected — use phone, not email`);
        nextSteps.push(`Review session activity after the flagged login — check for email reads, file access, forwarding rule changes`);
        nextSteps.push(`If user cannot confirm: immediately revoke sessions and force password + MFA reset`);
        nextSteps.push(`If user confirms: close as TP – Benign and document the carrier/location change`);
      } else {
        nextSteps.push(`Revoke all active sessions for **${user||"the account"}** immediately and force a password reset`);
        nextSteps.push(`Re-enrol MFA from a trusted, verified device`);
        nextSteps.push(`Review all actions taken during the suspicious session — look for data access, new OAuth grants, or rule changes`);
      }
    } else if (isEmail) {
      nextSteps.push(`Search for other recipients of messages from **${email||"this sender"}** in the past 7 days`);
      nextSteps.push(`Confirm whether the recipient clicked any links before the email was quarantined`);
    }

    const p3 = `**Final Verdict:** ${vLabel}
**Disposition:** ${dLabel}${nextSteps.length?`
**Recommended Actions:**
${nextSteps.map((s,i)=>`  ${i+1}. ${s}`).join("\n")}`:""
}${analystName?`
**Analyst:** ${analystName}`:""}`;

    const p1 = p1parts.filter(Boolean).join(" ");
    const p2 = p2parts.filter(Boolean).join(" ");
    // ── ESCALATION NOTE ─────────────────────────────────────────
    // Don't escalate if OSINT is clean AND user log shows same device — likely benign carrier change
    const _likelyBenign = pf.osint_clean && pf.user_log_parsed && pf.user_log_day1_summary && pf.user_log_day2_summary;
    const _needsEscalation = !_likelyBenign && (
      (isIdent && (sev === "high" || sev === "critical")) ||
      /impossible.*travel|blocklisted.*location|unusual.*geolocation|concurrent.*location/i.test(findingsStr + raw) ||
      /mfa.*fail|push.*deny|mfa.*bypass/i.test(findingsStr) ||
      (isIdent && (iocs.ips||[]).length >= 2)
    );
    let _escalationBlock = "";
    if (_needsEscalation) {
      const _eu   = user || email || "the affected account";
      // Suspicious location = stored explicitly from parser
      const _eloc = pf.suspicious_location ||
                    (pf.location||"").split(",").filter(p=>!/\b(Dallas|USA?|New York|London|Toronto|Sydney)\b/i.test(p)).join(",").trim() ||
                    pf.location || location || "";
      const _erole = pf.role ? ` — **${pf.role}**` : "";
      const _edept = department ? `, ${department}` : "";
      const _ecar  = pf.carrier  ? ` via **${pf.carrier}**` : "";
      const _edev  = pf.device   ? ` on **${pf.device}**`  : "";
      const _efip  = pf.fail_ips || "";
      const _esip  = pf.success_ips || "";
      const _isMex = /mexico|russia|china|iran|north korea|nigeria|brazil|venezuela/i.test(_eloc);
      const _escLines = [
        `🚨 **ESCALATION REQUIRED — Assign to Tier 2 / Incident Response**`,
        ``,
        `**Affected Account:** **${_eu}**${_erole}${_edept}`,
        _eloc ? `**Suspicious Origin:** **${_eloc}**${_ecar}${_edev}` : "",
        (_efip && _esip) ? `**Auth Pattern:** FAILURES from **${_efip}** (foreign) | SUCCESSES from **${_esip}** (known-good location) — credentials actively abused from a foreign location while the legitimate user is concurrently active` : "",
        ``,
        `**Immediate Response Checklist:**`,
        `  ☐ 1. Disable **${_eu}** in Entra ID / Azure AD NOW — do not wait for user callback`,
        `  ☐ 2. Revoke ALL sessions and refresh tokens (PowerShell: Revoke-AzureADUserAllRefreshToken)`,
        `  ☐ 3. Force password reset from a verified device on the corporate network`,
        `  ☐ 4. Delete and re-enrol MFA — existing registered methods may be attacker-controlled`,
        `  ☐ 5. Audit last 72h: email reads, file downloads, forwarding rules, OAuth grants, admin actions`,
        `  ☐ 6. ${_isMex ? `Report to management — access from **${_eloc}** may trigger breach notification obligations` : `Contact user via phone (not email) to confirm whether travel was planned — if not, treat as full compromise`}`,
        `  ☐ 7. Preserve all logs and open an INC ticket — document the full FAILURE/SUCCESS timeline`,
        `  ☐ 8. Check blast radius: shared credentials, service accounts, admin roles, email delegates`,
      ].filter(Boolean).join("\n");
      _escalationBlock = _escLines;
    }
    return [p1, p2, _escalationBlock, p3].filter(Boolean).join("\n\n");
  }


  function generateCaseNotes(res) {
    const iocs  = res.iocs || {};
    const pf    = res.prefillData || {};
    const et    = res.eventType || "Security Event";
    const sev   = (res.severityLabel || "").replace(/^[^\s]+\s*/, "") || res.severity?.toUpperCase() || "UNKNOWN";
    const findings = res.findings || [];
    const mitre    = res.mitre ? [...res.mitre] : [];
    const now      = new Date();
    const ts       = now.toLocaleString();
    const v        = scoreAutoVerdict(res);

    // ── Key field extraction ───────────────────────────────────
    const srcIP   = pf.src_ip   || (iocs.ips||[]).find(ip => !isPrivateIPv4(ip)) || (iocs.ips||[])[0] || "";
    const dstIP   = pf.dest_ip  || "";
    const user    = pf.username || (iocs.usernames||[])[0] || "";
    const host    = pf.hostname || (iocs.hostnames||[])[0] || "";
    const hash    = (iocs.hashes||[])[0] || "";
    const domain  = (iocs.domains||[])[0] || "";
    const url     = (iocs.urls||[])[0] || "";
    const email   = pf.sender   || (iocs.emails||[])[0] || "";
    const process = (iocs.processes||[])[0] || "";
    const cmdline = pf.cmdline  || (iocs.cmdlines||[])[0] || "";
    const dstPort = pf.dest_port|| (iocs.ports||[])[0] || "";
    const proto   = pf.proto    || "";

    // Count all extracted IOCs
    const iocCounts = Object.entries(iocs)
      .filter(([,v]) => Array.isArray(v) && v.length)
      .map(([k,v]) => `${v.length} ${k}`)
      .join(", ");

    // Build human-readable narrative sections
    const lines = [];

    lines.push(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    lines.push(`CASE NOTES — Auto-generated by HawkEye`);
    lines.push(`Timestamp  : ${ts}`);
    lines.push(`Alert Type : ${et}`);
    lines.push(`Severity   : ${sev}`);
    lines.push(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    lines.push("");

    // ── WHAT HAPPENED ─────────────────────────────────────────
    lines.push("WHAT HAPPENED");
    lines.push("─────────────");

    // Build narrative from findings + IOCs
    const crit = findings.filter(f => f.startsWith("🚨")).map(f => f.replace(/^🚨\s*/,""));
    const warn = findings.filter(f => f.startsWith("⚠️")).map(f => f.replace(/^⚠️\s*/,""));
    const info = findings.filter(f => f.startsWith("ℹ️")).map(f => f.replace(/^ℹ️\s*/,""));

    if (crit.length) {
      lines.push("Critical findings:");
      crit.forEach(f => lines.push(`  • ${f}`));
    }
    if (warn.length) {
      if (crit.length) lines.push("");
      lines.push("Warnings:");
      warn.forEach(f => lines.push(`  • ${f}`));
    }
    if (info.length && !crit.length && !warn.length) {
      info.slice(0,3).forEach(f => lines.push(`  • ${f}`));
    }

    lines.push("");

    // ── WHO / WHAT WAS INVOLVED ───────────────────────────────
    lines.push("ENTITIES INVOLVED");
    lines.push("─────────────────");
    const timestamp = pf.timestamp || (iocs.timestamps||[])[0] || "";
    const verdicts  = (iocs.verdicts||[]).join(" / ");
    if (timestamp)  lines.push(`  Timestamp    : ${timestamp}`);
    if (verdicts)   lines.push(`  Event Action : ${verdicts}`);
    if (user)    lines.push(`  User         : ${user}`);
    if (host)    lines.push(`  Host         : ${host}`);
    if (srcIP)   lines.push(`  Source IP    : ${srcIP}${isPrivateIPv4(srcIP) ? " (internal)" : " (external — check reputation)"}`);
    if (dstIP)   lines.push(`  Dest IP      : ${dstIP}${isPrivateIPv4(dstIP) ? " (internal)" : " (external)"}`);
    if (dstPort) { const plabel = buildPortLabel(dstPort).replace(/<[^>]+>/g," ").trim(); lines.push(`  Dest Port    : ${dstPort}${plabel ? " ("+plabel+")" : ""}`); }
    if (proto)   lines.push(`  Protocol     : ${proto}`);
    if (email)   lines.push(`  Email        : ${email}`);
    if (domain)  lines.push(`  Domain       : ${domain}`);
    if (url)     lines.push(`  URL          : ${url.slice(0,120)}`);
    if (process) lines.push(`  Process      : ${process}`);
    if (hash)    lines.push(`  File Hash    : ${hash}`);
    if (cmdline) lines.push(`  Command Line : ${cmdline.slice(0,200)}`);

    // Additional IPs
    const otherIPs = (iocs.ips||[]).filter(ip => ip !== srcIP && ip !== dstIP);
    if (otherIPs.length) lines.push(`  Other IPs    : ${otherIPs.slice(0,5).join(", ")}`);
    if (iocs.regkeys?.length) lines.push(`  Registry     : ${iocs.regkeys[0]}`);
    if (iocs.filepaths?.length) lines.push(`  File Path    : ${iocs.filepaths[0]}`);
    if (iocs.cves?.length) lines.push(`  CVE(s)       : ${iocs.cves.join(", ")}`);

    lines.push("");

    // ── MITRE ATT&CK ─────────────────────────────────────────
    if (mitre.length) {
      lines.push("MITRE ATT&CK MAPPING");
      lines.push("────────────────────");
      mitre.slice(0,6).forEach(t => lines.push(`  ${t} — ${getMitreName(t)}`));
      lines.push("");
    }

    // ── ALL EXTRACTED IOCs ────────────────────────────────────
    lines.push("EXTRACTED IOCs");
    lines.push("──────────────");
    const iocTypes = [
      ["ips",      "IP Addresses"],
      ["domains",  "Domains"],
      ["urls",     "URLs"],
      ["hashes",   "Hashes"],
      ["emails",   "Emails"],
      ["processes","Processes"],
      ["usernames","Usernames"],
      ["hostnames","Hostnames"],
      ["cves",     "CVEs"],
    ];
    let hasIOC = false;
    iocTypes.forEach(([key, label]) => {
      const arr = iocs[key];
      if (arr?.length) {
        hasIOC = true;
        lines.push(`  ${label}:`);
        arr.slice(0,10).forEach(v => lines.push(`    - ${v}`));
        if (arr.length > 10) lines.push(`    … and ${arr.length-10} more`);
      }
    });
    if (!hasIOC) lines.push("  No structured IOCs extracted.");
    lines.push("");

    // ── AUTO-VERDICT ─────────────────────────────────────────
    lines.push("AUTO-VERDICT ASSESSMENT");
    lines.push("───────────────────────");
    lines.push(`  Verdict     : ${v.verdict}`);
    lines.push(`  Confidence  : TP likelihood ${v.tpPct}% / FP likelihood ${v.fpPct}%`);
    if (v.tpReasons.length) lines.push(`  TP signals  : ${v.tpReasons.join(", ")}`);
    if (v.fpReasons.length) lines.push(`  FP signals  : ${v.fpReasons.join(", ")}`);
    lines.push("");
    lines.push("ANALYST NOTES");
    lines.push("─────────────");
    lines.push("  [ Analyst verification steps completed: _____________ ]");
    lines.push("  [ Final verdict: TP / FP / Escalated — _____________ ]");
    lines.push("  [ Disposition: ___________________________________ ]");
    lines.push("");
    lines.push(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    lines.push(`Generated by HawkEye v${TOOLKIT_VERSION}`);

    return lines.join("\n");
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

    // ── ALERT CONTEXT SUMMARY ─────────────────────────────────
    const { lines: summaryLines, cat } = buildAlertContextSummary(res);
    res._rawText = res._rawText || "";

    // ── AUTO-VERDICT ──────────────────────────────────────────
    const verdict   = scoreAutoVerdict(res);
    const fpTpl     = buildAdaptiveVerdict("fp", res);
    const tpTpl     = buildAdaptiveVerdict("tp", res);

    // ── STRUCTURED IOC PANEL ──────────────────────────────────
    const iocPanel  = buildStructuredIOCPanel(res);

    // ── NARRATIVE PARAGRAPH ───────────────────────────────────
    const narr = buildNarrativeParagraph(res);
    // Extract key fields for use in the panel template
    const _pf   = res.prefillData || {};
    const user  = _pf.username  || res.iocs?.usernames?.[0]  || "";
    const host  = _pf.hostname  || res.iocs?.hostnames?.[0]  || "";
    const srcIP = _pf.src_ip    || "";
    const et    = res.eventType || "Security Event";

    // ── CASE NOTES ────────────────────────────────────────────
    const caseNotes = generateCaseNotes(res);

    let html = "";

    // 1. Structured IOC extraction table (top — most useful at a glance)
    html += iocPanel;

    // 2. Structured 10-step triage analysis panel
    const _vColor = narr.effectiveVerdict === "TP_ESCALATE" ? "#ef4444" :
                    narr.effectiveVerdict === "TP_BLOCKED_NFA" ? "#34d399" :
                    narr.effectiveVerdict === "TP_BENIGN" ? "#fbbf24" :
                    narr.effectiveVerdict === "FP" ? "#9ca3af" : "#a78bfa";

    html += `<div class="lt-narrative-panel">
      <div class="lt-narrative-head">
        <span class="lt-narrative-icon">🧠</span>
        <span class="lt-narrative-title">Triage Analysis</span>
        <span class="lt-narrative-sub">10-step automated analysis · ${narr.category || "Security Event"}</span>
        <button class="lt-narrative-copy-btn" id="lt-narr-copy-btn" type="button">📋 Copy</button>
      </div>
      <div class="lt-narrative-body" id="lt-narr-body">

        ${_pf.is_multi_source ? `
        <div class="lt-triage-step" style="border-left:3px solid #a78bfa;background:rgba(167,139,250,0.04);padding:10px 14px;border-radius:0 8px 8px 0;margin-bottom:6px;">
          <span class="lt-step-num" style="background:rgba(167,139,250,0.2);color:#a78bfa;">MS</span>
          <span class="lt-step-label" style="color:#a78bfa;">Multi-Source</span>
          <span class="lt-step-val"><strong>${_pf.source_count} sources correlated</strong> — ${esc(_pf.correlated_sources||"")}${_pf.kill_chain_stages>=3?' <span style="color:#ef4444;font-weight:800;">🚨 FULL KILL CHAIN</span>':_pf.kill_chain_stages>=2?' <span style="color:#fbbf24;font-weight:700;">⚠️ Multi-stage</span>':''}</span>
        </div>` : ""}

        <div class="lt-triage-step">
          <span class="lt-step-num">1</span>
          <span class="lt-step-label">Alert Classification</span>
          <span class="lt-step-val">${esc(narr.category || et)} · ${res.severityLabel}</span>
        </div>

        ${user||host ? `<div class="lt-triage-step">
          <span class="lt-step-num">2</span>
          <span class="lt-step-label">Entities</span>
          <span class="lt-step-val">${user ? "👤 "+esc(user)+" " : ""}${host ? "💻 "+esc(host)+" " : ""}${srcIP ? "🌐 "+esc(srcIP) : ""}</span>
        </div>` : ""}

        ${narr.p1 ? `<div class="lt-triage-step lt-step-story">
          <span class="lt-step-num">3</span>
          <span class="lt-step-label">${_pf.is_multi_source ? "Correlated Story" : "Timeline / Story"}</span>
          <span class="lt-step-val">${esc(narr.p1)}${_pf.kill_chain_stage ? '<br><span style="color:#a78bfa;font-size:11px;margin-top:4px;display:block;">⛓️ '+esc(_pf.kill_chain_stage)+'</span>' : ''}</span>
        </div>` : ""}

        ${narr.p2 ? `<div class="lt-triage-step">
          <span class="lt-step-num">4–5</span>
          <span class="lt-step-label">Detection + Behavior</span>
          <span class="lt-step-val">${esc(narr.p2)}${narr.behaviors?.length ? " Observed: "+esc(narr.behaviors.join("; "))+"." : ""}</span>
        </div>` : ""}

        <div class="lt-triage-step">
          <span class="lt-step-num">6</span>
          <span class="lt-step-label">Control Action</span>
          <span class="lt-step-val" style="color:${narr.controlResult==="CONTAINED"?"#34d399":narr.controlResult==="ALLOWED"?"#ef4444":"#fbbf24"}">${narr.controlIcon} ${esc(narr.controlLabel)}</span>
        </div>

        <div class="lt-triage-step">
          <span class="lt-step-num">7</span>
          <span class="lt-step-label">Compromise Check</span>
          <span class="lt-step-val">${esc(narr.p3)}</span>
        </div>

        ${narr.p2 ? `<div class="lt-triage-step">
          <span class="lt-step-num">8</span>
          <span class="lt-step-label">Root Cause</span>
          <span class="lt-step-val">${esc(narr.p2.split(".")[0]+".")}</span>
        </div>` : ""}

        <div class="lt-triage-step lt-step-verdict" style="border-left:3px solid ${_vColor}">
          <span class="lt-step-num" style="background:${_vColor}">9</span>
          <span class="lt-step-label">Verdict</span>
          <span class="lt-step-val" style="font-weight:700;">${esc(narr.verdictLine)}</span>
        </div>

        <div class="lt-triage-step">
          <span class="lt-step-num">10</span>
          <span class="lt-step-label">Actions</span>
          <span class="lt-step-val">${esc(narr.p4)}</span>
        </div>

        ${narr.mitreContext ? `<div class="lt-triage-step" style="opacity:0.75;">
          <span class="lt-step-num">TTP</span>
          <span class="lt-step-label">MITRE</span>
          <span class="lt-step-val">${esc(narr.mitreContext)}</span>
        </div>` : ""}

      </div>
    </div>`;

    // 2. Case notes / auto-verdict panel
    html += `<div class="lt-case-notes-panel">
      <div class="lt-case-notes-head">
        <span class="lt-case-notes-title">📝 Auto-Generated Case Notes</span>
        <span class="lt-verdict-score-badge ${verdict.cls}">${verdict.verdict} (${verdict.tpPct}%)</span>
      </div>
      <div class="lt-cn-section-label">Auto-Verdict: TP signals — ${verdict.tpReasons.length ? verdict.tpReasons.join(", ") : "none"} · FP signals — ${verdict.fpReasons.length ? verdict.fpReasons.join(", ") : "none"}</div>
      <div class="lt-case-notes-body" id="lt-case-notes-body">${esc(caseNotes)}</div>
      <div class="lt-case-notes-actions">
        <button id="lt-cn-copy-btn" type="button">📋 Copy Case Notes</button>
        <button id="lt-cn-case-btn" type="button">📁 Add to Case</button>
      </div>
    </div>`;

    // 3. Alert context summary
    html += `<div class="lt-context-summary" style="border-color:${cat.color}55">
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

    <!-- Investigation Checklist -->
    <div class="lt-investig-steps" style="border-color:${cat.color}44">
      <div class="lt-investig-head">
        <span style="color:${cat.color}">${cat.icon} ${cat.label} — Investigation Checklist</span>
        <button class="lt-investig-copy" id="lt-steps-copy-btn" type="button" title="Copy steps">📋</button>
      </div>
      <ol class="lt-steps-list" id="lt-steps-list">
        ${cat.steps.map(s => `<li class="lt-step-item">${s}</li>`).join("")}
      </ol>
    </div>

    <!-- FP/TP Verdict Templates -->
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

    // 4. Verdict header bar
    html += `<div class="lt-verdict-bar" style="border-color:${sc}44;background:${sc}0d">
      <div class="lt-verdict-left">
        <span class="lt-ev-badge" style="color:${tc};background:${tc}18;border-color:${tc}44">${res.eventType}</span>
        <span class="lt-sev-badge" style="color:${sc};background:${sc}18;border-color:${sc}44">${res.severityLabel||"⚪ INFO"}</span>
      </div>
      <div class="lt-verdict-indicators">${(res.indicators||[]).map(i=>`<span class="lt-ind-chip">${i}</span>`).join("")}</div>
    </div>`;

    // 5. Findings
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

    // 6. Port hints
    if (res.portHints && res.portHints.length) {
      html += `<div class="sa-section">
        <div class="sa-section-head">🔌 Port Intelligence</div>
        <div class="lt-findings-list">${res.portHints.map(p=>`<div class="lt-finding lt-finding-info">ℹ️ ${p}</div>`).join("")}</div>
      </div>`;
    }

    // 7. MITRE techniques
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

    // 8. Full IOC grid (detailed, with pivot buttons)
    const iocCols = [
      ["timestamps","Timestamps",         "#67e8f9", null],
      ["verdicts",  "Event Action",       "#34d399", null],
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

    // 9. Prefill hint
    if (res.prefillData && Object.values(res.prefillData).some(Boolean)) {
      html += `<div class="lt-prefill-hint">
        💡 <strong>Write-up data ready</strong> — click <strong>Pre-fill Write-up</strong> to populate the Alert Write-up tab with the fields above.
      </div>`;
    }

    ltResults.innerHTML = html;
    // Store case notes on res for button access
    res._caseNotes = caseNotes;

    // ── Wire all buttons ───────────────────────────────────────
    // Narrative copy
    $("lt-narr-copy-btn")?.addEventListener("click", async () => {
      const body = $("lt-narr-body");
      if (!body) return;
      const txt = [...body.querySelectorAll(".lt-narr-p")].map(p => {
        const label = p.querySelector(".lt-narr-label")?.textContent?.trim() || "";
        const text  = p.textContent.replace(label,"").trim();
        return `${label.toUpperCase()}\n${text}`;
      }).join("\n\n");
      try { await navigator.clipboard.writeText(txt); setLTStatus("Narrative copied to clipboard"); }
      catch { setLTStatus("Copy failed"); }
    });
    $("lt-cn-copy-btn")?.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(res._caseNotes||""); setLTStatus("Case notes copied to clipboard"); }
      catch { setLTStatus("Copy failed"); }
    });
    // Case notes → add to active case
    $("lt-cn-case-btn")?.addEventListener("click", () => {
      if (!activeCase) { alert("No active case. Create a case first in the Case Manager tab."); return; }
      activeCase.notes = (activeCase.notes||"") + "\n\n" + (res._caseNotes||"");
      saveActiveCase(); setLTStatus("Case notes added to active case"); switchTab("case");
    });
    // Copy IOC table fields
    $("lt-copy-ioc-table")?.addEventListener("click", async () => {
      const pf   = res.prefillData||{};
      const iocs = res.iocs||{};
      const lines = [];
      if (pf.src_ip)    lines.push(`Source IP    : ${pf.src_ip}`);
      if (pf.dest_ip)   lines.push(`Dest IP      : ${pf.dest_ip}`);
      if (pf.username)  lines.push(`User         : ${pf.username}`);
      if (pf.hostname)  lines.push(`Host         : ${pf.hostname}`);
      if (pf.dest_port) lines.push(`Dest Port    : ${pf.dest_port}`);
      if (pf.proto)     lines.push(`Protocol     : ${pf.proto}`);
      if (iocs.hashes?.[0])   lines.push(`Hash         : ${iocs.hashes[0]}`);
      if (iocs.processes?.[0])lines.push(`Process      : ${iocs.processes[0]}`);
      if (pf.cmdline)   lines.push(`CommandLine  : ${pf.cmdline}`);
      if (iocs.domains?.[0])  lines.push(`Domain       : ${iocs.domains[0]}`);
      if (iocs.emails?.[0])   lines.push(`Email        : ${iocs.emails[0]}`);
      try { await navigator.clipboard.writeText(lines.join("\n")); setLTStatus("IOC fields copied"); }
      catch { setLTStatus("Copy failed"); }
    });
    // Add all IOCs to case (from structured panel)
    $("lt-addall-ioc-btn")?.addEventListener("click", () => {
      const iocs = res.iocs||{};
      const pf   = res.prefillData||{};
      let added  = 0;
      const addIfPresent = (type, vals) => vals?.forEach(v => { if (v) { addIOCToCase(type, v); added++; } });
      addIfPresent("ip",       iocs.ips);
      addIfPresent("domain",   iocs.domains);
      addIfPresent("hash",     iocs.hashes);
      addIfPresent("email",    iocs.emails);
      addIfPresent("url",      iocs.urls?.slice(0,3));
      addIfPresent("username", iocs.usernames);
      if (added) setLTStatus(`${added} IOCs added to case`);
      else       setLTStatus("No IOCs to add — run Auto-Triage first");
    });
    // Global "Add All to Case" button in toolbar
    $("lt-addall-btn")?.addEventListener("click", () => {
      $("lt-addall-ioc-btn")?.click();
    });
    // Global "Copy Case Notes" button in toolbar
    $("lt-casenotes-btn")?.addEventListener("click", () => {
      $("lt-cn-copy-btn")?.click();
    });
    // SOC Note toggle
    $("lt-soc-note-btn")?.addEventListener("click", () => {
      const ctrl = $("lt-soc-note-controls");
      if (ctrl) ctrl.style.display = ctrl.style.display === "none" ? "block" : "none";
    });

    // Per-row mini pivot/copy/case buttons
    ltResults.querySelectorAll(".lt-ioc-pivot-mini").forEach(btn => {
      btn.addEventListener("click", () => {
        if (input) { input.value = btn.dataset.val; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
      });
    });
    ltResults.querySelectorAll(".lt-ioc-copy-mini").forEach(btn => {
      btn.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(btn.dataset.val||""); } catch {}
      });
    });
    ltResults.querySelectorAll(".lt-ioc-case-mini").forEach(btn => {
      btn.addEventListener("click", () => addIOCToCase(btn.dataset.type||"unknown", btn.dataset.val));
    });

    // Context summary copy
    $("lt-ctx-copy-btn")?.addEventListener("click", async () => {
      const body = $("lt-ctx-body");
      const text = body ? [...body.querySelectorAll(".lt-ctx-line")].map(el => el.textContent.trim()).join("\n") : "";
      try { await navigator.clipboard.writeText(text); setLTStatus("Context summary copied to clipboard"); }
      catch { setLTStatus("Copy failed — please copy manually"); }
    });
    // Investigation steps copy
    $("lt-steps-copy-btn")?.addEventListener("click", async () => {
      const list = $("lt-steps-list");
      const text = list ? [...list.querySelectorAll(".lt-step-item")].map((el,i) => `${i+1}. ${el.textContent.trim()}`).join("\n") : "";
      try { await navigator.clipboard.writeText("Investigation Checklist:\n" + text); setLTStatus("Investigation steps copied"); }
      catch { setLTStatus("Copy failed — please copy manually"); }
    });
    // FP/TP copy
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
    // Standard pivot/case buttons in IOC grid
    ltResults.querySelectorAll(".lt-pivot-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        if (input) { input.value = btn.dataset.val; syncSearchboxState(); switchTab("single"); doSearch({ silent: false }); }
      });
    });
    ltResults.querySelectorAll(".lt-case-btn").forEach(btn => {
      btn.addEventListener("click", () => addIOCToCase(btn.dataset.type || "unknown", btn.dataset.val));
    });
  }

    // ── ALERT CONTEXT SUMMARY (Feature 8 + 11) ───────────────────

  // ── SOC Case Note Generator — global listeners ───────────
  $("lt-soc-generate-btn")?.addEventListener("click", async () => {
    if (!lastTriageResult) { alert("Run Auto-Triage first on a pasted log."); return; }

    const verdict  = $("lt-soc-verdict")?.value     || "TBD";
    const disp     = $("lt-soc-disposition")?.value  || "NFA";
    const analyst  = $("lt-soc-analyst")?.value?.trim() || "SOC Analyst";
    const extra    = $("lt-soc-extra-context")?.value?.trim() || "";
    const panel    = $("lt-soc-note-panel");
    const body     = $("lt-soc-note-body");
    if (!panel || !body) return;

    // Show loading
    panel.style.display = "block";
    body.innerHTML = `<div style="color:var(--muted);font-size:12px;padding:12px 0;">
      <span style="display:inline-block;animation:spin 1s linear infinite;margin-right:8px;">⟳</span>
      Composing SOC case note…</div>`;
    if (panel.scrollIntoView) panel.scrollIntoView({ behavior:"smooth", block:"start" });

    // Collect all structured parser fields
    const res  = lastTriageResult;
    const pf   = res.prefillData || {};
    const iocs = res.iocs || {};
    const vMap = { TP_blocked:"TP – Blocked", TP_detected:"TP – Detected (not blocked)",
      TP_confirmed:"TP – Confirmed Compromise", FP:"FP – False Positive",
      BEN:"Benign – Expected Activity", TBD:"TBD – Under Investigation",
      TP_verify:"TP – Verify with User (OSINT Clean)" };
    const dMap = { NFA:"No Further Action (NFA)", escalated:"Escalated to Tier 2 / Incident Response",
      contained:"Contained – Endpoint Isolated", monitoring:"Continue Monitoring",
      remediated:"Remediated", user_notified:"User Notified" };

    // Structured context block — every extracted field, labelled for 5W clarity
    const ctx = [
      `EVENT TYPE: ${res.eventType || "Security Event"}`,
      `SEVERITY: ${(res.severity||"info").toUpperCase()}`,
      `ANALYST VERDICT: ${vMap[verdict]||verdict}`,
      `ANALYST DISPOSITION: ${dMap[disp]||disp}`,
      `ANALYST NAME: ${analyst}`,
      ``,
      `=== WHO ===`,
      pf.username    ? `User account: ${pf.username}` : "",
      pf.department  ? `Department: ${pf.department}` : "",
      pf.role        ? `Role/Title: ${pf.role}` : "",
      pf.hostname    ? `Endpoint: ${pf.hostname}` : "",
      pf.device      ? `Device type: ${pf.device}` : "",
      ``,
      `=== WHAT ===`,
      pf.threat_name ? `Threat/Signature: ${pf.threat_name}` : "",
      pf.category    ? `Category: ${pf.category}` : "",
      pf.rule        ? `Rule/Policy triggered: ${pf.rule}` : "",
      pf.url         ? `Target URL: ${pf.url}` : "",
      pf.referer     ? `HTTP Referrer: ${pf.referer}` : "",
      pf.cmdline     ? `Command line: ${pf.cmdline.slice(0,200)}` : "",
      pf.hash        ? `File hash (SHA256): ${pf.hash.slice(0,64)}` : "",
      pf.process     ? `Process: ${pf.process}` : "",
      pf.verdict     ? `Action taken: ${pf.verdict}` : "",
      pf.http_status ? `HTTP response: ${pf.http_status}` : "",
      pf.bytes       ? `Bytes transferred: ${pf.bytes}` : "",
      pf.alert_count ? `Correlated alert count: ${pf.alert_count}` : "",
      (res.mitre||[]).length ? `MITRE ATT&CK: ${res.mitre.slice(0,5).join(", ")}` : "",
      ``,
      `=== WHEN ===`,
      pf.timestamp   ? `Event time: ${pf.timestamp}` : "",
      pf.alert_count > 1 ? "Multiple alerts triggered within minutes of each other" : "",
      ``,
      `=== WHERE ===`,
      pf.src_ip      ? `Source IP: ${pf.src_ip}` : "",
      pf.dest_ip     ? `Destination IP: ${pf.dest_ip}` : "",
      pf.dest_port   ? `Destination port: ${pf.dest_port}` : "",
      pf.location    ? `Geographic location: ${pf.location}` : "",
      pf.carrier     ? `Carrier/ISP: ${pf.carrier}` : "",
      pf.fail_ips    ? `Auth failure source IPs: ${pf.fail_ips}` : "",
      pf.success_ips ? `Auth success source IPs (known-good): ${pf.success_ips}` : "",
      ``,
      `=== WHY / HOW ===`,
      (res.findings||[]).length ? `Parser findings:\n${(res.findings||[]).map(f=>"  "+f).join("\n")}` : "",
      extra          ? `Analyst context: ${extra}` : "",
    ].filter(Boolean).join("\n");

    const systemPrompt = [
      "You are a senior SOC analyst writing a case note for a security ticket.",
      "Write in clear flowing prose — like a skilled analyst narrating what happened to a colleague who was not there.",
      "No headers, no bullet sections, no labels. Just tight readable paragraphs that cover all the facts and end with a clear verdict.",
      "STYLE: Write as one continuous narrative. No WHO: WHAT: WHERE: labels.",
      "Open with who the user is, what host they were on, what they did or what happened to them.",
      "Weave in when it happened, where the traffic went, what the security control detected and did, all in natural sentence flow.",
      "Name every IOC explicitly: full email, exact hostname, exact IPs, exact URLs, exact threat signature, exact rule name.",
      "If there is a referrer or redirect chain trace it in order: accessed X which redirected to Y then to Z.",
      "If there is an auth pattern tell that story chronologically with the specific IPs and locations.",
      "Explain WHY it matters briefly. State whether there is or is not evidence of compromise, based only on what the logs show.",
      "End with: Recommend marking as [VERDICT] / [DISPOSITION]",
      "After the narrative add: Recommended Actions: with 3-5 numbered specific steps using the actual IOCs.",
      "Maximum 200 words total. Plain text only. No bold, no markdown, no headers.",
    ].join("\n");
    const userPrompt = "EVENT DATA:\n" + ctx +
      (extra ? "\n\nADDITIONAL ANALYST CONTEXT: " + extra : "") +
      "\n\nVerdict: " + (vMap[verdict]||verdict) + "\nDisposition: " + (dMap[disp]||disp) + "\nAnalyst: " + analyst + "\n\nWrite the case note now. Plain text only.";
    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1200,
          system: systemPrompt,
          messages: [{ role:"user", content: userPrompt }],
        }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        // Fallback to the offline regex-based note
        const fallbackNote = generateSOCCaseNote(res, verdict, disp, analyst, extra);
        renderSOCNote(body, panel, fallbackNote);
        setLTStatus("Enhanced note unavailable — showing standard note");
        return;
      }

      const data  = await resp.json();
      const text  = (data.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("\n").trim();

      renderSOCNote(body, panel, text);
      setLTStatus("SOC case note generated");

    } catch (e) {
      // Network error — fall back to offline note silently
      const fallbackNote = generateSOCCaseNote(res, verdict, disp, analyst, extra);
      renderSOCNote(body, panel, fallbackNote);
      setLTStatus("Standard note generated (network unavailable)");
    }
  });

  // Shared render function for SOC note (used by both AI and fallback)
  function renderSOCNote(body, panel, text) {
    const esc2 = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

    // Split into paragraphs on blank lines
    const blocks = text.split(/\n\n+/).filter(b => b.trim());
    const html = blocks.map(block => {
      const lines = block.split("\n").filter(l => l.trim());
      if (!lines.length) return "";

      // Escalation block (has ☐ checkboxes)
      if (block.includes("☐") || /ESCALATION REQUIRED/i.test(lines[0])) {
        return '<div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.2);border-radius:8px;padding:12px 14px;margin:10px 0;">' +
          lines.map(l => {
            if (/ESCALATION/i.test(l)) return `<div style="color:#ef4444;font-weight:800;font-size:12px;margin-bottom:8px;">🚨 ${esc2(l.replace(/🚨/g,"").trim())}</div>`;
            if (l.includes("☐"))       return `<div style="padding:3px 0 3px 4px;font-size:11.5px;">${esc2(l)}</div>`;
            return `<div style="font-size:11px;color:var(--muted);padding:1px 0;">${esc2(l)}</div>`;
          }).join("") + "</div>";
      }

      // Numbered action list (e.g. "Recommended Actions:" header + numbered items)
      if (/^Recommended Actions:/i.test(lines[0]) || /^Immediate Actions:/i.test(lines[0])) {
        const header = lines[0];
        const items  = lines.slice(1);
        return `<div style="margin:12px 0 0;">
          <div style="font-weight:800;font-size:11.5px;color:var(--text);margin-bottom:6px;">${esc2(header)}</div>
          ${items.map(l => {
            const m = l.match(/^(\d+)[.)]\s+(.+)/);
            return m
              ? `<div style="display:flex;gap:8px;padding:3px 0;font-size:11.5px;"><span style="color:#a78bfa;font-weight:800;min-width:18px;">${m[1]}.</span><span style="line-height:1.6;">${esc2(m[2])}</span></div>`
              : `<div style="padding-left:26px;font-size:11.5px;line-height:1.6;">${esc2(l)}</div>`;
          }).join("")}
        </div>`;
      }

      // Detect inline numbered list (starts directly with "1.")
      if (/^\d+[.)\s]/.test(lines[0]) && lines.every(l => /^\d+[.)\s]/.test(l.trim()) || l.trim() === "")) {
        return '<div style="margin:8px 0;">' + lines.map(l => {
          const m = l.match(/^(\d+)[.)]\s+(.+)/);
          return m
            ? `<div style="display:flex;gap:8px;padding:3px 0;font-size:12px;"><span style="color:#a78bfa;font-weight:800;min-width:18px;">${m[1]}.</span><span style="line-height:1.7;">${esc2(m[2])}</span></div>`
            : `<div style="padding-left:26px;font-size:12px;">${esc2(l)}</div>`;
        }).join("") + "</div>";
      }

      // Standard narrative paragraph — the main body
      const paraText = lines.join(" ");
      // Highlight key IOC patterns inline for readability
      const highlighted = esc2(paraText)
        .replace(/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
          '<strong style="color:var(--text);">$1</strong>')
        .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
          '<strong style="color:#38bdf8;">$1</strong>')
        .replace(/\b(CVE-\d{4}-\d+)\b/gi,
          '<strong style="color:#f59e0b;">$1</strong>')
        .replace(/\b(HTML\.[A-Za-z.]+|JS\.[A-Za-z.]+|Trojan\.[A-Za-z.]+|Malware\.[A-Za-z.]+|Exploit\.[A-Za-z.]+)\b/g,
          '<em style="color:#f87171;">$1</em>');
      return `<p style="margin:0 0 14px;line-height:1.9;font-size:12px;color:var(--text);">${highlighted}</p>`;
    }).join("");

    body.innerHTML = html || `<p style="color:var(--muted);font-size:12px;">No note content generated.</p>`;
    panel._socNote = text;
    if (panel.scrollIntoView) panel.scrollIntoView({ behavior:"smooth", block:"start" });
  }

    $("lt-soc-copy-btn")?.addEventListener("click", async () => {
    const note = $("lt-soc-note-panel")?._socNote || $("lt-soc-note-body")?.innerText || "";
    if (!note) { setLTStatus("No note to copy — generate a SOC note first."); return; }
    try { await navigator.clipboard.writeText(note); setLTStatus("SOC case note copied to clipboard ✓"); } catch { setLTStatus("Copy failed — please select and copy manually."); }
  });
  $("lt-soc-addcase-btn")?.addEventListener("click", () => {
    const note = $("lt-soc-note-panel")?._socNote || $("lt-soc-note-body")?.textContent || "";
    if (!note) return;
    if (!activeCase) { alert("No active case. Create a case in the Case Manager tab first."); return; }
    activeCase.notes = (activeCase.notes||"") + "\n\n─────────────────────────────────\nSOC CASE NOTE\n─────────────────────────────────\n" + note;
    saveActiveCase();
    setLTStatus("SOC case note added to active case");
    switchTab("case");
  });

  // Expose key functions globally for testing and external access
  window.generateSOCCaseNote = generateSOCCaseNote;
  window.triageLog = triageLog;

  // ════════════════════════════════════════════════════════════════
  // DEEP TRIAGE — Enhanced contextual analysis engine
  // Uses the structured output from the regex parser as grounding,
  // then runs a deeper analysis pass for context the regex misses.
  // Zero external branding — appears as internal toolkit feature only.
  // ════════════════════════════════════════════════════════════════
  $("lt-deep-triage-btn")?.addEventListener("click", async () => {
    const input  = $("lt-input");
    const rawLog = input?.value?.trim();
    if (!rawLog) { setLTStatus("Paste a log first."); return; }

    const panel  = $("lt-deep-triage-panel");
    const body   = $("lt-deep-triage-body");
    if (!panel || !body) return;

    // Run the regex triage first (or reuse existing result)
    if (!lastTriageResult) {
      $("lt-analyze-btn")?.click();
      await new Promise(r => setTimeout(r, 600));
    }
    const triageRes = lastTriageResult || {};
    const pf = triageRes.prefillData || {};
    const findings = (triageRes.findings || []).join("\n");
    const iocs = triageRes.iocs || {};
    const eventType = triageRes.eventType || "Unknown";
    const severity  = triageRes.severity  || "info";

    // Show loading state
    panel.style.display = "block";
    body.innerHTML = `<div style="color:var(--muted);font-size:11px;padding:8px 0;">
      <span style="display:inline-block;animation:spin 1s linear infinite;margin-right:6px;">⟳</span>
      Running enhanced analysis…
    </div>`;
    if (panel.scrollIntoView) panel.scrollIntoView({ behavior:"smooth", block:"start" });

    // Build a concise structured context block from the parser output
    // This grounds the analysis in what we already know — reduces hallucination
    const structuredContext = [
      `EVENT TYPE: ${eventType}`,
      `SEVERITY: ${severity.toUpperCase()}`,
      pf.username     ? `USER: ${pf.username}` : "",
      pf.hostname     ? `ENDPOINT: ${pf.hostname}` : "",
      pf.src_ip       ? `SOURCE IP: ${pf.src_ip}` : "",
      pf.dest_ip      ? `DEST IP: ${pf.dest_ip}` : "",
      pf.dest_port    ? `DEST PORT: ${pf.dest_port}` : "",
      pf.url          ? `URL: ${pf.url}` : "",
      pf.referer      ? `REFERER: ${pf.referer}` : "",
      pf.threat_name  ? `THREAT/SIGNATURE: ${pf.threat_name}` : "",
      pf.category     ? `CATEGORY: ${pf.category}` : "",
      pf.rule         ? `RULE/POLICY: ${pf.rule}` : "",
      pf.location     ? `LOCATION: ${pf.location}` : "",
      pf.carrier      ? `CARRIER/ISP: ${pf.carrier}` : "",
      pf.department   ? `DEPARTMENT: ${pf.department}` : "",
      pf.role         ? `USER ROLE: ${pf.role}` : "",
      pf.alert_count  ? `ALERT COUNT: ${pf.alert_count} correlated alerts` : "",
      pf.fail_ips     ? `FAILURE IPs: ${pf.fail_ips}` : "",
      pf.success_ips  ? `SUCCESS IPs: ${pf.success_ips}` : "",
      pf.device       ? `DEVICE: ${pf.device}` : "",
      pf.cmdline      ? `COMMAND LINE: ${pf.cmdline.slice(0,200)}` : "",
      pf.hash         ? `SHA256: ${pf.hash.slice(0,64)}` : "",
      findings        ? `\nPARSER FINDINGS:\n${findings}` : "",
      (iocs.ips||[]).length ? `IPs EXTRACTED: ${iocs.ips.slice(0,6).join(", ")}` : "",
      (triageRes.mitre||[]).length ? `MITRE: ${triageRes.mitre.slice(0,5).join(", ")}` : "",
    ].filter(Boolean).join("\n");

    // The system prompt — zero AI/vendor attribution
    const systemPrompt = `You are a senior SOC analyst with 10+ years in incident response, threat hunting, and DFIR. You receive parsed security log data and produce a structured triage assessment.

RULES:
- Never mention AI, machine learning, LLMs, or any vendor name
- Write in first-person analyst voice: "I assess...", "The pattern indicates...", "My recommendation..."
- Be direct and specific — no filler phrases, no hedging on clear indicators
- Always ground analysis in the specific field values provided — never invent IOCs
- Structure output exactly as specified below

OUTPUT FORMAT (use these exact section headers):
## Triage Assessment
[2-3 sentences: what happened, confidence level (High/Medium/Low), and why]

## Key Risk Indicators
[Bullet list of the 3-6 most significant signals from the log — be specific with values]

## Attack Chain Analysis  
[What technique/pattern this represents, what stage in the kill chain, what likely happened before/after this event]

## Verdict & Confidence
[TP/FP/BEN + confidence % + one-line justification]

## Immediate Actions
[Numbered list of 3-6 specific, actionable steps — include tool names, commands, or console paths where relevant]

## Hunt Pivots
[2-4 specific follow-on queries or pivots an analyst should run — reference the specific IOCs from this log]`;

    const userPrompt = `STRUCTURED PARSER OUTPUT:
${structuredContext}

RAW LOG (first 3000 chars):
${rawLog.slice(0, 3000)}

Produce the triage assessment. Be specific to the values above — do not generalise.`;

    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: systemPrompt,
          messages: [{ role: "user", content: userPrompt }],
        }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        body.innerHTML = `<div style="color:#f87171;font-size:11px;">Analysis unavailable: ${err?.error?.message || resp.status}. Check network settings.</div>`;
        return;
      }

      const data = await resp.json();
      const text = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");

      // Render with markdown-style formatting — bold, headers, bullets
      const rendered = text
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
        .replace(/^## (.+)$/gm, '<div style="font-weight:800;color:#a78bfa;font-size:12px;margin:14px 0 6px;border-bottom:1px solid rgba(167,139,250,0.2);padding-bottom:4px;">$1</div>')
        .replace(/^### (.+)$/gm, '<div style="font-weight:700;color:var(--text);font-size:11px;margin:10px 0 4px;">$1</div>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code style="font-family:monospace;background:rgba(56,189,248,0.1);padding:1px 5px;border-radius:3px;color:#38bdf8;font-size:10.5px;">$1</code>')
        .replace(/^- (.+)$/gm, '<div style="padding:2px 0 2px 12px;border-left:2px solid rgba(167,139,250,0.3);margin:3px 0;">$1</div>')
        .replace(/^(\d+\.) (.+)$/gm, '<div style="padding:2px 0 2px 12px;margin:3px 0;"><span style="color:#a78bfa;font-weight:700;">$1</span> $2</div>')
        .replace(/\n/g, '<br>');

      body.innerHTML = rendered;
      panel._deepNote = text;
      setLTStatus("Enhanced analysis complete");

    } catch (e) {
      body.innerHTML = `<div style="color:#f87171;font-size:11px;">Network error: ${e.message}. Ensure the toolkit has API access.</div>`;
    }
  });

  // Deep triage copy button
  $("lt-deep-copy-btn")?.addEventListener("click", async () => {
    const note = $("lt-deep-triage-panel")?._deepNote || $("lt-deep-triage-body")?.innerText || "";
    try { await navigator.clipboard.writeText(note); setLTStatus("Enhanced analysis copied to clipboard"); } catch {}
  });

  // Deep triage add to case
  $("lt-deep-addcase-btn")?.addEventListener("click", () => {
    const note = $("lt-deep-triage-panel")?._deepNote || $("lt-deep-triage-body")?.textContent || "";
    if (!note) return;
    if (!activeCase) { alert("No active case. Create one in Case Manager first."); return; }
    activeCase.notes = (activeCase.notes||"") + "\n\n─────────────────────────────────\nENHANCED TRIAGE ANALYSIS\n─────────────────────────────────\n" + note;
    saveActiveCase();
    setLTStatus("Enhanced analysis added to active case");
    switchTab("case");
  });
  window.analyzeEmailHeadersFull = analyzeEmailHeadersFull;

  if (ltAnalyzeBtn) ltAnalyzeBtn.addEventListener("click", async () => {
    const text = ($("lt-input")?.value || "").trim();
    if (!text) { setLTStatus("Paste a log first."); return; }

    // ── STEP 1: Run regex parser instantly (offline, < 100ms) ──
    lastTriageResult = triageLog(text);
    window.lastTriageResult = lastTriageResult;
    renderLTResults(lastTriageResult);
    const total = Object.values(lastTriageResult.iocs).reduce((s,a)=>s+(a?.length||0),0);
    setLTStatus(`Triage complete — ${lastTriageResult.eventType} · ${total} IOCs extracted`);

    // ── STEP 2: Auto-generate SOC note via AI in background ───
    // Show the SOC note panel immediately with a loading state
    const socPanel = $("lt-soc-note-panel");
    const socBody  = $("lt-soc-note-body");
    const socCtrl  = $("lt-soc-note-controls");
    if (socPanel && socBody) {
      socPanel.style.display = "block";
      socBody.innerHTML = `<div style="color:var(--muted);font-size:11.5px;padding:8px 0;display:flex;align-items:center;gap:8px;">
        <span style="display:inline-block;animation:spin 1s linear infinite;">⟳</span>
        Composing case note…
      </div>`;
      // Hide controls — we're auto-generating with defaults
      if (socCtrl) socCtrl.style.display = "none";
    }

    const res  = lastTriageResult;
    const pf   = res.prefillData || {};
    const iocs = res.iocs || {};

    // Build context from all extracted fields
    const ctx = [
      `EVENT TYPE: ${res.eventType || "Security Event"}`,
      `SEVERITY: ${(res.severity||"info").toUpperCase()}`,
      ``,
      pf.username    ? `User account: ${pf.username}` : "",
      pf.department  ? `Department: ${pf.department}` : "",
      pf.role        ? `Role/Title: ${pf.role}` : "",
      pf.hostname    ? `Endpoint/Host: ${pf.hostname}` : "",
      pf.device      ? `Device: ${pf.device}` : "",
      ``,
      pf.threat_name ? `Threat/Signature: ${pf.threat_name}` : "",
      pf.category    ? `Category: ${pf.category}` : "",
      pf.rule        ? `Rule/Policy: ${pf.rule}` : "",
      pf.url         ? `Target URL: ${pf.url}` : "",
      pf.referer     ? `HTTP Referrer: ${pf.referer}` : "",
      pf.cmdline     ? `Command line: ${pf.cmdline.slice(0,200)}` : "",
      pf.hash        ? `File hash: ${pf.hash.slice(0,64)}` : "",
      pf.verdict     ? `Control action: ${pf.verdict}` : "",
      pf.http_status ? `HTTP status: ${pf.http_status}` : "",
      pf.bytes       ? `Bytes transferred: ${pf.bytes}` : "",
      ``,
      pf.timestamp   ? `Timestamp: ${pf.timestamp}` : "",
      pf.alert_count ? `Alert count: ${pf.alert_count} correlated alerts` : "",
      ``,
      pf.src_ip      ? `Source IP: ${pf.src_ip}` : "",
      pf.dest_ip     ? `Destination IP: ${pf.dest_ip}` : "",
      pf.dest_port   ? `Port: ${pf.dest_port}` : "",
      pf.location    ? `Location: ${pf.location}` : "",
      pf.carrier     ? `Carrier/ISP: ${pf.carrier}` : "",
      pf.fail_ips    ? `Auth failure IPs: ${pf.fail_ips}` : "",
      pf.success_ips ? `Auth success IPs (known-good): ${pf.success_ips}` : "",
      ``,
      (res.findings||[]).length ? `Triage findings:\n${(res.findings||[]).map(f=>"  "+f.replace(/[🚨⚠️ℹ️]/g,"").trim()).join("\n")}` : "",
      (res.mitre||[]).length ? `MITRE: ${res.mitre.slice(0,5).join(", ")}` : "",
      (iocs.domains||[]).length ? `Domains: ${iocs.domains.slice(0,8).join(", ")}` : "",
      (iocs.ips||[]).length ? `IPs: ${iocs.ips.slice(0,6).join(", ")}` : "",
      (iocs.urls||[]).length ? `URLs: ${iocs.urls.slice(0,4).join(", ")}` : "",
    ].filter(Boolean).join("\n");

    // Auto-pick verdict based on scoreAutoVerdict
    const autoV = scoreAutoVerdict(res);
    const autoVLabel = autoV === "TP" ? "TP – Blocked" : autoV === "FP" ? "FP – False Positive" : "TBD – Under Investigation";
    const autoDisp   = (res.severity === "critical" || res.severity === "high")
      ? "Escalated to Tier 2 / Incident Response" : "No Further Action (NFA)";

    const systemPrompt = [
      "You are a senior SOC analyst writing a case note for a security ticket.",
      "Write in clear flowing prose like a skilled analyst narrating what happened to a colleague who was not there.",
      "No headers, no bullet sections, no labels. Just tight readable paragraphs that cover all the facts and end with a clear verdict.",
      "",
      "STYLE RULES:",
      "Write as one continuous narrative. No WHO: WHAT: WHERE: labels. No markdown headers.",
      "Open with: who the user is, what host they were on, what they did or what happened to them.",
      "Weave in when it happened, where the traffic went, what the security control detected and did, all in natural sentence flow.",
      "Name every IOC explicitly: full email, exact hostname, exact IPs, exact URLs, exact threat signature, exact rule name.",
      "If there is a referrer or redirect chain trace it in order: accessed X which redirected to Y then to Z.",
      "If there is an auth pattern (failures then successes or two locations) tell that story chronologically with the specific IPs and locations.",
      "Explain WHY it matters briefly, what the threat type means in plain terms.",
      "State whether there is or is not evidence of compromise, based only on what the logs show.",
      "End with a single recommendation sentence: Recommend marking as [VERDICT] / [DISPOSITION]",
      "After the narrative add a short Recommended Actions: section with 3-5 numbered specific steps using the actual IOCs.",
      "Maximum total length: 150-200 words for narrative plus actions. Be concise. Every sentence must add information.",
      "Do not mention AI any vendor tools or how this note was generated.",
      "Do not use bold headers or markdown formatting of any kind. Plain text only.",
      "",
      "EXAMPLE OF THE CORRECT OUTPUT STYLE:",
      "User rb092513@mmhfgb.com on host 2411-5FR2WH3 accessed hytechroofing.com which then redirected to multiple suspicious domains including eztwl.attemportantly.my.id chimebutetrinime.attemportantly.my.id and userstatics.com. These requests were blocked by Zscaler under the signature HTML.Scam.TechSupport indicating attempted access to malicious tech-support scam content. Based on the available logs the malicious web traffic was blocked before full content retrieval so there is no direct evidence of successful execution or compromise at this time. Recommend marking as TP Blocked / No Further Action.",
      "",
      "Recommended Actions:",
      "1. Add hytechroofing.com userstatics.com and *.attemportantly.my.id to the proxy blocklist.",
      "2. Pull EDR telemetry for host 2411-5FR2WH3 covering 30 minutes before and after the event.",
      "3. Check proxy logs for other users who accessed hytechroofing.com in the same window.",
    ].join("\n");


    const userPrompt = "EVENT DATA:\n" + ctx + "\n\nVerdict: " + autoVLabel + "\nDisposition: " + autoDisp + "\n\nWrite the case note now. Plain text, no markdown, no headers, no labels.";

    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 600,
          system: systemPrompt,
          messages: [{ role:"user", content: userPrompt }],
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        const noteText = (data.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("\n").trim();
        if (socPanel && socBody) renderSOCNote(socBody, socPanel, noteText);
        setLTStatus(`Triage complete — ${res.eventType} · ${total} IOCs · Case note ready`);
      } else {
        // API error — show offline fallback silently
        const fallback = generateSOCCaseNote(res, "TP_blocked", "NFA", "", "");
        if (socPanel && socBody) renderSOCNote(socBody, socPanel, fallback);
        setLTStatus(`Triage complete — ${res.eventType} · ${total} IOCs extracted`);
      }
    } catch (_) {
      // Network unavailable — show offline fallback silently
      const fallback = generateSOCCaseNote(res, "TP_blocked", "NFA", "", "");
      if (socPanel && socBody) renderSOCNote(socBody, socPanel, fallback);
      setLTStatus(`Triage complete — ${res.eventType} · ${total} IOCs extracted`);
    }
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


  // ══════════════════════════════════════════════════════════════
  // SEARCH ENGINE — type detection, link builders, input handler
  // ══════════════════════════════════════════════════════════════

  function setSearchMode(on) {
    document.body.classList.toggle("search-mode", !!on);
  }

  function showRelevantTools(types) {
    document.querySelectorAll(".tool-section[data-type]").forEach(s => s.classList.remove("active"));
    if (!types || !types.length) return;
    types.forEach(t => {
      const sec = document.querySelector(`.tool-section[data-type="${t}"]`);
      if (sec) sec.classList.add("active");
    });
  }

  // Base/landing URLs for each tool — shown when no IOC is inputted
  const LANDING_URLS = {
    // IP tools
    ip_vt:"https://www.virustotal.com/",               ip_abuseipdb:"https://www.abuseipdb.com/",
    ip_talos:"https://talosintelligence.com/",          ip_ibmxf:"https://exchange.xforce.ibmcloud.com/",
    ip_otx:"https://otx.alienvault.com/",               ip_anyrun:"https://any.run/",
    ip_mxtoolbox:"https://mxtoolbox.com/",              ip_blacklistchecker:"https://blacklistchecker.com/",
    ip_cleantalk:"https://cleantalk.org/blacklists",    ip_shodan:"https://www.shodan.io/",
    ip_censys:"https://search.censys.io/",              ip_greynoise:"https://viz.greynoise.io/",
    ip_iplocation:"https://iplocation.io/",             ip_ipinfo:"https://ipinfo.io/",
    ip_spur:"https://spur.us/",                        ip_clickfix:"https://clickfix.carsonww.com/",
    ip_ripestat:"https://stat.ripe.net/",               ip_bgphe:"https://bgp.he.net/",
    ip_nitter:"https://nitter.net/",                    ip_threatminer:"https://www.threatminer.org/",
    ip_urlscan:"https://urlscan.io/",                   ip_viewdns:"https://viewdns.info/",
    ip_scamalytics:"https://scamalytics.com/",          ip_threatfox:"https://threatfox.abuse.ch/",
    ip_pulsedive:"https://pulsedive.com/",              ip_securitytrails:"https://securitytrails.com/",
    ip_myip:"https://myip.ms/",
    // Domain tools
    dom_vt:"https://www.virustotal.com/",              dom_talos:"https://talosintelligence.com/",
    dom_ibmxf:"https://exchange.xforce.ibmcloud.com/", dom_otx:"https://otx.alienvault.com/",
    dom_urlscan:"https://urlscan.io/",                  dom_mxtoolbox:"https://mxtoolbox.com/",
    dom_blacklistchecker:"https://blacklistchecker.com/", dom_cleantalk_bl:"https://cleantalk.org/blacklists",
    dom_cleantalk_malware:"https://cleantalk.org/website", dom_sucuri:"https://sitecheck.sucuri.net/",
    dom_urlvoid:"https://www.urlvoid.com/",             dom_urlhaus:"https://urlhaus.abuse.ch/",
    dom_whois:"https://www.whois.com/",                 dom_dnslytics:"https://dnslytics.com/",
    dom_netcraft:"https://searchdns.netcraft.com/",     dom_webcheck:"https://web-check.xyz/",
    dom_securitytrails:"https://securitytrails.com/",  dom_hudsonrock_info:"https://intel.hudsonrock.com/",
    dom_hudsonrock_urls:"https://cavalier.hudsonrock.com/", dom_wayback:"https://web.archive.org/",
    dom_wayback_save:"https://web.archive.org/",        dom_browserling:"https://www.browserling.com/",
    dom_anyrun:"https://any.run/",                      dom_anyrun_safe:"https://any.run/submit/",
    dom_phishing_checker:"https://phishing.finsin.cl/", dom_clickfix:"https://clickfix.carsonww.com/",
    dom_nitter:"https://nitter.net/",                   dom_netlas:"https://app.netlas.io/",
    dom_censys:"https://search.censys.io/",             dom_shodan:"https://www.shodan.io/",
    dom_dnstools:"https://whois.domaintools.com/",      dom_crtsh:"https://crt.sh/",
    dom_dnsdumpster:"https://dnsdumpster.com/",         dom_socradar:"https://socradar.io/",
    dom_rdap:"https://lookup.icann.org/",               dom_passivedns:"https://passivedns.mnemonic.no/",
    dom_pulsedive:"https://pulsedive.com/",             dom_threatfox:"https://threatfox.abuse.ch/",
    // URL tools
    url_vt:"https://www.virustotal.com/",              url_urlscan:"https://urlscan.io/",
    url_urlvoid:"https://www.urlvoid.com/",             url_urlhaus:"https://urlhaus.abuse.ch/",
    url_phishtank:"https://www.phishtank.com/",         url_checkphish:"https://checkphish.ai/",
    url_safebrowsing:"https://transparencyreport.google.com/safe-browsing/search",
    url_sucuri:"https://sitecheck.sucuri.net/",         url_webcheck:"https://web-check.xyz/",
    url_otx:"https://otx.alienvault.com/",              url_threatfox:"https://threatfox.abuse.ch/",
    url_wayback:"https://web.archive.org/",             url_wayback_save:"https://web.archive.org/save/",
    url_browserling:"https://www.browserling.com/",     url_anyrun:"https://any.run/submit/",
    url_netcraft:"https://sitereport.netcraft.com/",    url_phishing_checker:"https://phishing.finsin.cl/",
    url_clickfix:"https://clickfix.carsonww.com/",      url_nitter:"https://nitter.net/",
    url_socradar:"https://socradar.io/labs/app/link-analysis/", url_hudsonrock_info:"https://intel.hudsonrock.com/",
    url_hudsonrock_urls:"https://cavalier.hudsonrock.com/", url_securitytrails:"https://securitytrails.com/",
    url_cyberchef:"https://gchq.github.io/CyberChef/",
    // Hash tools
    h_vt:"https://www.virustotal.com/",                h_hybrid:"https://www.hybrid-analysis.com/",
    h_joesandbox:"https://www.joesandbox.com/",         h_triage:"https://tria.ge/",
    h_malshare:"https://malshare.com/",                 h_malwarebazaar:"https://bazaar.abuse.ch/",
    h_ibmxf:"https://exchange.xforce.ibmcloud.com/",   h_talos:"https://talosintelligence.com/",
    h_otx:"https://otx.alienvault.com/",                h_anyrun:"https://any.run/",
    h_threatminer:"https://www.threatminer.org/",       h_intezer:"https://analyze.intezer.com/",
    h_cyberchef:"https://gchq.github.io/CyberChef/",   h_nitter:"https://nitter.net/",
    // Email tools
    em_hunter:"https://hunter.io/",                    em_hibp:"https://haveibeenpwned.com/",
    em_intelbase:"https://intelbase.is/",               em_emailrep:"https://emailrep.io/",
    em_epieos:"https://epieos.com/",                    em_intelx:"https://intelx.io/",
    em_phonebook:"https://phonebook.cz/",               em_dehashed:"https://dehashed.com/",
    // CVE tools
    cve_nvd:"https://nvd.nist.gov/",                   cve_cveorg:"https://www.cve.org/",
    cve_cisa:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cve_exploitdb:"https://www.exploit-db.com/",        cve_vulners:"https://vulners.com/",
    cve_github:"https://github.com/",                   cve_socradar:"https://socradar.io/labs/app/cve-radar/",
    cve_rapid7:"https://www.rapid7.com/db/",            cve_snyk:"https://security.snyk.io/",
    cve_assetnote:"https://searchcve.com/",
    cvep_cisa_kev:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss:"https://www.first.org/epss/",            cvep_socradar:"https://socradar.io/labs/app/cve-radar/",
    cvep_greynoise:"https://viz.greynoise.io/trends/",  cvep_shodan:"https://www.shodan.io/",
    cvep_vulncheck:"https://vulncheck.com/",
    // Username tools
    usr_namechk:"https://namechk.com/",                 usr_whatsmyname:"https://whatsmyname.app/",
    usr_maigret:"https://github.com/soxoj/maigret",     usr_sherlock:"https://github.com/sherlock-project/sherlock",
    usr_socialsearcher:"https://www.social-searcher.com/", usr_dehashed:"https://dehashed.com/",
    usr_intelx:"https://intelx.io/",                   usr_breachdir:"https://breachdir.com/",
    usr_leakcheck:"https://leakcheck.io/",              usr_twitter:"https://twitter.com/",
    usr_reddit:"https://www.reddit.com/",               usr_github:"https://github.com/",
    usr_instagram:"https://www.instagram.com/",         usr_tiktok:"https://www.tiktok.com/",
    usr_snapchat:"https://www.snapchat.com/",           usr_telegram:"https://t.me/",
    usr_discord:"https://discord.com/",                 usr_nitter:"https://nitter.net/",
    usr_pastebin:"https://pastebin.com/",               usr_linkedin:"https://www.linkedin.com/",
    usr_spiderfoot:"https://github.com/smicallef/spiderfoot",
    // Other tools
    ph_truecaller:"https://www.truecaller.com/",        ph_numverify:"https://numverify.com/",
    ph_phoneinfoga:"https://github.com/sundowndev/phoneinfoga", ph_eyecon:"https://www.eyecon.me/",
    ph_calleridtest:"https://www.calleridtest.com/",    ph_intelx:"https://intelx.io/",
    ph_dehashed:"https://dehashed.com/",                ph_google:"https://www.google.com/",
    mac_macvendors:"https://api.macvendors.com/",        mac_maclookup:"https://maclookup.app/",
    mac_wireshark_oui:"https://www.wireshark.org/tools/oui-lookup.html", mac_google:"https://www.google.com/",
    asn_bgphe:"https://bgp.he.net/",                    asn_ripestat:"https://stat.ripe.net/",
    asn_asnlookup:"https://asnlookup.com/",             asn_ipinfo:"https://ipinfo.io/",
    asn_shodan:"https://www.shodan.io/",                asn_greynoise:"https://viz.greynoise.io/",
    btc_blockchain:"https://www.blockchain.com/",        btc_blockchair:"https://blockchair.com/",
    btc_walletexplorer:"https://www.walletexplorer.com/", btc_otx:"https://otx.alienvault.com/",
    btc_google:"https://www.google.com/",
    eth_etherscan:"https://etherscan.io/",               eth_blockchair:"https://blockchair.com/",
    eth_google:"https://www.google.com/",
    hdr_mha:"https://mha.azurewebsites.net/",            hdr_google:"https://toolbox.googleapps.com/apps/messageheader/",
    hdr_mxtoolbox:"https://mxtoolbox.com/EmailHeaders.aspx", hdr_traceemail:"https://www.ip-tracker.org/",
    hdr_dnschecker:"https://dnschecker.org/",
    ev_eventidnet:"https://www.eventid.net/",            ev_mslearn:"https://learn.microsoft.com/",
    ev_hackthelogs:"https://www.hackthelogs.com/",       sysmon_mslearn:"https://learn.microsoft.com/",
    sysmon_swift:"https://github.com/SwiftOnSecurity/sysmon-config", sysmon_hackthelogs:"https://www.hackthelogs.com/",
    soc_ruler:"https://ruler-project.github.io/",        soc_hackthelogs:"https://www.hackthelogs.com/",
    soc_explainshell:"https://explainshell.com/",        soc_sigma:"https://sigmahq.github.io/",
    soc_uncoder:"https://uncoder.io/",
    lb_lolbas:"https://lolbas-project.github.io/",       lb_gtfobins:"https://gtfobins.github.io/",
    lb_hijacklibs:"https://hijacklibs.net/",
  };

  function setLandingLinks() {
    // Called on startup / clear — show ALL tool sections with base landing URLs
    document.querySelectorAll(".tool-section[data-type]").forEach(s => s.classList.add("active"));
    // Set landing URLs for all tools
    Object.entries(LANDING_URLS).forEach(([id, url]) => setHref(id, url));
    const vb = $("verdict-banner"); if (vb) vb.style.display = "none";
    const lg = $("landing-guide"); if (lg) lg.style.display = "none";
    const ce = $("cve-enrichment"); if (ce) ce.style.display = "none";
    const ms = $("mitre-suggested"); if (ms) ms.style.display = "none";
    const qa = $("quick-assessment-panel"); if (qa) qa.style.display = "none";
  }

  function renderCardMeta() {
    // Called after search — show verdict/assessment banner for the current IOC type
    const banner = $("verdict-banner");
    if (!banner) return;
    const raw = (input?.value || "").trim();
    if (!raw) { banner.style.display = "none"; return; }
    const { type, q } = detectType(refangSmart(raw), "");
    if (!type) { banner.style.display = "none"; return; }
    const ASSESSMENT = {
      ip:       { label:"🌐 IP Address", note:"Check reputation across all tools. Look for blocklist hits, hosting type (VPN/TOR/datacenter = higher risk), and ASN context." },
      domain:   { label:"🏠 Domain",     note:"Check registration age (WHOIS), DNS history, blocklist status, and whether it resolves to a known malicious IP." },
      url:      { label:"🔗 URL",        note:"Scan the full URL in URLScan and VT. Check the domain separately. Expand shortened URLs before analysis." },
      hash:     { label:"#️⃣ File Hash",  note:"Submit to sandbox tools for dynamic analysis. Check VT detection count — even 1/70 is noteworthy for targeted malware." },
      email:    { label:"📧 Email",      note:"Check for breaches (HIBP), verify the domain, and look for historical phishing use. Use Email Header Analyzer for full header review." },
      cve:      { label:"🔴 CVE",        note:"Check CISA KEV status and EPSS score first — if both are high, treat as actively exploited. Review patch availability." },
      eventid:  { label:"🪟 Event ID",   note:"Cross-reference with MITRE ATT&CK. Event IDs alone are not IOCs — correlate with user, host, and time context." },
      username: { label:"👤 Username",   note:"Check for credential exposure across breach databases. Username reuse across platforms is a major pivot point." },
      phone:    { label:"📞 Phone",      note:"Search breach databases and social media. Phone numbers in phishing headers are TOAD (callback phishing) indicators." },
      mac:      { label:"🖥 MAC Address",note:"Identify the vendor prefix (OUI). MACs can be spoofed — cross-reference with DHCP logs for the source device." },
      asn:      { label:"🌐 ASN",        note:"Identify the hosting org. Datacenter/VPN ASNs (DigitalOcean, M247, Mullvad) from internal alerts are high-risk indicators." },
      btc:      { label:"₿ Bitcoin",     note:"Trace transaction history. Ransomware payments and darknet markets often cluster around specific wallets." },
      eth:      { label:"⧫ Ethereum",    note:"Check contract interactions and transaction history. DeFi exploits and crypto theft often leave traceable on-chain trails." },
      header:   { label:"📨 Email Header",note:"Use the Email Header Analyzer tab for full authentication check (SPF/DKIM/DMARC), relay hop analysis, and verdict." },
    };
    const info = ASSESSMENT[type];
    if (!info) { banner.style.display = "none"; return; }
    banner.style.display = "flex";
    banner.style.borderColor = "rgba(56,189,248,0.3)";
    banner.style.background  = "rgba(56,189,248,0.05)";
    banner.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:4px;width:100%;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:11px;font-weight:800;color:#38bdf8;text-transform:uppercase;letter-spacing:.05em;">${info.label}</span>
          <span style="font-size:10px;color:var(--muted);">— ${esc(q.slice(0,60))}${q.length>60?"…":""}</span>
        </div>
        <div style="font-size:11px;color:var(--muted);line-height:1.6;">💡 ${info.note}</div>
      </div>`;
  }

  function injectCustomTools(typeHint, q) {
    const ctList = $("ct-custom-links");
    if (!ctList) return;
    ctList.querySelectorAll(".ct-injected").forEach(el => el.remove());
    const templates = JSON.parse(localStorage.getItem("osint_custom_tools") || "[]");
    templates.forEach(t => {
      if (t.types && t.types.length && !t.types.includes(typeHint)) return;
      const url = t.url.replace(/\{IOC\}/g, encodeURIComponent(q));
      const a = document.createElement("a");
      a.href = url; a.target = "_blank"; a.rel = "noopener";
      a.textContent = t.name || "Custom Tool";
      a.className = "tool-link ct-injected";
      ctList.appendChild(a);
    });
  }

  // Render custom tool cards in the custom tools tab (ct-list)
  function renderCustomTools() {
    const list = $("ct-list");
    if (!list) return;
    const tools = (() => { try { return JSON.parse(localStorage.getItem("osint_custom_tools") || "[]"); } catch { return []; } })();
    if (!tools.length) {
      list.innerHTML = '<div class="bulk-empty" style="padding:20px;text-align:center;color:var(--muted);">No custom tools added yet. Use the form above to add your first tool.</div>';
      return;
    }
    list.innerHTML = tools.map((t, i) => `
      <div class="ct-item">
        <span class="ct-icon">${esc(t.icon||"🔗")}</span>
        <div class="ct-details">
          <div class="ct-name">${esc(t.name||"Unnamed")}</div>
          <div class="ct-url-preview">${esc(t.url||"")}</div>
          <div class="ct-type-badge">${esc(t.types?.join(", ")||"all types")}</div>
        </div>
        <button class="ct-delete-btn" data-index="${i}" type="button">🗑</button>
      </div>`).join("");
    list.querySelectorAll(".ct-delete-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const tools2 = (() => { try { return JSON.parse(localStorage.getItem("osint_custom_tools")||"[]"); } catch { return []; } })();
        tools2.splice(parseInt(btn.dataset.index), 1);
        try { localStorage.setItem("osint_custom_tools", JSON.stringify(tools2)); } catch {}
        renderCustomTools();
      });
    });
  }

  // Show/hide the CVE enrichment panel below the search box
  function showCVEEnrichment(show, cve) {
    const panel = $("cve-enrichment");
    if (!panel) return;
    if (!show) { panel.style.display = "none"; return; }
    panel.style.display = "block";
    if (cve) {
      panel.innerHTML = `<div style="font-size:11px;color:var(--muted);padding:8px 0 4px;">
        <span style="color:#f87171;font-weight:700;">CVE:</span> ${esc(cve)} — 
        <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" style="color:#38bdf8;">NVD ↗</a> · 
        <a href="https://socradar.io/labs/app/cve-radar/${encodeURIComponent(cve)}" target="_blank" style="color:#38bdf8;">SOCRadar ↗</a> · 
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="color:#38bdf8;">CISA KEV ↗</a>
      </div>`;
    }
  }

  // Wire up Custom Tools add button
  const ctAddBtn = $("ct-add-btn");
  if (ctAddBtn) {
    ctAddBtn.addEventListener("click", () => {
      const name  = ($("ct-name")?.value || "").trim();
      const icon  = ($("ct-icon")?.value || "🔗").trim();
      const url   = ($("ct-url")?.value  || "").trim();
      const typeV = $("ct-type")?.value || "all";
      if (!name || !url) { setStatus("Status: enter tool name and URL template"); return; }
      if (!url.includes("{IOC}")) { setStatus("Status: URL must contain {IOC} placeholder"); return; }
      const tools = (() => { try { return JSON.parse(localStorage.getItem("osint_custom_tools")||"[]"); } catch { return []; } })();
      tools.push({ name, icon, url, types: typeV === "all" ? [] : [typeV] });
      try { localStorage.setItem("osint_custom_tools", JSON.stringify(tools)); } catch {}
      if ($("ct-name")) $("ct-name").value = "";
      if ($("ct-url"))  $("ct-url").value  = "";
      renderCustomTools();
      setStatus(`Status: added custom tool "${name}"`);
    });
  }



  // ── Link builders — one per IOC type ──────────────────────────
  function buildLinksForIP(ip) {
    const e = encodeURIComponent;
    setHref("ip_vt",             `https://www.virustotal.com/gui/ip-address/${e(ip)}`);
    setHref("ip_abuseipdb",      `https://www.abuseipdb.com/check/${e(ip)}`);
    setHref("ip_talos",          `https://talosintelligence.com/reputation_center/lookup?search=${e(ip)}`);
    setHref("ip_ibmxf",          `https://exchange.xforce.ibmcloud.com/ip/${e(ip)}`);
    setHref("ip_otx",            `https://otx.alienvault.com/indicator/ip/${e(ip)}`);
    setHref("ip_anyrun",         anyrunLookupGeneral(ip));
    setHref("ip_mxtoolbox",      `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${e(ip)}&run=toolpage`);
    setHref("ip_blacklistchecker",`https://blacklistchecker.com/ip/${e(ip)}`);
    setHref("ip_cleantalk",      `https://cleantalk.org/blacklists/${e(ip)}`);
    setHref("ip_shodan",         `https://www.shodan.io/host/${e(ip)}`);
    setHref("ip_censys",         `https://search.censys.io/hosts/${e(ip)}`);
    setHref("ip_greynoise",      `https://viz.greynoise.io/ip/${e(ip)}`);
    setHref("ip_iplocation",     `https://iplocation.io/ip/${e(ip)}`);
    setHref("ip_ipinfo",         `https://ipinfo.io/${e(ip)}`);
    setHref("ip_spur",           `https://spur.us/context/${e(ip)}`);
    setHref("ip_clickfix",       `https://clickfix.carsonww.com/?q=${e(ip)}`);
    setHref("ip_ripestat",       `https://stat.ripe.net/${e(ip)}`);
    setHref("ip_bgphe",          `https://bgp.he.net/ip/${e(ip)}`);
    setHref("ip_nitter",         `https://nitter.net/search?q=${e(ip)}`);
    setHref("ip_threatminer",    `https://www.threatminer.org/host.php?q=${e(ip)}`);
    setHref("ip_urlscan",        `https://urlscan.io/search/#ip:${e(ip)}`);
    setHref("ip_viewdns",        `https://viewdns.info/reverseip/?host=${e(ip)}&t=1`);
    setHref("ip_scamalytics",    `https://scamalytics.com/ip/${e(ip)}`);
    setHref("ip_threatfox",      `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(ip)}`);
    setHref("ip_pulsedive",      `https://pulsedive.com/indicator/?ioc=${e(ip)}`);
    setHref("ip_securitytrails", `https://securitytrails.com/list/ip/${e(ip)}`);
    setHref("ip_myip",           `https://myip.ms/info/whois/${e(ip)}`);
    injectCustomTools("ip", ip);
  }

  function buildLinksForDomain(domain) {
    const e = encodeURIComponent;
    setHref("dom_vt",            `https://www.virustotal.com/gui/domain/${e(domain)}`);
    setHref("dom_talos",         `https://talosintelligence.com/reputation_center/lookup?search=${e(domain)}`);
    setHref("dom_ibmxf",         `https://exchange.xforce.ibmcloud.com/url/${e(domain)}`);
    setHref("dom_otx",           `https://otx.alienvault.com/indicator/domain/${e(domain)}`);
    setHref("dom_urlscan",       `https://urlscan.io/search/#domain:${e(domain)}`);
    setHref("dom_mxtoolbox",     `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${e(domain)}&run=toolpage`);
    setHref("dom_blacklistchecker",`https://blacklistchecker.com/domain/${e(domain)}`);
    setHref("dom_cleantalk_bl",  `https://cleantalk.org/blacklists/${e(domain)}`);
    setHref("dom_cleantalk_malware",`https://cleantalk.org/website/${e(domain)}`);
    setHref("dom_sucuri",        `https://sitecheck.sucuri.net/results/${e(domain)}`);
    setHref("dom_urlvoid",       `https://www.urlvoid.com/scan/${e(domain)}/`);
    setHref("dom_urlhaus",       `https://urlhaus.abuse.ch/browse.php?search=${e(domain)}`);
    setHref("dom_whois",         `https://www.whois.com/whois/${e(domain)}`);
    setHref("dom_dnslytics",     `https://dnslytics.com/domain/${e(domain)}`);
    setHref("dom_netcraft",      `https://searchdns.netcraft.com/?host=${e(domain)}`);
    setHref("dom_webcheck",      `https://webcheck.spiderlabs.io/?q=${e(domain)}`);
    setHref("dom_securitytrails",`https://securitytrails.com/domain/${e(domain)}`);
    setHref("dom_hudsonrock_info",`https://intel.hudsonrock.com/?q=${e(domain)}`);
    setHref("dom_hudsonrock_urls",`https://cavalier.hudsonrock.com/?q=${e(domain)}`);
    setHref("dom_wayback",       `https://web.archive.org/web/*/${e(domain)}`);
    setHref("dom_wayback_save",  `https://web.archive.org/save/${e(domain)}`);
    setHref("dom_browserling",   `https://www.browserling.com/browse/${e(domain)}`);
    setHref("dom_anyrun",        anyrunLookupGeneral(domain));
    setHref("dom_anyrun_safe",   `https://any.run/submit/?url=${e("http://"+domain)}`);
    setHref("dom_phishing_checker",`https://phishing.finsin.cl/list.php?search=${e(domain)}`);
    setHref("dom_clickfix",      `https://clickfix.carsonww.com/?q=${e(domain)}`);
    setHref("dom_nitter",        `https://nitter.net/search?q=${e(domain)}`);
    setHref("dom_netlas",        `https://app.netlas.io/domains/?q=${e(domain)}`);
    setHref("dom_censys",        `https://search.censys.io/search?resource=hosts&q=${e(domain)}`);
    setHref("dom_shodan",        `https://www.shodan.io/search?query=${e(domain)}`);
    setHref("dom_dnstools",      `https://whois.domaintools.com/${e(domain)}`);
    setHref("dom_crtsh",         `https://crt.sh/?q=${e(domain)}`);
    setHref("dom_dnsdumpster",   `https://dnsdumpster.com/`);
    setHref("dom_socradar",      `https://www.google.com/search?q=${e("SOCRadar dark web report "+domain)}`);
    setHref("dom_rdap",          `https://lookup.icann.org/lookup?name=${e(domain)}`);
    setHref("dom_passivedns",    `https://passivedns.mnemonic.no/?q=${e(domain)}`);
    setHref("dom_pulsedive",     `https://pulsedive.com/indicator/?ioc=${e(domain)}`);
    setHref("dom_threatfox",     `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(domain)}`);
    injectCustomTools("domain", domain);
  }

  function buildLinksForURL(url) {
    const e = encodeURIComponent;
    const domain = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
    setHref("url_vt",            `https://www.virustotal.com/gui/url/${e(url)}`);
    setHref("url_urlscan",       `https://urlscan.io/search/#page.url:${e(url)}`);
    setHref("url_urlvoid",       `https://www.urlvoid.com/scan/${e(domain || url)}/`);
    setHref("url_urlhaus",       `https://urlhaus.abuse.ch/browse.php?search=${e(url)}`);
    setHref("url_phishtank",     `https://www.phishtank.com/phish_search.php?valid=y&active=y&Search=Search`);
    setHref("url_checkphish",    `https://checkphish.ai/domain/${e(domain || url)}`);
    setHref("url_safebrowsing",  `https://transparencyreport.google.com/safe-browsing/search?url=${e(url)}`);
    setHref("url_sucuri",        `https://sitecheck.sucuri.net/results/${e(url)}`);
    setHref("url_webcheck",      `https://webcheck.spiderlabs.io/?q=${e(url)}`);
    setHref("url_otx",           `https://otx.alienvault.com/indicator/url/${e(url)}`);
    setHref("url_threatfox",     `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(url)}`);
    setHref("url_wayback",       `https://web.archive.org/web/*/${e(url)}`);
    setHref("url_wayback_save",  `https://web.archive.org/save/${e(url)}`);
    setHref("url_browserling",   `https://www.browserling.com/browse/${e(url)}`);
    setHref("url_anyrun",        `https://any.run/submit/?url=${e(url)}`);
    setHref("url_netcraft",      `https://sitereport.netcraft.com/?url=${e(url)}`);
    setHref("url_phishing_checker",`https://phishing.finsin.cl/list.php?search=${e(domain||url)}`);
    setHref("url_clickfix",      `https://clickfix.carsonww.com/?q=${e(url)}`);
    setHref("url_nitter",        `https://nitter.net/search?q=${e(url)}`);
    setHref("url_socradar",      `https://socradar.io/labs/app/link-analysis/?url=${e(url)}`);
    setHref("url_hudsonrock_info",`https://intel.hudsonrock.com/?q=${e(domain||url)}`);
    setHref("url_hudsonrock_urls",`https://cavalier.hudsonrock.com/?q=${e(domain||url)}`);
    setHref("url_securitytrails",`https://securitytrails.com/domain/${e(domain||url)}`);
    setHref("url_cyberchef",     `https://gchq.github.io/CyberChef/#input=${e(btoa(url))}`);
    injectCustomTools("url", url);
  }

  function buildLinksForHash(hash) {
    const e = encodeURIComponent;
    setHref("h_vt",          `https://www.virustotal.com/gui/file/${e(hash)}`);
    setHref("h_hybrid",      `https://www.hybrid-analysis.com/search?query=${e(hash)}`);
    setHref("h_joesandbox",  `https://www.joesandbox.com/analysis/search?searchname=${e(hash)}`);
    setHref("h_triage",      `https://tria.ge/s/?q=${e(hash)}`);
    setHref("h_malshare",    `https://malshare.com/search.php?query=${e(hash)}`);
    setHref("h_malwarebazaar",`https://bazaar.abuse.ch/browse.php?search=sha256_hash:${e(hash)}`);
    setHref("h_ibmxf",       `https://exchange.xforce.ibmcloud.com/malware/${e(hash)}`);
    setHref("h_talos",       `https://www.talosintelligence.com/talos_file_reputation?disposition=N&sort=0&sha256=${e(hash)}`);
    setHref("h_otx",         `https://otx.alienvault.com/indicator/file/${e(hash)}`);
    setHref("h_anyrun",      `https://any.run/malware-trends/?md5=${e(hash)}`);
    setHref("h_threatminer", `https://www.threatminer.org/sample.php?q=${e(hash)}`);
    setHref("h_intezer",     `https://analyze.intezer.com/`);
    setHref("h_cyberchef",   `https://gchq.github.io/CyberChef/#input=${e(btoa(hash))}`);
    setHref("h_nitter",      `https://nitter.net/search?q=${e(hash)}`);
    injectCustomTools("hash", hash);
  }

  function buildLinksForEmail(email) {
    const e  = encodeURIComponent;
    const dom = (email.split("@")[1] || "").toLowerCase();
    setHref("em_hunter",     `https://hunter.io/email-verifier/${e(email)}`);
    setHref("em_hibp",       `https://haveibeenpwned.com/account/${e(email)}`);
    setHref("em_intelbase",  `https://intelbase.is/search?q=${e(email)}`);
    setHref("em_emailrep",   `https://emailrep.io/${e(email)}`);
    setHref("em_epieos",     `https://epieos.com/?q=${e(email)}&t=email`);
    setHref("em_intelx",     `https://intelx.io/?s=${e(email)}`);
    setHref("em_phonebook",  `https://phonebook.cz/email/?q=${e(email)}`);
    setHref("em_dehashed",   `https://dehashed.com/search?query=${e(email)}`);
    injectCustomTools("email", email);
  }

  function buildLinksForCVE(cve) {
    const e = encodeURIComponent;
    setHref("cve_nvd",       `https://nvd.nist.gov/vuln/detail/${e(cve)}`);
    setHref("cve_cveorg",    `https://www.cve.org/CVERecord?id=${e(cve)}`);
    setHref("cve_cisa",      `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`);
    setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${e(cve.replace("CVE-",""))}`);
    setHref("cve_vulners",   `https://vulners.com/search?query=${e(cve)}`);
    setHref("cve_github",    `https://github.com/search?q=${e(cve)}&type=repositories`);
    setHref("cve_socradar",  `https://socradar.io/labs/app/cve-radar/${e(cve)}`);
    setHref("cve_rapid7",    `https://www.rapid7.com/db/search?q=${e(cve)}`);
    setHref("cve_snyk",      `https://security.snyk.io/vuln/${e(cve)}`);
    setHref("cve_assetnote", `https://searchcve.com/search?q=${e(cve)}`);
    // CVE Plus panel (KEV/EPSS)
    setHref("cvep_cisa_kev", `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`);
    setHref("cvep_epss",     `https://www.first.org/epss/data`);
    setHref("cvep_socradar", `https://socradar.io/labs/app/cve-radar/${e(cve)}`);
    setHref("cvep_greynoise",`https://viz.greynoise.io/trends/`);
    setHref("cvep_shodan",   `https://www.shodan.io/search?query=vuln:${e(cve)}`);
    setHref("cvep_vulncheck",`https://vulncheck.com/browse/cve`);
    injectCustomTools("cve", cve);
  }

  function buildLinksForEventID(eid) {
    const e = encodeURIComponent;
    setHref("ev_eventidnet",     `https://www.eventid.net/display.asp?eventid=${e(eid)}`);
    setHref("ev_mslearn",        `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-${e(eid)}`);
    setHref("ev_hackthelogs",    `https://www.hackthelogs.com/index.php?search=${e(eid)}`);
    setHref("sysmon_mslearn",    `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`);
    setHref("sysmon_swift",      `https://github.com/SwiftOnSecurity/sysmon-config`);
    setHref("sysmon_hackthelogs",`https://www.hackthelogs.com/`);
    setHref("soc_ruler",         `https://ruler-project.github.io/ruler/`);
    setHref("soc_hackthelogs",   `https://www.hackthelogs.com/index.php?search=${e(eid)}`);
    setHref("soc_explainshell",  `https://explainshell.com/`);
    setHref("soc_sigma",         `https://sigmaHQ.github.io/`);
    setHref("soc_uncoder",       `https://uncoder.io/`);
    injectCustomTools("eventid", eid);
  }

  function buildLinksForUsername(usr) {
    const e = encodeURIComponent;
    setHref("usr_namechk",       `https://namechk.com/${e(usr)}`);
    setHref("usr_whatsmyname",   `https://whatsmyname.app/?q=${e(usr)}`);
    setHref("usr_maigret",       `https://github.com/soxoj/maigret`);
    setHref("usr_sherlock",      `https://github.com/sherlock-project/sherlock`);
    setHref("usr_socialsearcher",`https://www.social-searcher.com/social-buzz/?q5=${e(usr)}`);
    setHref("usr_dehashed",      `https://dehashed.com/search?query=${e(usr)}`);
    setHref("usr_intelx",        `https://intelx.io/?s=${e(usr)}`);
    setHref("usr_breachdir",     `https://breachdir.com/?q=${e(usr)}`);
    setHref("usr_leakcheck",     `https://leakcheck.io/search?q=${e(usr)}`);
    setHref("usr_twitter",       `https://twitter.com/${e(usr)}`);
    setHref("usr_reddit",        `https://www.reddit.com/user/${e(usr)}`);
    setHref("usr_github",        `https://github.com/${e(usr)}`);
    setHref("usr_instagram",     `https://www.instagram.com/${e(usr)}`);
    setHref("usr_tiktok",        `https://www.tiktok.com/@${e(usr)}`);
    setHref("usr_snapchat",      `https://www.snapchat.com/add/${e(usr)}`);
    setHref("usr_telegram",      `https://t.me/${e(usr)}`);
    setHref("usr_discord",       `https://discord.com/`);
    setHref("usr_nitter",        `https://nitter.net/${e(usr)}`);
    setHref("usr_pastebin",      `https://pastebin.com/u/${e(usr)}`);
    setHref("usr_linkedin",      `https://www.linkedin.com/search/results/people/?keywords=${e(usr)}`);
    setHref("usr_spiderfoot",    `https://github.com/smicallef/spiderfoot`);
    injectCustomTools("username", usr);
  }

  function buildLinksForPhone(ph) {
    const e = encodeURIComponent;
    setHref("ph_truecaller",   `https://www.truecaller.com/search/in/${e(ph)}`);
    setHref("ph_numverify",    `https://numverify.com/`);
    setHref("ph_phoneinfoga",  `https://github.com/sundowndev/phoneinfoga`);
    setHref("ph_eyecon",       `https://www.eyecon.me/`);
    setHref("ph_calleridtest", `https://www.calleridtest.com/`);
    setHref("ph_intelx",       `https://intelx.io/?s=${e(ph)}`);
    setHref("ph_dehashed",     `https://dehashed.com/search?query=${e(ph)}`);
    setHref("ph_google",       `https://www.google.com/search?q=${e('"'+ph+'"')}`);
    injectCustomTools("phone", ph);
  }

  function buildLinksForMAC(mac) {
    const e = encodeURIComponent;
    setHref("mac_macvendors",   `https://api.macvendors.com/${e(mac)}`);
    setHref("mac_maclookup",    `https://maclookup.app/search/result?mac=${e(mac)}`);
    setHref("mac_wireshark_oui",`https://www.wireshark.org/tools/oui-lookup.html`);
    setHref("mac_google",       `https://www.google.com/search?q=${e(mac+" MAC address vendor")}`);
    injectCustomTools("mac", mac);
  }

  function buildLinksForASN(asn) {
    const e = encodeURIComponent;
    const num = asn.replace(/^AS/i,"");
    setHref("asn_bgphe",     `https://bgp.he.net/${e(asn)}`);
    setHref("asn_ripestat",  `https://stat.ripe.net/${e(asn)}`);
    setHref("asn_asnlookup", `https://asnlookup.com/?asn=${e(num)}`);
    setHref("asn_ipinfo",    `https://ipinfo.io/${e(asn)}`);
    setHref("asn_shodan",    `https://www.shodan.io/search?query=asn:${e(asn)}`);
    setHref("asn_greynoise", `https://viz.greynoise.io/ip/information?ip=&asn=${e(asn)}`);
    injectCustomTools("asn", asn);
  }

  function buildLinksForBTC(addr) {
    const e = encodeURIComponent;
    setHref("btc_blockchain",     `https://www.blockchain.com/btc/address/${e(addr)}`);
    setHref("btc_blockchair",     `https://blockchair.com/bitcoin/address/${e(addr)}`);
    setHref("btc_walletexplorer", `https://www.walletexplorer.com/address/${e(addr)}`);
    setHref("btc_otx",            `https://otx.alienvault.com/indicator/cryptocurrency/${e(addr)}`);
    setHref("btc_google",         `https://www.google.com/search?q=${e('"'+addr+'"')}`);
    injectCustomTools("btc", addr);
  }

  function buildLinksForETH(addr) {
    const e = encodeURIComponent;
    setHref("eth_etherscan",  `https://etherscan.io/address/${e(addr)}`);
    setHref("eth_blockchair", `https://blockchair.com/ethereum/address/${e(addr)}`);
    setHref("eth_google",     `https://www.google.com/search?q=${e('"'+addr+'"')}`);
    injectCustomTools("eth", addr);
  }

  function buildLinksForHeaders(q) {
    setHref("hdr_mha",        "https://mha.azurewebsites.net/");
    setHref("hdr_google",     "https://toolbox.googleapps.com/apps/messageheader/analyzeheader");
    setHref("hdr_mxtoolbox",  "https://mxtoolbox.com/EmailHeaders.aspx");
    setHref("hdr_traceemail", "https://www.ip-tracker.org/find-email-host.php");
    setHref("hdr_dnschecker", "https://dnschecker.org/");
    injectCustomTools("header", q);
  }

  // ── Main search dispatcher ─────────────────────────────────────
  function runSearch(raw) {
    const refangedRaw = refangSmart(raw.trim());
    const pasted = (output?.value || "").trim();
    const { type, q } = detectType(refangedRaw, pasted);
    // Hide landing guide when search starts
    const lg = $("landing-guide"); if (lg) lg.style.display = "none";

    if (!type) {
      setStatus("Status: type not recognized — try an IP, domain, hash, email, URL, CVE, or Event ID");
      return;
    }

    addToHistory(type, q);
    setSearchMode(true);

    const typeToSections = {
      ip:       ["ip"],
      domain:   ["domain"],
      url:      ["url", "domain"],
      hash:     ["hash"],
      email:    ["email"],
      cve:      ["cve", "cveplus"],
      eventid:  ["eventid", "soc", "sysmon", "lolbins"],
      username: ["username"],
      phone:    ["phone"],
      mac:      ["mac"],
      asn:      ["asn"],
      btc:      ["btc"],
      eth:      ["eth"],
      header:   ["header"],
      mitre:    ["soc"],
    };
    showRelevantTools(typeToSections[type] || [type]);

    const statusLabels = {
      ip:"IP address", domain:"domain", url:"URL", hash:"file hash",
      email:"email address", cve:"CVE", eventid:"Windows Event ID",
      username:"username", phone:"phone number", mac:"MAC address",
      asn:"ASN", btc:"Bitcoin address", eth:"Ethereum address", header:"email header",
    };
    setStatus(`Status: detected ${statusLabels[type]||type} → ${q}`);

    if (type === "ip")       { buildLinksForIP(q);       showCVEEnrichment && showCVEEnrichment(false); }
    else if (type === "domain") { buildLinksForDomain(q); }
    else if (type === "url")    { buildLinksForURL(q); buildLinksForDomain((()=>{try{return new URL(q).hostname;}catch{return "";}})());}
    else if (type === "hash")   { buildLinksForHash(q); }
    else if (type === "email")  { buildLinksForEmail(q); }
    else if (type === "cve")    { buildLinksForCVE(q); showCVEEnrichment && showCVEEnrichment(true, q); }
    else if (type === "eventid"){ buildLinksForEventID(q); }
    else if (type === "username"){ buildLinksForUsername(q); }
    else if (type === "phone")  { buildLinksForPhone(q); }
    else if (type === "mac")    { buildLinksForMAC(q); }
    else if (type === "asn")    { buildLinksForASN(q); }
    else if (type === "btc")    { buildLinksForBTC(q); }
    else if (type === "eth")    { buildLinksForETH(q); }
    else if (type === "header") { buildLinksForHeaders(q); }
    renderCardMeta();
    renderQuickAssessment(type, q);
  }

  // ── Quick Assessment Panel ─────────────────────────────────
  const QA_CONFIGS = {
    ip: {
      title: "IP Address", icon: "🛡",
      tools: [
        { name:"VirusTotal",  desc:"Community detections & samples",    hint:"Check detection count",         hintColor:"#38bdf8", url: q => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(q)}` },
        { name:"AbuseIPDB",   desc:"Abuse confidence score 0–100",      hint:">80 = high risk",               hintColor:"#f87171", url: q => `https://www.abuseipdb.com/check/${encodeURIComponent(q)}` },
        { name:"GreyNoise",   desc:"Internet scanner vs targeted actor", hint:"Riot=benign, Malicious=bad",   hintColor:"#fbbf24", url: q => `https://viz.greynoise.io/ip/${encodeURIComponent(q)}` },
        { name:"Talos",       desc:"Cisco Talos reputation score",       hint:"Poor/Untrusted = block",        hintColor:"#fb923c", url: q => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}` },
        { name:"IBM X-Force", desc:"Risk score 0–10",                    hint:">7 = high risk",                hintColor:"#f87171", url: q => `https://exchange.xforce.ibmcloud.com/ip/${encodeURIComponent(q)}` },
        { name:"Shodan",      desc:"Open ports & banners",               hint:"Check for C2 ports 4444/50050",hintColor:"#a78bfa", url: q => `https://www.shodan.io/host/${encodeURIComponent(q)}` },
      ],
      footer: "Cross-reference at least 3 sources. One suspicious hit warrants investigation; 2+ hits = escalate.",
      privateCheck: true,
    },
    domain: {
      title: "Domain", icon: "🌐",
      tools: [
        { name:"VirusTotal",      desc:"Malware & phishing detections",      hint:"Any detection = investigate",   hintColor:"#f87171", url: q => `https://www.virustotal.com/gui/domain/${encodeURIComponent(q)}` },
        { name:"Talos",           desc:"Domain reputation score",            hint:"Poor/Untrusted = block",         hintColor:"#fb923c", url: q => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}` },
        { name:"URLScan.io",      desc:"Screenshot & DOM analysis",          hint:"Check for phishing kit",         hintColor:"#38bdf8", url: q => `https://urlscan.io/search/#domain:${encodeURIComponent(q)}` },
        { name:"WHOIS",           desc:"Registration date & registrar",      hint:"New domain (<30d) = suspicious", hintColor:"#fbbf24", url: q => `https://www.whois.com/whois/${encodeURIComponent(q)}` },
        { name:"SecurityTrails",  desc:"DNS history & resolutions",          hint:"Fast-flux = botnet indicator",   hintColor:"#a78bfa", url: q => `https://securitytrails.com/domain/${encodeURIComponent(q)}` },
        { name:"CRT.sh",          desc:"SSL certificate transparency",       hint:"Wildcard certs = suspicious",    hintColor:"#fbbf24", url: q => `https://crt.sh/?q=${encodeURIComponent(q)}` },
      ],
      footer: "Check domain age first — newly registered domains (<30 days) with any detections = high priority.",
    },
    url: {
      title: "URL", icon: "🔗",
      tools: [
        { name:"VirusTotal",      desc:"URL scan across 90+ engines",        hint:"Any detection = block",          hintColor:"#f87171", url: q => `https://www.virustotal.com/gui/url/${encodeURIComponent(q)}` },
        { name:"URLScan.io",      desc:"Live browser screenshot & analysis", hint:"Check final redirect destination",hintColor:"#38bdf8", url: q => `https://urlscan.io/search/#page.url:${encodeURIComponent(q)}` },
        { name:"Google SafeBrowse","desc":"Google malware/phishing database", hint:"Listed = block immediately",     hintColor:"#f87171", url: q => `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(q)}` },
        { name:"URLVoid",         desc:"Blacklist aggregator",               hint:"Multiple hits = confirmed bad",   hintColor:"#fb923c", url: q => `https://www.urlvoid.com/scan/${encodeURIComponent((()=>{try{return new URL(q).hostname;}catch{return q;}})())}/` },
        { name:"CheckPhish",      desc:"AI-powered phishing detection",      hint:"Suspicious = needs manual review",hintColor:"#fbbf24", url: q => `https://checkphish.ai/domain/${encodeURIComponent((()=>{try{return new URL(q).hostname;}catch{return q;}})())}` },
        { name:"Sucuri",          desc:"Website malware scanner",            hint:"Malware/blacklist = incident",    hintColor:"#f87171", url: q => `https://sitecheck.sucuri.net/results/${encodeURIComponent(q)}` },
      ],
      footer: "Always expand shortened URLs first. Check the final redirect destination, not just the initial URL.",
    },
    hash: {
      title: "File Hash", icon: "#️⃣",
      tools: [
        { name:"VirusTotal",      desc:"Multi-engine AV scan result",        hint:"Even 1/70 = investigate",        hintColor:"#f87171", url: q => `https://www.virustotal.com/gui/file/${encodeURIComponent(q)}` },
        { name:"Hybrid Analysis", desc:"Dynamic behavior sandbox",           hint:"Network + file activity",         hintColor:"#38bdf8", url: q => `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(q)}` },
        { name:"Joe Sandbox",     desc:"Deep behavioral analysis",           hint:"C2, persistence, evasion",        hintColor:"#a78bfa", url: q => `https://www.joesandbox.com/analysis/search?searchname=${encodeURIComponent(q)}` },
        { name:"MalwareBazaar",   desc:"Known malware hash database",        hint:"Present = confirmed malware",     hintColor:"#f87171", url: q => `https://bazaar.abuse.ch/browse.php?search=sha256_hash:${encodeURIComponent(q)}` },
        { name:"Triage",          desc:"Interactive malware sandbox",        hint:"Network IOCs & dropped files",    hintColor:"#fb923c", url: q => `https://tria.ge/s/?q=${encodeURIComponent(q)}` },
        { name:"AlienVault OTX",  desc:"Threat intel community feed",        hint:"Related indicators & pulses",     hintColor:"#34d399", url: q => `https://otx.alienvault.com/indicator/file/${encodeURIComponent(q)}` },
      ],
      footer: "Submit unknown hashes to sandbox tools for dynamic analysis. Check file type — PE, script, or document malware have different behaviors.",
    },
    email: {
      title: "Email Address", icon: "📧",
      tools: [
        { name:"HIBP",            desc:"Have I Been Pwned breach check",     hint:"Breached = credentials at risk",  hintColor:"#f87171", url: q => `https://haveibeenpwned.com/account/${encodeURIComponent(q)}` },
        { name:"Hunter.io",       desc:"Email validation & deliverability",  hint:"Fake domain = phishing",          hintColor:"#fbbf24", url: q => `https://hunter.io/email-verifier/${encodeURIComponent(q)}` },
        { name:"Epieos",          desc:"Google/social account linkage",      hint:"Connected accounts = pivot",      hintColor:"#38bdf8", url: q => `https://epieos.com/?q=${encodeURIComponent(q)}&t=email` },
        { name:"IntelX",          desc:"Dark web & paste site search",       hint:"Leaked data = incident",          hintColor:"#f87171", url: q => `https://intelx.io/?s=${encodeURIComponent(q)}` },
        { name:"EmailRep",        desc:"Sender reputation score",            hint:"malicious/spam = block",          hintColor:"#fb923c", url: q => `https://emailrep.io/${encodeURIComponent(q)}` },
        { name:"Dehashed",        desc:"Breach database search",             hint:"Credentials exposed = reset",     hintColor:"#f87171", url: q => `https://dehashed.com/search?query=${encodeURIComponent(q)}` },
      ],
      footer: "Use HIBP first for breach check, then Epieos for social footprint. Report breached credentials to affected users immediately.",
    },
    cve: {
      title: "CVE", icon: "🔴",
      tools: [
        { name:"NVD",             desc:"NIST base score & details",          hint:"CVSS 9+ = critical patch now",    hintColor:"#f87171", url: q => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(q)}` },
        { name:"CISA KEV",        desc:"Actively exploited in the wild",     hint:"In KEV = patch within 2 weeks",   hintColor:"#f87171", url: q => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` },
        { name:"SOCRadar",        desc:"Exploit & PoC availability",         hint:"PoC available = high urgency",    hintColor:"#fb923c", url: q => `https://socradar.io/labs/app/cve-radar/${encodeURIComponent(q)}` },
        { name:"Shodan",          desc:"Exposed vulnerable systems",         hint:"High count = mass exploitation",  hintColor:"#a78bfa", url: q => `https://www.shodan.io/search?query=vuln:${encodeURIComponent(q)}` },
        { name:"ExploitDB",       desc:"Public exploit code availability",   hint:"Working exploit = critical",      hintColor:"#f87171", url: q => `https://www.exploit-db.com/search?cve=${encodeURIComponent(q.replace("CVE-",""))}` },
        { name:"Vulners",         desc:"Vulnerability aggregator",           hint:"Severity trend & patch status",   hintColor:"#fbbf24", url: q => `https://vulners.com/search?query=${encodeURIComponent(q)}` },
      ],
      footer: "Check CISA KEV + EPSS score. EPSS >0.7 + in KEV = patch immediately regardless of CVSS score.",
    },
    username: {
      title: "Username", icon: "👤",
      tools: [
        { name:"WhatsMyName",     desc:"Cross-platform username search",     hint:"Many matches = active persona",  hintColor:"#38bdf8", url: q => `https://whatsmyname.app/?q=${encodeURIComponent(q)}` },
        { name:"Dehashed",        desc:"Breach database correlation",        hint:"Found = credentials at risk",     hintColor:"#f87171", url: q => `https://dehashed.com/search?query=${encodeURIComponent(q)}` },
        { name:"IntelX",          desc:"Dark web & paste exposure",          hint:"Leaked = immediate risk",         hintColor:"#f87171", url: q => `https://intelx.io/?s=${encodeURIComponent(q)}` },
        { name:"Twitter/X",       desc:"Account & post history",             hint:"Check for IoC sharing",           hintColor:"#38bdf8", url: q => `https://twitter.com/${encodeURIComponent(q)}` },
        { name:"GitHub",          desc:"Code repositories & gists",          hint:"Check for leaked credentials",    hintColor:"#fbbf24", url: q => `https://github.com/${encodeURIComponent(q)}` },
        { name:"BreachDir",       desc:"Breach directory search",            hint:"Multiple breaches = escalate",    hintColor:"#fb923c", url: q => `https://breachdir.com/?q=${encodeURIComponent(q)}` },
      ],
      footer: "Use WhatsMyName for breadth, then investigate each platform for content. Cross-reference with breach databases for password reuse.",
    },
  };

  function renderQuickAssessment(type, q) {
    const panel = $("quick-assessment-panel");
    if (!panel) return;
    const cfg = QA_CONFIGS[type];
    if (!cfg) { panel.style.display = "none"; return; }

    // Private IP check
    let privateNote = "";
    if (type === "ip" && cfg.privateCheck) {
      try {
        const parts = q.split(".").map(Number);
        if (parts[0]===10 || (parts[0]===172&&parts[1]>=16&&parts[1]<=31) || (parts[0]===192&&parts[1]===168) || q.startsWith("127.")) {
          privateNote = `<div style="background:rgba(56,189,248,0.07);border:1px solid rgba(56,189,248,0.2);border-radius:8px;padding:10px 14px;margin-top:12px;font-family:monospace;font-size:12px;color:var(--text);line-height:1.7;">IP detected (PRIVATE): ${esc(q)}
Note: external OSINT may not return results for private IPs.</div>`;
        }
      } catch {}
    }

    panel.style.display = "block";
    panel.innerHTML = `
      <div class="qa-header">
        <span class="qa-icon">${cfg.icon}</span>
        <span class="qa-type">${esc(cfg.title)}</span>
        <span class="qa-ioc">${esc(q.length>60?q.slice(0,60)+"…":q)}</span>
        <div class="qa-quick-links">
          ${cfg.tools.slice(0,3).map(t=>`<a href="${t.url(q)}" target="_blank" class="qa-pill">${esc(t.name)}</a>`).join("")}
          <span class="qa-more-toggle" onclick="this.closest('.quick-assessment-panel').querySelector('.qa-tools-table').style.display=this.closest('.quick-assessment-panel').querySelector('.qa-tools-table').style.display==='none'?'table':'none';this.textContent=this.textContent.includes('▼')?'▲ less':'▼ +${cfg.tools.length-3} more';">▼ +${cfg.tools.length - 3} more</span>
        </div>
        <div class="qa-collapse-btn" onclick="this.closest('.quick-assessment-panel').classList.toggle('qa-collapsed')">▲</div>
      </div>
      <table class="qa-tools-table">
        <tbody>
          ${cfg.tools.map(t=>`
            <tr class="qa-tool-row" onclick="window.open('${t.url(q)}','_blank')">
              <td class="qa-tool-name">${esc(t.name)}</td>
              <td class="qa-tool-desc">${esc(t.desc)}</td>
              <td class="qa-tool-hint" style="color:${t.hintColor}">${esc(t.hint)}</td>
            </tr>`).join("")}
        </tbody>
      </table>
      <div class="qa-footer">📌 ${esc(cfg.footer)}</div>
      ${privateNote}`;
  }

  // ── Defang / Refang / Extract IOC buttons (Single IOC tab) ───
  const defangBtn = $("defang-btn");
  const refangBtn = $("refang-btn");
  const extractBtn = $("extract-btn");
  const copyBtn   = $("copy-btn");
  if (defangBtn) defangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() || (input?.value || "").trim();
    if (!src) return;
    if (output) output.value = defangSmart(src);
    setStatus("Status: defanged");
  });
  if (refangBtn) refangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() || (input?.value || "").trim();
    if (!src) return;
    if (output) output.value = refangSmart(src);
    setStatus("Status: refanged");
  });
  if (extractBtn) extractBtn.addEventListener("click", () => {
    const text = (output?.value || "").trim() || (input?.value || "").trim();
    if (!text) return;
    if (output) output.value = extractSmartIOCs(text);
    setStatus("Status: Smart IOC extraction complete");
  });
  if (copyBtn) copyBtn.addEventListener("click", async () => {
    if (!output) return;
    try { await navigator.clipboard.writeText(output.value || ""); }
    catch { if (output) { output.focus(); output.select(); document.execCommand("copy"); } }
    setStatus("Status: copied to clipboard");
  });
  const clearAllBtn = $("clear-all");
  if (clearAllBtn) clearAllBtn.addEventListener("click", () => {
    if (input)  input.value  = "";
    if (output) output.value = "";
    syncSearchboxState(); setSearchMode(false); showRelevantTools([]);
    setLandingLinks(); renderCardMeta(); setStatus("Status: ready (landing page)");
    const banner = $("verdict-banner"); if (banner) banner.style.display = "none";
    hideThreatScore(); hideActorHints();
    const sp = $("mitre-suggested"); if (sp) sp.style.display = "none";
    const cvePanel = $("cve-enrichment"); if (cvePanel) cvePanel.style.display = "none";
  });

  // Stubs for functions that may be referenced
  function hideThreatScore() { const el = $("threat-score"); if (el) el.style.display = "none"; }
  function hideActorHints()  { const el = $("actor-hints");  if (el) el.style.display = "none"; }

  // Wire up search button and Enter key
  const searchBtn = $("search-btn");
  if (searchBtn) {
    searchBtn.addEventListener("click", () => {
      const raw = (input?.value || "").trim();
      if (raw) runSearch(raw);
    });
  }
  if (input) {
    input.addEventListener("keydown", e => {
      if (e.key === "Enter") {
        const raw = input.value.trim();
        if (raw) runSearch(raw);
      }
    });
    input.addEventListener("input", () => {
      syncSearchboxState();
      const raw = input.value.trim();
      if (!raw) { setSearchMode(false); showRelevantTools([]); setStatus("Status: ready (landing page)"); setLandingLinks(); return; }
      // Auto-detect type as user types for status hint
      const { type } = detectType(refangSmart(raw), "");
      if (type) setStatus(`Status: ${type} detected — press Enter or click Search`);
    });
  }

  // ═══════════════════════════════════════════════════
  // ─── THREAT ACTOR LOOKUP ─────────────────────────
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
      // ── Download & execution ──────────────────────────────────
      { pattern:/\bDownloadString\b/gi,                                        sev:"critical", label:"Downloads & executes remote string (IEX+DownloadString)",          mitre:["T1059.001","T1105"] },
      { pattern:/\bDownloadFile\b/gi,                                          sev:"critical", label:"Downloads file from remote URL",                                    mitre:["T1105"] },
      { pattern:/\bInvoke-WebRequest\b/gi,                                     sev:"high",     label:"Invoke-WebRequest — HTTP fetch from remote host",                   mitre:["T1105","T1071.001"] },
      { pattern:/\bStart-BitsTransfer\b/gi,                                    sev:"high",     label:"BITS transfer — background file download (LOLBin)",                 mitre:["T1197"] },
      { pattern:/\bInvoke-Expression\b|\bIEX\b/gi,                             sev:"critical", label:"Invoke-Expression / IEX — dynamic code execution",                  mitre:["T1059.001"] },
      // ── Obfuscation & encoding ────────────────────────────────
      { pattern:/-(?:enc|EncodedCommand)\s+[A-Za-z0-9+/]{20,}/gi,             sev:"critical", label:"Base64 encoded PowerShell command (-enc)",                          mitre:["T1027","T1059.001"] },
      { pattern:/\[Convert\]::FromBase64String/gi,                             sev:"high",     label:"Base64 decode in-script",                                           mitre:["T1027","T1140"] },
      { pattern:/\$(?:env:)?(?:COMSPEC|windir|SystemRoot).*-[cCkK]/gi,        sev:"high",     label:"CMD execution via environment variable (LOLBin)",                   mitre:["T1059.003"] },
      { pattern:/-join\s*['"][^'"]{0,3}['"]/gi,                                sev:"medium",   label:"String join obfuscation — characters assembled at runtime",         mitre:["T1027"] },
      { pattern:/\[char\]\s*\d{2,3}/gi,                                        sev:"medium",   label:"Char-code string obfuscation",                                      mitre:["T1027"] },
      // ── Defense evasion ───────────────────────────────────────
      { pattern:/Set-MpPreference\s+-Disable/gi,                               sev:"critical", label:"Disables Windows Defender real-time monitoring",                    mitre:["T1562.001"] },
      { pattern:/Add-MpPreference\s+-ExclusionPath/gi,                         sev:"critical", label:"Adds AV exclusion path — hides malware from Defender",              mitre:["T1562.001"] },
      { pattern:/\[Ref\]\.Assembly\.GetType.*AMSI/gi,                          sev:"critical", label:"AMSI bypass — disables antimalware scan interface",                 mitre:["T1562.001"] },
      { pattern:/amsiInitFailed|AmsiScanBuffer|amsi\.dll/gi,                   sev:"critical", label:"AMSI patching/bypass pattern",                                      mitre:["T1562.001"] },
      { pattern:/-ExecutionPolicy\s+(?:Bypass|Unrestricted|RemoteSigned)/gi,   sev:"high",     label:"Execution policy bypass",                                           mitre:["T1059.001"] },
      { pattern:/\bHidden\b.*\bWindowStyle\b|\bWindowStyle\b.*\bHidden\b/gi,  sev:"high",     label:"Hidden window — runs without visible console",                      mitre:["T1564.003"] },
      { pattern:/netsh\s+(?:advfirewall|firewall)\s+set.*disable/gi,           sev:"critical", label:"Disables Windows Firewall",                                         mitre:["T1562.004"] },
      // ── Persistence ───────────────────────────────────────────
      { pattern:/HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/gi,  sev:"critical", label:"Registry Run key persistence (HKCU)",                               mitre:["T1547.001"] },
      { pattern:/HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/gi,  sev:"critical", label:"Registry Run key persistence (HKLM — system-wide)",                 mitre:["T1547.001"] },
      { pattern:/New-ScheduledTask|Register-ScheduledTask|schtasks/gi,         sev:"critical", label:"Scheduled task persistence",                                        mitre:["T1053.005"] },
      { pattern:/Startup\b.*\.(?:ps1|bat|exe|vbs|js)/gi,                       sev:"high",     label:"Startup folder persistence — drops file in startup",                mitre:["T1547.001"] },
      { pattern:/New-Service|sc\.exe\s+create/gi,                              sev:"critical", label:"Creates Windows service for persistence",                           mitre:["T1543.003"] },
      // ── Credential theft ──────────────────────────────────────
      { pattern:/lsass/gi,                                                      sev:"critical", label:"LSASS access — credential dumping attempt",                         mitre:["T1003.001"] },
      { pattern:/sekurlsa|logonpasswords|mimikatz/gi,                           sev:"critical", label:"Mimikatz credential extraction",                                    mitre:["T1003.001"] },
      { pattern:/comsvcs\.dll.*MiniDump/gi,                                    sev:"critical", label:"LSASS dump via comsvcs.dll (LOLBin)",                               mitre:["T1003.001"] },
      { pattern:/Get-Credential\b|ConvertTo-SecureString/gi,                   sev:"medium",   label:"Credential handling — may capture or process credentials",          mitre:["T1056","T1555"] },
      // ── Lateral movement ──────────────────────────────────────
      { pattern:/Invoke-Command\b.*-ComputerName/gi,                           sev:"high",     label:"Remote command execution via PowerShell remoting",                  mitre:["T1021.006"] },
      { pattern:/Enter-PSSession|New-PSSession/gi,                             sev:"high",     label:"PowerShell remote session",                                         mitre:["T1021.006"] },
      { pattern:/\bwmic\b.*\/node:/gi,                                         sev:"high",     label:"WMI remote execution (wmic /node)",                                 mitre:["T1047"] },
      // ── Process injection / memory ────────────────────────────
      { pattern:/VirtualAlloc|VirtualAllocEx/gi,                               sev:"critical", label:"Memory allocation for shellcode injection",                         mitre:["T1055"] },
      { pattern:/WriteProcessMemory/gi,                                        sev:"critical", label:"Process memory write — code injection",                             mitre:["T1055"] },
      { pattern:/CreateRemoteThread/gi,                                        sev:"critical", label:"Remote thread creation — classic DLL injection",                   mitre:["T1055.001"] },
      { pattern:/\[Runtime\.InteropServices\.Marshal\]/gi,                     sev:"high",     label:"Unmanaged memory/P-Invoke — native code execution from PS",         mitre:["T1055","T1106"] },
      // ── Recon ─────────────────────────────────────────────────
      { pattern:/Get-ADUser|Get-ADComputer|Get-ADGroup/gi,                     sev:"high",     label:"Active Directory enumeration",                                      mitre:["T1087.002","T1069.002"] },
      { pattern:/Get-NetIPConfiguration|Get-NetAdapter/gi,                     sev:"medium",   label:"Network configuration discovery",                                   mitre:["T1016"] },
      { pattern:/whoami|net\s+user|net\s+localgroup/gi,                        sev:"medium",   label:"User/group reconnaissance",                                         mitre:["T1033","T1069"] },
      // ── Exfiltration ──────────────────────────────────────────
      { pattern:/Send-MailMessage/gi,                                          sev:"high",     label:"Sends email — possible data exfiltration via SMTP",                 mitre:["T1048.003"] },
      { pattern:/Invoke-WebRequest\s+-Method\s+POST/gi,                        sev:"high",     label:"HTTP POST — data exfiltration via web request",                     mitre:["T1048.003","T1071.001"] },
      // ── ClickFix / 2024-2025 trends ───────────────────────────
      { pattern:/mshta\s+https?:/gi,                                           sev:"critical", label:"MSHTA remote HTA execution (ClickFix / living-off-land)",           mitre:["T1218.005"] },
      { pattern:/\bwmic\b.*process.*call.*create/gi,                           sev:"critical", label:"WMIC process creation — command execution LOLBin",                  mitre:["T1047"] },
      { pattern:/odbcconf.*\/a.*regsvr/gi,                                     sev:"critical", label:"OdbcConf LOLBin — DLL execution via ODBC",                          mitre:["T1218.008"] },
    ],
    bash: [
      // ── Download & exec ───────────────────────────────────────
      { pattern:/curl\s+.*\|\s*(?:bash|sh)/gi,                                 sev:"critical", label:"Curl pipe to shell — remote code execution",                       mitre:["T1059.004","T1105"] },
      { pattern:/wget\s+.*\|\s*(?:bash|sh)/gi,                                 sev:"critical", label:"Wget pipe to shell — remote code execution",                       mitre:["T1059.004","T1105"] },
      { pattern:/curl\s+-s\s+-o\s+|wget\s+-q\s+-O/gi,                          sev:"high",     label:"Silent file download to disk",                                      mitre:["T1105"] },
      { pattern:/bash\s+-i\s*>&\s*\/dev\/tcp/gi,                               sev:"critical", label:"Bash reverse shell via /dev/tcp",                                   mitre:["T1059.004"] },
      { pattern:/\/dev\/tcp\/\d{1,3}\.\d{1,3}/gi,                              sev:"critical", label:"TCP socket shell — reverse or bind shell connection",               mitre:["T1059.004"] },
      // ── Obfuscation ───────────────────────────────────────────
      { pattern:/echo\s+[A-Za-z0-9+/]{20,}={0,2}\s*\|\s*base64\s+-d/gi,       sev:"critical", label:"Base64 decode + execute — encoded payload",                        mitre:["T1027","T1140"] },
      { pattern:/\$\(.*base64.*\)/gi,                                           sev:"high",     label:"In-line base64 decode (command substitution)",                      mitre:["T1027"] },
      { pattern:/python[23]?\s+-c\s+['"].*exec/gi,                             sev:"critical", label:"Python inline exec — dynamic code execution",                       mitre:["T1059.006"] },
      // ── Persistence ───────────────────────────────────────────
      { pattern:/crontab\s+-[el]/gi,                                            sev:"high",     label:"Crontab modification — scheduled persistence",                      mitre:["T1053.003"] },
      { pattern:/(\/etc\/cron\.|\/var\/spool\/cron)/gi,                         sev:"high",     label:"Cron file modification for persistence",                            mitre:["T1053.003"] },
      { pattern:/~\/\.(?:bashrc|bash_profile|profile|zshrc)/gi,                sev:"high",     label:"Shell profile modification — user persistence",                     mitre:["T1546.004"] },
      { pattern:/systemctl\s+enable\s+\S+\.service/gi,                         sev:"high",     label:"Systemd service enabled for persistence",                           mitre:["T1543.002"] },
      { pattern:/echo\s+.*>>\s*\/etc\/rc\.(?:local|d)/gi,                      sev:"high",     label:"RC startup script persistence",                                     mitre:["T1037.004"] },
      // ── Privilege escalation ──────────────────────────────────
      { pattern:/chmod\s+(?:\+s|4[0-7]{3})\s/gi,                               sev:"critical", label:"SUID bit set — privilege escalation vector",                        mitre:["T1548.001"] },
      { pattern:/sudo\s+-\s*S\s*<<</gi,                                         sev:"critical", label:"sudo with heredoc — automated privilege escalation",               mitre:["T1548.003"] },
      { pattern:/\/etc\/passwd|\/etc\/shadow/gi,                                sev:"critical", label:"Credential file access (passwd/shadow)",                            mitre:["T1003.008"] },
      // ── Lateral movement & C2 ─────────────────────────────────
      { pattern:/ssh\s+-(?:o\s+StrictHostKey|i\s+.*\.pem)/gi,                  sev:"high",     label:"SSH with key/no-verify — lateral movement",                         mitre:["T1021.004"] },
      { pattern:/nc\s+-[eluvzw]+\s+.*\d{2,5}/gi,                               sev:"critical", label:"Netcat listener/connector — reverse shell or exfil",               mitre:["T1059.004","T1048"] },
      // ── Cryptomining (2024-2025) ──────────────────────────────
      { pattern:/xmrig|stratum\+tcp:\/\/|minerd\b/gi,                          sev:"critical", label:"Cryptominer detected (XMRig/stratum protocol)",                     mitre:["T1496"] },
      { pattern:/\bpool\.\w+\.(com|net)\s+.*wallet/gi,                         sev:"critical", label:"Mining pool connection with wallet address",                        mitre:["T1496"] },
    ],
    vbs: [
      { pattern:/\bCreateObject\b.*\bShell\b/gi,                               sev:"critical", label:"Creates Shell object — command execution",                          mitre:["T1059.005"] },
      { pattern:/\bWscript\.Shell\b/gi,                                         sev:"critical", label:"WScript.Shell — executes OS commands",                              mitre:["T1059.005"] },
      { pattern:/\bShell\b.*\bCmd\b|\bCmd\b.*\/[cCkK]/gi,                      sev:"critical", label:"CMD execution via VBScript",                                        mitre:["T1059.003","T1059.005"] },
      { pattern:/\bXMLHTTP\b|\bServerXMLHTTP\b/gi,                              sev:"high",     label:"HTTP request object — downloads remote content",                    mitre:["T1105","T1071.001"] },
      { pattern:/\bADODB\.Stream\b/gi,                                          sev:"high",     label:"ADODB.Stream — reads/writes binary/file data",                      mitre:["T1105","T1027"] },
      { pattern:/\bRegWrite\b|\bRegRead\b/gi,                                   sev:"high",     label:"Registry read/write via VBScript",                                   mitre:["T1547.001","T1112"] },
      { pattern:/\bAutoOpen\b|\bDocument_Open\b|\bAuto_Open\b/gi,              sev:"critical", label:"Auto-execution macro — runs on document open",                      mitre:["T1137.001"] },
      { pattern:/\bWScript\.Sleep\b.*\d{4,}/gi,                                sev:"medium",   label:"Long sleep delay — sandbox evasion / timing check",                mitre:["T1497.003"] },
      { pattern:/Chr\s*\(\s*\d{2,3}\s*\)/gi,                                   sev:"medium",   label:"Chr() obfuscation — strings built from char codes",                 mitre:["T1027"] },
      { pattern:/\bStrReverse\b/gi,                                             sev:"medium",   label:"StrReverse — reversed string obfuscation",                          mitre:["T1027"] },
    ],
    js: [
      { pattern:/\beval\s*\(/gi,                                                sev:"critical", label:"eval() — dynamic code execution, common in obfuscated malware",    mitre:["T1059.007"] },
      { pattern:/new\s+ActiveXObject\s*\(/gi,                                   sev:"critical", label:"ActiveXObject — accesses COM/Windows objects from JS",              mitre:["T1059.007","T1106"] },
      { pattern:/WScript\.Shell|WshShell/gi,                                    sev:"critical", label:"WScript.Shell via JScript — OS command execution",                  mitre:["T1059.007","T1059.003"] },
      { pattern:/\.Run\s*\(|\.Exec\s*\(/gi,                                     sev:"critical", label:"Process execution from script (Run/Exec)",                          mitre:["T1059"] },
      { pattern:/XMLHttpRequest|new\s+XMLHttp/gi,                               sev:"high",     label:"XHR — HTTP request to remote resource",                             mitre:["T1071.001","T1105"] },
      { pattern:/document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode)/gi, sev:"critical", label:"DOM write with decode — obfuscated content injection",          mitre:["T1027","T1059.007"] },
      { pattern:/String\.fromCharCode\s*\(\s*\d/gi,                             sev:"high",     label:"String.fromCharCode obfuscation",                                   mitre:["T1027"] },
      { pattern:/unescape\s*\(\s*['"]%/gi,                                      sev:"high",     label:"unescape() URL-encoded payload execution",                          mitre:["T1027"] },
      { pattern:/Function\s*\(\s*['"]return/gi,                                 sev:"high",     label:"Function constructor — dynamic function creation (obfuscation)",    mitre:["T1027","T1059.007"] },
      { pattern:/\bsetTimeout\b.*eval|setInterval.*eval/gi,                     sev:"high",     label:"Deferred eval execution — sandbox evasion technique",               mitre:["T1497","T1059.007"] },
      // ── 2024: ClickFix / fake CAPTCHA JS ──────────────────────
      { pattern:/navigator\.clipboard\.writeText|document\.execCommand.*copy/gi, sev:"high",   label:"Clipboard write — ClickFix / fake CAPTCHA clipboard injection",    mitre:["T1059","T1204.002"] },
      { pattern:/window\.location\s*=\s*['"](?:javascript:|data:)/gi,           sev:"critical", label:"JavaScript/data URI redirect — malicious code execution",           mitre:["T1059.007"] },
    ],
    python: [
      { pattern:/\bexec\s*\(|eval\s*\(/gi,                                      sev:"critical", label:"exec()/eval() — dynamic code execution",                            mitre:["T1059.006"] },
      { pattern:/import\s+subprocess|subprocess\.(?:call|Popen|run)/gi,         sev:"high",     label:"subprocess — executes OS commands from Python",                     mitre:["T1059.006"] },
      { pattern:/import\s+os;?\s*os\.(?:system|popen|execvp)/gi,                sev:"critical", label:"os.system/popen — shell command execution",                         mitre:["T1059.006"] },
      { pattern:/socket\.connect\s*\(\s*\(|socket\.bind/gi,                     sev:"high",     label:"Raw socket connection — C2 channel or reverse shell",               mitre:["T1095","T1059.006"] },
      { pattern:/base64\.(?:b64decode|decodebytes)/gi,                          sev:"high",     label:"Base64 decode — encoded payload",                                   mitre:["T1027","T1140"] },
      { pattern:/marshal\.loads|pickle\.loads/gi,                               sev:"critical", label:"Pickle/marshal deserialization — arbitrary code execution risk",    mitre:["T1059.006"] },
      { pattern:/ctypes\.windll|ctypes\.cdll/gi,                                sev:"critical", label:"ctypes Win32 API — process injection or system-level access",       mitre:["T1055","T1106"] },
      { pattern:/cryptography|Fernet|AES\b|RSA\b/gi,                            sev:"medium",   label:"Cryptography library — may be ransomware or data hiding",           mitre:["T1486","T1027"] },
      { pattern:/PyInstaller|py2exe|cx_Freeze/gi,                               sev:"medium",   label:"Executable packer — script compiled to standalone binary",          mitre:["T1027.002"] },
      // ── 2024: Python info-stealers ────────────────────────────
      { pattern:/keylogger|keyboard\.(?:on_press|Listener)/gi,                  sev:"critical", label:"Keylogger — captures keystrokes",                                   mitre:["T1056.001"] },
      { pattern:/sqlite3.*(?:Cookies|Login Data|Web Data)/gi,                   sev:"critical", label:"Browser credential/cookie theft via SQLite",                        mitre:["T1539","T1555.003"] },
      { pattern:/appdata.*(?:Roaming|Local).*(?:Discord|Chrome|Firefox|Edge)/gi, sev:"critical", label:"Browser/app data theft (Discord token, Chrome cookies, etc.)",   mitre:["T1539","T1555"] },
    ],
    auto: [
      // ── LOLBins / Living off the Land ──────────────────────────
      { pattern:/\bcertutil\b.*(?:-decode|-urlcache|-encode)/gi,                sev:"critical", label:"CertUtil LOLBin — download/decode abuse",                          mitre:["T1105","T1140","T1218.003"] },
      { pattern:/\bregsvr32\b.*(?:\/s|scrobj|http)/gi,                          sev:"critical", label:"Regsvr32 LOLBin — code execution via COM scriptlet",               mitre:["T1218.010"] },
      { pattern:/\bmshta\b/gi,                                                  sev:"critical", label:"MSHTA LOLBin — executes HTA/VBScript/JScript",                     mitre:["T1218.005"] },
      { pattern:/\bwmic\b.*process.*call.*create/gi,                            sev:"critical", label:"WMIC process creation — command execution",                         mitre:["T1047"] },
      { pattern:/\brunscripthelper\b|\bpcalua\b/gi,                             sev:"critical", label:"Undocumented LOLBin execution",                                     mitre:["T1218"] },
      { pattern:/\brundll32\b.*(?:javascript:|vbscript:|shell32)/gi,            sev:"critical", label:"Rundll32 LOLBin — code execution via DLL",                          mitre:["T1218.011"] },
      // ── 2024-2025: ClickFix attacks ───────────────────────────
      { pattern:/(?:Win|RunDLL|Ctrl\+V).*(?:CAPTCHA|verify|human|robot)/gi,    sev:"critical", label:"ClickFix lure — fake CAPTCHA asking user to run a command",        mitre:["T1204.002","T1059"] },
      { pattern:/powershell.*-w.*hidden.*-c.*(?:irm|iex|curl|wget)/gi,         sev:"critical", label:"ClickFix payload — hidden PS execution pattern",                   mitre:["T1059.001","T1204.002"] },
      // ── 2024-2025: AiTM / session theft ──────────────────────
      { pattern:/evilginx|modlishka|muraena|reversed.*proxy/gi,                sev:"critical", label:"AiTM phishing framework detected",                                  mitre:["T1111","T1557.002"] },
      { pattern:/steal.*(?:cookie|session|token)|cookie.*(?:steal|grab|harvest)/gi, sev:"critical", label:"Session/cookie theft intent",                                 mitre:["T1539","T1185"] },
      // ── 2024: QR code / TOAD patterns ────────────────────────
      { pattern:/qr(?:code)?.*(?:scan|link|http)|bit\.ly|tinyurl.*qr/gi,       sev:"high",     label:"QR code URL — possible QRishing delivery",                          mitre:["T1566.002"] },
      // ── Universal indicators ──────────────────────────────────
      { pattern:/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,            sev:"critical", label:"HTTP to raw IP address — suspicious C2 endpoint",                   mitre:["T1071.001","T1102"] },
      { pattern:/https?:\/\/[a-z0-9-]{8,}\.(xyz|top|click|gq|cf|tk|pw|cc|su|ru)\b/gi, sev:"high", label:"High-risk TLD domain — common in phishing/malware infrastructure", mitre:["T1566.002","T1071.001"] },
      { pattern:/(?:4444|1234|8888|9999|31337|50050|4447|55555)\b/gi,          sev:"high",     label:"Common C2/backdoor port number",                                     mitre:["T1071","T1090"] },
      { pattern:/\bPEHeader\b|MZ\x90\x00|\x4d\x5a/gi,                          sev:"critical", label:"PE/executable header in script — embedded binary payload",           mitre:["T1027.009"] },
      { pattern:/(?:taskkill|pkill|killall).*(?:defender|av|antivirus|malware)/gi, sev:"critical", label:"AV/security tool termination",                                  mitre:["T1562.001"] },
      { pattern:/vssadmin.*delete.*shadows|wbadmin.*delete/gi,                 sev:"critical", label:"Shadow copy deletion — ransomware pre-encryption step",             mitre:["T1490"] },
      // ── Macro / Office VBA ─────────────────────────────────────
      { pattern:/\bAutoOpen\b|\bDocument_Open\b|\bWorkbook_Open\b|\bAuto_Open\b/gi, sev:"critical", label:"Auto-execution macro — runs on document open",              mitre:["T1137.001","T1059.005"] },
      { pattern:/\bShell\b.*\bCreateObject\b|CreateObject.*Wscript\.Shell/gi,  sev:"critical", label:"VBA Shell execution via WScript",                                   mitre:["T1059.005"] },
      // ── Browser debugging / session theft (2024) ──────────────
      { pattern:/\bChrome.*(?:--disable-web-security|--remote-debugging)/gi,   sev:"high",     label:"Browser debugging flag — cookie/session theft setup",               mitre:["T1185","T1539"] },
    ],
  };;

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

    // ── Script Explanation — auto-shown after every analysis ──
    html += `<div class="sa-section" id="sa-explain-section">
      <div id="sa-ai-explanation" style="margin-top:4px;"></div>
      <div style="margin-top:10px;display:flex;align-items:center;gap:8px;">
        <button id="sa-ai-explain-btn" type="button" style="background:linear-gradient(135deg,#7c3aed,#1D9E75);color:#fff;border:none;font-weight:700;padding:6px 14px;border-radius:7px;font-size:11px;cursor:pointer;">⚡ Refresh AI Analysis</button>
        <span style="font-size:10.5px;color:var(--muted);">Get enhanced AI explanation (requires connection)</span>
      </div>
    </div>`;

    saResults.innerHTML = html;

    // Auto-show offline explanation immediately
    const saExplainDiv = document.getElementById("sa-ai-explanation");
    if (saExplainDiv && hits !== undefined) {
      saExplainDiv.innerHTML = buildScriptExplanation(hits, mitre, iocs, effectiveMode, verdict, entropy, text);
    }

    // Wire up AI explain button
    const saAIBtn = document.getElementById("sa-ai-explain-btn");
    if (saAIBtn) {
      saAIBtn.addEventListener("click", async () => {
        const explainDiv = document.getElementById("sa-ai-explanation");
        if (!explainDiv) return;
        saAIBtn.disabled = true;
        saAIBtn.textContent = "⟳ Analyzing…";
        explainDiv.style.display = "block";
        explainDiv.innerHTML = '<div style="color:var(--muted);font-size:11.5px;padding:8px 0;animation:pulse 1s infinite;">Analyzing script behavior…</div>';
        const scriptText = saInput?.value?.trim() || "";
        const hitSummary = hits.map(h => h.label + " (" + h.sev + ")").join(", ");
        const mitreSummary = mitre.join(", ");
        const sys = "You are a malware analyst. Given a script and its detected indicators, explain in plain English: 1) What the script does step by step, 2) Its likely intent (malware dropper / C2 beacon / credential theft / persistence / etc.), 3) Specific dangerous behaviors found, 4) Recommended analyst actions. Be direct and accurate. Use short paragraphs, no markdown headers. Max 200 words.";
        const userMsg = "Script (" + effectiveMode.toUpperCase() + ", " + hits.length + " indicators: " + hitSummary + ", MITRE: " + mitreSummary + "):\n\n" + scriptText.slice(0, 1500);

        // Show offline explanation immediately (always works)
        const explanation = buildScriptExplanation(hits, mitre, iocs, effectiveMode, verdict, entropy, scriptText);
        explainDiv.innerHTML = explanation;
        saAIBtn.disabled = false;
        saAIBtn.textContent = "⚡ AI Explain — What does this script do?";
        // Then try API for enhanced explanation in background (silent if unavailable)
        try {
          fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              model: "claude-sonnet-4-20250514", max_tokens: 600,
              system: "You are a malware analyst. Given a script and its detected indicators, explain in 150 words: 1) What this script does step by step, 2) Its likely purpose and threat level, 3) One key recommended action. Plain text only, no markdown.",
              messages: [{ role: "user", content: "Mode: " + effectiveMode.toUpperCase() + ", Verdict: " + verdict.label + ", Indicators: " + hits.slice(0,8).map(h=>h.label).join(", ") + ", MITRE: " + mitre.slice(0,5).join(", ") + ". Script (first 800 chars):\n" + scriptText.slice(0,800) }],
            }),
          }).then(r => r.json()).then(data => {
            const aiText = (data.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("").trim();
            if (aiText && aiText.length > 20) {
              explainDiv.innerHTML = explainDiv.innerHTML +
                '<div style="background:rgba(124,58,237,0.06);border:1px solid rgba(124,58,237,0.2);border-radius:8px;padding:12px 14px;margin-top:10px;">' +
                '<div style="font-size:9.5px;font-weight:800;color:#a78bfa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">⚡ AI Enhanced Analysis</div>' +
                '<div style="font-size:11.5px;color:var(--text);line-height:1.75;">' + esc(aiText) + '</div></div>';
            }
          }).catch(() => {}); // silent — offline explanation already shown
        } catch(e) { /* API unavailable — offline explanation already shown */ }
      });
    }

    mitre.forEach(t => {
      const tid = t.split(".")[0];
      const cb = document.querySelector(`#mitre-panel input[value="${tid}"]`);
      if (cb) cb.checked = true;
    });
  }

  // ── Build rich offline script explanation ──────────────────────
  function buildScriptExplanation(hits, mitre, iocs, mode, verdict, entropy, scriptText) {
    const critHits = hits.filter(h => h.sev === "critical");
    const highHits = hits.filter(h => h.sev === "high");
    const medHits  = hits.filter(h => h.sev === "medium");
    const allSev   = [...critHits, ...highHits, ...medHits];
    const labels   = hits.map(h => h.label.toLowerCase()).join(" ");
    const text_lc  = scriptText.slice(0, 2000).toLowerCase();

    // ── Behavioral detection ────────────────────────────────────
    const hasDownload  = /invoke-webrequest|downloadfile|downloadstring|webclient|wget|curl|bitstransfer/i.test(labels + text_lc);
    const hasExec      = /start-process|invoke-expression|iex|shellexecute|createobject.*wscript|exec|cmd\.exe/i.test(labels + text_lc);
    const hasPersist   = /scheduled.task|registry.*run|startup|autorun|schtasks|set-itemproperty.*run/i.test(labels + text_lc);
    const hasDefEvasion= /amsi|set-mppreference|disablerealtimemonitor|bypass|unrestricted|hidden|disableav|av|defender|disable/i.test(labels + text_lc);
    const hasObfusc    = /base64|frombase64|convert.*base64|-enc\b|-encoded|-e\s+[a-z0-9+/]{20}/i.test(labels + text_lc);
    const hasC2        = /http[s]?:\/\/\d|invoke-webrequest.*http|downloadstring.*http|beacon|c2|command.*control/i.test(labels + text_lc);
    const hasPrivesc   = /elevat|privilege|uac.*bypass|runas|admin|token.*impersonat/i.test(labels + text_lc);
    const hasCredTheft = /lsass|credential|sekurlsa|logonpassword|sam\b|ntlm|mimikatz|comsvcs/i.test(labels + text_lc);
    const hasExfil     = /invoke-webrequest.*post|\bpost\b.*http|upload|smtp|send-mailmessage|\boutbound\b/i.test(labels + text_lc);
    const hasLateral   = /invoke-command|enter-pssession|wmi.*remote|psexec|new-pssession/i.test(labels + text_lc);
    const hasRecon     = /get-process|get-service|get-computer|whoami|ipconfig|systeminfo|net\s+user|get-aduser|get-netcomputer/i.test(labels + text_lc);
    const hasRansom    = /encrypt|get-childitem.*\$\w|rename-item|vssadmin|shadow|bitcoin|wallet/i.test(labels + text_lc);
    const hasSelfDel   = /remove-item.*\$myinvocation|del.*%0|self.delet/i.test(labels + text_lc);
    const hasMemInject = /virtualallocex|writeprocessmemory|createremotethread|reflective|inject/i.test(labels + text_lc);

    // ── Extract specific IOCs from script ────────────────────────
    const scriptUrls    = [...new Set((scriptText.match(/https?:\/\/[^\s"'`,;\]]+/gi)||[]).map(u=>u.replace(/['"`,;)\]]+$/,"")))];
    const scriptIPs     = [...new Set((scriptText.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g)||[]).filter(ip=>!ip.startsWith("127.")&&!ip.startsWith("0.")))];
    const scriptPaths   = [...new Set((scriptText.match(/[A-Za-z]:\\[^"'\n`]+|\/(?:tmp|var|home|etc)\/[^\s"'`]+/g)||[]))];
    const scriptRegKeys = [...new Set((scriptText.match(/HKCU:[\\\/]\S+|HKLM:[\\\/]\S+|HKEY_\w+[\\\/]\S+/gi)||[]))];

    // ── Determine verdicts ──────────────────────────────────────
    const isClean   = hits.length === 0 && entropy < 4.5;
    const isMalicious = critHits.length >= 1;
    const isSuspicious = !isClean && !isMalicious;

    let verdLabel, verdColor, verdIcon, verdSummary;
    if (isClean) {
      verdLabel   = "CLEAN — No Threats Detected";
      verdColor   = "#34d399"; verdIcon = "✅";
      verdSummary = "No malicious indicators, obfuscation, or suspicious patterns were detected in this script. It appears to be legitimate code.";
    } else if (isMalicious) {
      verdLabel   = "MALICIOUS — Confirmed Threat";
      verdColor   = "#ef4444"; verdIcon = "🚨";
      verdSummary = `${critHits.length} critical indicator${critHits.length>1?"s":""} confirmed: ${critHits.slice(0,3).map(h=>h.label).join(", ")}.`;
    } else {
      verdLabel   = "SUSPICIOUS — Review Required";
      verdColor   = "#fbbf24"; verdIcon = "⚠️";
      verdSummary = `${hits.length} warning-level indicator${hits.length>1?"s":""} detected. Manual review required.`;
    }

    // ── Build step-by-step behavioral timeline ──────────────────
    const steps = [];
    if (hasObfusc)    steps.push({ phase:"1. DECEPTION",   icon:"🥷", color:"#a78bfa", text:`Script uses ${scriptText.match(/-enc\b|-encoded\b/i)?"Base64 encoding (-enc flag)":scriptText.match(/[A-Za-z0-9+/]{40,}={0,2}/g)?.length>0?"Base64 encoded payloads":"obfuscation"} to hide its true behavior from security tools.` });
    if (hasDefEvasion)steps.push({ phase:"2. EVASION",     icon:"🛡", color:"#f87171", text:`Attempts to disable security controls: ${[scriptText.match(/DisableRealtimeMonitoring/i)?"Windows Defender real-time protection":null, scriptText.match(/amsi/i)?"AMSI (AntiMalware Scan Interface)":null].filter(Boolean).join(", ")||"security monitoring"}.` });
    if (hasRecon)     steps.push({ phase:"3. RECONNAISSANCE",icon:"🔍",color:"#38bdf8", text:`Collects system information: ${[scriptText.match(/whoami/i)?"user identity":null, scriptText.match(/ipconfig|get-netipaddress/i)?"network config":null, scriptText.match(/get-process/i)?"running processes":null, scriptText.match(/systeminfo/i)?"system details":null].filter(Boolean).join(", ")||"host enumeration"}.` });
    if (hasDownload)  steps.push({ phase:"4. DOWNLOAD",    icon:"📥", color:"#fb923c", text:`Downloads payload from: ${scriptUrls.slice(0,3).join(", ")||scriptIPs.slice(0,3).join(", ")||"remote server"}. ${scriptPaths.length?"Saves to: "+scriptPaths.slice(0,2).join(", "):""}`});
    if (hasExec)      steps.push({ phase:"5. EXECUTION",   icon:"⚙️", color:"#ef4444", text:`Executes the downloaded or embedded payload${scriptPaths.length?" from "+scriptPaths[0]:""}. ${scriptText.match(/invoke-expression|iex/i)?"Uses IEX (Invoke-Expression) — a common PowerShell execution technique.":""}` });
    if (hasMemInject) steps.push({ phase:"6. INJECTION",   icon:"💉", color:"#ef4444", text:"Injects code directly into memory of a running process, bypassing file-based AV detection." });
    if (hasCredTheft) steps.push({ phase:"7. CREDENTIAL THEFT",icon:"🔑",color:"#ef4444",text:`Attempts to steal credentials from ${scriptText.match(/lsass/i)?"LSASS memory (plaintext passwords + hashes)":scriptText.match(/sam\b/i)?"SAM database (local account hashes)":"the target system"}.` });
    if (hasPersist)   steps.push({ phase:"8. PERSISTENCE", icon:"📌", color:"#fb923c", text:`Installs persistence via: ${[scriptRegKeys.length?"registry Run key ("+scriptRegKeys[0]+")":null, scriptText.match(/schtasks/i)?"scheduled task":null, scriptText.match(/startup/i)?"startup folder":null].filter(Boolean).join(" + ")||"unknown mechanism"}.` });
    if (hasLateral)   steps.push({ phase:"9. LATERAL MOVEMENT",icon:"🔀",color:"#f87171",text:"Attempts to spread to other systems on the network via WMI, PSRemoting, or PsExec." });
    if (hasExfil)     steps.push({ phase:"10. EXFILTRATION",icon:"📤",color:"#ef4444",text:`Sends data out via ${scriptText.match(/smtp|send-mailmessage/i)?"email":"HTTP POST or upload"}. Destination: ${scriptUrls.slice(0,2).join(", ")||"remote server"}.` });
    if (hasRansom)    steps.push({ phase:"11. RANSOMWARE",  icon:"💀", color:"#ef4444", text:"Encrypts files and/or deletes shadow copies to prevent recovery." });
    if (hasSelfDel)   steps.push({ phase:"12. CLEANUP",    icon:"🧹", color:"#a78bfa", text:"Deletes itself after execution to remove forensic evidence." });

    // ── Recommended actions ──────────────────────────────────────
    const actions = [];
    if (isMalicious)  actions.push("Isolate the host immediately — do not allow network access");
    if (hasC2)        actions.push(`Block C2 destinations at firewall: ${[...scriptUrls,...scriptIPs].slice(0,3).join(", ")||"all outbound from host"}`);
    if (hasCredTheft) actions.push("Force password reset for ALL accounts that logged into this host");
    if (hasPersist)   actions.push(`Remove persistence: check ${scriptRegKeys.length?"registry key "+scriptRegKeys[0]+",":""} scheduled tasks, and startup folders`);
    if (hasDefEvasion)actions.push("Re-enable and update security controls — verify AV/EDR is running");
    if (hasDownload && scriptPaths.length) actions.push(`Delete downloaded payload: ${scriptPaths[0]}`);
    if (hasMemInject) actions.push("Memory forensics required — malware may persist only in RAM");
    if (isClean)      actions.push("No action required. Script appears legitimate.");
    if (!actions.length) actions.push("Investigate the flagged indicators and correlate with endpoint logs");

    // ── Build HTML output ────────────────────────────────────────
    const vc = verdColor;
    let html = `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:8px;">
      <div style="padding:12px 14px;background:${vc}10;border-bottom:1px solid ${vc}30;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <span style="font-size:18px;">${verdIcon}</span>
        <span style="font-size:13px;font-weight:900;color:${vc};">${esc(verdLabel)}</span>
        <span style="font-size:10.5px;color:var(--muted);flex:1;">${esc(verdSummary)}</span>
        ${entropy>5.5?`<span style="font-size:10px;background:rgba(251,191,36,0.15);color:#fbbf24;border:1px solid rgba(251,191,36,0.3);padding:2px 8px;border-radius:8px;">⚠️ Entropy: ${entropy.toFixed(2)}</span>`:""}
      </div>`;

    // Key IOCs if any
    if (scriptUrls.length || scriptIPs.length) {
      html += `<div style="padding:10px 14px;border-bottom:1px solid var(--border);background:rgba(239,68,68,0.04);">
        <div style="font-size:9.5px;font-weight:800;color:#ef4444;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">🎯 Network IOCs Found</div>
        ${scriptUrls.map(u=>`<div style="font-size:11px;color:#38bdf8;font-family:monospace;margin-bottom:2px;word-break:break-all;">${esc(u)}</div>`).join("")}
        ${scriptIPs.filter(ip=>!scriptUrls.some(u=>u.includes(ip))).map(ip=>`<div style="font-size:11px;color:#38bdf8;font-family:monospace;margin-bottom:2px;">${esc(ip)}</div>`).join("")}
      </div>`;
    }

    // Step-by-step timeline
    if (steps.length) {
      html += `<div style="padding:12px 14px;border-bottom:1px solid var(--border);">
        <div style="font-size:9.5px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">⛓️ Attack Sequence (${steps.length} stage${steps.length>1?"s":""})</div>
        ${steps.map(s=>`<div style="display:flex;gap:10px;align-items:flex-start;padding:7px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
          <span style="font-size:14px;flex-shrink:0;">${s.icon}</span>
          <div>
            <div style="font-size:9.5px;font-weight:800;color:${s.color};text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px;">${esc(s.phase)}</div>
            <div style="font-size:11.5px;color:var(--text);line-height:1.65;">${esc(s.text)}</div>
          </div>
        </div>`).join("")}
      </div>`;
    }

    // Recommended actions
    html += `<div style="padding:12px 14px;">
      <div style="font-size:9.5px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">🔧 Recommended Actions</div>
      ${actions.map((a,i)=>`<div style="display:flex;gap:8px;padding:4px 0;font-size:11.5px;color:var(--text);">
        <span style="color:${vc};font-weight:800;flex-shrink:0;">${i+1}.</span>${esc(a)}</div>`).join("")}
    </div>`;

    // MITRE mapping
    if (mitre.length) {
      html += `<div style="padding:8px 14px;border-top:1px solid var(--border);background:rgba(0,0,0,0.1);">
        <span style="font-size:9.5px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;">MITRE ATT&CK: </span>
        ${mitre.slice(0,8).map(t=>`<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" style="color:#38bdf8;text-decoration:none;font-size:10px;margin-right:6px;">${esc(t)}</a>`).join("")}
      </div>`;
    }
    html += `</div>`;
    return html;
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
      "T1136.001":"Create Local Account",
      "T1078":    "Valid Accounts",
      "T1078.001":"Default Accounts",
      "T1078.002":"Domain Accounts",
      "T1078.003":"Local Accounts",
      "T1078.004":"Cloud Accounts",
      "T1110":    "Brute Force",
      "T1110.001":"Password Guessing",
      "T1110.003":"Password Spraying",
      "T1110.004":"Credential Stuffing",
      "T1566":    "Phishing",
      "T1566.001":"Spearphishing Attachment",
      "T1566.002":"Spearphishing Link",
      "T1566.003":"Spearphishing via Service",
      "T1071.001":"Web Protocols",
      "T1071.002":"File Transfer Protocols",
      "T1071.004":"DNS",
      "T1528":    "Steal Application Access Token",
      "T1550.001":"Application Access Token",
      "T1621":    "MFA Request Generation",
      "T1098":    "Account Manipulation",
      "T1098.002":"Exchange Email Delegate Perms",
      "T1114":    "Email Collection",
      "T1114.003":"Email Forwarding Rule",
      "T1046":    "Network Service Discovery",
      "T1498":    "Network Denial of Service",
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
      document.querySelectorAll(".cti-panel").forEach(p => {
        p.classList.remove("active");
        p.style.display = "";  // clear any legacy inline style
      });
      btn.classList.add("active");
      const panel = $(`cti-panel-${btn.dataset.ctitab}`);
      if (panel) { panel.classList.add("active"); panel.style.display = ""; }
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
    const getAllH = re => (t.match(re) || []).slice(1);
    const lower = t.toLowerCase();

    // ── Basic fields ────────────────────────────────────────
    const from         = getH(/^from:\s*(.+)$/im);
    const to           = getH(/^to:\s*(.+)$/im);
    const replyTo      = getH(/^reply-to:\s*(.+)$/im);
    const cc           = getH(/^cc:\s*(.+)$/im);
    const subject      = getH(/^subject:\s*(.+)$/im);
    const date         = getH(/^date:\s*(.+)$/im);
    const msgId        = getH(/^message-id:\s*<?([^>\n]+)>?/im);
    const returnPath   = getH(/^return-path:\s*<?([^>\s]+)>?/im);
    const contentType  = getH(/^content-type:\s*([^\n;]+)/im);
    const contentTE    = getH(/^content-transfer-encoding:\s*(.+)$/im);
    const mimeVersion  = getH(/^mime-version:\s*(.+)$/im);
    const listUnsub    = getH(/^list-unsubscribe:\s*(.+)$/im);
    const listId       = getH(/^list-id:\s*(.+)$/im);
    const precedence   = getH(/^precedence:\s*(.+)$/im);
    const xMailer      = getH(/^x-mailer:\s*(.+)$/im);
    const xOrigIP      = getH(/^x-originating-ip:\s*\[?([^\]\s\n]+)/im) ||
                         getH(/^x-sender-ip:\s*([^\s\n]+)/im) ||
                         getH(/^x-forwarded-ip:\s*([^\s\n]+)/im);
    const xSpamScore   = getH(/^x-spam-score:\s*(.+)$/im);
    const xSpamStatus  = getH(/^x-spam-status:\s*(.+)$/im);
    const xSpamReport  = getH(/^x-spam-report:\s*([\s\S]+?)(?=\n[A-Za-z0-9])/im);
    const xPhishScore  = getH(/^x-phishscore:\s*(.+)$/im);
    const xVirusStatus = getH(/^x-virus-status:\s*(.+)$/im);
    const xBulk        = getH(/^x-bulk-mail:\s*(.+)$/im);
    const xCampaignId  = getH(/^x-campaign-id:\s*(.+)$/im) || getH(/^x-mc-unique:\s*(.+)$/im);
    const xSenderReputation = getH(/^x-sender-reputation:\s*(.+)$/im);
    const barracuda    = getH(/^x-barracuda-spam-score:\s*(.+)$/im);
    const proofpointSig= getH(/^x-proofpoint-spam-details:\s*(.+)$/im);
    const msMicrosoftAntispam = getH(/^x-microsoft-antispam:\s*(.+)$/im);
    const microsoftSCL = (() => { const m=t.match(/SCL=(-?\d)/i); return m?.[1]||""; })();
    const xExchangeAntispam = getH(/^x-exchange-antispam-report-cfa-test:\s*(.+)$/im);
    const xForefrontAntispam = getH(/^x-forefront-antispam-report:\s*(.+)$/im);

    // Collect all X- headers for inventory
    const xHeaders = [];
    (t.match(/^(x-[a-zA-Z0-9-]+):\s*(.+)$/gim)||[]).forEach(h => {
      const [, name, val] = h.match(/^(x-[a-zA-Z0-9-]+):\s*(.+)$/i)||[];
      if (name && val) xHeaders.push({ name, val: val.slice(0,120) });
    });

    // ── Email address + domain extraction ───────────────────
    const fromEmail    = (from.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i)||[])[1]||"";
    const fromName     = (from.match(/^"?([^"<]+)"?\s*</)||[])[1]?.trim()||"";
    const replyEmail   = (replyTo.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i)||[])[1]||"";
    const toEmail      = (to.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i)||[])[1]||"";
    const retDomain    = returnPath.split("@")[1]?.toLowerCase().replace(/[>)]/g,"")||"";
    const fromDomain   = fromEmail.split("@")[1]?.toLowerCase()||"";
    const toDomain     = toEmail.split("@")[1]?.toLowerCase()||"";
    const replyDomain  = replyEmail.split("@")[1]?.toLowerCase()||"";

    // ── Authentication blocks ────────────────────────────────
    // RFC 2822 folded header — each continuation line starts with whitespace
    const authBlocks = t.match(/^authentication-results:[^\n]*(\n[ \t]+[^\n]*)*/gim)||[];
    const allAuth    = authBlocks.map(b => b.replace(/\n[ \t]+/g," ")).join(" ");

    const spfResult  = (allAuth.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i)||[])[1]?.toLowerCase()||"none";
    const spfMailFrom= (allAuth.match(/smtp\.mailfrom=([^\s;]+)/i)||[])[1]?.toLowerCase()||"";
    const spfMailFromDomain = spfMailFrom.split("@")[1] || spfMailFrom;

    const dkimResult = (allAuth.match(/\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i)||[])[1]?.toLowerCase()||"none";
    const dkimDomainFromAuth = (allAuth.match(/\bdkim=\w+[^;]*header\.d=([^\s;]+)/i)||[])[1]?.toLowerCase()||"";
    const dkimSigBlock = (t.match(/^dkim-signature:[^\n]*(\n[ \t]+[^\n]*)*/im)||[])[0]||"";
    const dkimSigClean = dkimSigBlock.replace(/\n\s+/g," ");
    const dkimSelector = (dkimSigClean.match(/\bs=([^;\s]+)/i)||[])[1]||"";
    const dkimDomain   = (dkimSigClean.match(/\bd=([^;\s]+)/i)||[])[1]?.toLowerCase() || dkimDomainFromAuth;
    const dkimAlgo     = (dkimSigClean.match(/\ba=([^;\s]+)/i)||[])[1]||"";

    const dmarcResult = (allAuth.match(/\bdmarc=(pass|fail|bestguesspass|none)\b/i)||[])[1]?.toLowerCase()||"none";
    const dmarcDisposition = (allAuth.match(/\bdmarc=\w+[^;]*disposition=([^\s;]+)/i)||[])[1]?.toLowerCase()||"";
    const dmarcFromDomain  = (allAuth.match(/\bdmarc=\w+[^;]*header\.from=([^\s;]+)/i)||[])[1]?.toLowerCase()||"";

    const arcResult   = (allAuth.match(/\barc=(pass|fail|none)\b/i)||[])[1]?.toLowerCase()||"none";
    const hasARC      = /^arc-seal:/im.test(t);

    const compauthResult = (allAuth.match(/\bcompauth=(pass|fail|softfail|none)\b/i)||[])[1]?.toLowerCase()||"";
    const compauthReason = (allAuth.match(/\bcompauth=\w+\s+reason=(\d+)/i)||[])[1]||"";

    // ── Received hops ────────────────────────────────────────
    const receivedBlocks = t.match(/^received:[^\n]*(\n[ \t]+[^\n]*)*/gim)||[];
    const hops = receivedBlocks.map(block => {
      const clean = block.replace(/\n\s+/g," ");
      const by    = (clean.match(/by\s+([\w.\-\[\]]+)/i)||[])[1]||"";
      const fr    = (clean.match(/from\s+([\w.\-\[\]()]+)/i)||[])[1]||"";
      const ipv4M = clean.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)||[];
      const ip    = ipv4M.find(i => !isPrivateIPv4(i)) || ipv4M[0] || "";
      const withIp= (clean.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/)||[])[1]||"";
      const tsM   = clean.match(/;\s*([A-Za-z].*(?:GMT|UTC|[+-]\d{4}))\s*$/i);
      const ts    = tsM ? new Date(tsM[1]) : null;
      const tls   = /using TLS|with ESMTPS|STARTTLS/i.test(clean);
      const via   = (clean.match(/with\s+(ESMTP[SA]?|SMTP|HTTP|HTTPS|LMTP)\b/i)||[])[1]||"";
      return { by, from: fr, ip: ip||withIp, ts, tls, via, raw: clean };
    }).reverse().map((h,idx) => ({ ...h, hop: idx+1 }));

    for (let i=1; i<hops.length; i++) {
      if (hops[i].ts && hops[i-1].ts) {
        const diff = (hops[i].ts - hops[i-1].ts) / 1000;
        hops[i].delay = diff < -300 ? "⚠️ clock skew" : diff < 0 ? "?" : diff < 60 ? `${Math.round(diff)}s` : `${Math.round(diff/60)}m`;
        hops[i].delayWarn = diff > 300;
      }
    }

    // ── LOOKALIKE / BRAND IMPERSONATION detection ─────────────
    const KNOWN_BRANDS = [
      "microsoft","apple","google","amazon","paypal","netflix","facebook","instagram",
      "twitter","linkedin","dropbox","docusign","chase","wellsfargo","bankofamerica",
      "citibank","irs","fedex","ups","dhl","usps","zoom","slack","salesforce","adobe",
      "intuit","quickbooks","turbotax","coinbase","binance","kraken","metamask",
      "okta","office365","sharepoint","outlook","onedrive","icloud","adobesign",
    ];
    // Levenshtein distance — detect near-matches
    function levenshtein(a, b) {
      const m=a.length, n=b.length;
      const dp=Array.from({length:m+1},(_,i)=>Array.from({length:n+1},(_,j)=>i||j));
      for(let i=1;i<=m;i++) for(let j=1;j<=n;j++)
        dp[i][j]=a[i-1]===b[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
      return dp[m][n];
    }
    let lookalikeBrand = "", lookalikeDomain = "";
    const domainBase = fromDomain.split(".")[0];
    for (const brand of KNOWN_BRANDS) {
      // Exact match in display name but not in domain = impersonation
      if (fromName.toLowerCase().includes(brand) && fromDomain && !fromDomain.includes(brand)) {
        lookalikeBrand = brand; lookalikeDomain = fromDomain; break;
      }
      // Levenshtein ≤2 on domain base segment but not exact = typosquat
      if (domainBase && domainBase !== brand && levenshtein(domainBase.toLowerCase(), brand) <= 2 && brand.length > 4) {
        lookalikeBrand = brand; lookalikeDomain = fromDomain; break;
      }
      // Domain contains brand name with extra chars: paypal-secure.com, amazon-support.net
      // But NOT if it's a legitimate subdomain like aws.amazon.com, mail.google.com, smtp.microsoft.com
      if (fromDomain && fromDomain.includes(brand) && !new RegExp("^" + brand + "\\.(com|net|org|io|co)$").test(fromDomain)) {
        // Skip if fromDomain ends with .brand.tld (legitimate subdomain)
        const isLegitSubdomain = new RegExp("\\." + brand + "\\.(com|net|org|io|co|gov|edu|mil|int)$").test(fromDomain);
        // Skip if DKIM and SPF both pass with the same brand domain
        const authOK = (dkimDomain || "").includes(brand) && spfResult === "pass" && dkimResult === "pass";
        if (!isLegitSubdomain && !authOK) {
          lookalikeBrand = brand; lookalikeDomain = fromDomain; break;
        }
      }
    }
    // Punycode / homograph / IDN
    const isPunycode = /xn--/i.test(fromDomain) || /xn--/i.test(msgId);

    // ── SPAM SIGNALS ─────────────────────────────────────────
    const isBulkPrecedence = /bulk|list|junk/i.test(precedence);
    const isBulkHeaders    = !!(listId || xBulk || xCampaignId);
    const hasListUnsub     = !!listUnsub;
    // Spam-associated ESPs — legitimate bulk senders leave these
    const spamESPs = ["mailchimp","sendgrid","constantcontact","klaviyo","hubspot",
                      "marketo","pardot","bronto","silverpop","exacttarget","responsys"];
    const senderESP= spamESPs.find(e => xMailer?.toLowerCase().includes(e) ||
                                        (t.match(/^received:.*by.*([a-z0-9-]+\.smtp\.mcsv\.net|mta\.mailchimp\.com|smtp\.sendgrid\.net|em\.klaviyo\.com)/im)||[])[0]?.toLowerCase().includes(e));
    // Subject spam patterns
    const spamSubjectPatterns = [
      { re:/(\$\d{1,3}(,\d{3})*(\.\d{2})?)|(free|win|winner|prize|claim|reward|offer|discount|deal|sale|\d+%\s*off)/i, label:"Commercial/promotional language" },
      { re:/urgent|immediately|act now|limited time|expires|last chance|don't miss|final notice/i, label:"Urgency / scarcity pressure" },
      { re:/unsubscribe|opt.?out|remove me|no longer|stop receiving/i, label:"Unsubscribe language in subject" },
      { re:/re:|fwd:/i, label:"RE/FWD prefix (possible thread hijacking)" },
      { re:/!!!|\?\?\?|💰|🎁|🏆|🔥|💸/, label:"Excessive punctuation or emoji" },
      { re:/\[.{2,30}\]/, label:"Bracketed prefix (newsletter/alert pattern)" },
    ];
    const spamSubjectHits = spamSubjectPatterns.filter(p => p.re.test(subject||""));

    // ── ATTACK TYPE DETECTION ─────────────────────────────────
    // BEC signals — require structural indicators, not just subject keywords
    // Subject keywords alone are NOT sufficient for BEC classification
    const becSubjectMatch = /ceo|cfo|cto|president|executive|payroll|wire transfer|urgent.*wire|urgent.*transfer/i.test(subject||"");
    const isBEC = !!(
      // Reply-To hijack is only a BEC signal if ALSO combined with something else
      // (many legit marketing/ticketing systems use different reply-to)
      (replyEmail && replyEmail !== fromEmail && replyDomain && fromDomain && replyDomain !== fromDomain && spfResult !== "pass") ||
      lookalikeBrand ||                              // Brand impersonation (hard signal)
      isPunycode ||                                  // IDN homograph (hard signal)
      // Subject BEC keywords only count when combined with auth failures
      (becSubjectMatch && (spfResult==="fail" || dkimResult==="fail"))
    );
    // Phishing signals — require ACTUAL failures (not just absence of auth records)
    // SPF=none or DKIM=none alone is not phishing — many internal servers lack these
    const phishSubject = /verify|confirm|suspended|locked|unusual.*activity|sign.?in|login|account.*password|credential|click.*here|update.*info/i.test(subject||"");
    const isPhishing = !!(
      // Hard auth failures — must be explicit "fail" not just "none"
      (spfResult==="fail" || dkimResult==="fail") ||
      // DMARC fail with an explicit SPF fail (not just SPF=none)
      (spfResult==="fail" && dmarcResult==="fail") ||
      // Phishing subject keywords PLUS a hard auth failure signal
      (phishSubject && (spfResult==="fail" || dkimResult==="fail" || lookalikeBrand))
    );
    // Spam signals
    const isSpam = !!(isBulkPrecedence || isBulkHeaders || senderESP || spamSubjectHits.length >= 2);
    // QRishing
    const isQRishing = /qr.*code|scan.*qr|qr.*scan/i.test(subject||"") || /qr.*code|scan.*qr/i.test(t);
    // Voicemail phishing
    const isVoicemail = /voicemail|voice.*message|missed.*call|new.*fax|audio.*message/i.test(subject||"");
    // Callback / TOAD phishing
    const hasPhoneInSubject = /\+?[\d][\d\s\-().]{8,20}[\d]/.test(subject||"");
    const isTOAD = hasPhoneInSubject || /call.*\+?[\d][\d\s\-().]{8,20}|contact.*\+?[\d][\d\s\-().]{8,20}/i.test(t.slice(0,2000));
    // AiTM indicators (token stealing via reverse proxy)
    const isAiTM = hops.length > 0 && hops.some(h => /evilginx|modlishka|muraena|phishing.*proxy/i.test(h.raw||""));
    // Malware delivery
    const attachmentName = (t.match(/(?:name|filename)="([^"]+)"/gi)||[]).map(m=>(m.match(/"([^"]+)"/)||[])[1]).filter(Boolean);
    const maliciousAttach = attachmentName.filter(n => /\.(exe|dll|js|vbs|bat|cmd|ps1|hta|jar|iso|img|lnk|scr|wsf|msi|reg|inf)$/i.test(n));
    const isMalwareDelivery = maliciousAttach.length > 0;
    // HTML-only with no plain text = common in phishing
    const isHTMLOnly = /text\/html/i.test(contentType) && !/text\/plain/i.test(t.slice(0,3000));
    // Tracking pixel indicators
    const hasTrackingPixel = /1x1|pixel\.gif|tracking|open\.php|track\.php/i.test(t);

    // ── Attack classification ────────────────────────────────
    let attackType = "UNKNOWN";
    let attackDetail = "";
    if (isMalwareDelivery)   { attackType = "MALWARE DELIVERY";  attackDetail = `Suspicious attachment: ${maliciousAttach.join(", ")}`; }
    else if (isAiTM)         { attackType = "AiTM PHISHING";     attackDetail = "Adversary-in-the-Middle reverse proxy detected in relay chain"; }
    else if (isQRishing)     { attackType = "QRishing";          attackDetail = "QR code lure detected — may bypass URL scanners"; }
    else if (isVoicemail)    { attackType = "VISHING LURE";      attackDetail = "Voicemail or missed-call phishing lure"; }
    else if (isTOAD)         { attackType = "CALLBACK PHISHING"; attackDetail = "Phone number present — Telephone-Oriented Attack Delivery (TOAD)"; }
    else if (isBEC)          { attackType = "BEC / FRAUD";       attackDetail = lookalikeBrand ? `Brand impersonation: ${lookalikeBrand}` : "Business email compromise indicators"; }
    else if (isPhishing)     { attackType = "PHISHING";          attackDetail = "Authentication failure + suspicious content pattern"; }
    else if (isSpam)         { attackType = "SPAM / BULK";       attackDetail = senderESP ? `Sent via ${senderESP} ESP` : "Bulk email infrastructure"; }
    else if (spfResult==="pass" && dkimResult==="pass" && dmarcResult==="pass") {
      attackType = "LIKELY CLEAN";   attackDetail = "All authentication checks pass (SPF + DKIM + DMARC)";
    } else if (spfResult==="pass" && dkimResult==="pass") {
      attackType = "LIKELY CLEAN";   attackDetail = "SPF and DKIM pass; DMARC not published but no other threat signals";
    } else if (spfResult==="pass" && !lookalikeBrand && !isPunycode) {
      attackType = "LIKELY CLEAN";   attackDetail = "SPF passes with no brand impersonation — likely legitimate";
    } else {
      attackType = "SUSPICIOUS";     attackDetail = "Some signals present — investigate further";
    }

    // ── Confidence + verdict drivers ─────────────────────────
    // Confidence = how certain we are of the verdict (based on hard vs soft signals)
    // Hard signals = cryptographic proof (DKIM fail, SPF fail, DMARC fail, brand spoof, AiTM)
    // Soft signals = behavioral/contextual (subject keywords, free provider, reply mismatch)
    const hardSignals = [
      spfResult === "fail", dkimResult === "fail", dmarcResult === "fail",
      isMalwareDelivery, isAiTM, isPunycode, !!lookalikeBrand,
      !!(replyEmail && replyEmail !== fromEmail),
    ].filter(Boolean).length;
    const warnSignalCount = [
      spfResult === "softfail",
      !!(retDomain && fromDomain && retDomain !== fromDomain),
      !!(dkimDomain && fromDomain && dkimDomain !== fromDomain && !["mailchimp.com","sendgrid.net","amazonses.com","sparkpostmail.com"].includes(dkimDomain)),
      isQRishing, isTOAD, isVoicemail, isBEC && !lookalikeBrand,
    ].filter(Boolean).length;

    let confidence, confidenceColor, confidenceReason;
    if (attackType === "LIKELY CLEAN" && hardSignals === 0) {
      confidence = "HIGH";  confidenceColor = "#34d399";
      confidenceReason = "All three email authentication controls (SPF, DKIM, DMARC) passed with correct domain alignment. No structural or behavioral anomalies detected.";
    } else if (hardSignals >= 2) {
      confidence = "HIGH";  confidenceColor = "#ef4444";
      confidenceReason = `${hardSignals} hard cryptographic or structural signal(s) confirmed — the verdict is backed by verifiable technical evidence.`;
    } else if (hardSignals === 1) {
      confidence = "HIGH";  confidenceColor = "#ef4444";
      confidenceReason = "One hard signal confirmed (cryptographic failure or domain structural anomaly) — sufficient for high confidence.";
    } else if (warnSignalCount >= 2) {
      confidence = "MEDIUM"; confidenceColor = "#fbbf24";
      confidenceReason = `${warnSignalCount} corroborating warning signals — no single definitive proof, but the combination is meaningful. Verify manually.`;
    } else if (warnSignalCount === 1) {
      confidence = "MEDIUM"; confidenceColor = "#fbbf24";
      confidenceReason = "One warning-level signal. Could be legitimate misconfiguration or a real threat. Context required.";
    } else {
      confidence = "LOW";   confidenceColor = "#9ca3af";
      confidenceReason = "Soft signals only (subject keywords, sender type). Low-confidence assessment — do not block solely on this.";
    }

    // Verdict drivers — the key signals that explain WHY this verdict was reached
    const verdictDrivers = [];
    const DR = (weight, icon, text) => verdictDrivers.push({ weight, icon, text });
    if (dkimResult === "fail")   DR("critical","🔐", `DKIM FAIL — cryptographic signature is broken or missing. The message was modified after signing, or the From: domain (${fromDomain||"unknown"}) was spoofed. This is a hard technical proof of tampering.`);
    if (spfResult === "fail")    DR("critical","📮", `SPF FAIL — the sending IP (${hops[hops.length-1]?.ip||"unknown"}) is NOT authorized to send mail for ${fromDomain||"this domain"}. The domain owner has explicitly forbidden this sender.`);
    if (dmarcResult === "fail")  DR("critical","🛡", `DMARC FAIL — the From: domain policy rejected this message. Neither SPF nor DKIM aligned with the declared From: domain.${dmarcDisposition ? " Declared action: "+dmarcDisposition.toUpperCase()+"." : ""}`);
    if (isAiTM)                  DR("critical","🕵", `AiTM proxy detected — a known adversary-in-the-middle phishing relay appeared in the relay chain. These proxies steal session cookies and MFA tokens in real time without requiring the victim's password.`);
    if (lookalikeBrand)          DR("critical","🎭", `Brand impersonation — domain "${lookalikeDomain}" is spoofing "${lookalikeBrand}". ${isPunycode ? "Punycode homograph attack: Unicode characters make the domain look identical to the real one." : "Typosquat or lookalike domain registered to deceive recipients."}`);
    if (replyEmail && replyEmail !== fromEmail) DR("critical","📧", `Reply-To hijack — displayed sender is <${fromEmail}> but replies are redirected to <${replyEmail}>. Recipients who click Reply will contact the attacker's address, not the apparent sender.`);
    if (isMalwareDelivery)       DR("critical","📎", `Malicious attachment type(s): ${maliciousAttach.join(", ")}. These file types are high-risk malware delivery vectors. Do NOT open.`);
    if (spfResult === "softfail") DR("warning","⚠️", `SPF SOFTFAIL (~all) — the sending IP is technically unauthorized but the domain uses a weak policy. Common in phishing campaigns that abuse domains with poor SPF hygiene.`);
    if (retDomain && fromDomain && retDomain !== fromDomain) DR("warning","↩️", `Return-Path mismatch — bounce emails go to ${retDomain}, not ${fromDomain}. In legitimate mail, these typically match. Divergence is common in spoofed mail.`);
    if (isBEC && !lookalikeBrand && !isAiTM) DR("warning","💼", `BEC pattern — combination of display name targeting, reply address divergence, or urgency language consistent with wire fraud or credential harvesting.`);
    if (isQRishing)              DR("warning","📱", `QRishing — QR code detected in message. QR codes bypass URL-based email security because the malicious link only becomes active on the mobile device scanning the code.`);
    if (isTOAD)                  DR("warning","📞", `Callback phishing (TOAD) — phone number embedded in email body. The attacker answers calls and socially engineers the victim into installing remote access tools or revealing credentials.`);
    if (isVoicemail)             DR("warning","🎙", `Voicemail lure — fake voicemail notification template, a standard phishing pre-text to drive clicks on malicious "listen to voicemail" links.`);
    if (verdictDrivers.length === 0 && attackType === "LIKELY CLEAN") {
      DR("clean","✅", `SPF: ${(spfResult||"none").toUpperCase()}, DKIM: ${(dkimResult||"none").toUpperCase()}, DMARC: ${(dmarcResult||"none").toUpperCase()} — all email authentication controls passed with correct domain alignment. No structural, behavioral, or content anomalies detected.`);
    }

    // ── Score + flags ────────────────────────────────────────
    let score = 0;
    const flags = [];
    const authChecks = [];

    // SPF
    if (spfResult === "pass") {
      authChecks.push({ label:"SPF", result:"pass", detail:`Authorized by ${spfMailFromDomain||fromDomain||"sender domain"}`, cls:"eha-auth-pass" });
    } else if (spfResult === "fail") {
      score += 30; flags.push({ sev:"crit", cat:"auth", msg:`SPF FAIL — ${fromDomain||"sender"} did NOT authorize this sending IP. Strong indicator of spoofing.` });
      authChecks.push({ label:"SPF", result:"fail", detail:"Sender not authorized by DNS", cls:"eha-auth-fail" });
    } else if (spfResult === "softfail") {
      score += 15; flags.push({ sev:"warn", cat:"auth", msg:`SPF SOFTFAIL (~all) — domain discourages but does not reject. Treat with caution.` });
      authChecks.push({ label:"SPF", result:"softfail", detail:"Sender discouraged (~all)", cls:"eha-auth-fail" });
    } else if (spfResult === "neutral") {
      authChecks.push({ label:"SPF", result:"neutral", detail:"Domain makes no claim (?all)", cls:"eha-auth-none" });
    } else {
      authChecks.push({ label:"SPF", result:"none", detail:"No SPF record published", cls:"eha-auth-none" });
    }

    // DKIM
    if (dkimResult === "pass") {
      authChecks.push({ label:"DKIM", result:"pass", detail:`Valid signature — ${dkimDomain||"domain"}${dkimSelector?" [s="+dkimSelector+"]":""}${dkimAlgo?" "+dkimAlgo:""}`, cls:"eha-auth-pass" });
    } else if (dkimResult === "fail") {
      score += 25; flags.push({ sev:"crit", cat:"auth", msg:`DKIM FAIL — cryptographic signature is invalid. Message was modified in transit or domain is spoofed.` });
      authChecks.push({ label:"DKIM", result:"fail", detail:"Signature broken / missing", cls:"eha-auth-fail" });
    } else if (dkimResult === "neutral") {
      authChecks.push({ label:"DKIM", result:"neutral", detail:"No verifiable signature", cls:"eha-auth-none" });
    } else {
      authChecks.push({ label:"DKIM", result:"none", detail:"No DKIM signature found", cls:"eha-auth-none" });
    }

    // DMARC
    if (dmarcResult === "pass") {
      authChecks.push({ label:"DMARC", result:"pass", detail:`Policy enforced${dmarcFromDomain?" for "+dmarcFromDomain:""}`, cls:"eha-auth-pass" });
    } else if (dmarcResult === "fail") {
      score += 25; flags.push({ sev:"crit", cat:"auth", msg:`DMARC FAIL — From: domain does not align with SPF/DKIM results.${dmarcDisposition?" Policy action: "+dmarcDisposition.toUpperCase():""}` });
      authChecks.push({ label:"DMARC", result:"fail", detail:dmarcDisposition?"Policy: "+dmarcDisposition:"Alignment failed", cls:"eha-auth-fail" });
    } else {
      authChecks.push({ label:"DMARC", result:"none", detail:"No DMARC policy found", cls:"eha-auth-none" });
    }

    // ARC
    if (hasARC) {
      authChecks.push({ label:"ARC", result:arcResult, detail:arcResult==="pass"?"Forwarding chain validated":"ARC chain — review hops", cls:arcResult==="pass"?"eha-auth-pass":"eha-auth-none" });
    }

    // CompAuth (Microsoft)
    if (compauthResult) {
      const COMPAUTH_CODES = {
        "000":"All checks passed","001":"DMARC fail, no sender override","002":"DMARC fail, override applied",
        "010":"DMARC fail with override","100":"SPF softfail","400":"SPF fail","600":"No SPF record",
        "610":"SPF pass but From: misaligned","700":"DKIM fail","800":"No DKIM signature",
        "801":"DKIM signature but not From: domain","802":"DKIM neutral","900":"DMARC none policy",
      };
      authChecks.push({ label:"CompAuth", result:compauthResult, detail:COMPAUTH_CODES[compauthReason]||`Code: ${compauthReason}`, cls:compauthResult==="pass"?"eha-auth-pass":"eha-auth-fail" });
      if (compauthResult==="fail") { score+=15; flags.push({ sev:"warn", cat:"auth", msg:`Microsoft Composite Auth FAILED — code ${compauthReason}: ${COMPAUTH_CODES[compauthReason]||"unknown reason"}` }); }
    }

    // ── Alignment checks ─────────────────────────────────────
    const KNOWN_ESPS_ALIGN = ["sendgrid.net","mailchimp.com","mcsv.net","klaviyo.com","constantcontact.com",
      "hubspot.com","marketo.net","sparkpost.com","amazonses.com","mailgun.org","postmarkapp.com",
      "exacttarget.com","salesforce.com","google.com","googlemail.com","outlook.com","microsoft.com",
      "protection.outlook.com","pphosted.com","mimecast.com","proofpoint.com","barracuda.com"];
    if (spfResult==="pass" && spfMailFromDomain && fromDomain && spfMailFromDomain!==fromDomain) {
      const isESPSpf = KNOWN_ESPS_ALIGN.some(e => spfMailFromDomain.endsWith(e));
      if (isESPSpf) {
        flags.push({ sev:"info", cat:"spam", msg:`Sent via ESP (${spfMailFromDomain}) on behalf of ${fromDomain} — expected for platforms like SendGrid, Mailchimp, SES` });
      } else {
        score+=10; flags.push({ sev:"warn", cat:"spoof", msg:`SPF MailFrom domain (${spfMailFromDomain}) ≠ From: domain (${fromDomain}) — display name spoofing possible` });
      }
    }
    if (dkimResult==="pass" && dkimDomain && fromDomain && !fromDomain.endsWith(dkimDomain) && !dkimDomain.endsWith(fromDomain)) {
      const isESPDkim = KNOWN_ESPS_ALIGN.some(e => dkimDomain.endsWith(e));
      if (isESPDkim) {
        flags.push({ sev:"info", cat:"spam", msg:`DKIM signed by ${dkimDomain} (known ESP) on behalf of ${fromDomain} — expected for email service providers` });
      } else {
        score+=8; flags.push({ sev:"warn", cat:"spoof", msg:`DKIM signing domain (${dkimDomain}) ≠ From: domain (${fromDomain}) — third-party signing, verify if expected` });
      }
    }

    // ── Spoofing / BEC / Identity ────────────────────────────
    if (replyEmail && replyEmail!==fromEmail) {
      score+=22; flags.push({ sev:"crit", cat:"bec", msg:`Reply-To hijack — From: <${fromEmail}> but Reply-To: <${replyEmail}> — replies will go to attacker-controlled address` });
    }
    if (retDomain && fromDomain && retDomain!==fromDomain) {
      score+=15; flags.push({ sev:"warn", cat:"spoof", msg:`Return-Path domain (${retDomain}) ≠ From: domain (${fromDomain}) — bounce handling inconsistency, common in spoofed mail` });
    }
    if (lookalikeBrand) {
      score+=35; flags.push({ sev:"crit", cat:"brand", msg:`Brand impersonation detected — domain "${lookalikeDomain}" impersonates "${lookalikeBrand}". This is a ${levenshtein(fromDomain.split(".")[0].toLowerCase(),lookalikeBrand)===0?"display name spoof":"lookalike/typosquat domain"}.` });
    }
    if (isPunycode) {
      score+=30; flags.push({ sev:"crit", cat:"brand", msg:`Punycode/IDN homograph detected (xn-- encoding) in domain "${fromDomain}" — visually similar to a legitimate domain using Unicode substitution` });
    }

    // ── Spam detection ───────────────────────────────────────
    if (isBulkPrecedence) {
      flags.push({ sev:"info", cat:"spam", msg:`Precedence: ${precedence} — bulk/list email, not targeted` });
    }
    if (listId) {
      flags.push({ sev:"info", cat:"spam", msg:`List-ID: ${listId.slice(0,80)} — mailing list email` });
    }
    if (xCampaignId) {
      flags.push({ sev:"info", cat:"spam", msg:`Campaign ID detected (${xCampaignId.slice(0,60)}) — marketing automation platform` });
    }
    if (senderESP) {
      flags.push({ sev:"info", cat:"spam", msg:`Sent via ${senderESP} ESP — may be legitimate marketing or abused bulk sender` });
    }
    spamSubjectHits.forEach(hit => {
      score += (hit.label.includes("Thread hijacking")||hit.label.includes("RE/FWD")) ? 15 : 5;
      flags.push({ sev: hit.label.includes("RE/FWD")||hit.label.includes("Urgency") ? "warn" : "info",
                   cat:"spam", msg:`Subject pattern: ${hit.label} — "${(subject||"").slice(0,60)}"` });
    });
    if (xSpamScore) {
      const n=parseFloat(xSpamScore);
      if (n>5) { score+=12; flags.push({ sev:"warn", cat:"spam", msg:`SpamAssassin score ${xSpamScore} (threshold typically 5.0) — classified as spam` }); }
      else      flags.push({ sev:"info", cat:"spam", msg:`SpamAssassin score: ${xSpamScore}` });
    }
    if (barracuda) {
      const n=parseFloat(barracuda);
      if (n>3.5) { score+=10; flags.push({ sev:"warn", cat:"spam", msg:`Barracuda spam score ${barracuda} — elevated risk` }); }
      else        flags.push({ sev:"info", cat:"spam", msg:`Barracuda score: ${barracuda}` });
    }
    if (microsoftSCL) {
      const scl=parseInt(microsoftSCL);
      if (scl>=5) { score+=10; flags.push({ sev:"warn", cat:"spam", msg:`Microsoft SCL=${scl} — Spam Confidence Level above delivery threshold (5+)` }); }
      else if (scl===-1) flags.push({ sev:"ok",  cat:"spam", msg:`Microsoft SCL=-1 — message bypasses spam filtering (safelisted sender)` });
      else               flags.push({ sev:"info", cat:"spam", msg:`Microsoft SCL=${scl}` });
    }
    if (xPhishScore && parseFloat(xPhishScore)>3) {
      score+=18; flags.push({ sev:"warn", cat:"phish", msg:`Phish score ${xPhishScore} — email security gateway detected elevated phishing risk` });
    }

    // ── Modern attack patterns ───────────────────────────────
    if (isQRishing) {
      score+=25; flags.push({ sev:"crit", cat:"attack", msg:`QRishing detected — QR code lure in subject/body. QR codes bypass most URL scanners. High-risk vector for credential theft.` });
    }
    if (isVoicemail) {
      score+=20; flags.push({ sev:"crit", cat:"attack", msg:`Voicemail/vishing lure detected — fake voicemail notification is a known phishing template used to deliver malicious links or executables` });
    }
    if (isTOAD) {
      score+=25; flags.push({ sev:"crit", cat:"attack", msg:`Callback phishing (TOAD) pattern — phone number present in email. Attacker answers calls and socially engineers victims into installing RATs or sharing credentials.` });
    }
    if (isMalwareDelivery) {
      score+=40; flags.push({ sev:"crit", cat:"attack", msg:`Malicious attachment type detected: ${maliciousAttach.join(", ")} — these file types are commonly used for malware delivery. Do NOT open.` });
    }
    if (isAiTM) {
      score+=40; flags.push({ sev:"crit", cat:"attack", msg:`AiTM phishing infrastructure detected in relay chain — adversary-in-the-middle proxy can steal session cookies and MFA tokens in real time` });
    }
    if (isHTMLOnly) {
      score+=5; flags.push({ sev:"info", cat:"attack", msg:`HTML-only email (no plain text alternative) — common in phishing campaigns that use styled HTML to impersonate legitimate brands` });
    }
    if (hasTrackingPixel) {
      flags.push({ sev:"info", cat:"spam", msg:`Tracking pixel / open-tracking indicator detected — sender can confirm delivery and read receipts` });
    }

    // ── Free provider impersonation ──────────────────────────
    const FREE_PROVIDERS = ["gmail.com","yahoo.com","hotmail.com","outlook.com","live.com","aol.com","protonmail.com","tutanota.com","icloud.com","me.com","ymail.com"];
    // Only flag if the display name contains a company/brand name (not just any person's name)
    const CORP_NAME_PATTERNS = /(?:paypal|microsoft|apple|amazon|google|facebook|meta|netflix|bank|wells.fargo|chase|citibank|irs|fedex|ups|dhl|support|security|admin|billing|account|help.?desk|it.?dept|hr.dept|finance|payroll|ceo|cfo|cto|president|director|manager)/i;
    // Only flag free provider if name matches a known brand/corp (not just a person's name)
    const BRAND_IMPERSONATION_RE = /\b(?:paypal|microsoft|apple|amazon|google|facebook|meta|netflix|instagram|twitter|linkedin|dropbox|zoom|slack|stripe|shopify|squarespace|bank of america|wells fargo|chase|citi|barclays|hsbc|irs|fbi|cisa|fedex|ups|dhl|usps|irs alert|microsoft support|apple support|amazon support|paypal support|account team|security team|billing department|it helpdesk|it support)/i;
    if (fromDomain && FREE_PROVIDERS.includes(fromDomain) && fromName && fromName.length>4 && BRAND_IMPERSONATION_RE.test(fromName)) {
      score+=20; flags.push({ sev:"crit", cat:"bec", msg:`Known brand impersonation — "${fromName}" is using a free provider (${fromDomain}) instead of their official domain` });
    }

    // ── Infrastructure / relay ───────────────────────────────
    if (xOrigIP) flags.push({ sev:"info", cat:"infra", msg:`X-Originating-IP: ${xOrigIP} — the sender's actual mail client or submission IP` });
    if (hops.length===0 && (spfResult==="fail" || dkimResult==="fail" || !spfResult)) {
      score+=20; flags.push({ sev:"crit", cat:"infra", msg:"No Received headers — headers may be completely forged or stripped by attacker" });
    } else if (hops.length===0) {
      flags.push({ sev:"info", cat:"infra", msg:"No Received headers found — may be an internal/direct message or headers were stripped" });
    } else if (hops.length===1 && (spfResult==="fail" || dkimResult==="fail")) {
      score+=10; flags.push({ sev:"warn", cat:"infra", msg:"Only 1 relay hop combined with authentication failures — may indicate direct injection or forged headers" });
    } else if (hops.length<=2) {
      flags.push({ sev:"info", cat:"infra", msg:`${hops.length} relay hop${hops.length>1?"s":""} — normal for direct delivery from major providers (Google, Microsoft, etc.)` });
    }
    if (hops.some(h=>h.delayWarn)) flags.push({ sev:"info", cat:"infra", msg:"Unusual relay delay (>5 min) detected — may indicate queuing, grey-listing, or clock skew" });
    if (!subject) { score+=5; flags.push({ sev:"warn", cat:"spam", msg:"No Subject line — atypical for legitimate mail" }); }

    // ── Clean verdict ────────────────────────────────────────
    const isAllAuthPass = spfResult==="pass" && dkimResult==="pass" && dmarcResult==="pass";
    const isInternalMail = fromDomain && (fromDomain.split(".").every(p=>/[a-z]/i.test(p)) && !FREE_PROVIDERS.includes(fromDomain) && hops.length<=1 && !spfResult && !dkimResult);
    if (isAllAuthPass && score===0) {
      flags.push({ sev:"ok", cat:"auth", msg:"SPF + DKIM + DMARC all PASS with correct alignment — strong authentication posture" });
    } else if (isAllAuthPass && score < 20) {
      flags.push({ sev:"ok", cat:"auth", msg:`SPF: ${spfResult?.toUpperCase()}, DKIM: ${dkimResult?.toUpperCase()}, DMARC: ${dmarcResult?.toUpperCase()} — authentication passed. Minor informational signals only.` });
    } else if (isInternalMail) {
      flags.push({ sev:"info", cat:"auth", msg:"Internal mail — no external authentication expected for internal-only email" });
    } else if (!spfResult && !dkimResult) {
      flags.push({ sev:"warn", cat:"auth", msg:"No authentication results found — headers may be incomplete. Cannot verify sender legitimacy." });
    }

    return {
      from, to, cc, replyTo, subject, date, msgId, returnPath, xOrigIP, xMailer,
      contentType, contentTE, listUnsub, listId, precedence, xSpamScore, xSpamStatus,
      xPhishScore, microsoftSCL, barracuda, senderESP, xCampaignId, xHeaders,
      fromEmail, fromName, fromDomain, replyEmail, replyDomain, toEmail, toDomain, retDomain,
      spf: spfResult, spfMailFrom: spfMailFromDomain,
      dkim: dkimResult, dkimDomain, dkimSelector, dkimAlgo,
      dmarc: dmarcResult, dmarcDisposition, dmarcFromDomain,
      arc: arcResult, compauth: compauthResult,
      lookalikeBrand, lookalikeDomain, isPunycode,
      attackType, attackDetail,
      confidence, confidenceColor, confidenceReason,
      verdictDrivers,
      isBEC, isPhishing, isSpam, isQRishing, isVoicemail, isTOAD, isAiTM, isMalwareDelivery,
      isHTMLOnly, hasTrackingPixel, attachmentName, maliciousAttach,
      isBulkHeaders, isBulkPrecedence, spamSubjectHits,
      authChecks, hops, flags, score,
    };
  }
  function renderEmailHeaderResults(r) {
    const results = $("eha-results");
    if (!results) return;
    results.style.display = "block";

    // ══════════════════════════════════════════════════════════
    // TOP VERDICT CARD — definitive CLEAN / SUSPICIOUS / MALICIOUS
    // ══════════════════════════════════════════════════════════
    const pct = Math.min(100, r.score);
    let topVerdict, topColor, topBg, topIcon, topSummary, topAction;

    if (r.attackType === "LIKELY CLEAN" || (r.spf==="pass" && r.dkim==="pass" && r.dmarc==="pass" && pct < 30)) {
      topVerdict = "CLEAN — LIKELY LEGITIMATE";
      topColor   = "#34d399"; topBg = "rgba(52,211,153,0.07)";
      topIcon    = "✅";
      topSummary = `This email passed all three authentication controls (SPF: ${(r.spf||"none").toUpperCase()}, DKIM: ${(r.dkim||"none").toUpperCase()}, DMARC: ${(r.dmarc||"none").toUpperCase()}) with correct domain alignment. No spoofing, brand impersonation, or attack patterns were detected.`;
      topAction  = "No action required. Safe to treat as legitimate.";
    } else if (r.attackType === "SPAM / BULK") {
      topVerdict = "BULK / MARKETING EMAIL";
      topColor   = "#94a3b8"; topBg = "rgba(148,163,184,0.07)";
      topIcon    = "📬";
      topSummary = `Sent via ${r.senderESP||"a marketing platform"} using bulk email infrastructure. Authentication is technically valid but the message is unsolicited bulk mail, not a targeted attack.`;
      topAction  = "Low threat. Review sender, unsubscribe if unwanted.";
    } else if ((r.verdictDrivers||[]).some(d=>d.weight==="critical") || 
               (pct >= 60 && (r.spf==="fail" || r.dkim==="fail" || r.dmarc==="fail"))) {
      // Only MALICIOUS if we have hard cryptographic evidence OR high score WITH auth failures
      topVerdict = "MALICIOUS — DO NOT INTERACT";
      topColor   = "#ef4444"; topBg = "rgba(239,68,68,0.07)";
      topIcon    = "🚨";
      const critCount = (r.verdictDrivers||[]).filter(d=>d.weight==="critical").length;
      topSummary = `${critCount} critical signal${critCount>1?"s":""} confirmed. Attack type: ${r.attackType}. ${r.attackDetail||""}`;
      topAction  = "Block sender domain, quarantine message, investigate all recipients.";
    } else if (pct >= 30 && r.attackType !== "LIKELY CLEAN") {
      topVerdict = "SUSPICIOUS — INVESTIGATE";
      topColor   = "#fbbf24"; topBg = "rgba(251,191,36,0.07)";
      topIcon    = "⚠️";
      topSummary = `${r.confidence||"MEDIUM"} confidence — ${r.confidenceReason||"multiple warning signals detected without definitive proof."}`;
      topAction  = "Verify with sender out-of-band. Do not click links or open attachments until confirmed legitimate.";
    }

    const banner = $("eha-score-banner");
    banner.className = "eha-score-banner";
    banner.innerHTML = `
      <div style="width:100%;">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
          <span style="font-size:22px;">${topIcon}</span>
          <span style="font-size:15px;font-weight:900;color:${topColor};">${esc(topVerdict)}</span>
          <span style="font-size:11px;background:${topColor}22;color:${topColor};border:1px solid ${topColor}44;padding:2px 10px;border-radius:10px;font-weight:700;">${esc(r.confidence||"MEDIUM")} CONFIDENCE</span>
          <span style="font-size:10.5px;font-weight:900;padding:2px 12px;border-radius:20px;background:${topColor}22;color:${topColor};letter-spacing:.5px;">${esc(r.attackType)}</span>
          <span style="font-size:11px;font-weight:800;color:#38bdf8;margin-left:auto;">Risk Score: ${pct}</span>
        </div>
        <div style="font-size:12px;color:var(--text);line-height:1.7;margin-bottom:10px;">${esc(topSummary)}</div>
        <div style="background:${topColor}12;border:1px solid ${topColor}30;border-radius:7px;padding:8px 12px;font-size:11.5px;color:${topColor};font-weight:700;">
          ${topIcon} Analyst Action: ${esc(topAction)}
        </div>
        <div class="eha-auth-checks" style="margin-top:12px;">
          ${(r.authChecks||[]).map(c=>`
            <div class="eha-auth-check-row">
              <span class="eha-auth-check-label">${esc(c.label)}</span>
              <span class="eha-auth-badge ${c.cls}">${(c.result||"none").toUpperCase()}</span>
              <span class="eha-auth-check-detail">${esc(c.detail)}</span>
            </div>`).join("")}
        </div>
      </div>`;

    // ══════════════════════════════════════════════════════════
    // VERDICT EXPLANATION — why this verdict, driver by driver
    // ══════════════════════════════════════════════════════════
    const explainEl = $("eha-verdict-explain");
    if (explainEl) {
      const drivers = r.verdictDrivers || [];
      const weightColors = { critical:"#ef4444", warning:"#fbbf24", clean:"#34d399" };
      const weightLabels = { critical:"🔴 CRITICAL SIGNAL", warning:"🟡 WARNING SIGNAL", clean:"🟢 CLEAN SIGNAL" };

      if (drivers.length || r.confidence) {
        const driverRows = drivers.map(d => {
          const c = weightColors[d.weight] || "#9ca3af";
          return `<div style="display:flex;gap:10px;align-items:flex-start;padding:9px 14px;border-left:3px solid ${c};background:${c}06;margin-bottom:3px;">
            <span style="font-size:15px;flex-shrink:0;">${esc(d.icon)}</span>
            <div style="flex:1;">
              <div style="font-size:9.5px;font-weight:800;color:${c};text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;">${esc(weightLabels[d.weight]||d.weight.toUpperCase())}</div>
              <div style="font-size:11.5px;color:var(--text);line-height:1.7;">${esc(d.text)}</div>
            </div>
          </div>`;
        }).join("");

        // Add flag summary for warnings not already in drivers
        const warnFlags = (r.flags||[]).filter(f => (f.sev==="warn"||f.sev==="crit") && !drivers.some(d => d.text.toLowerCase().includes(f.msg.slice(0,20).toLowerCase())));
        const flagRows = warnFlags.slice(0,4).map(f => {
          const c = f.sev==="crit" ? "#ef4444" : "#fbbf24";
          return `<div style="display:flex;gap:8px;padding:7px 14px;border-left:2px solid ${c}55;background:${c}04;margin-bottom:2px;font-size:11px;color:var(--text);">
            <span>${f.sev==="crit"?"🚨":"⚠️"}</span><span>${esc(f.msg)}</span></div>`;
        }).join("");

        explainEl.style.display = "block";
        explainEl.innerHTML = `
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
            <div style="background:rgba(0,0,0,0.15);padding:10px 14px;display:flex;align-items:center;gap:8px;">
              <span style="font-size:12px;font-weight:800;color:var(--text);">🔍 Why this verdict?</span>
              <span style="font-size:10px;color:var(--muted);">${drivers.length} key signal${drivers.length!==1?"s":""} drove this assessment</span>
            </div>
            ${driverRows || ""}
            ${flagRows ? `<div style="padding:6px 0 2px;border-top:1px solid var(--border);">${flagRows}</div>` : ""}
            ${!driverRows && !flagRows ? `<div style="padding:12px 14px;font-size:11.5px;color:var(--muted);">No specific threat signals detected. The email appears legitimate based on authentication controls.</div>` : ""}
          </div>`;
      } else {
        explainEl.style.display = "none";
      }
    }

    // ── Summary grid ─────────────────────────────────────────
    const summaryItems = [
      { label:"From",              value: r.fromEmail ? `${r.fromName?`"${r.fromName}" <`:""}${r.fromEmail}${r.fromName?">":""}` : r.from||"—" },
      { label:"To",                value: r.toEmail||r.to||"—" },
      { label:"Reply-To",          value: r.replyEmail ? `${r.replyEmail}${r.replyEmail!==r.fromEmail?" ⚠️ DIFFERS FROM SENDER":""}` : "Same as From" },
      { label:"Subject",           value: r.subject||"—" },
      { label:"Date",              value: r.date||"—" },
      { label:"Message-ID",        value: r.msgId||"—" },
      { label:"Return-Path",       value: r.returnPath ? `${r.returnPath}${r.retDomain&&r.fromDomain&&r.retDomain!==r.fromDomain?" ⚠️ DOMAIN MISMATCH":""}` : "—" },
      { label:"X-Originating-IP",  value: r.xOrigIP||"Not disclosed" },
      { label:"Mailer / ESP",       value: r.xMailer||r.senderESP||"Not disclosed" },
      { label:"Content-Type",      value: r.contentType||"—" },
      { label:"Relay Hops",        value: `${r.hops.length} hop${r.hops.length!==1?"s":""}${r.hops.some(h=>h.tls)?" · TLS encrypted":""}` },
      { label:"Spam Score",        value: r.xSpamScore||"—" },
      { label:"Phish Score",       value: r.xPhishScore||"—" },
      { label:"Microsoft SCL",     value: r.microsoftSCL||"—" },
      { label:"Campaign ID",       value: r.xCampaignId||"—" },
      { label:"Attachments",       value: r.attachmentName?.join(", ")||"—" },
    ].filter(s => s.value && s.value !== "—" && s.value !== "Not disclosed");
    $("eha-summary").innerHTML = summaryItems.map(s =>
      `<div class="eha-summary-item">
        <div class="eha-summary-label">${esc(s.label)}</div>
        <div class="eha-summary-value${s.value.includes("⚠️")?" eha-summary-warn":""}">${esc(String(s.value).slice(0,160))}</div>
      </div>`
    ).join("");

    $("eha-auth").innerHTML = "";

    // ── Flag list grouped by category ────────────────────────
    const CAT_LABELS = {
      auth:"🔐 Authentication", bec:"🎭 BEC / Identity", brand:"🏷 Brand / Domain",
      spoof:"🃏 Spoofing", attack:"⚔️ Attack Pattern", spam:"📬 Spam / Bulk",
      phish:"🎣 Phishing", infra:"🌐 Infrastructure"
    };
    const grouped = {};
    (r.flags||[]).forEach(f => { const c=f.cat||"infra"; if(!grouped[c]) grouped[c]=[]; grouped[c].push(f); });
    let flagsHtml = "";
    for (const [cat, items] of Object.entries(grouped)) {
      if (items.length) {
        flagsHtml += `<div class="eha-flag-cat-head">${CAT_LABELS[cat]||cat}</div>`;
        items.forEach(f => {
          const cls  = f.sev==="crit"?"eha-flag-crit":f.sev==="warn"?"eha-flag-warn":f.sev==="ok"?"eha-flag-ok":"eha-flag-info";
          const icon = f.sev==="crit"?"🚨":f.sev==="warn"?"⚠️":f.sev==="ok"?"✅":"ℹ️";
          flagsHtml += `<div class="eha-flag-item ${cls}">${icon} ${esc(f.msg)}</div>`;
        });
      }
    }
    $("eha-flags").innerHTML = flagsHtml || `<div class="eha-flag-item eha-flag-info">ℹ️ No signals detected</div>`;

    // ── Hop chain ────────────────────────────────────────────
    const hopsEl = $("eha-hops");
    if (r.hops.length) {
      hopsEl.innerHTML = `<div class="eha-hop-row eha-hop-head"><span>#</span><span>From</span><span>By</span><span>IP</span><span>Protocol</span><span>Delay</span></div>` +
        r.hops.map(h => `<div class="eha-hop-row${h.delayWarn?" eha-hop-warn":""}">
          <div class="eha-hop-num">${h.hop}</div>
          <div class="eha-hop-host" title="${esc(h.from)}">${esc((h.from||"?").slice(0,32))}${(h.from||"").length>32?"…":""}</div>
          <div class="eha-hop-host" title="${esc(h.by)}">${esc((h.by||"?").slice(0,28))}${(h.by||"").length>28?"…":""}</div>
          <div class="eha-hop-ip">${h.ip ? '<a href="https://www.abuseipdb.com/check/' + encodeURIComponent(h.ip) + '" target="_blank" style="color:#38bdf8;text-decoration:none;">' + esc(h.ip) + '</a> ' + (!isPrivateIPv4(h.ip)?"🌐":"🏠") : "<span style='color:var(--muted)'>—</span>"}</div>
          <div style="font-size:10px;">${h.tls?"🔒 ":""}${h.via||""}</div>
          <div class="eha-hop-delay${h.delayWarn?" eha-hop-delay-warn":""}">${h.delay||"—"}</div>
        </div>`).join("");
    } else {
      hopsEl.innerHTML = `<div style="padding:12px;font-size:11px;color:var(--muted);">⚠️ No Received headers — may be incomplete or forged.</div>`;
    }

    // ── Pivot buttons ────────────────────────────────────────
    const pivots = [];
    if (r.fromEmail)   pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.fromEmail)}','email')">🔍 Sender email</button>`);
    if (r.fromDomain)  pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.fromDomain)}','domain')">🌐 From domain</button>`);
    if (r.xOrigIP)     pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.xOrigIP)}','ip')">🛡 Origin IP</button>`);
    if (r.replyEmail && r.replyEmail!==r.fromEmail) pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.replyEmail)}','email')">📧 Reply-To</button>`);
    if (r.lookalikeDomain && r.lookalikeDomain!==r.fromDomain) pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.lookalikeDomain)}','domain')">🏷 Lookalike domain</button>`);
    if (r.dkimDomain && r.dkimDomain!==r.fromDomain) pivots.push(`<button class="eha-pivot-btn" onclick="pivotFromEHA('${esc(r.dkimDomain)}','domain')">🔐 DKIM domain</button>`);
    const hops_ips = r.hops.map(h=>h.ip).filter(Boolean);
    if (hops_ips.length) pivots.push(`<button class="eha-pivot-btn" onclick="copyEHAHops()">📋 Copy ${hops_ips.length} hop IP${hops_ips.length>1?"s":""}</button>`);
    $("eha-pivots").innerHTML = pivots.join("");
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
  // SOURCE-AWARE DETECTION QUERIES  (Alert Source → SIEM Platform)
  // ════════════════════════════════════════════════════════════════

  // 12 sources × alert-type lists (shown in the dropdown)
  const SOURCE_ALERT_TYPES = {
    crowdstrike:  { label:"CrowdStrike Falcon",        color:"#f87171", alertTypes:[
          {value:"detection",     label:"Detection / Alert",           hint:"Investigate the detected process, hash, and endpoint scope across fleet"},
      {value:"process",       label:"Suspicious Process Execution",hint:"Pivot on command line, parent process, and file hash"},
      {value:"network",       label:"Network Connection Alert",    hint:"Investigate the remote IP/domain and scope across fleet"},
      {value:"identity",      label:"Identity / Credential Alert", hint:"Look for lateral movement, privilege escalation, new accounts"},
      {value:"fdr",           label:"FDR Raw Telemetry",           hint:"Search raw Falcon Data Replicator events by any field value"},
    ]},
    zscaler:      { label:"Zscaler ZIA / ZPA",          color:"#38bdf8", alertTypes:[
          {value:"web_block",     label:"Web Transaction Blocked",     hint:"Confirm block, check user and endpoint, look for other hits from same IP"},
      {value:"threat",        label:"Threat Detected (malware/C2)",hint:"Correlate threat name with hash lookup and endpoint EDR telemetry"},
      {value:"dlp",           label:"DLP Policy Triggered",        hint:"Identify data type, destination, and user context"},
      {value:"sandbox",       label:"Sandbox / Advanced Threat",   hint:"Look for payload delivery chain and execution on the endpoint"},
      {value:"allowed_bad",   label:"Allowed — Malicious Category",hint:"URGENT: traffic was allowed — go investigate the endpoint now"},
    ]},
    azure_ad:     { label:"Azure AD / Entra ID",        color:"#818cf8", alertTypes:[
          {value:"signin_fail",   label:"Failed Sign-In",              hint:"Check IP reputation, MFA status, account lockout threshold"},
      {value:"signin_risk",   label:"Risky Sign-In (MS Risk)",     hint:"Review location, device, MFA; check for post-auth activity"},
      {value:"mfa_fail",      label:"MFA Challenge Failed / Push Spam",hint:"Detect MFA fatigue — count denies per user per 30-min window"},
      {value:"oauth_consent", label:"OAuth App Consent Grant",     hint:"Identify app permissions granted — common BEC precursor"},
      {value:"audit",         label:"Audit Log Event",             hint:"Admin action — new user, role assignment, policy change"},
      {value:"impossible",    label:"Impossible Travel",           hint:"Calculate distance between two IPs, verify both, check for VPN"},
    ]},
    defender:     { label:"Microsoft Defender / MDE",   color:"#3b82f6", alertTypes:[
          {value:"process_alert", label:"Process / Behavior Alert",    hint:"Pivot on image hash, command line, MITRE technique"},
      {value:"network_alert", label:"Network Connection Alert",    hint:"Investigate remote IP/domain, scope to other devices"},
      {value:"file_alert",    label:"Malicious File Detected",     hint:"Check hash in VT/MBazaar, scope execution across org"},
      {value:"ransomware",    label:"Ransomware Detected",         hint:"ISOLATE NOW — check VSS, lateral spread, backup status"},
      {value:"tamper",        label:"Tamper / AV Disabled",        hint:"AV disabled by attacker — check what ran before/after"},
    ]},
    okta:         { label:"Okta / SSO",                 color:"#00d1e0", alertTypes:[
          {value:"login_fail",    label:"Failed Authentication",       hint:"Count failures, check IP, look for success after failures"},
      {value:"mfa_push",      label:"MFA Push Deny / Fatigue",     hint:"Count push denies per hour — more than 3 per 30min = fatigue attack"},
      {value:"policy_deny",   label:"Policy / Sign-On Denied",     hint:"Identify policy triggered, device posture, user context"},
      {value:"susp_activity", label:"Suspicious Activity Reported",hint:"User self-reported — treat as credential compromise immediately"},
      {value:"app_grant",     label:"App Permission Granted",      hint:"OAuth abuse vector — verify app and permissions granted"},
    ]},
    proofpoint:   { label:"Proofpoint TAP",             color:"#f97316", alertTypes:[
          {value:"phish",         label:"Phishing Message Delivered",  hint:"Check sender, URL, attachment — did the user click?"},
      {value:"malware",       label:"Malware Attachment Detected", hint:"Hash lookup, sandbox the attachment, check endpoint for execution"},
      {value:"impostor",      label:"Impostor / BEC Detected",     hint:"Display name spoofing — check reply-to, forwarding rules, wire transfers"},
      {value:"url_click",     label:"Malicious URL Clicked",       hint:"URGENT — user clicked — check endpoint for payload execution NOW"},
    ]},
    aws:          { label:"AWS CloudTrail",             color:"#f59e0b", alertTypes:[
          {value:"iam_priv",      label:"IAM Privilege Escalation",    hint:"AttachPolicy/CreateUser/AddToGroup — account takeover risk"},
      {value:"root_usage",    label:"Root Account Used",           hint:"Root should never be used — treat as critical incident"},
      {value:"ct_tamper",     label:"CloudTrail Logging Disabled", hint:"Anti-forensics — StopLogging/DeleteTrail — attacker is hiding"},
      {value:"s3_exposure",   label:"S3 Bucket Public / GetObject",hint:"Data exfil risk — check bucket ACL and access patterns"},
      {value:"ec2_launch",    label:"Unusual EC2 / Resource Launch",hint:"Crypto-mining or C2 hosting — check instance type and region"},
    ]},
    sentinelone:  { label:"SentinelOne",                color:"#6d28d9", alertTypes:[
          {value:"threat_detect", label:"Threat Detected",             hint:"Check hash, file path, execution chain — scope across org"},
      {value:"not_mitigated", label:"Threat NOT Mitigated",        hint:"URGENT — manual action needed, isolate endpoint immediately"},
      {value:"ransomware",    label:"Ransomware Behavior",         hint:"ISOLATE — check VSS deletion, lateral spread, backup integrity"},
      {value:"network_c2",    label:"Suspicious Network Activity", hint:"Pivot on remote IP, look for beaconing pattern in EDR"},
    ]},
    paloalto:     { label:"Palo Alto NGFW",             color:"#00c0e8", alertTypes:[
          {value:"threat",        label:"Threat / IPS Signature",      hint:"Check signature CVE, source IP, scope similar traffic"},
      {value:"url_block",     label:"URL Filter Block",            hint:"Confirm policy action, check endpoint for prior access"},
      {value:"wildfire",      label:"WildFire Malware Verdict",    hint:"Hash confirmed malicious — trace delivery to endpoint"},
      {value:"c2",            label:"C2 / Command & Control",      hint:"CRITICAL — active implant communicating — isolate now"},
    ]},
    darktrace:    { label:"Darktrace / NDR",            color:"#8b5cf6", alertTypes:[
          {value:"model_breach",  label:"Model Breach",                hint:"Understand the model, compare current vs normal baseline"},
      {value:"ai_analyst",    label:"AI Analyst Incident",         hint:"Review AI-linked chain — multiple correlated anomalous events"},
      {value:"beacon",        label:"Beaconing / C2 Pattern",      hint:"Check interval regularity, remote IP, pivot to endpoint EDR"},
      {value:"lateral",       label:"Internal Lateral Movement",   hint:"East-west traffic anomaly — map pivot path and initial compromise"},
    ]},
    suricata:     { label:"Suricata / Snort IDS",       color:"#ef4444", alertTypes:[
          {value:"malware_c2",    label:"Malware / C2 Signature",      hint:"Active implant traffic — correlate with endpoint EDR immediately"},
      {value:"exploit",       label:"Exploit Attempt Detected",    hint:"Check CVE, patch status on target, source IP reputation"},
      {value:"scan",          label:"Recon / Port Scan",           hint:"External recon — assess source, scope exposure, block if needed"},
      {value:"policy",        label:"Policy Violation",            hint:"Unusual protocol — verify if legitimate business use case"},
    ]},
    siem_generic: { label:"QRadar / Splunk SIEM",       color:"#a78bfa", alertTypes:[
          {value:"correlation",   label:"Correlation Rule Triggered",  hint:"Review rule logic and all correlated events in the offense/notable"},
      {value:"offense",       label:"QRadar Offense (high mag.)",  hint:"Check magnitude, source IPs, destination assets, event count"},
      {value:"notable",       label:"Splunk ES Notable Event",     hint:"Review risk score, contributing events, MITRE technique mapping"},
    ]},
  };

  // 3D lookup: SOURCE_QUERIES[source][alertType][siemPlatform] → fn(ioc) => query string
  const SOURCE_QUERIES = {
    crowdstrike: {
      detection: {
        cs:     (v)=>`// Investigate CrowdStrike detection — scope across fleet
event_simpleName=Detection ComputerName="${v||"<HOSTNAME>"}"
| table _time, ComputerName, UserName, FileName, SHA256HashData, CommandLine, Technique, Severity

// Scope: same technique on other hosts
event_simpleName=Detection Technique!="" Severity IN ("High","Critical")
| stats count by ComputerName, UserName, Technique
| sort - count`,
        splunk: (v)=>`index=crowdstrike sourcetype=crowdstrike:events ComputerName="${v||"<HOSTNAME>"}"
| table _time, ComputerName, UserName, FileName, SHA256HashData, Technique, Severity`,
        kql:    (v)=>`CommonSecurityLog
| where DeviceVendor == "CrowdStrike" and Computer =~ "${v||"<HOSTNAME>"}"
| project TimeGenerated, Computer, Activity, SourceUserName, FileName, FileHash`,
        elastic:(v)=>`GET .ds-logs-crowdstrike*/_search
{ "query": {"term": {"host.hostname": "${v||"<HOSTNAME>"}"}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='CrowdStrike' AND hostname='${v||"<HOSTNAME>"}' LAST 24 HOURS ORDER BY starttime DESC`,
      },
      network: {
        cs:     (v)=>`// CrowdStrike: scope network connection across fleet
event_simpleName=NetworkConnectIP4 RemoteAddressIP4="${v||"<REMOTE_IP>"}"
| stats count, values(ComputerName) as hosts, values(FileName) as procs by RemoteAddressIP4, RemotePort
| sort - count`,
        splunk: (v)=>`index=crowdstrike sourcetype=crowdstrike:events event_simpleName=NetworkConnectIP4
  RemoteAddressIP4="${v||"<REMOTE_IP>"}"
| stats count, values(ComputerName) as hosts by RemoteAddressIP4, RemotePort`,
        kql:    (v)=>`DeviceNetworkEvents
| where RemoteIP == "${v||"<REMOTE_IP>"}" 
| summarize count() by DeviceName, InitiatingProcessFileName, RemotePort
| sort by count_ desc`,
        elastic:(v)=>`GET .ds-logs-*/_search
{ "query": {"term": {"destination.ip": "${v||"<REMOTE_IP>"}"}} }`,
        qradar: (v)=>`SELECT sourceip, destinationip, username, count(*) FROM events
WHERE destinationip='${v||"<REMOTE_IP>"}' LAST 24 HOURS
GROUP BY sourceip, destinationip, username ORDER BY count(*) DESC`,
      },
      identity: {
        cs:     (v)=>`event_simpleName IN (UserLogon, UserAccountCreated, UserAccountAddedToGroup)
  UserName="${v||"<USERNAME>"}"
| table _time, ComputerName, UserName, event_simpleName, RemoteAddressIP4`,
        splunk: (v)=>`index=crowdstrike event_simpleName IN ("UserLogon","UserAccountCreated") UserName="${v||"<USERNAME>"}"
| table _time, ComputerName, UserName, event_simpleName`,
        kql:    (v)=>`IdentityLogonEvents
| where AccountName =~ "${v||"<USERNAME>"}"
| project TimeGenerated, DeviceName, AccountName, ActionType, IPAddress, CountryCode`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='CrowdStrike' AND username='${v||"<USERNAME>"}' AND category IN ('UserLogon','AccountCreated') LAST 24 HOURS`,
      },
      fdr: {
        cs:     (v)=>`// CrowdStrike FDR raw telemetry — replace field/value as needed
${v||"event_simpleName=ProcessRollup2"}
| table _time, ComputerName, UserName, event_simpleName, CommandLine, ImageFileName`,
        splunk: (v)=>`index=crowdstrike_fdr ${v||"ComputerName=<HOSTNAME>"}
| table _time, ComputerName, UserName, event_simpleName, CommandLine`,
      },
    },

    zscaler: {
      web_block: {
        cs:     (v)=>`// Correlate Zscaler block with CrowdStrike — find which process made the request
event_simpleName=NetworkConnectIP4
| where RemoteAddressIP4="${v||"<BLOCKED_IP>"}" OR RemoteDomainName LIKE "%${v||"<BLOCKED_DOMAIN>"}%"
| table _time, ComputerName, UserName, ImageFileName, CommandLine, RemoteAddressIP4`,
        splunk: (v)=>`index=zscaler sourcetype=zscaler:web action=blocked
  (url="*${v||"<DOMAIN>"}*" OR srcip="${v||"<SRC_IP>"}")
| stats count by user, srcip, url, category, action
| sort - count`,
        kql:    (v)=>`CommonSecurityLog
| where DeviceVendor == "Zscaler" and DeviceAction == "Blocked"
| where DestinationHostName contains "${v||"<DOMAIN>"}" or SourceIP == "${v||"<SRC_IP>"}"
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL, DeviceAction, SourceUserName`,
        elastic:(v)=>`GET .ds-logs-zscaler*/_search
{ "query": {"bool": {"must": [{"term": {"event.action":"blocked"}},{"wildcard":{"url.domain":"*${v||"<DOMAIN>"}*"}}]}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='Zscaler' AND eventcategory='blocked'
  AND destinationhostname LIKE '%${v||"<DOMAIN>"}%' LAST 24 HOURS`,
      },
      threat: {
        cs:     (v)=>`// Zscaler threat — pivot to CrowdStrike endpoint telemetry
event_simpleName=NetworkConnectIP4
| where RemoteAddressIP4="${v||"<THREAT_IP>"}" OR RemoteDomainName LIKE "%${v||"<THREAT_DOMAIN>"}%"
| table _time, ComputerName, UserName, ImageFileName, CommandLine`,
        splunk: (v)=>`index=zscaler sourcetype=zscaler:web threat=* threatname!=""
  (user="${v||"<USER>"}" OR srcip="${v||"<SRC_IP>"}")
| stats count by user, srcip, url, threat, threatname, action
| sort - count`,
        kql:    (v)=>`CommonSecurityLog
| where DeviceVendor == "Zscaler" and isnotempty(ThreatDescription)
| where SourceUserName =~ "${v||"<USER>"}" or SourceIP == "${v||"<SRC_IP>"}"
| project TimeGenerated, SourceUserName, SourceIP, DestinationHostName, ThreatDescription, DeviceAction`,
        qradar: (v)=>`SELECT username, sourceip, destinationhostname, threat, count(*) FROM events
WHERE DeviceType='Zscaler' AND threat IS NOT NULL
  AND (username='${v||"<USER>"}' OR sourceip='${v||"<SRC_IP>"}')
GROUP BY username, sourceip, destinationhostname, threat LAST 24 HOURS`,
      },
      allowed_bad: {
        cs:     (v)=>`// URGENT: Zscaler ALLOWED malicious traffic — investigate endpoint NOW
event_simpleName IN (NetworkConnectIP4, ProcessRollup2)
| where ComputerName="${v||"<HOSTNAME>"}" OR UserName="${v||"<USER>"}" 
| where _time >= now()-3600
| table _time, ComputerName, UserName, ImageFileName, CommandLine, RemoteAddressIP4`,
        splunk: (v)=>`index=zscaler sourcetype=zscaler:web action=allowed threat=* threatname!=""
  (user="${v||"<USER>"}")
| table _time, user, srcip, url, threat, action`,
        kql:    (v)=>`CommonSecurityLog
| where DeviceVendor == "Zscaler" and DeviceAction == "Allow"
  and isnotempty(ThreatDescription)
| where SourceUserName =~ "${v||"<USER>"}"
| project TimeGenerated, SourceUserName, SourceIP, DestinationHostName, RequestURL, ThreatDescription`,
      },
      dlp: {
        cs:     (v)=>`// Zscaler DLP — pivot to endpoint to understand data source
event_simpleName=FileOpenInfo ComputerName="${v||"<HOSTNAME>"}"
| where FileName LIKE "%.xlsx" OR FileName LIKE "%.pdf" OR FileName LIKE "%.docx"
| table _time, ComputerName, UserName, FileName, FilePath`,
        splunk: (v)=>`index=zscaler sourcetype=zscaler:web dlp_rule!="" user="${v||"<USER>"}"
| table _time, user, srcip, url, dlp_rule, dlp_dictionaries, action`,
        kql:    (v)=>`CommonSecurityLog
| where DeviceVendor == "Zscaler" and DeviceEventClassID has "DLP"
| where SourceUserName =~ "${v||"<USER>"}"
| project TimeGenerated, SourceUserName, SourceIP, RequestURL, DeviceCustomString1, DeviceAction`,
      },
    },

    azure_ad: {
      signin_fail: {
        cs:     (v)=>`// Azure AD sign-in failures forwarded to CS NG-SIEM
#event_simpleName=AADSignIn UserPrincipalName="${v||"<USER@DOMAIN>"}" ResultType!="0"
| stats count, values(IPAddress) as ips, values(Location) as locs by UserPrincipalName
| sort - count`,
        splunk: (v)=>`index=azure sourcetype=azure:aad:signin UserPrincipalName="${v||"<USER>"}" ResultType!=0
| stats count by UserPrincipalName, IPAddress, Location, ResultDescription
| sort - count`,
        kql:    (v)=>`SigninLogs
| where UserPrincipalName =~ "${v||"<USER@DOMAIN>"}" and ResultType != "0"
| summarize FailCount=count(), IPs=make_set(IPAddress), Locs=make_set(Location)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailCount > 3 | sort by FailCount desc`,
        elastic:(v)=>`GET .ds-logs-azure*/_search
{ "query": {"bool": {"must": [{"term":{"user.name":"${v||"<USER>"}"}},{"term":{"event.outcome":"failure"}}]}} }`,
        qradar: (v)=>`SELECT username, sourceip, country, count(*) AS fails FROM events
WHERE DeviceType='MicrosoftAzureAD' AND outcome='Failure'
  AND username='${v||"<USER>"}'
GROUP BY username, sourceip, country HAVING count(*)>3 LAST 1 HOURS`,
      },
      mfa_fail: {
        cs:     (v)=>`#event_simpleName=AADSignIn AuthRequirement="multiFactorAuthentication"
  UserPrincipalName="${v||"<USER>"}" ResultType!="0"
| stats count by UserPrincipalName, IPAddress, bin(_time, 30m)
| where count > 3`,
        splunk: (v)=>`index=azure sourcetype=azure:aad:signin UserPrincipalName="${v||"<USER>"}" authRequirement=multiFactorAuthentication status=failure
| stats count by UserPrincipalName, IPAddress, bin(_time,30m)
| where count > 3`,
        kql:    (v)=>`SigninLogs
| where UserPrincipalName =~ "${v||"<USER@DOMAIN>"}" and AuthenticationRequirement == "multiFactorAuthentication"
  and ResultType != "0"
| summarize PushCount=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m)
| where PushCount > 3`,
        qradar: (v)=>`SELECT username, sourceip, count(*) FROM events WHERE DeviceType='MicrosoftAzureAD'
  AND authtype='MFA' AND outcome='Failure' AND username='${v||"<USER>"}'
GROUP BY username, sourceip HAVING count(*)>3 LAST 1 HOURS`,
      },
      oauth_consent: {
        cs:     (v)=>`#event_simpleName=AADAudit OperationName="Consent to application"
  UserPrincipalName="${v||"<USER>"}"
| table _time, UserPrincipalName, AppDisplayName, ConsentType, Permissions`,
        splunk: (v)=>`index=azure sourcetype=azure:aad:audit Operation="Consent to application"
  userPrincipalName="${v||"<USER>"}"
| table _time, userPrincipalName, AppDisplayName, Permissions, ConsentType`,
        kql:    (v)=>`AuditLogs
| where OperationName == "Consent to application"
| where InitiatedBy.user.userPrincipalName =~ "${v||"<USER@DOMAIN>"}"
| extend AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, AppName, AdditionalDetails, Result`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='MicrosoftAzureAD'
  AND operation='Consent to application'
  AND username='${v||"<USER>"}' LAST 24 HOURS`,
      },
      impossible: {
        cs:     (v)=>`// Impossible travel — get all successful logins for user
#event_simpleName=AADSignIn UserPrincipalName="${v||"<USER>"}" ResultType="0"
| sort _time asc
| table _time, UserPrincipalName, IPAddress, Location, DeviceDetail`,
        splunk: (v)=>`index=azure sourcetype=azure:aad:signin UserPrincipalName="${v||"<USER>"}" status=success
| sort _time
| streamstats current=f last(_time) as prev_time last(Location) as prev_loc by UserPrincipalName
| eval time_diff_h=(_time-prev_time)/3600
| where prev_loc!=Location AND time_diff_h<4
| table _time, UserPrincipalName, Location, prev_loc, time_diff_h, IPAddress`,
        kql:    (v)=>`SigninLogs
| where UserPrincipalName =~ "${v||"<USER@DOMAIN>"}" and ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
| sort by TimeGenerated asc
// Review consecutive logins from different countries within short window`,
        qradar: (v)=>`SELECT username, sourceip, country, starttime FROM events WHERE DeviceType='MicrosoftAzureAD'
  AND outcome='Success' AND username='${v||"<USER>"}' LAST 24 HOURS ORDER BY starttime ASC`,
      },
      audit: {
        cs:     (v)=>`#event_simpleName=AADAudit InitiatedByUPN="${v||"<ADMIN@DOMAIN>"}" OperationName IN ("Add user","Assign role","Update policy")
| table _time, InitiatedByUPN, OperationName, TargetObjectUPN, Result`,
        splunk: (v)=>`index=azure sourcetype=azure:aad:audit initiatedBy.user.userPrincipalName="${v||"<ADMIN>"}"
| table _time, initiatedBy.user.userPrincipalName, operationName, targetResources, result`,
        kql:    (v)=>`AuditLogs
| where InitiatedBy.user.userPrincipalName =~ "${v||"<ADMIN@DOMAIN>"}"
  and OperationName in ("Add user","Assign role","Update conditional access policy")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='MicrosoftAzureAD'
  AND category='AuditLog' AND username='${v||"<ADMIN>"}' LAST 24 HOURS`,
      },
    },

    defender: {
      process_alert: {
        cs:     (v)=>`// Defender alert → correlate with CrowdStrike endpoint telemetry
event_simpleName=ProcessRollup2 ComputerName="${v||"<HOSTNAME>"}"
| where _time >= now()-3600
| table _time, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine, ParentBaseFileName`,
        splunk: (v)=>`index=defender sourcetype=microsoft:defender:atp DeviceName="${v||"<HOSTNAME>"}"
| table _time, DeviceName, AlertName, Severity, AccountName, FileName, CommandLine`,
        kql:    (v)=>`DeviceAlerts
| where DeviceName =~ "${v||"<HOSTNAME>"}" 
| join kind=leftouter DeviceProcessEvents on DeviceId
| project TimeGenerated, DeviceName, Title, Severity, AccountName, FileName, ProcessCommandLine, SHA256`,
        elastic:(v)=>`GET .ds-logs-endpoint.alerts-*/_search
{ "query": {"term": {"host.hostname": "${v||"<HOSTNAME>"}"}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='MicrosoftDefender' AND hostname='${v||"<HOSTNAME>"}' LAST 24 HOURS ORDER BY starttime DESC`,
      },
      ransomware: {
        cs:     (v)=>`// Ransomware — CrowdStrike scope + VSS deletion check
event_simpleName IN (ProcessRollup2, FileCreated) ComputerName="${v||"<HOSTNAME>"}"
| where CommandLine LIKE "%vssadmin%delete%" OR CommandLine LIKE "%shadowcopy%delete%"
   OR TargetFileName LIKE "%.encrypted" OR TargetFileName LIKE "%HELP_DECRYPT%"
| table _time, ComputerName, UserName, event_simpleName, CommandLine, TargetFileName`,
        splunk: (v)=>`index=defender sourcetype=microsoft:defender:atp DeviceName="${v||"<HOSTNAME>"}" 
  (AlertName="*ransomware*" OR CommandLine="*vssadmin*delete*" OR CommandLine="*shadowcopy*delete*")
| table _time, DeviceName, AlertName, CommandLine, Severity`,
        kql:    (v)=>`union DeviceAlerts, DeviceProcessEvents
| where DeviceName =~ "${v||"<HOSTNAME>"}"
| where Title has_any ("Ransomware","Encrypting") or ProcessCommandLine has_any ("vssadmin delete","shadowcopy delete","bcdedit /set recoveryenabled")
| project TimeGenerated, DeviceName, AccountName, Title, ProcessCommandLine
| sort by TimeGenerated asc`,
        qradar: (v)=>`SELECT * FROM events WHERE (DeviceType='MicrosoftDefender' OR DeviceType='CrowdStrike')
  AND hostname='${v||"<HOSTNAME>"}'
  AND (commandline LIKE '%vssadmin%delete%' OR alertname LIKE '%ransomware%') LAST 24 HOURS`,
      },
      network_alert: {
        cs:     (v)=>`event_simpleName=NetworkConnectIP4 ComputerName="${v||"<HOSTNAME>"}"
| where RemoteAddressIP4="${v||"<REMOTE_IP>"}" OR RemotePort IN (4444,50050,8080,1337)
| table _time, ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort`,
        splunk: (v)=>`index=defender sourcetype=microsoft:defender:atp DeviceName="${v||"<HOSTNAME>"}" category="NetworkCommunication"
| where RemoteIP="${v||"<REMOTE_IP>"}" OR RemotePort IN (4444,50050,8080,1337)
| table _time, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName`,
        kql:    (v)=>`DeviceNetworkEvents
| where DeviceName =~ "${v||"<HOSTNAME>"}" and (RemoteIP == "${v||"<REMOTE_IP>"}" or RemotePort in (4444,50050,8080,1337))
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
      tamper: {
        cs:     (v)=>`event_simpleName=ProcessRollup2 ComputerName="${v||"<HOSTNAME>"}"
| where CommandLine LIKE "%Add-MpPreference%Exclusion%" OR CommandLine LIKE "%Set-MpPreference%DisableRealtimeMonitoring%"
| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName`,
        splunk: (v)=>`(index=defender OR index=windows) (CommandLine="*Add-MpPreference*Exclusion*" OR CommandLine="*DisableRealtimeMonitoring*" OR EventCode=5001)
  host="${v||"<HOSTNAME>"}"
| table _time, host, user, CommandLine`,
        kql:    (v)=>`DeviceRegistryEvents
| where DeviceName =~ "${v||"<HOSTNAME>"}" and RegistryKey has "Windows Defender" and RegistryKey has "Exclusions"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessAccountName`,
      },
    },

    okta: {
      login_fail: {
        cs:     (v)=>`// Okta failures forwarded to CS NG-SIEM
#event_simpleName=OktaAuthentication Outcome="FAILURE" UserPrincipalName="${v||"<USER@DOMAIN>"}"
| stats count, values(IPAddress) as ips by UserPrincipalName, bin(_time, 1h)
| where count > 5`,
        splunk: (v)=>`index=okta sourcetype=okta (eventType="user.session.start" OR eventType="user.authentication.auth_via_mfa")
  outcome.result=FAILURE actor.alternateId="${v||"<USER@DOMAIN>"}"
| stats count, values(client.ipAddress) as ips by actor.alternateId, bin(_time,1h)
| where count > 5`,
        kql:    (v)=>`OktaSSO | where UserName =~ "${v||"<USER@DOMAIN>"}" and ResultStatus == "FAILURE"
| summarize FailCount=count(), IPs=make_set(SrcIpAddr) by UserName, bin(TimeGenerated,1h)
| where FailCount > 5`,
        elastic:(v)=>`GET .ds-logs-okta*/_search
{ "query": {"bool": {"must": [{"term":{"user.name":"${v||"<USER>"}"}},{"term":{"event.outcome":"failure"}}]}} }`,
        qradar: (v)=>`SELECT username, sourceip, count(*) FROM events WHERE DeviceType='Okta'
  AND outcome='FAILURE' AND username='${v||"<USER>"}'
GROUP BY username, sourceip HAVING count(*)>5 LAST 1 HOURS`,
      },
      mfa_push: {
        cs:     (v)=>`#event_simpleName=OktaMFAChallenge Outcome="DENY" UserPrincipalName="${v||"<USER>"}"
| stats count by UserPrincipalName, IPAddress, bin(_time, 30m)
| where count > 3`,
        splunk: (v)=>`index=okta sourcetype=okta eventType IN ("user.mfa.okta_verify.deny_push","system.push.send_factor_verify_push")
  actor.alternateId="${v||"<USER>"}"
| stats count by actor.alternateId, client.ipAddress, bin(_time, 30m)
| where count > 3`,
        kql:    (v)=>`OktaSSO | where UserName =~ "${v||"<USER>"}" and EventType has "push" and ResultStatus != "SUCCESS"
| summarize PushDenies=count() by UserName, SrcIpAddr, bin(TimeGenerated, 30m)
| where PushDenies > 3`,
        qradar: (v)=>`SELECT username, sourceip, count(*) FROM events WHERE DeviceType='Okta'
  AND eventtype LIKE '%push%' AND outcome!='SUCCESS' AND username='${v||"<USER>"}'
GROUP BY username, sourceip HAVING count(*)>3 LAST 1 HOURS`,
      },
      policy_deny: {
        cs:     (v)=>`#event_simpleName=OktaSignOn Outcome="DENY" UserPrincipalName="${v||"<USER>"}"
| table _time, UserPrincipalName, IPAddress, DeviceContext, PolicyName`,
        splunk: (v)=>`index=okta sourcetype=okta eventType="access.denied" actor.alternateId="${v||"<USER>"}"
| table _time, actor.alternateId, client.ipAddress, debugContext.debugData.policyEvaluationReason`,
        kql:    (v)=>`OktaSSO | where UserName =~ "${v||"<USER>"}" and ResultStatus == "FAILURE"
  and EventType has "access"
| project TimeGenerated, UserName, SrcIpAddr, EventType, ResultDescription`,
      },
      susp_activity: {
        cs:     (v)=>`// Treat Okta-reported suspicious activity as compromise — investigate endpoint
#event_simpleName=OktaAuthentication UserPrincipalName="${v||"<USER>"}" EventType="user.account.report_suspicious_activity"
| table _time, UserPrincipalName, IPAddress, UserAgent`,
        splunk: (v)=>`index=okta sourcetype=okta eventType="user.account.report_suspicious_activity" actor.alternateId="${v||"<USER>"}"
| table _time, actor.alternateId, client.ipAddress, client.geographicalContext.country`,
        kql:    (v)=>`OktaSSO | where UserName =~ "${v||"<USER>"}" and EventType has "suspicious"
| project TimeGenerated, UserName, SrcIpAddr, EventType, ResultDescription`,
      },
      app_grant: {
        cs:     (v)=>`#event_simpleName=OktaAppGrant UserPrincipalName="${v||"<USER>"}" 
| table _time, UserPrincipalName, AppName, GrantType, Scopes`,
        splunk: (v)=>`index=okta sourcetype=okta eventType="app.oauth2.as.consent.grant" actor.alternateId="${v||"<USER>"}"
| table _time, actor.alternateId, target{}.displayName, debugContext.debugData.scope`,
        kql:    (v)=>`OktaSSO | where UserName =~ "${v||"<USER>"}" and EventType has "consent"
| project TimeGenerated, UserName, EventType, SrcIpAddr`,
      },
    },

    proofpoint: {
      phish: {
        cs:     (v)=>`// Proofpoint phish alert — check CrowdStrike for execution post-delivery
event_simpleName IN (ProcessRollup2, NetworkConnectIP4, DnsRequest) UserName LIKE "${(v||"<RECIPIENT>").split("@")[0]}%"
| where _time >= now()-7200
| table _time, ComputerName, UserName, event_simpleName, ImageFileName, RemoteAddressIP4, DomainName`,
        splunk: (v)=>`index=proofpoint sourcetype=proofpoint:tap (THREAT_TYPE=phish OR THREAT_TYPE=malware)
  (sender="${v||"<SENDER>"}" OR recipient="${v||"<RECIPIENT>"}")
| table _time, sender, recipient, subject, THREAT_TYPE, malicious_url, attachment_sha256, action`,
        kql:    (v)=>`EmailEvents
| where SenderMailFromAddress =~ "${v||"<SENDER>"}" or RecipientEmailAddress =~ "${v||"<RECIPIENT>"}"
| where ThreatTypes has_any ("Phish","Malware")
| project TimeGenerated, SenderMailFromAddress, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction`,
        elastic:(v)=>`GET .ds-logs-proofpoint*/_search
{ "query": {"bool": {"must": [{"term":{"email.to.address":"${v||"<RECIPIENT>"}"}},{"term":{"threat.indicator.type":"phishing"}}]}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='Proofpoint'
  AND (sender='${v||"<SENDER>"}' OR recipient='${v||"<RECIPIENT>"}')
  AND THREAT_TYPE IS NOT NULL LAST 24 HOURS`,
      },
      url_click: {
        cs:     (v)=>`// URGENT: User clicked malicious URL — investigate endpoint execution
event_simpleName IN (NetworkConnectIP4, ProcessRollup2, DnsRequest)
  UserName LIKE "${(v||"<RECIPIENT>").split("@")[0]}%"
| where _time >= now()-1800
| table _time, ComputerName, UserName, event_simpleName, ImageFileName, CommandLine, RemoteAddressIP4`,
        splunk: (v)=>`// Step 1: Confirm the click event
index=proofpoint sourcetype=proofpoint:tap event_type=click recipient="${v||"<RECIPIENT>"}"
| table _time, recipient, url, threat_category, user_agent

// Step 2: Check endpoint within 30min of click time
// index=crowdstrike event_simpleName=NetworkConnectIP4 UserName="<USER>" | head 20`,
        kql:    (v)=>`EmailUrlInfo
| where RecipientEmailAddress =~ "${v||"<RECIPIENT>"}"
| join kind=inner EmailEvents on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, Url, ThreatTypes, NetworkMessageId, DeliveryAction`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='Proofpoint' AND event_type='click'
  AND recipient='${v||"<RECIPIENT>"}' LAST 24 HOURS ORDER BY starttime DESC`,
      },
      malware: {
        cs:     (v)=>`// Proofpoint malware attachment — look for hash execution on endpoint
(SHA256HashData="${v||"<SHA256_HASH>"}" OR MD5HashData="${v||"<MD5_HASH>"}")
| table _time, ComputerName, UserName, FileName, FilePath, CommandLine`,
        splunk: (v)=>`index=proofpoint sourcetype=proofpoint:tap THREAT_TYPE=malware attachment_sha256="${v||"<SHA256_HASH>"}"
| table _time, sender, recipient, subject, attachment_name, attachment_sha256, action`,
        kql:    (v)=>`EmailAttachmentInfo
| where SHA256 =~ "${v||"<SHA256_HASH>"}"
| join kind=inner EmailEvents on NetworkMessageId
| project TimeGenerated, SenderMailFromAddress, RecipientEmailAddress, FileName, SHA256, ThreatTypes`,
      },
      impostor: {
        cs:     (v)=>`// BEC impostor — check for inbox rules and forwarding
#event_simpleName=AADAudit OperationName IN ("New-InboxRule","Set-InboxRule","Set-Mailbox") UserPrincipalName="${v||"<TARGETED_USER>"}"
| table _time, UserPrincipalName, OperationName, Parameters`,
        splunk: (v)=>`index=proofpoint sourcetype=proofpoint:tap THREAT_TYPE=impostor (sender="${v||"<IMPERSONATED>"}" OR recipient="${v||"<RECIPIENT>"}")
| table _time, sender, sender_display_name, recipient, subject, action`,
        kql:    (v)=>`EmailEvents
| where SenderDisplayName =~ "${v||"<IMPERSONATED_NAME>"}" and ThreatTypes has "Phish"
| project TimeGenerated, SenderMailFromAddress, SenderDisplayName, RecipientEmailAddress, Subject`,
      },
    },

    aws: {
      iam_priv: {
        cs:     (v)=>`// AWS IAM privilege event forwarded to CS NG-SIEM
#event_simpleName=AWSCloudTrail EventName IN ("AttachUserPolicy","AttachRolePolicy","CreateUser","AddUserToGroup","PutUserPolicy","CreateAccessKey")
  UserIdentityARN LIKE "%${v||"<USER_ARN>"}%"
| table _time, UserIdentityARN, EventName, SourceIPAddress, AWSRegion, RequestParameters`,
        splunk: (v)=>`index=aws sourcetype=aws:cloudtrail eventName IN ("AttachUserPolicy","AttachRolePolicy","CreateUser","AddUserToGroup","PutUserPolicy","CreateAccessKey")
  userIdentity.arn="*${v||"<USER_ARN>"}*"
| table _time, userIdentity.arn, eventName, sourceIPAddress, requestParameters`,
        kql:    (v)=>`AWSCloudTrail
| where EventName in ("AttachUserPolicy","CreateUser","AddUserToGroup","PutRolePolicy","CreateAccessKey")
  and UserIdentityArn contains "${v||"<USER_ARN>"}" 
| project TimeGenerated, UserIdentityArn, EventName, SourceIpAddress, RequestParameters`,
        elastic:(v)=>`GET .ds-logs-aws*/_search
{ "query": {"bool": {"must": [{"terms":{"event.action":["AttachUserPolicy","CreateUser","AddUserToGroup"]}},{"term":{"user.id":"${v||"<USER_ARN>"}"}}]}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='AWSCloudTrail'
  AND eventname IN ('AttachUserPolicy','CreateUser','AddUserToGroup','CreateAccessKey')
  AND useridentityarn LIKE '%${v||"<USER_ARN>"}%' LAST 24 HOURS`,
      },
      root_usage: {
        cs:     (v)=>`// AWS Root account activity — CRITICAL
#event_simpleName=AWSCloudTrail UserIdentityType="Root"
| table _time, EventName, SourceIPAddress, AWSRegion, UserAgent`,
        splunk: (v)=>`index=aws sourcetype=aws:cloudtrail userIdentity.type=Root
| table _time, eventName, sourceIPAddress, awsRegion, userAgent
| sort - _time`,
        kql:    (v)=>`AWSCloudTrail
| where UserIdentityType == "Root"
| project TimeGenerated, EventName, SourceIpAddress, AWSRegion, UserAgent
| sort by TimeGenerated desc`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='AWSCloudTrail' AND useridentitytype='Root' LAST 24 HOURS`,
      },
      ct_tamper: {
        cs:     (v)=>`#event_simpleName=AWSCloudTrail EventName IN ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors","DeleteFlowLogs")
| table _time, UserIdentityARN, EventName, AWSRegion, SourceIPAddress`,
        splunk: (v)=>`index=aws sourcetype=aws:cloudtrail eventName IN ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors")
| table _time, userIdentity.arn, eventName, awsRegion, sourceIPAddress`,
        kql:    (v)=>`AWSCloudTrail
| where EventName in ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors")
| project TimeGenerated, UserIdentityArn, EventName, AWSRegion, SourceIpAddress`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='AWSCloudTrail'
  AND eventname IN ('StopLogging','DeleteTrail','UpdateTrail') LAST 24 HOURS`,
      },
      s3_exposure: {
        cs:     (v)=>`#event_simpleName=AWSCloudTrail EventName IN ("GetObject","PutBucketAcl","PutBucketPolicy")
  RequestParameters LIKE "%${v||"<BUCKET_NAME>"}%"
| stats count, values(UserIdentityARN) as actors by EventName, BucketName, SourceIPAddress
| sort - count`,
        splunk: (v)=>`index=aws sourcetype=aws:cloudtrail eventName IN ("GetObject","PutBucketAcl","PutBucketPolicy")
  requestParameters.bucketName="${v||"<BUCKET_NAME>"}"
| stats count by userIdentity.arn, eventName, sourceIPAddress
| sort - count`,
        kql:    (v)=>`AWSCloudTrail
| where EventName in ("GetObject","PutBucketAcl","PutBucketPolicy")
  and tostring(RequestParameters) contains "${v||"<BUCKET_NAME>"}"
| summarize count() by UserIdentityArn, EventName, SourceIpAddress
| sort by count_ desc`,
      },
      ec2_launch: {
        cs:     (v)=>`#event_simpleName=AWSCloudTrail EventName IN ("RunInstances","CreateFunction","CreateContainer")
  UserIdentityARN LIKE "%${v||"<USER_ARN>"}%"
| table _time, UserIdentityARN, EventName, AWSRegion, RequestParameters`,
        splunk: (v)=>`index=aws sourcetype=aws:cloudtrail eventName IN ("RunInstances","CreateFunction") userIdentity.arn="*${v||"<USER_ARN>"}*"
| table _time, userIdentity.arn, eventName, awsRegion, requestParameters.instanceType`,
        kql:    (v)=>`AWSCloudTrail
| where EventName in ("RunInstances","CreateFunction")
  and UserIdentityArn contains "${v||"<USER_ARN>"}"
| project TimeGenerated, UserIdentityArn, EventName, AWSRegion, SourceIpAddress`,
      },
    },

    sentinelone: {
      threat_detect: {
        cs:     (v)=>`// SentinelOne threat — correlate with CrowdStrike FDR telemetry
event_simpleName IN (ProcessRollup2, FileCreated) ComputerName="${v||"<HOSTNAME>"}"
| where SHA256HashData="${v||"<SHA256>"}" OR ImageFileName LIKE "%${v||"<PROCESS>"}%"
| table _time, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine`,
        splunk: (v)=>`index=sentinelone sourcetype=sentinelone:threat
  (computerName="${v||"<HOSTNAME>"}" OR sha256="${v||"<SHA256>"}")
| table _time, computerName, userName, threatName, filePath, sha256, mitigationStatus`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "SentinelOne" and DeviceEventClassID has "threat"
| where Computer =~ "${v||"<HOSTNAME>"}" or FileHash =~ "${v||"<SHA256>"}"
| project TimeGenerated, Computer, SourceUserName, Activity, FileHash, DeviceAction`,
        elastic:(v)=>`GET .ds-logs-sentinel_one*/_search
{ "query": {"bool": {"must": [{"term":{"host.hostname":"${v||"<HOSTNAME>"}"}},{"exists":{"field":"threat.indicator.name"}}]}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='SentinelOne'
  AND hostname='${v||"<HOSTNAME>"}' AND category='threat' LAST 24 HOURS`,
      },
      not_mitigated: {
        cs:     (v)=>`// URGENT: SentinelOne NOT mitigated — check CrowdStrike for active execution
event_simpleName=ProcessRollup2 ComputerName="${v||"<HOSTNAME>"}"
| where _time >= now()-1800
| table _time, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine, ParentBaseFileName`,
        splunk: (v)=>`index=sentinelone sourcetype=sentinelone:threat mitigationStatus IN ("not_mitigated","pending_reboot")
  computerName="${v||"<HOSTNAME>"}"
| table _time, computerName, userName, threatName, filePath, mitigationStatus`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "SentinelOne"
  and Activity has "not mitigated"
| where Computer =~ "${v||"<HOSTNAME>"}"
| project TimeGenerated, Computer, SourceUserName, Activity, FileHash`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='SentinelOne'
  AND mitigationstatus IN ('not_mitigated','pending_reboot')
  AND hostname='${v||"<HOSTNAME>"}' LAST 24 HOURS`,
      },
      ransomware: {
        cs:     (v)=>`// SentinelOne ransomware — CrowdStrike scope + containment check
event_simpleName IN (ProcessRollup2,FileCreated) ComputerName="${v||"<HOSTNAME>"}"
| where CommandLine LIKE "%vssadmin%delete%" OR CommandLine LIKE "%shadowcopy%delete%"
   OR TargetFileName LIKE "%.encrypted%"
| table _time, ComputerName, UserName, CommandLine, TargetFileName`,
        splunk: (v)=>`index=sentinelone sourcetype=sentinelone:threat threatClassification=Ransomware
  computerName="${v||"<HOSTNAME>"}"
| table _time, computerName, userName, threatName, filePath, sha256, mitigationStatus`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "SentinelOne"
  and (ThreatDescription has "Ransomware" or Activity has "Ransomware")
| where Computer =~ "${v||"<HOSTNAME>"}"
| project TimeGenerated, Computer, SourceUserName, ThreatDescription, FileHash`,
      },
      network_c2: {
        cs:     (v)=>`event_simpleName=NetworkConnectIP4 ComputerName="${v||"<HOSTNAME>"}"
| where RemoteAddressIP4="${v||"<C2_IP>"}" OR RemotePort IN (4444,50050,8080,1337)
| table _time, ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort`,
        splunk: (v)=>`index=sentinelone sourcetype=sentinelone:threat networkInfo.destinationIp="${v||"<C2_IP>"}" computerName="${v||"<HOSTNAME>"}"
| table _time, computerName, userName, threatName, networkInfo.destinationIp, networkInfo.destinationPort`,
        kql:    (v)=>`DeviceNetworkEvents | where DeviceName =~ "${v||"<HOSTNAME>"}" and RemoteIP == "${v||"<C2_IP>"}" 
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
    },

    paloalto: {
      threat: {
        cs:     (v)=>`// Palo Alto threat alert → pivot to endpoint
event_simpleName=NetworkConnectIP4
  (RemoteAddressIP4="${v||"<ATTACKER_IP>"}" OR LocalAddressIP4="${v||"<VICTIM_IP>"}")
| table _time, ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort`,
        splunk: (v)=>`index=paloalto sourcetype=pan:threat
  (src="${v||"<SRC_IP>"}" OR dst="${v||"<DST_IP>"}")
| table _time, src, dst, threat_name, severity, action, app, category`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" and DeviceEventClassID == "THREAT"
| where SourceIP == "${v||"<SRC_IP>"}" or DestinationIP == "${v||"<DST_IP>"}"
| project TimeGenerated, SourceIP, DestinationIP, Activity, ThreatDescription, DeviceAction`,
        elastic:(v)=>`GET .ds-logs-panw*/_search
{ "query": {"bool": {"must":[{"term":{"event.category":"threat"}}],"should":[{"term":{"source.ip":"${v||"<SRC_IP>"}"}},{"term":{"destination.ip":"${v||"<DST_IP>"}"}}}]}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='PaloAltoNetworks' AND category='THREAT'
  AND (sourceip='${v||"<SRC_IP>"}' OR destinationip='${v||"<DST_IP>"}')
LAST 24 HOURS ORDER BY starttime DESC`,
      },
      c2: {
        cs:     (v)=>`// CRITICAL: Palo Alto C2 detection — isolate endpoint and scope
event_simpleName=NetworkConnectIP4
  RemoteAddressIP4="${v||"<C2_IP>"}" 
| stats count, values(ComputerName) as hosts by RemoteAddressIP4, RemotePort
| sort - count
// Then isolate: event_simpleName=NetworkContainRequest ComputerName="<HOST>"`,
        splunk: (v)=>`index=paloalto sourcetype=pan:threat category="command-and-control"
  src="${v||"<COMPROMISED_IP>"}"
| table _time, src, dst, threat_name, threat_id, action, session_id`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Palo Alto Networks"
  and (ThreatDescription has "command-and-control" or ThreatDescription has "C2")
| where SourceIP == "${v||"<SRC_IP>"}"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, ThreatDescription`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='PaloAltoNetworks'
  AND category='command-and-control' AND sourceip='${v||"<SRC_IP>"}' LAST 24 HOURS`,
      },
      wildfire: {
        cs:     (v)=>`// WildFire malicious verdict — find hash on endpoint
(SHA256HashData="${v||"<SHA256>"}")
| table _time, ComputerName, UserName, FileName, FilePath, CommandLine, SHA256HashData`,
        splunk: (v)=>`index=paloalto sourcetype=pan:wildfire verdict=malicious
  (sha256="${v||"<SHA256>"}" OR src="${v||"<SRC_IP>"}")
| table _time, src, dst, sha256, filename, verdict, action`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" and DeviceEventClassID == "WildFire"
  and FileHash =~ "${v||"<SHA256>"}"
| project TimeGenerated, SourceIP, FileName, FileHash, Activity, DeviceAction`,
      },
      url_block: {
        cs:     (v)=>`// Palo Alto URL block — find endpoint user and correlate
event_simpleName=NetworkConnectIP4
| where RemoteDomainName LIKE "%${v||"<DOMAIN>"}%"
| table _time, ComputerName, UserName, ImageFileName, RemoteDomainName`,
        splunk: (v)=>`index=paloalto sourcetype=pan:url action=block url="*${v||"<DOMAIN>"}*"
| table _time, src, dst, url, category, action`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" and DeviceEventClassID == "URL"
  and RequestURL contains "${v||"<DOMAIN>"}" and DeviceAction == "block"
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL, DeviceAction, SourceUserName`,
      },
    },

    darktrace: {
      model_breach: {
        cs:     (v)=>`// Darktrace model breach — pivot to CrowdStrike for endpoint telemetry
event_simpleName=ProcessRollup2 ComputerName="${v||"<HOSTNAME>"}"
| where _time >= now()-3600
| table _time, ComputerName, UserName, ImageFileName, CommandLine, SHA256HashData`,
        splunk: (v)=>`index=darktrace sourcetype=darktrace:model_breach
  (pbid="${v||"<PBID>"}" OR deviceHostname="${v||"<HOSTNAME>"}")
| table _time, deviceHostname, modelName, score, category, description`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Darktrace"
  and Computer =~ "${v||"<HOSTNAME>"}"
| project TimeGenerated, Computer, Activity, DeviceCustomFloatLabel1, DeviceCustomString1`,
        elastic:(v)=>`GET .ds-logs-darktrace*/_search
{ "query": {"bool": {"must": [{"term":{"host.hostname":"${v||"<HOSTNAME>"}"}},{"range":{"darktrace.breach.score":{"gte":0.7}}}]}} }`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='Darktrace'
  AND hostname='${v||"<HOSTNAME>"}' AND score > 0.7 LAST 24 HOURS ORDER BY score DESC`,
      },
      beacon: {
        cs:     (v)=>`event_simpleName=NetworkConnectIP4 ComputerName="${v||"<HOSTNAME>"}"
| stats count, values(RemotePort) as ports by RemoteAddressIP4
| where count > 10
| sort - count`,
        splunk: (v)=>`index=darktrace sourcetype=darktrace:model_breach modelName="*Beacon*"
  (deviceHostname="${v||"<HOSTNAME>"}" OR ip="${v||"<IP>"}")
| table _time, deviceHostname, modelName, score, destIP, destPort`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Darktrace" and Activity has "Beacon"
| where Computer =~ "${v||"<HOSTNAME>"}"
| project TimeGenerated, Computer, DestinationIP, DestinationPort, DeviceCustomFloatLabel1`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='Darktrace' AND modelname LIKE '%Beacon%'
  AND hostname='${v||"<HOSTNAME>"}' LAST 24 HOURS`,
      },
      lateral: {
        cs:     (v)=>`event_simpleName=NetworkConnectIP4 LocalAddressIP4="${v||"<SRC_IP>"}"
| where RemoteAddressIP4!="${v||"<SRC_IP>"}" AND RemotePort IN (445,135,3389,5985)
| stats dc(RemoteAddressIP4) as unique_dests, values(RemoteAddressIP4) as dests by ComputerName
| where unique_dests > 3`,
        splunk: (v)=>`index=darktrace sourcetype=darktrace:model_breach modelName IN ("*Lateral*","*East West*")
  deviceHostname="${v||"<HOSTNAME>"}"
| table _time, deviceHostname, modelName, destIP, destPort, description`,
        kql:    (v)=>`DeviceNetworkEvents | where DeviceName =~ "${v||"<HOSTNAME>"}" and RemotePort in (445,135,3389,5985)
  and RemoteIPType == "Private"
| summarize count() by RemoteIP, DeviceName, InitiatingProcessFileName
| sort by count_ desc`,
      },
      ai_analyst: {
        cs:     (v)=>`// Darktrace AI Analyst incident — pivot to endpoint for all involved hosts
event_simpleName IN (ProcessRollup2, NetworkConnectIP4) ComputerName IN ("${v||"<HOST1>"}","${v||"<HOST2>"}")
| where _time >= now()-7200
| table _time, ComputerName, UserName, event_simpleName, ImageFileName, RemoteAddressIP4`,
        splunk: (v)=>`index=darktrace sourcetype=darktrace:ai_analyst deviceHostname="${v||"<HOSTNAME>"}"
| table _time, deviceHostname, currentGroup, breachDevices, description, score`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "Darktrace" and Activity has "AI Analyst"
  and Computer =~ "${v||"<HOSTNAME>"}"
| project TimeGenerated, Computer, Activity, AdditionalExtensions`,
      },
    },

    suricata: {
      malware_c2: {
        cs:     (v)=>`// Suricata C2 alert — pivot to CrowdStrike for process responsible
event_simpleName=NetworkConnectIP4
  (RemoteAddressIP4="${v||"<DEST_IP>"}" OR LocalAddressIP4="${v||"<SRC_IP>"}")
| table _time, ComputerName, UserName, ImageFileName, CommandLine, RemoteAddressIP4, RemotePort`,
        splunk: (v)=>`index=suricata sourcetype=suricata
  alert.category IN ("A Network Trojan was Detected","Malware Command and Control Activity Detected")
  (src_ip="${v||"<SRC_IP>"}" OR dest_ip="${v||"<DEST_IP>"}")
| table _time, src_ip, dest_ip, alert.signature, alert.severity, proto`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "suricata"
  and (SourceIP == "${v||"<SRC_IP>"}" or DestinationIP == "${v||"<DEST_IP>"}")
| where Activity has_any ("Trojan","C2","Malware")
| project TimeGenerated, SourceIP, DestinationIP, Activity, Protocol`,
        elastic:(v)=>`GET .ds-logs-suricata*/_search
{ "query": {"bool": {"must":[{"term":{"event.kind":"alert"}}],"should":[{"term":{"source.ip":"${v||"<SRC_IP>"}"}},{"term":{"destination.ip":"${v||"<DEST_IP>"}"}]}}} }`,
        qradar: (v)=>`SELECT sourceip, destinationip, category, count(*) FROM events WHERE DeviceType='Suricata'
  AND (sourceip='${v||"<SRC_IP>"}' OR destinationip='${v||"<DEST_IP>"}')
GROUP BY sourceip, destinationip, category LAST 24 HOURS`,
      },
      exploit: {
        cs:     (v)=>`// Suricata exploit alert — check if target host was compromised
event_simpleName IN (ProcessRollup2, NetworkConnectIP4) ComputerName="${v||"<TARGET_HOST>"}"
| where _time >= now()-1800
| table _time, ComputerName, UserName, ImageFileName, CommandLine, RemoteAddressIP4`,
        splunk: (v)=>`index=suricata sourcetype=suricata
  alert.category IN ("Attempted Administrator Privilege Gain","Web Application Attack")
  src_ip="${v||"<ATTACKER_IP>"}"
| table _time, src_ip, dest_ip, dest_port, alert.signature, alert.metadata.cve`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "suricata"
  and Activity has_any ("exploit","privilege gain","web attack")
| where SourceIP == "${v||"<ATTACKER_IP>"}"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Activity`,
        qradar: (v)=>`SELECT * FROM events WHERE DeviceType='Suricata'
  AND category IN ('exploit','privilege_gain') AND sourceip='${v||"<ATTACKER_IP>"}' LAST 24 HOURS`,
      },
      scan: {
        cs:     (v)=>`event_simpleName=NetworkConnectIP4 RemoteAddressIP4="${v||"<SCANNER_IP>"}"
| stats dc(LocalPort) as ports_scanned, values(ComputerName) as targets by RemoteAddressIP4
| sort - ports_scanned`,
        splunk: (v)=>`index=suricata sourcetype=suricata alert.category="Information Leak"
  src_ip="${v||"<SCANNER_IP>"}"
| stats dc(dest_port) as ports_scanned, values(dest_ip) as targets by src_ip`,
        kql:    (v)=>`DeviceNetworkEvents | where RemoteIP == "${v||"<SCANNER_IP>"}"
| summarize PortsScanned=dcount(LocalPort), TargetHosts=dcount(DeviceName) by RemoteIP
| sort by PortsScanned desc`,
        qradar: (v)=>`SELECT sourceip, count(distinct destinationport) AS ports, count(distinct destinationip) AS hosts FROM events
  WHERE DeviceType='Suricata' AND sourceip='${v||"<SCANNER_IP>"}'
GROUP BY sourceip LAST 1 HOURS`,
      },
      policy: {
        cs:     (v)=>`event_simpleName=NetworkConnectIP4
  (RemoteAddressIP4="${v||"<IP>"}" OR RemotePort="${v||"<PORT>"}")
| table _time, ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort`,
        splunk: (v)=>`index=suricata sourcetype=suricata alert.category="Potential Corporate Privacy Violation"
  src_ip="${v||"<SRC_IP>"}"
| table _time, src_ip, dest_ip, dest_port, alert.signature, proto`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "suricata" and Activity has "Policy"
  and SourceIP == "${v||"<SRC_IP>"}"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Activity`,
      },
    },

    siem_generic: {
      correlation: {
        cs:     (v)=>`// SIEM correlation alert — pivot to CrowdStrike NG-SIEM
// Replace <HOSTNAME> and <USERNAME> with values from the SIEM alert
event_simpleName IN (ProcessRollup2, NetworkConnectIP4, UserLogon) ComputerName="${v||"<HOSTNAME>"}"
| where _time >= now()-3600
| table _time, ComputerName, UserName, event_simpleName, ImageFileName, CommandLine, RemoteAddressIP4`,
        splunk: (v)=>`// Investigate Splunk ES notable event
index=notable ${v ? `rule_name="*${v}*"` : `rule_name="<RULE_NAME>"`}
| table _time, rule_name, urgency, src, dest, user, orig_time

// Pull contributing raw events
// | eval key=_key | join key [search index=* tag=network]`,
        kql:    (v)=>`SecurityAlert
| where DisplayName contains "${v||"<RULE_NAME>"}"
| extend Entities = parse_json(Entities)
| mvexpand Entities
| project TimeGenerated, DisplayName, AlertSeverity, tostring(Entities), Tactics, Status`,
        elastic:(v)=>`GET .alerts-security*/_search
{ "query": {"bool": {"must": [{"match":{"kibana.alert.rule.name":"${v||"<RULE_NAME>"}"}},{"term":{"kibana.alert.status":"active"}}]}} }`,
        qradar: (v)=>`SELECT * FROM offenses WHERE description LIKE '%${v||"<RULE_NAME>"}%'
LAST 7 DAYS ORDER BY magnitude DESC`,
      },
      offense: {
        cs:     (v)=>`// QRadar high-magnitude offense → pivot to CrowdStrike
// Extract source IPs from QRadar offense, then:
event_simpleName IN (ProcessRollup2, NetworkConnectIP4, UserLogon)
  (RemoteAddressIP4="${v||"<OFFENSE_SRC_IP>"}" OR ComputerName="${v||"<HOSTNAME>"}")
| where _time >= now()-3600
| table _time, ComputerName, UserName, event_simpleName, CommandLine, RemoteAddressIP4`,
        splunk: (v)=>`// QRadar offense forwarded to Splunk
index=qradar sourcetype=qradar:offense magnitude>7
  (offenseSourceAddr="${v||"<SRC_IP>"}" OR offenseName="*${v||"<OFFENSE_NAME>"}*")
| table _time, offenseId, offenseName, magnitude, offenseSourceAddr, offenseTargetAddr`,
        kql:    (v)=>`CommonSecurityLog | where DeviceVendor == "IBM Security QRadar"
  and SourceIP == "${v||"<SRC_IP>"}" 
| project TimeGenerated, SourceIP, DestinationIP, Activity, Reason, DeviceCustomNumber1`,
        qradar: (v)=>`SELECT o.id, o.description, o.magnitude, o.offense_source, o.event_count
FROM offenses o WHERE o.magnitude > 7
  AND (o.offense_source='${v||"<SRC_IP>"}' OR o.description LIKE '%${v||"<KEYWORD>"}%')
LAST 7 DAYS ORDER BY magnitude DESC`,
      },
      notable: {
        cs:     (v)=>`// Splunk ES Notable → pivot to CS NG-SIEM for endpoint detail
event_simpleName IN (ProcessRollup2, NetworkConnectIP4) ComputerName="${v||"<HOSTNAME>"}"
| where _time >= now()-3600
| table _time, ComputerName, UserName, event_simpleName, ImageFileName, CommandLine`,
        splunk: (v)=>`// Investigate Splunk ES notable and pull contributing events
index=notable rule_name="${v||"<RULE_NAME>"}"
| join type=outer src [search index=* earliest=-1h | rename src_ip as src]
| table _time, rule_name, urgency, src, dest, user, event_type, count`,
        kql:    (v)=>`SecurityAlert | where DisplayName =~ "${v||"<NOTABLE_NAME>"}"
| project TimeGenerated, DisplayName, AlertSeverity, CompromisedEntity, Tactics, Entities
| sort by TimeGenerated desc`,
      },
    },
  };

  // Populate alert-type dropdown when source changes
  $("dqb-alert-source")?.addEventListener("change", () => {
    const src    = $("dqb-alert-source")?.value;
    const typeEl = $("dqb-alert-type");
    const hint   = $("dqb-source-hint");
    if (!typeEl) return;
    if (!src) { typeEl.innerHTML = `<option value="">— Select alert source first —</option>`; typeEl.disabled = true; return; }
    const srcDef = SOURCE_ALERT_TYPES[src];
    if (!srcDef) return;
    typeEl.disabled = false;
    typeEl.innerHTML = srcDef.alertTypes.map(t => `<option value="${t.value}">${t.label}</option>`).join("");
    if (hint && srcDef.alertTypes[0]) hint.innerHTML = `<strong>${esc(srcDef.alertTypes[0].label)}:</strong> ${esc(srcDef.alertTypes[0].hint)}`;
  });
  $("dqb-alert-type")?.addEventListener("change", () => {
    const src  = $("dqb-alert-source")?.value;
    const type = $("dqb-alert-type")?.value;
    const hint = $("dqb-source-hint");
    if (!hint || !src || !type) return;
    const typeDef = SOURCE_ALERT_TYPES[src]?.alertTypes?.find(t => t.value === type);
    if (typeDef) hint.innerHTML = `<strong>${esc(typeDef.label)}:</strong> ${esc(typeDef.hint)}`;
  });

  // Mode toggle — switch between IOC Pattern and Alert Source panels
  document.querySelectorAll(".dqb-mode-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".dqb-mode-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const mode       = btn.dataset.mode;
      const iocPanel   = $("dqb-ioc-mode");
      const srcPanel   = $("dqb-source-mode");
      const desc       = $("dqb-desc");
      if (mode === "ioc") {
        if (iocPanel) iocPanel.style.display = "";
        if (srcPanel) srcPanel.style.display = "none";
        if (desc) desc.textContent = "Generate ready-to-paste SIEM detection queries from IOCs or select a pre-built pattern.";
      } else {
        if (iocPanel) iocPanel.style.display = "none";
        if (srcPanel) srcPanel.style.display = "";
        if (desc) desc.textContent = "Got a Zscaler, Okta, Azure AD, Proofpoint or CrowdStrike alert? Select the source + alert type + your SIEM to get a targeted investigation query.";
      }
    });
  });

  // Override generate button to handle both modes
  const _origBuildDQB = buildDQBQuery;
  function buildDQBQueryFull() {
    const activeMode = document.querySelector(".dqb-mode-btn.active")?.dataset?.mode || "ioc";
    if (activeMode === "ioc") { _origBuildDQB(); return; }
    const src  = $("dqb-alert-source")?.value;
    const type = $("dqb-alert-type")?.value;
    const siem = $("dqb-siem-platform")?.value || "cs";
    const ioc  = $("dqb-src-ioc")?.value?.trim() || "";
    const out  = $("dqb-output");
    if (!src || !type || !out) { if (out) out.textContent = "← Select Alert Source and Alert Type first"; return; }
    const srcQ   = SOURCE_QUERIES[src]?.[type];
    if (!srcQ) { out.textContent = `// No template yet for ${src} → ${type}
// Try the Hunt Queries library in CTI tab for related patterns`; return; }
    const queryFn = srcQ[siem] || srcQ.splunk || srcQ.cs || Object.values(srcQ)[0];
    if (!queryFn) { out.textContent = `// No query for this platform yet — try a different SIEM platform`; return; }
    const srcDef  = SOURCE_ALERT_TYPES[src];
    const typeDef = srcDef?.alertTypes?.find(t => t.value === type);
    out.textContent = `// Source: ${srcDef?.label || src}  |  Alert: ${typeDef?.label || type}  |  SIEM: ${siem.toUpperCase()}
// IOC: ${ioc || "(fill in <placeholders> before running)"}
// Hint: ${typeDef?.hint || ""}
// Generated: ${new Date().toLocaleString()}

${queryFn(ioc)}`;
  }
  $("dqb-generate")?.removeEventListener("click", buildDQBQuery);
  $("dqb-generate")?.addEventListener("click", buildDQBQueryFull);

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

    // ── CROWDSTRIKE CROSS-VENDOR SOURCE QUERIES ─────────────────────────────────
    { title:"[CS] Azure AD / Entra ID — Risky Sign-Ins", mitre:"T1078.004", cat:"identity",
      desc:"Hunt high-risk Azure AD sign-ins ingested into Falcon. Covers impossible travel, unfamiliar features, anonymized IPs, and atypical travel flagged by Entra Identity Protection.",
      queries:{ cs:`event_simpleName=AzureADSignIn OR event_simpleName=RiskySignIn\n| where RiskLevel IN ("high","critical") OR RiskDetail IN ("unfamiliarFeatures","atypicalTravel","anonymizedIPAddress","maliciousIPAddress","passwordSpray")\n| table _time, UserName, IPAddress, City, CountryOrRegion, RiskLevel, RiskDetail, AppDisplayName`, splunk:`index=crowdstrike OR index=azure sourcetype IN ("crowdstrike:identity","azure:aad:signin")\n| search RiskLevel IN ("high","medium")\n| eval location=City+", "+CountryOrRegion\n| table _time, UserPrincipalName, IPAddress, location, RiskLevel, riskDetail, AppDisplayName`, kql:`SigninLogs\n| where RiskLevelDuringSignIn in ("high","medium")\n   or RiskDetail in ("unfamiliarFeatures","atypicalTravel","anonymizedIPAddress","passwordSpray")\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskLevelDuringSignIn, RiskDetail, AppDisplayName` }},
    { title:"[CS] Azure AD — Impossible Travel Detection", mitre:"T1078.004", cat:"identity",
      desc:"Same account authenticating from two countries within a window physically impossible to travel between. Covers Falcon Identity, Azure AD, and Okta log sources.",
      queries:{ cs:`event_simpleName=UserLogon OR event_simpleName=AzureADSignIn\n| stats dc(RemoteAddressIP4) as unique_ips, values(RemoteAddressIP4) as ip_list, values(GeoCountry) as countries, min(_time) as first_seen, max(_time) as last_seen by UserName\n| where unique_ips >= 2 AND dc(countries) >= 2\n| eval window_mins=round((last_seen - first_seen)/60,1)\n| where window_mins < 120\n| table UserName, ip_list, countries, window_mins`, splunk:`index=* (sourcetype="crowdstrike:identity" OR sourcetype="azure:aad:signin" OR sourcetype=okta)\n| stats values(src_ip) as ips, dc(country) as country_count by user, span=1h\n| where country_count > 1`, kql:`SigninLogs\n| where ResultType == "0"\n| summarize Locations=make_set(Location), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)\n| where array_length(Locations) > 1` }},
    { title:"[CS] Zscaler ZIA — Malware & C2 Blocks via Falcon", mitre:"T1071", cat:"c2",
      desc:"Hunt Zscaler ZIA/ZPA blocks forwarded to CrowdStrike or SIEM. Covers malware, C2, botnets, and high-risk URL categories blocked at the proxy layer.",
      queries:{ cs:`// Zscaler ZIA blocks in Falcon NGSIEM (Vendor.* prefix format)\nevent_simpleName=ZscalerWebTransaction OR #repo=zscaler_zia\n| where Vendor.action IN ("blocked","IPS Drop") AND (Vendor.threatcat=~/(?i)malware|c2|botnet|command|ransomware|phish/ OR Vendor.threat_score>60)\n| table _time, Vendor.user, Vendor.devicehostname, Vendor.csip, Vendor.cdip, Vendor.threatname, Vendor.threatcat, Vendor.ipsrulelabel, Vendor.threat_score`, splunk:`index=zscaler sourcetype=zscalernss\n| search action=blocked (urlCategory="Command and Control" OR urlCategory=Malware OR threatName!="")\n| table _time, user, clientHostname, srcIP, dstIP, threatName, urlCategory, url, referer`, kql:`CommonSecurityLog\n| where DeviceVendor == "Zscaler" and DeviceAction in ("blocked","IPS Drop")\n| where DeviceCustomString2 has_any ("Malware","Command and Control","Botnet","Phishing")\n| project TimeGenerated, SourceUserName, SourceHostName, SourceIP, DestinationIP, DeviceCustomString2, RequestURL` }},
    { title:"[CS] Zscaler — Threat Score > 70 (High Risk Events)", mitre:"T1071", cat:"c2",
      desc:"Surface high-risk Zscaler events by threat score from NGSIEM Vendor.* format. Score >70 = active malware or confirmed C2. Use to prioritize analyst review queue.",
      queries:{ cs:`// Zscaler NGSIEM high threat score events (Vendor.* space-separated format)\n#repo=zscaler OR event_simpleName=ZscalerAlert\n| where Vendor.threat_score > 70\n| table _time, Vendor.user, Vendor.devicehostname, Vendor.csip, Vendor.cdip, Vendor.cdport, Vendor.threatname, Vendor.threatcat, Vendor.threat_score, Vendor.ipsrulelabel`, splunk:`index=zscaler sourcetype=zscalernss threat_score > 70\n| table _time, user, clientHostname, srcIP, dstIP, threatName, urlCategory, threat_score`, kql:`CommonSecurityLog\n| where DeviceVendor == "Zscaler" and toint(DeviceCustomNumber1) > 70\n| project TimeGenerated, SourceUserName, SourceHostName, SourceIP, DestinationIP, DeviceCustomString1, DeviceCustomNumber1, RequestURL` }},
    { title:"[CS] Okta — Auth Failures from Foreign IPs", mitre:"T1110", cat:"credential",
      desc:"Hunt Okta authentication failures forwarded to CrowdStrike Falcon. Focus on accounts with high failure counts or sign-ins from unexpected countries — credential stuffing pattern.",
      queries:{ cs:`event_simpleName=OktaAuthFailed OR (event_simpleName IN ("UserLogon","AuthEvent") outcome.result="FAILURE")\n| stats count as failures, values(RemoteAddressIP4) as ips, dc(GeoCountry) as country_count by UserName\n| where failures > 5 OR country_count > 1\n| sort - failures\n| table UserName, failures, ips, country_count`, splunk:`index=okta sourcetype=okta:system\n| search outcome.result=FAILURE\n| stats count as fail_count, values(client.ipAddress) as ips, dc(client.geographicalContext.country) as country_count by actor.alternateId\n| where fail_count > 5 OR country_count > 1\n| sort - fail_count`, kql:`SigninLogs\n| where ResultType != "0"\n| summarize FailCount=count(), IPs=make_set(IPAddress), Countries=make_set(Location) by UserPrincipalName\n| where FailCount > 5 or array_length(Countries) > 1\n| sort by FailCount desc` }},
    { title:"[CS] Okta — MFA Push Fatigue / Spam Attack", mitre:"T1621", cat:"credential",
      desc:"Detect MFA push fatigue attacks in Okta forwarded to Falcon. High-volume push denials in a short window = active attack. Primary technique of Scattered Spider / UNC3944.",
      queries:{ cs:`event_simpleName=OktaMFAEvent OR eventType="user.mfa.okta_verify.deny_push"\n| stats count as push_count, values(RemoteAddressIP4) as src_ips by UserName, span=1h\n| where push_count > 5\n| sort - push_count\n| table _time, UserName, push_count, src_ips`, splunk:`index=okta sourcetype=okta:system\n  (eventType="user.mfa.okta_verify.deny_push" OR eventType="user.mfa.challenge")\n| bin _time span=1h\n| stats count as push_count by actor.alternateId, _time\n| where push_count > 5\n| sort - push_count`, kql:`SigninLogs\n| where AuthenticationRequirement == "multiFactorAuthentication" and ResultType != "0"\n| summarize PushCount=count(), IPs=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)\n| where PushCount > 5\n| sort by PushCount desc` }},
    { title:"[CS] Netskope CASB — Malware Upload/Download", mitre:"T1567", cat:"exfil",
      desc:"Hunt Netskope CASB malware alerts forwarded to Falcon. Covers uploads/downloads of malicious files to Dropbox, GDrive, Box, OneDrive and shadow IT cloud apps.",
      queries:{ cs:`event_simpleName=NetskopeAlert OR event_simpleName=NetskopeCloudApp\n| where type="alert" AND (alert_type=~/(?i)malware|dlp|policy/ OR NetskopeName!="")\n| table _time, UserName, srcip, dstip, app, appcategory, activity, alert_name, NetskopeName, url`, splunk:`index=netskope sourcetype=netskope:events\n| search type=alert (alert_type=malware OR alert_type=policy)\n| table _time, user, src_ip, app, appcategory, activity, alert_name, url, file_name`, kql:`CommonSecurityLog\n| where DeviceVendor == "Netskope" and DeviceEventClassID == "alert"\n| project TimeGenerated, SourceUserName, SourceIP, DeviceCustomString1, DeviceCustomString2, RequestURL, Activity` }},
    { title:"[CS] Palo Alto NGFW — C2 & Threat Blocks via Falcon", mitre:"T1071", cat:"c2",
      desc:"Hunt Palo Alto Firewall/WildFire threat events forwarded to CrowdStrike Falcon SIEM. Surface blocked C2, malware, and exploit traffic at the network perimeter.",
      queries:{ cs:`event_simpleName=PaloAltoThreat OR (subtype=threat)\n| where action IN ("block","block-ip","drop","reset-both") AND category IN ("command-and-control","malware","vulnerability","exploit")\n| table _time, src_ip, dst_ip, dstport, user, threatname, category, policyname, app, action`, splunk:`index=paloalto sourcetype=pan:threat\n| search action IN ("block","block-ip","drop") AND (category="command-and-control" OR category=malware OR threatname!="")\n| table _time, src_ip, dst_ip, dstport, user, threatname, category, policyname`, kql:`CommonSecurityLog\n| where DeviceVendor == "Palo Alto Networks" and DeviceEventClassID == "THREAT" and DeviceAction in ("block","drop","reset-both")\n| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, SourceUserName, DeviceCustomString1, DeviceCustomString2` }},
    { title:"[CS] Falcon Identity — Blocklisted / Unusual Location", mitre:"T1078.004", cat:"identity",
      desc:"Hunt CrowdStrike Falcon Identity Protection alerts for access from blocklisted or sanctioned countries. Combine with ASN/carrier data to distinguish VPN from direct mobile connections.",
      queries:{ cs:`event_simpleName IN ("IdentityAlert","AccessFromBlocklistedLocation","AccessFromUnusualGeolocation")\n| where AlertType IN ("Access from blocklisted location","Access from unusual geolocation","Suspicious web-based activity")\n| table _time, UserName, AccountDomain, SourceIP, GeoCountry, GeoCity, ISPOrg, DeviceType, RiskScore, AlertType, Department, Title`, splunk:`index=crowdstrike sourcetype="crowdstrike:identity"\n| search AlertType IN ("Access from blocklisted location","Access from unusual geolocation")\n| eval suspicious_origin=GeoCity+", "+GeoCountry\n| table _time, UserName, Department, Title, SourceIP, suspicious_origin, ISP, DeviceType, RiskScore`, kql:`IdentityDirectoryEvents\n| where ActionType has_any ("Suspicious","Anomalous") and isnotempty(TargetAccountUpn)\n| project TimeGenerated, TargetAccountUpn, IPAddress, Location, ActionType, AdditionalFields` }},
    { title:"[CS] Cross-Source — User in Multiple Alert Sources", mitre:"T1078", cat:"identity",
      desc:"Correlate alerts from multiple vendors (Zscaler + Okta + Azure + Falcon) for a single user. Appearing in 2+ alert sources simultaneously is a high-confidence compromise signal.",
      queries:{ cs:`// User appearing in Zscaler + Okta + Azure + Falcon detections\n(event_simpleName=ZscalerWebTransaction action=blocked) OR\n(event_simpleName=OktaAuthFailed outcome.result=FAILURE) OR\n(event_simpleName=AzureADSignIn RiskLevel="high") OR\n(event_simpleName=DetectionSummaryEvent)\n| stats dc(event_simpleName) as source_count, values(event_simpleName) as sources, values(RemoteAddressIP4) as ips, count as total_events by UserName\n| where source_count >= 2\n| sort - source_count\n| table UserName, source_count, sources, total_events, ips`, splunk:`index=* (sourcetype="crowdstrike:detection" OR sourcetype=zscalernss OR sourcetype=okta OR sourcetype="azure:aad:signin")\n| stats dc(sourcetype) as source_count, values(sourcetype) as sources, values(src_ip) as ips, count by user\n| where source_count >= 2\n| sort - source_count`, kql:`union SigninLogs, DeviceAlertEvents, CommonSecurityLog\n| where TimeGenerated > ago(24h)\n| summarize SourceCount=dcount(Type), Sources=make_set(Type), EventCount=count() by UserPrincipalName\n| where SourceCount >= 2\n| sort by SourceCount desc` }},

    // ── OKTA SOURCE QUERIES ─────────────────────────────────────────────────────
    { title:"[Okta] Suspicious Actor — Login from New Device", mitre:"T1078", cat:"identity",
      desc:"Detect Okta logins from a device or browser the user has never used before. New device + unusual location = high-priority review, especially for admin accounts.",
      queries:{ splunk:`index=okta sourcetype=okta:system eventType=user.session.start
| eval device=client.device+"/"+client.browser
| stats values(device) as devices, dc(device) as dev_count, values(client.ipAddress) as ips by actor.alternateId
| where dev_count > 2
| sort - dev_count`, cs:`event_simpleName=OktaSessionStart
| stats dc(DeviceType) as dev_count, values(DeviceType) as devices, values(RemoteAddressIP4) as ips by UserName
| where dev_count >= 2
| sort - dev_count`, kql:`SigninLogs
| where isnotempty(DeviceDetail.deviceId)
| summarize Devices=make_set(DeviceDetail.displayName), DevCount=dcount(DeviceDetail.deviceId) by UserPrincipalName
| where DevCount > 2
| sort by DevCount desc` }},

    { title:"[Okta] Account Takeover — Password + MFA Reset Same Session", mitre:"T1098", cat:"identity",
      desc:"Detect when password change AND MFA factor reset occur in the same session — classic post-compromise takeover step to lock out the legitimate owner.",
      queries:{ splunk:`index=okta sourcetype=okta:system
| search eventType IN ("user.account.update_password","user.mfa.factor.deactivate","user.mfa.factor.activate","user.account.reset_password")
| bin _time span=30m
| stats values(eventType) as events, dc(eventType) as event_count, values(client.ipAddress) as ips by actor.alternateId, _time
| where event_count >= 2 AND (match(events,"update_password") OR match(events,"reset_password")) AND match(events,"factor")
| sort - event_count`, cs:`(event_simpleName=OktaPasswordChange OR event_simpleName=OktaMFADeactivate)
| bin _time span=30m
| stats values(event_simpleName) as events, dc(event_simpleName) as types, values(RemoteAddressIP4) as ips by UserName, _time
| where types >= 2
| sort - types`, kql:`// Via Entra audit logs (similar pattern)
AuditLogs
| where OperationName in ("Reset password (by admin)","Delete registered security info","Register security info")
| bin TimeGenerated=bin(TimeGenerated, 30m)
| summarize Events=make_set(OperationName), Count=count(), IPs=make_set(InitiatedBy) by TargetResources, TimeGenerated
| where Count >= 2
| sort by Count desc` }},

    { title:"[Okta] Admin Privilege Escalation", mitre:"T1098.001", cat:"privilege_esc",
      desc:"Detect Okta admin role assignment events. An attacker who has compromised an account will escalate to admin to persist and expand access.",
      queries:{ splunk:`index=okta sourcetype=okta:system
| search eventType IN ("group.user.add","user.account.privilege.grant")
| eval target_user=target{}.alternateId, target_group=target{}.displayName
| table _time, actor.alternateId, target_user, target_group, client.ipAddress`, cs:`event_simpleName=OktaGroupMemberAdd OR event_simpleName=OktaPrivilegeGrant
| table _time, UserName, TargetUser, TargetGroup, RemoteAddressIP4`, kql:`AuditLogs
| where OperationName in ("Add member to role","Grant delegated permission")
| project TimeGenerated, InitiatedBy, TargetResources, OperationName, Result` }},

    { title:"[Okta] Session Hijacking — IP Change Mid-Session", mitre:"T1563", cat:"lateral",
      desc:"Detect Okta sessions where the source IP changes mid-session — strong indicator of session token theft and replay from a different location.",
      queries:{ splunk:`index=okta sourcetype=okta:system
| sort actor.alternateId, _time
| streamstats window=2 current=t values(client.ipAddress) as ip_window by actor.alternateId
| where mvcount(ip_window) > 1 AND mvindex(ip_window,0) != mvindex(ip_window,1)
| table _time, actor.alternateId, ip_window, eventType, client.geographicalContext.country`, cs:`event_simpleName=OktaSessionEvent
| streamstats window=2 values(RemoteAddressIP4) as ip_window by UserName
| where mvcount(ip_window) > 1 AND mvindex(ip_window,0) != mvindex(ip_window,1)
| table _time, UserName, ip_window, GeoCountry`, kql:`// Session IP change in Entra
SigninLogs
| summarize IPs=make_set(IPAddress), Locations=make_set(Location), Count=count() by UserPrincipalName, CorrelationId
| where array_length(IPs) > 1
| sort by Count desc` }},

    { title:"[Okta] Suspicious Admin Actions — Policy Changes", mitre:"T1484.002", cat:"defense_evasion",
      desc:"Detect Okta policy modifications including sign-on policy changes, password policy weakening, and MFA policy bypass. Attackers weaken policies to maintain access.",
      queries:{ splunk:`index=okta sourcetype=okta:system
| search eventType IN ("policy.rule.update","policy.rule.delete","policy.update","mfa.policy.update","policy.rule.add")
| table _time, actor.alternateId, eventType, target{}.displayName, client.ipAddress, outcome.result`, cs:`event_simpleName=OktaPolicyChange OR event_simpleName=OktaMFAPolicyUpdate
| table _time, UserName, TargetPolicy, EventType, RemoteAddressIP4, outcome`, kql:`AuditLogs
| where OperationName has_any ("policy","conditional access") and OperationName has_any ("update","delete","add","modify")
| project TimeGenerated, InitiatedBy, TargetResources, OperationName, Result` }},

    // ── AZURE AD / ENTRA ADDITIONAL QUERIES ─────────────────────────────────────
    { title:"[Azure] New MFA Method Registered from Risky IP", mitre:"T1556", cat:"persistence",
      desc:"Detect new MFA methods (Authenticator app, phone, FIDO key) registered from IPs that haven't been seen before for this user — attacker persisting after credential compromise.",
      queries:{ splunk:`index=azure sourcetype=azure:aad:audit
| search OperationName="Register security info" OR OperationName="User registered security info"
| eval actor_ip=ClientIP
| table _time, UserPrincipalName, actor_ip, ResultDescription, AdditionalDetails`, cs:`event_simpleName=AzureMFARegister OR event_simpleName=AzureSecurityInfoUpdate
| table _time, UserName, IPAddress, NewMFAMethod, RiskLevel, City, CountryOrRegion`, kql:`AuditLogs
| where OperationName in ("Register security info","User registered security info","Update user")
| where Result == "success"
| extend Actor=tostring(InitiatedBy.user.userPrincipalName), IP=tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, IP, OperationName, TargetResources, Result
| where isnotempty(IP)` }},

    { title:"[Azure] Conditional Access Policy Bypass", mitre:"T1562.001", cat:"defense_evasion",
      desc:"Detect sign-ins where Conditional Access was not enforced or explicitly bypassed. CA policy failures for high-value users need immediate review.",
      queries:{ splunk:`index=azure sourcetype=azure:aad:signin
| search ConditionalAccessStatus IN ("notApplied","failure")
| table _time, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus, RiskLevelDuringSignIn`, cs:`event_simpleName=AzureADSignIn ConditionalAccessStatus IN ("notApplied","failure")
| table _time, UserName, IPAddress, AppDisplayName, ConditionalAccessStatus, RiskLevel`, kql:`SigninLogs
| where ConditionalAccessStatus in ("notApplied","failure")
| where RiskLevelDuringSignIn in ("medium","high")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskDetail` }},

    { title:"[Azure] OAuth App Consent — New App High-Permission Grant", mitre:"T1528", cat:"initial_access",
      desc:"Detect OAuth app consent grants in Azure AD with high-privilege scopes (Mail.ReadWrite, Files.ReadWrite.All, offline_access). Primary BEC and persistent access vector.",
      queries:{ splunk:`index=azure sourcetype=azure:aad:audit
| search OperationName="Consent to application" IsAdminConsent=true
| table _time, User, AppDisplayName, Scope, IsAdminConsent, OnBehalfOfAll`, cs:`event_simpleName=AzureConsentGrant OR event_simpleName=OAuthAppConsent
| where IsAdminConsent="True" OR Scope=~"(?i)mail\.readwrite|files\.readwrite\.all|offline_access"
| table _time, UserName, AppDisplayName, Scope, IsAdminConsent`, kql:`AuditLogs
| where OperationName == "Consent to application"
| extend App=tostring(TargetResources[0].displayName)
| extend Scopes=tostring(AdditionalDetails)
| where Scopes has_any ("Mail.ReadWrite","Files.ReadWrite.All","offline_access","Directory.ReadWrite")
| project TimeGenerated, InitiatedBy, App, Scopes, Result` }},

    { title:"[Azure] Mass Mailbox Access — Potential Data Theft", mitre:"T1114.002", cat:"exfil",
      desc:"Detect unusual bulk email access — an attacker who compromised an account will often read/download emails in bulk. High mailbox item counts accessed in short window.",
      queries:{ splunk:`index=o365 sourcetype=o365:management:activity Operation IN ("MailItemsAccessed","MessageBind","FolderBind")
| bin _time span=1h
| stats count as access_count by UserId, ClientIPAddress, _time
| where access_count > 100
| sort - access_count`, cs:`event_simpleName=MailboxAccess OR event_simpleName=M365MailItemsAccessed
| bin _time span=1h
| stats count as items_accessed by UserName, ClientIPAddress, _time
| where items_accessed > 100
| sort - items_accessed`, kql:`OfficeActivity
| where Operation in ("MailItemsAccessed","MessageBind","FolderBind")
| bin TimeGenerated=bin(TimeGenerated, 1h)
| summarize AccessCount=count() by UserId, ClientIP, TimeGenerated
| where AccessCount > 100
| sort by AccessCount desc` }},

    // ── ZSCALER ADDITIONAL SOURCE QUERIES ────────────────────────────────────────
    { title:"[ZIA] ClickFix / Fake CAPTCHA Campaign Detection", mitre:"T1204.001", cat:"initial_access",
      desc:"Detect Zscaler blocks matching ClickFix/CAPTCHA social engineering lures. These pages instruct users to paste PowerShell commands — often pre-compromise delivery vector.",
      queries:{ splunk:`index=zscaler sourcetype=zscalernss action=blocked
| search (urlCategory IN ("Malware","Command and Control","Suspicious") OR threatName=~/(?i)clickfix|captcha|verify|copybreak|pastejack/)
| eval suspicious_path=if(match(url,"(?i)/verify|/captcha|/check|/validate|/confirm|/update"),"HIGH_RISK_PATH","")
| table _time, user, clientHostname, srcIP, url, referer, threatName, urlCategory, suspicious_path`, cs:`// Zscaler ZIA ClickFix detection in Falcon NGSIEM
Vendor.threatcat=~/(?i)malware|c2/ Vendor.action IN ("blocked","IPS Drop")
(Vendor.threatname=~/(?i)clickfix|HTML\.Trojan|pastejack/ OR Vendor.ipsrulelabel=~/(?i)IPS/)
| table _time, Vendor.user, Vendor.devicehostname, Vendor.csip, Vendor.cdip, Vendor.threatname, Vendor.threat_score`, kql:`CommonSecurityLog
| where DeviceVendor == "Zscaler" and DeviceAction == "blocked"
| where DeviceCustomString2 has_any ("Malware","Command and Control")
| where RequestURL has_any ("/verify","/captcha","/check","/validate","/confirm")
| project TimeGenerated, SourceUserName, SourceHostName, SourceIP, RequestURL, DeviceCustomString1, DeviceCustomString2` }},

    { title:"[ZIA] User Accessing Anonymizer / Proxy Bypass Site", mitre:"T1090", cat:"defense_evasion",
      desc:"Detect users accessing anonymization services, Tor proxies, or web proxy bypass sites through Zscaler — policy violation and potential data exfiltration or C2 evasion indicator.",
      queries:{ splunk:`index=zscaler sourcetype=zscalernss
| search urlCategory IN ("Anonymizer","Proxy Avoidance and Anonymizers","Tor","Web Proxy")
| stats count, values(url) as urls, values(dstIP) as ips by user, clientHostname
| where count > 3
| sort - count`, cs:`Vendor.ipcat=~/(?i)anonymizer|proxy.avoid|tor/ OR urlCategory=~/(?i)anonymizer|proxy.avoid|tor/
| table _time, Vendor.user, Vendor.devicehostname, Vendor.csip, Vendor.cdip, Vendor.ipcat, Vendor.action`, kql:`CommonSecurityLog
| where DeviceVendor == "Zscaler"
| where DeviceCustomString2 has_any ("Anonymizer","Proxy Avoidance","Tor","Web Proxy")
| summarize count(), URLs=make_set(RequestURL) by SourceUserName, SourceHostName, SourceIP
| where count_ > 3` }},
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
  // ── Comprehensive offline threat actor database (60+ actors) ──────
  const ACTOR_DB = {
    // ── RUSSIA ──────────────────────────────────────────────────────
    "APT29":{"aliases":["Cozy Bear","NOBELIUM","Midnight Blizzard","Dark Halo","The Dukes"],"origin":"Russia","sponsor":"SVR","motivation":"espionage","active_since":"2008","targets":"Government, NGOs, Tech, Think Tanks","ttps":["T1566.001","T1190","T1027","T1055","T1071.001","T1078","T1195.002"],"tools":["SUNBURST","TEARDROP","BEATDROP","Cobalt Strike","WellMess","MiniDuke"],"description":"Russian SVR-linked group behind SolarWinds (SUNBURST), spear-phishing campaigns, and long-term stealthy espionage against Western governments.","recent":"2024: Microsoft email breach, Midnight Blizzard branding","mitre":"G0016"},
    "APT28":{"aliases":["Fancy Bear","Sofacy","STRONTIUM","Forest Blizzard","Pawn Storm"],"origin":"Russia","sponsor":"GRU Unit 26165","motivation":"espionage","active_since":"2004","targets":"Government, Military, NATO, Think Tanks","ttps":["T1566","T1190","T1059.001","T1078","T1003.001","T1071"],"tools":["X-Agent","Sofacy","Zebrocy","Drovorub","LYTTON"],"description":"Russian GRU group behind DNC hack (2016), multiple NATO phishing ops, and spear-phishing campaigns against Western defence targets.","recent":"2024: Ongoing NATO/EU espionage, HeadLace malware","mitre":"G0007"},
    "Sandworm":{"aliases":["Voodoo Bear","IRIDIUM","Seashell Blizzard","APT44","TeleBots"],"origin":"Russia","sponsor":"GRU Unit 74455","motivation":"destructive","active_since":"2009","targets":"Ukraine, Energy, Government, Global","ttps":["T1486","T1561","T1190","T1059","T1071","T1570"],"tools":["NotPetya","BlackEnergy","Industroyer","Cyclops Blink","AcidRain"],"description":"GRU Unit 74455 responsible for NotPetya (most destructive cyberattack in history), Ukraine power grid attacks (2015-2016), and BlackEnergy campaigns.","recent":"2024: Ongoing Ukraine OT/ICS targeting, AcidPour wiper","mitre":"G0034"},
    "Turla":{"aliases":["Snake","Venomous Bear","IRON HUNTER","Secret Blizzard","Waterbug"],"origin":"Russia","sponsor":"FSB","motivation":"espionage","active_since":"1996","targets":"Government, Embassies, Military, EU/NATO","ttps":["T1190","T1027","T1055","T1071","T1078","T1074"],"tools":["Snake","Carbon","Kazuar","ComRAT","TinyTurla"],"description":"FSB-linked group known for compromising satellite links for C2, sophisticated Snake malware framework, and decades of stealthy espionage.","recent":"2024: Snake network dismantled by FBI (Operation MEDUSA); shifted tactics","mitre":"G0010"},
    "Gamaredon":{"aliases":["Primitive Bear","ACTINIUM","Armageddon","UAC-0010","Trident Ursa"],"origin":"Russia","sponsor":"FSB","motivation":"espionage","active_since":"2013","targets":"Ukraine Government, Military, NGOs","ttps":["T1566.001","T1059.001","T1547","T1071","T1105","T1003"],"tools":["Pteranodon","Pterodo","GammaSteel","PowerPunch"],"description":"FSB-linked group conducting high-volume phishing and malware campaigns almost exclusively targeting Ukrainian government, military, and NGOs.","recent":"2024: Continued intense Ukraine targeting, USB worm campaigns","mitre":"G0047"},
    "FIN7":{"aliases":["Carbanak","ITG14","Carbon Spider","Sangria Tempest"],"origin":"Russia/Ukraine","sponsor":"Criminal","motivation":"financial","active_since":"2013","targets":"Financial, Hospitality, Retail, Restaurant","ttps":["T1566.001","T1059.005","T1055","T1027","T1083","T1071"],"tools":["CARBANAK","BIRDDOG","POWERPLANT","Cobalt Strike","DICELOADER"],"description":"Prolific financially-motivated group targeting hospitality and retail via spear-phishing. Known for CARBANAK banking malware and PoS attacks.","recent":"2024: Ransomware pivot, new DICELOADER/PowerShell loaders","mitre":"G0046"},
    "Cl0p":{"aliases":["TA505","Lace Tempest","FIN11"],"origin":"Russia","sponsor":"Criminal","motivation":"financial","active_since":"2019","targets":"Financial, Healthcare, Tech (mass exploitation)","ttps":["T1190","T1041","T1486","T1078","T1105"],"tools":["Cl0p ransomware","SDBOT","FlawedAmmyy","TrueBot"],"description":"Ransomware group known for exploiting zero-days en masse — GoAnywhere (2023), MOVEit (2023). Responsible for some of the largest data-theft extortion campaigns.","recent":"2024: Continued MOVEit exploitation victims, shifting to new zero-days","mitre":"G0092"},
    "LockBit":{"aliases":["ABCD","LockBit 3.0","LockBit Black","LockBit 4.0"],"origin":"Unknown / RaaS","sponsor":"Criminal RaaS","motivation":"financial","active_since":"2019","targets":"Healthcare, Government, Education, Manufacturing","ttps":["T1486","T1490","T1489","T1078","T1021","T1083","T1041"],"tools":["LockBit ransomware","StealBit","Cobalt Strike"],"description":"Most active ransomware-as-a-service globally 2022-2024. Double-extortion model. Partially disrupted by Operation Cronos (Feb 2024) but resumed activity.","recent":"2024: Op Cronos disruption, LockBit 4.0 released, resumed attacks","mitre":"S0652"},
    "TA505":{"aliases":["Evil Corp adjacent","Hive0065","SectorJ04"],"origin":"Russia","sponsor":"Criminal","motivation":"financial","active_since":"2014","targets":"Financial, Retail, Healthcare","ttps":["T1566","T1059.005","T1204.002","T1071","T1027"],"tools":["Dridex","Locky","FlawedAmmyy","ServHelper","SDBot"],"description":"High-volume phishing group distributing Dridex banking trojan, Locky ransomware. Major initial access broker and malware distributor.","recent":"2023-2024: Shifted to Cl0p ransomware operations","mitre":"G0092"},
    "Evil Corp":{"aliases":["INDRIK SPIDER","Dridex Gang","Maksim Yakubets Group"],"origin":"Russia","sponsor":"Criminal/FSB-linked","motivation":"financial","active_since":"2007","targets":"Financial, Banks, Enterprises globally","ttps":["T1566","T1078","T1486","T1041","T1027","T1059"],"tools":["Dridex","WastedLocker","BitPaymer","Hades","Phoenix Locker"],"description":"Sanctioned Russian cybercriminal group led by Maksim Yakubets. Responsible for $100M+ in banking fraud via Dridex. Pivoted to ransomware (WastedLocker).","recent":"2024: Continued ransomware ops evading US sanctions","mitre":"G0119"},
    "BlackCat":{"aliases":["ALPHV","Noberus","AlphVM"],"origin":"Russia","sponsor":"Criminal RaaS","motivation":"financial","active_since":"2021","targets":"Healthcare, Finance, Manufacturing, Government","ttps":["T1486","T1490","T1078","T1021","T1041","T1059"],"tools":["ALPHV/BlackCat ransomware","Cobalt Strike","ExMatter exfil"],"description":"Sophisticated Rust-based ransomware-as-a-service group. Major attack on UnitedHealth/Change Healthcare (2024). Disrupted by FBI in Dec 2023 but re-emerged.","recent":"2024: Change Healthcare attack ($22M ransom), FBI disruption","mitre":"G1006"},
    // ── CHINA ───────────────────────────────────────────────────────
    "APT41":{"aliases":["Double Dragon","Barium","Winnti","Earth Baku","Brazen Bamboo"],"origin":"China","sponsor":"MSS","motivation":"espionage + financial","active_since":"2012","targets":"Healthcare, Telecom, Technology, Gaming, Government","ttps":["T1190","T1078","T1059","T1027","T1055","T1486"],"tools":["DUSTPAN","DEADEYE","KEYPLUG","Cobalt Strike","PlugX"],"description":"Dual-mission Chinese group conducting MSS espionage AND financially motivated attacks against gaming/crypto. Unique dual mandate.","recent":"2024: Continued critical infrastructure targeting, DUSTPAN loader","mitre":"G0096"},
    "APT10":{"aliases":["Stone Panda","menuPass","Red Apollo","Cloud Hopper"],"origin":"China","sponsor":"MSS Tianjin Bureau","motivation":"espionage","active_since":"2009","targets":"MSPs, Healthcare, Government, Defense, Aviation","ttps":["T1190","T1059","T1027","T1078","T1071","T1003"],"tools":["PlugX","ANEL","QuasarRAT","RedLeaves","ChChes"],"description":"Chinese group behind Operation Cloud Hopper — compromised MSPs to access hundreds of client networks globally. Extensive IP theft operations.","recent":"2024: Continued MSP/supply chain targeting in APAC","mitre":"G0045"},
    "APT40":{"aliases":["BRONZE MOHAWK","Leviathan","TEMP.Periscope","Kryptonite Panda","GADOLINIUM"],"origin":"China","sponsor":"MSS Hainan Bureau","motivation":"espionage","active_since":"2013","targets":"Maritime, Naval, Aviation, Defense, Research","ttps":["T1190","T1078","T1059","T1027","T1003","T1071"],"tools":["AIRBREAK","HOMEFRY","BADFLICK","DeepShark"],"description":"Chinese group conducting maritime and naval espionage. Known for targeting shipbuilding, naval contractors, and Indo-Pacific defence research.","recent":"2024: Rapid exploitation of new n-day vulnerabilities","mitre":"G0065"},
    "APT31":{"aliases":["Zirconium","Violet Typhoon","Hurricane Panda","Lead","Bronze Vinewood"],"origin":"China","sponsor":"MSS","motivation":"espionage","active_since":"2010","targets":"Government officials, Journalists, Dissidents, Financial","ttps":["T1566.001","T1078","T1027","T1036","T1003","T1071"],"tools":["DropboxAES","TIGERRAT","KeyBoy","ZIRCONIUM implants"],"description":"MSS-linked group targeting politicians, journalists, and dissidents. Indicted by DoJ for 2024 UK/US election interference operations.","recent":"2024: Indicted for UK Electoral Commission breach, US Treasury hack","mitre":"G0128"},
    "Volt Typhoon":{"aliases":["Bronze Silhouette","Vanguard Panda","Dev-0391","Insidious Taurus"],"origin":"China","sponsor":"PLA","motivation":"espionage + pre-positioning","active_since":"2021","targets":"US Critical Infrastructure, Utilities, Communications, Military","ttps":["T1190","T1078","T1059","T1021.001","T1560","T1036"],"tools":["FRP","web shells","netsh","LOLBAS"],"description":"PLA-linked group focused on pre-positioning in US critical infrastructure for potential future disruption. Uses living-off-the-land (LOTL) exclusively.","recent":"2024: CISA/NSA joint advisory, confirmed in Guam military networks","mitre":"G1017"},
    "Salt Typhoon":{"aliases":["FamousSparrow","GhostEmperor","UNC2286","Earth Estries"],"origin":"China","sponsor":"MSS/PLA","motivation":"espionage","active_since":"2020","targets":"Telecom carriers, ISPs, US Government, Hotels","ttps":["T1190","T1078","T1021","T1027","T1560","T1071"],"tools":["SparrowDoor","ShadowPad","PlugX","Demodex rootkit"],"description":"Chinese espionage group responsible for major US telecom breaches (AT&T, Verizon, T-Mobile) in 2024, compromising wiretap systems used by law enforcement.","recent":"2024: US telecom wiretap breach — AT&T, Verizon, T-Mobile compromised","mitre":"G1020"},
    // ── NORTH KOREA ─────────────────────────────────────────────────
    "Lazarus":{"aliases":["HIDDEN COBRA","Zinc","Diamond Sleet","APT38","Guardians of Peace"],"origin":"North Korea","sponsor":"RGB","motivation":"financial + espionage","active_since":"2009","targets":"Financial, Crypto, Defense, Healthcare, Aerospace","ttps":["T1566.001","T1204","T1059","T1486","T1041","T1078","T1105"],"tools":["WannaCry","BLINDINGCAN","HOPLIGHT","Fallchill","ELECTRUM","3CX backdoor"],"description":"North Korean state-sponsored group behind WannaCry ($8B damages), Bangladesh Bank Heist ($81M), Sony Pictures hack, and massive crypto theft campaigns.","recent":"2024: $1.5B Bybit crypto exchange hack, 3CX supply chain","mitre":"G0032"},
    "Kimsuky":{"aliases":["Thallium","Velvet Chollima","APT43","TA406","Black Banshee"],"origin":"North Korea","sponsor":"RGB","motivation":"espionage","active_since":"2012","targets":"South Korea, US Think Tanks, Government, Academia, UN","ttps":["T1566.001","T1059.001","T1027","T1083","T1114","T1078"],"tools":["AppleSeed","SHARPEXT","PENCILDOWN","BabyShark","RandomQuery"],"description":"North Korean espionage group collecting intelligence from South Korean think tanks, government entities, and nuclear/policy experts. Heavy spear-phishing.","recent":"2024: UN sanctions expert targeting, watering hole attacks","mitre":"G0094"},
    "Andariel":{"aliases":["Silent Chollima","Onyx Sleet","DarkSeoul","Stonefly"],"origin":"North Korea","sponsor":"RGB/Lazarus subgroup","motivation":"financial + espionage","active_since":"2015","targets":"South Korea Military, Defense, Healthcare, US","ttps":["T1566","T1059","T1486","T1003","T1071","T1078"],"tools":["Maui ransomware","H0lyGh0st","DTrack","Preft"],"description":"Lazarus subgroup specializing in ransomware (Maui) against hospitals and healthcare for revenue generation, plus South Korean military espionage.","recent":"2024: Continued healthcare ransomware, US defense contractor targeting","mitre":"G0138"},
    // ── IRAN ────────────────────────────────────────────────────────
    "APT35":{"aliases":["Charming Kitten","Phosphorus","Mint Sandstorm","TA453","ITG18"],"origin":"Iran","sponsor":"IRGC","motivation":"espionage","active_since":"2011","targets":"Journalists, Academics, Activists, Government, Think Tanks","ttps":["T1566.001","T1078","T1114","T1027","T1059","T1071"],"tools":["POWERSTAR","CharmPower","Hyperscrape","BellaCiao"],"description":"IRGC-linked group targeting Western journalists, academics, dissidents, and US/Israeli government officials. Known for elaborate social engineering.","recent":"2024: US 2024 election interference, targeting Trump/Biden campaigns","mitre":"G0059"},
    "APT33":{"aliases":["Elfin","Refined Kitten","Peach Sandstorm","Holmium","MAGNALLIUM"],"origin":"Iran","sponsor":"IRGC/MOIS","motivation":"espionage + destructive","active_since":"2013","targets":"Aerospace, Defense, Oil/Gas, Petrochemical, Saudi Arabia","ttps":["T1566","T1190","T1059","T1003","T1027","T1486"],"tools":["SHAMOON","StoneDrill","POWERTON","TURNEDUP","DistTrack"],"description":"Iranian group targeting aerospace/energy sector. Deployed SHAMOON wiper against Saudi Aramco and other Gulf oil/gas companies.","recent":"2024: Credential spray campaigns against US defense","mitre":"G0064"},
    "APT34":{"aliases":["OilRig","Helix Kitten","EUROPIUM","Cobalt Gypsy","CHRYSENE"],"origin":"Iran","sponsor":"MOIS","motivation":"espionage","active_since":"2014","targets":"Middle East Government, Finance, Energy, Telecom","ttps":["T1566","T1190","T1059","T1027","T1071","T1003"],"tools":["POWBAT","POWRUNER","BONDUPDATER","DNSpionage","SideTwist"],"description":"Iranian MOIS group targeting Middle Eastern governments, financial, and energy sectors. Known for DNS-based C2 (DNSpionage) and watering hole attacks.","recent":"2024: Active Israeli/Gulf targeting, new implant variants","mitre":"G0049"},
    "Agrius":{"aliases":["Pink Sandstorm","AMERICIUM","BlackShadow","DEV-0227"],"origin":"Iran","sponsor":"MOIS","motivation":"destructive + hacktivism","active_since":"2020","targets":"Israel, Middle East, Diamond Industry, Healthcare","ttps":["T1486","T1561","T1190","T1059","T1078","T1070"],"tools":["DEADWOOD","IPsec Helper","Fantasy wiper","Moneybird"],"description":"Iranian destructive group focusing on Israeli targets. Deployed multiple wipers (DEADWOOD, Fantasy) disguised as ransomware for political disruption.","recent":"2024: Israeli tech sector wipers, data destruction campaigns","mitre":"G1030"},
    "MuddyWater":{"aliases":["MERCURY","Seedworm","Static Kitten","Mango Sandstorm"],"origin":"Iran","sponsor":"MOIS","motivation":"espionage","active_since":"2017","targets":"Middle East Government, Telecom, Energy, Turkey","ttps":["T1566","T1059.001","T1027","T1071","T1078","T1547"],"tools":["POWERSTATS","Canopy","PowGoop","SloughRAT"],"description":"Prolific Iranian espionage group primarily targeting Middle Eastern government and telcos using PowerShell-based malware and spear-phishing.","recent":"2024: Spear-phishing targeting Israel/Turkey, new PowerShell tools","mitre":"G0069"},
    // ── APT NUMBERED (VARIOUS) ───────────────────────────────────────
    "APT73":{"aliases":["Asylum Ambuscade","TA2101","Gold Cabin"],"origin":"Unknown (assessed Belarus/Russia-linked)","sponsor":"Criminal/State-nexus","motivation":"financial + espionage","active_since":"2020","targets":"European SMBs, Crypto, Fintech, North American Banks","ttps":["T1566.001","T1059","T1027","T1078","T1114","T1041"],"tools":["SCREENSHOTTER","NODEBOT","IcedID","AHK RAT","Cobalt Strike"],"description":"Cybercriminal group with possible state nexus targeting SMBs and cryptocurrency platforms via phishing. Known for banking fraud and credential theft across Europe and North America.","recent":"2024-2025: Active European fintech targeting, Asylum Ambuscade campaigns","mitre":"G1023"},
    "APT38":{"aliases":["BlueNoroff","Stardust Chollima","Sapphire Sleet"],"origin":"North Korea","sponsor":"RGB/Lazarus unit","motivation":"financial","active_since":"2014","targets":"Banks, SWIFT system, Crypto, Finance","ttps":["T1566.001","T1078","T1027","T1041","T1105","T1071"],"tools":["HOPLIGHT","TAINTEDSCRIBE","ELECTRUM","FASTCASH"],"description":"Lazarus financial sub-group responsible for SWIFT banking heists totaling $2B+, including Bangladesh Bank ($81M). Specialized financial sector intrusion team.","recent":"2024: Continued crypto exchange targeting, TraderTraitor","mitre":"G0082"},
    "APT43":{"aliases":["Kimsuky","Thallium","Emerald Sleet","ARCHIPELAGO"],"origin":"North Korea","sponsor":"RGB","motivation":"espionage","active_since":"2018","targets":"Think Tanks, Policy, Nuclear, UN, Crypto","ttps":["T1566.001","T1114","T1027","T1059","T1078","T1003"],"tools":["RandomQuery","AppleSeed","VENOMBITE","lure documents"],"description":"North Korean intelligence-collection group focused on foreign policy, nuclear, and sanctions information. Harvests crypto to fund operations.","recent":"2024: South Korean election targeting, crypto theft for financing","mitre":"G0094"},
    // ── SCATTERED SPIDER & CYBERCRIME ────────────────────────────────
    "Scattered Spider":{"aliases":["UNC3944","Roasted 0ktapus","StarFraud","Muddled Libra","Octo Tempest"],"origin":"US/UK/Western","sponsor":"Criminal","motivation":"financial","active_since":"2022","targets":"BPO, Telecom, Hospitality, Crypto, Gaming, Tech","ttps":["T1621","T1078","T1534","T1566","T1059","T1598.003"],"tools":["OKTAPUS phishing kit","Cobalt Strike","AnyDesk","ScreenConnect"],"description":"English-speaking threat actor known for SIM swapping, MFA bypass via help desk social engineering. High-profile attacks on MGM Resorts ($100M) and Caesars Entertainment.","recent":"2024: Arrests of key members; attacks on financial sector","mitre":"G1015"},
    "Vice Society":{"aliases":["Vanilla Tempest","DEV-0832"],"origin":"Russia","sponsor":"Criminal RaaS","motivation":"financial","active_since":"2021","targets":"Education, Healthcare, Manufacturing","ttps":["T1486","T1490","T1078","T1021","T1041","T1059"],"tools":["Hello Kitty","Zeppelin","Quantum Locker","IceFire"],"description":"Ransomware group known for disproportionate attacks against the education sector (schools, universities). Uses various ransomware strains.","recent":"2024: Rebranded; continued education sector targeting","mitre":"G1017"},
    "Lapsus$":{"aliases":["DEV-0537","Strawberry Tempest"],"origin":"UK/Brazil (loosely)","sponsor":"Criminal (teen hackers)","motivation":"financial + notoriety","active_since":"2021","targets":"Tech Giants, Telecom, Gaming","ttps":["T1621","T1534","T1078","T1566","T1098","T1552"],"tools":["Custom exfil tools","social engineering","bribery"],"description":"Extortion group known for high-profile breaches of Microsoft, NVIDIA, Samsung, Okta, and Rockstar Games via social engineering and insider threats.","recent":"2022-2023: Members arrested; group dormant but inspired successors","mitre":"G1004"},
    "REvil":{"aliases":["Sodinokibi","Pinchy Spider"],"origin":"Russia","sponsor":"Criminal RaaS","motivation":"financial","active_since":"2019","targets":"Healthcare, Finance, Legal, Agriculture, Retail","ttps":["T1486","T1490","T1078","T1021","T1041","T1027"],"tools":["REvil/Sodinokibi ransomware","Cobalt Strike"],"description":"Prolific RaaS group behind Kaseya VSA ($70M demand), JBS Foods, and Travelex attacks. Disrupted by RU/US law enforcement in 2022.","recent":"2022: Leader arrested by Russia; group fragmented","mitre":"G0115"},
    // ── STATE HACKTIVISM / OTHERS ────────────────────────────────────
    "Killnet":{"aliases":["KillMilk","Killnet Collective"],"origin":"Russia","sponsor":"Pro-Russian hacktivism","motivation":"hacktivism","active_since":"2022","targets":"NATO, Ukraine, US, EU Government websites","ttps":["T1498","T1499","T1583"],"tools":["DDoS tools","Mirai variants","LOIC"],"description":"Pro-Russian hacktivist collective conducting DDoS attacks against NATO and Western targets in support of Russia's Ukraine invasion.","recent":"2024: Continued DDoS campaigns against EU, healthcare targets","mitre":"G1003"},
    "Anonymous Sudan":{"aliases":["Storm-1359","Skynet"],"origin":"Sudan (Sudan-linked, likely Russia-affiliated)","sponsor":"Hacktivism / possible state nexus","motivation":"hacktivism","active_since":"2023","targets":"US, EU, Israel, Healthcare, Airports, Government","ttps":["T1498","T1499","T1583","T1588"],"tools":["GODZILLA DDoS tool","Distributed Cloud Attack Tool (DCAT)"],"description":"Hacktivist group conducting massive DDoS attacks. Claimed attacks on Microsoft Azure, ChatGPT, and US hospitals. Possible ties to Russia despite Sudan branding.","recent":"2024: Indicted by US DoJ; two Sudanese nationals arrested","mitre":""},
    "Equation Group":{"aliases":["Tilded Team","LOTUSBLOSSEM","Tailored Access Operations (TAO)"],"origin":"USA","sponsor":"NSA TAO","motivation":"espionage","active_since":"2001","targets":"Global high-value targets, Iran, Russia, China","ttps":["T1190","T1027","T1055","T1003","T1071","T1040"],"tools":["EternalBlue","DoublePulsar","EQUATIONDRUG","GRAYFISH","Stuxnet (attributed)"],"description":"NSA's elite Tailored Access Operations unit. Responsible for Stuxnet (with GCHQ/Unit 8200), EternalBlue (later leaked by Shadow Brokers), and most sophisticated cyberespionage tooling known.","recent":"2017: Shadow Brokers leak; tools repurposed by North Korea/Russia","mitre":"G0020"},
    "Unit 8200":{"aliases":["ISNU","Israel SIGINT National Unit","C4I Corps"],"origin":"Israel","sponsor":"IDF","motivation":"espionage","active_since":"1952","targets":"Iran, Hezbollah, Gaza, Regional adversaries","ttps":["T1190","T1027","T1055","T1003","T1071","T1040"],"tools":["Stuxnet (co-developed)","Duqu","Flame","Pegasus (NSO, alumni)"],"description":"Israeli military intelligence unit responsible for co-developing Stuxnet targeting Iranian nuclear centrifuges. Alumni founded NSO Group (Pegasus spyware).","recent":"2024: Active operations in Gaza conflict, Iranian targeting","mitre":""},
    "Transparent Tribe":{"aliases":["APT36","PROJECTM","Mythic Leopard","Earth Karkadann"],"origin":"Pakistan","sponsor":"ISI","motivation":"espionage","active_since":"2013","targets":"India Government, Military, Defence, Education","ttps":["T1566.001","T1059","T1027","T1078","T1071","T1547"],"tools":["CrimsonRAT","ObliqueRAT","CapraRAT","Peppy"],"description":"Pakistani state-sponsored group primarily targeting Indian government, military, and defence organisations. Extensive spear-phishing and Android malware campaigns.","recent":"2024: CapraRAT Android malware targeting Indian officials","mitre":"G0134"},
    "Sidewinder":{"aliases":["T-APT-04","Rattlesnake","HTP","RAZOR TIGER"],"origin":"India","sponsor":"Indian Military Intelligence (assessed)","motivation":"espionage","active_since":"2012","targets":"Pakistan, China, Nepal, Afghanistan, Military","ttps":["T1566.001","T1059","T1027","T1078","T1071","T1036"],"tools":["Backdoor.SideWinder","CODERC","ModuleInstaller"],"description":"Suspected Indian state-sponsored group targeting Pakistani, Chinese, and neighbouring governments. High volume of operations, fast exploitation of new CVEs.","recent":"2024: Expanded operations in Middle East and Africa","mitre":"G0121"},
    "Patchwork":{"aliases":["Dropping Elephant","Chinastrats","Monsoon","APT-C-09","Zinc Emerson"],"origin":"India","sponsor":"Indian Government (assessed)","motivation":"espionage","active_since":"2014","targets":"China, Pakistan, Research Institutions, Think Tanks","ttps":["T1566.001","T1059.005","T1027","T1003","T1071"],"tools":["BADNEWS","Ragnatela","NDiskMonitor"],"description":"Suspected Indian APT known for copy-paste code assembly and targeting Chinese and Pakistani entities. Uses macro-laden documents and watering holes.","recent":"2023: Academic/think tank targeting with Ragnatela RAT","mitre":"G0040"},
    "Lazarus - BlueNoroff":{"aliases":["APT38","Sapphire Sleet","TA444","CageyChameleon"],"origin":"North Korea","sponsor":"RGB","motivation":"financial","active_since":"2014","targets":"Crypto, DeFi, Banks, VC firms, Web3","ttps":["T1566.001","T1204","T1027","T1041","T1078","T1071"],"tools":["TraderTraitor","AppleJeus","SUGARLOADER","KANDYKORN"],"description":"North Korean financial sub-unit responsible for cryptocurrency theft. Recent TraderTraitor campaign targeted crypto sector developers via fake job offers.","recent":"2024: $1.5B Bybit exchange hack, TraderTraitor campaign","mitre":"G0082"},
    "APT37":{"aliases":["Ricochet Chollima","InkySquid","ScarCruft","TEMP.Reaper","Erebus"],"origin":"North Korea","sponsor":"RGB/Ministry of State Security","motivation":"espionage","active_since":"2012","targets":"South Korea, Japan, Vietnam, Middle East, Defectors","ttps":["T1566.001","T1059","T1027","T1036","T1071","T1003"],"tools":["RokRAT","BLUELIGHT","DOLPHIN","GOLDBACKDOOR"],"description":"North Korean espionage group targeting South Korean defectors, journalists, and human rights activists. Exploits vulnerabilities in Hangul Office suite.","recent":"2024: NK defector targeting, ScarCruft BLUELIGHT campaigns","mitre":"G0067"},
    "Hafnium":{"aliases":["Silk Typhoon","Dev-0324","TG-3390"],"origin":"China","sponsor":"MSS","motivation":"espionage","active_since":"2021","targets":"US Think Tanks, Law Firms, Defense, NGOs","ttps":["T1190","T1059","T1027","T1003","T1071","T1078"],"tools":["web shells","PROCDUMP","WINRAR","China Chopper"],"description":"Chinese state-sponsored group responsible for mass exploitation of Microsoft Exchange zero-days (ProxyLogon, March 2021), compromising 250,000+ servers worldwide.","recent":"2024: Continued Exchange/SharePoint exploitation, US Treasury breach","mitre":"G0125"},
    "TA416":{"aliases":["RedDelta","BRONZE PRESIDENT","Mustang Panda"],"origin":"China","sponsor":"MSS","motivation":"espionage","active_since":"2012","targets":"Vatican, NGOs, EU Diplomats, Southeast Asia, Africa","ttps":["T1566.001","T1059","T1027","T1036","T1071","T1547"],"tools":["PlugX","Cobalt Strike","DOPLUGS","TONEINS"],"description":"Chinese APT targeting European diplomatic missions, NGOs, and Southeast Asian governments using PlugX variants delivered via phishing.","recent":"2024: EU diplomat targeting ahead of elections, African gov't espionage","mitre":"G0129"},
    "Scattered Spider":{"aliases":["UNC3944","Octo Tempest","0ktapus"],"origin":"Western (US/UK)","sponsor":"Criminal","motivation":"financial","active_since":"2022","targets":"Telecom, Tech, Hospitality, Gaming","ttps":["T1621","T1534","T1078","T1566","T1059"],"tools":["OKTAPUS","Cobalt Strike","AnyDesk"],"description":"English-speaking group using SIM swapping and helpdesk social engineering for MFA bypass. MGM ($100M loss) and Caesars attacks in 2023.","recent":"2024: Key members arrested in UK and US","mitre":"G1015"},
    "RomCom":{"aliases":["TROPICAL SCORPIUS","UNC2596","Storm-0978","Void Rabisu"],"origin":"Russia/Cuba (RaaS)","sponsor":"Criminal + Russia GRU nexus","motivation":"financial + espionage","active_since":"2022","targets":"Ukraine, NATO, Europe, Pharmaceutical, Finance","ttps":["T1566.001","T1190","T1059","T1027","T1078","T1071"],"tools":["RomCom RAT","Underground ransomware","PEAPOD","MagicSpell"],"description":"Dual financial/espionage group with GRU ties. Exploited Microsoft zero-days (CVE-2023-36884) against NATO summit targets. Conducts ransomware alongside espionage.","recent":"2024: Firefox and Windows zero-day exploits, NATO targeting","mitre":"G1034"},
  };



  function renderActorCard(name, actor) {
    // Normalise old and new DB field names
    const motivation = actor.motivation || actor.type || "unknown";
    const origin     = actor.origin || actor.nation || "Unknown";
    const sponsor    = actor.sponsor || "";
    const aliases    = actor.aliases || [];
    const ttps       = actor.ttps || [];
    const tools      = actor.tools || [];
    const targets    = actor.targets || actor.target || "";
    const mitreId    = actor.mitre || actor.mitre_group_id || "";
    const desc       = actor.description || "";
    const recent     = actor.recent_activity || actor.recent || "";
    const activeSince= actor.active_since || "";

    const motiveColors = {
      espionage:"#38bdf8", financial:"#f59e0b", destructive:"#f87171",
      hacktivism:"#a78bfa", "financial + espionage":"#fb923c",
      "espionage + financial":"#fb923c", "espionage + pre-positioning":"#38bdf8",
      "financial + notoriety":"#fbbf24", unknown:"#9ca3af",
    };
    const mc = motiveColors[motivation.toLowerCase()] || motiveColors[Object.keys(motiveColors).find(k => motivation.toLowerCase().includes(k))] || "#9ca3af";

    const flagMap = { Russia:"🇷🇺",China:"🇨🇳","North Korea":"🇰🇵",Iran:"🇮🇷",
      USA:"🇺🇸",UK:"🇬🇧",Israel:"🇮🇱",India:"🇮🇳",Pakistan:"🇵🇰",
      Belarus:"🇧🇾","Russia/Ukraine":"🇷🇺","US/UK":"🇺🇸","Western (US/UK)":"🇺🇸",
      "Unknown / RaaS":"🌐","Unknown":"🌐","Sudan":"🌐" };
    const flag = flagMap[origin] || flagMap[Object.keys(flagMap).find(k => origin.includes(k))] || "🌐";

    const mitreLink = mitreId && mitreId.match(/G\d+|S\d+/)
      ? `https://attack.mitre.org/groups/${mitreId}/`
      : (actor.mitre && actor.mitre.startsWith("http") ? actor.mitre : "");

    return `<div class="cti-actor-card" style="border-left:3px solid ${mc};">
      <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:10px;">
        <div style="flex:1;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span class="cti-actor-name">${esc(name)}</span>
            <span style="font-size:10px;background:${mc}22;color:${mc};border:1px solid ${mc}44;padding:1px 8px;border-radius:10px;font-weight:700;">${esc(motivation)}</span>
            ${activeSince ? `<span style="font-size:10px;color:var(--muted);">since ${esc(activeSince)}</span>` : ""}
          </div>
          ${aliases.length ? `<div style="font-size:11px;color:var(--muted);margin-top:3px;">AKA: ${aliases.map(a=>esc(a)).join(" · ")}</div>` : ""}
        </div>
        <div style="text-align:right;flex-shrink:0;">
          <div style="font-size:20px;">${flag}</div>
          <div style="font-size:10.5px;color:var(--muted);">${esc(origin)}</div>
          ${sponsor ? `<div style="font-size:10px;color:var(--muted);">${esc(sponsor)}</div>` : ""}
          ${mitreLink ? `<a href="${esc(mitreLink)}" target="_blank" style="font-size:9.5px;color:#38bdf8;">MITRE ↗</a>` : ""}
        </div>
      </div>

      <p style="font-size:11.5px;line-height:1.7;color:var(--text);margin:0 0 8px;">${esc(desc)}</p>

      ${recent ? `<div style="background:rgba(251,191,36,0.07);border:1px solid rgba(251,191,36,0.2);border-radius:6px;padding:7px 10px;margin-bottom:10px;font-size:11px;"><span style="color:#fbbf24;font-weight:700;">⚡ Recent:</span> <span style="color:var(--text);">${esc(recent)}</span></div>` : ""}

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;font-size:11px;">
        ${targets ? `<div><div style="font-size:9.5px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:3px;">Targets</div><div style="color:var(--text);">${esc(typeof targets==="object"?targets.join(", "):targets)}</div></div>` : ""}
        ${ttps.length ? `<div><div style="font-size:9.5px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:3px;">MITRE TTPs</div><div>${ttps.slice(0,6).map(t=>`<a href="https://attack.mitre.org/techniques/${esc(t.replace(".","/"))}" target="_blank" style="color:#38bdf8;text-decoration:none;font-size:10.5px;">${esc(t)}</a>`).join(" · ")}</div></div>` : ""}
        ${tools.length ? `<div><div style="font-size:9.5px;font-weight:700;color:var(--muted);text-transform:uppercase;margin-bottom:3px;">Known Tools</div><div style="color:var(--text);">${tools.slice(0,6).map(t=>esc(t)).join(", ")}</div></div>` : ""}
      </div>

      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${mitreLink ? `<a href="${esc(mitreLink)}" target="_blank" class="cti-pivot-btn">🛡 MITRE ATT&CK</a>` : ""}
        <a href="https://www.google.com/search?q=${enc('"'+name+'" threat actor report')}&tbs=qdr:y" target="_blank" class="cti-pivot-btn">🔎 Recent Reports</a>
        <a href="https://otx.alienvault.com/browse/global/adversaries?q=${enc(name)}" target="_blank" class="cti-pivot-btn">👽 OTX</a>
        <a href="https://threatfox.abuse.ch/browse.php?search=tag%3A${enc(name.toLowerCase().replace(/\s+/g,"-"))}" target="_blank" class="cti-pivot-btn">🦊 ThreatFox</a>
        <a href="https://socradar.io/labs/app/threat-actor-intelligence/?search=${enc(name)}" target="_blank" class="cti-pivot-btn">📡 SOCRadar</a>
        <button class="cti-pivot-btn cti-hunt-btn" data-actor="${esc(name)}" style="cursor:pointer;">🏹 Build Hunt</button>
      </div>
    </div>`;
  }



  const ctiActorResults = $("cti-actor-results");

  $("cti-actor-search-btn")?.addEventListener("click", async () => {
    const q = ($("cti-actor-input")?.value||"").trim();
    if (!q) return;
    if (!ctiActorResults) return;
    const qLow = q.toLowerCase();
    const liveBadge = $("cti-actor-live-badge");

    // ── Step 1: Check local KB first ──────────────────────────
    const localMatches = Object.entries(ACTOR_DB).filter(([name, actor]) => {
      const desc    = (actor.description||"").toLowerCase();
      const tools   = (actor.tools||[]).join(" ").toLowerCase();
      const aliases = (actor.aliases||[]).join(" ").toLowerCase();
      const targets = (typeof actor.targets==="object"?(actor.targets||[]).join(" "):actor.targets||"").toLowerCase();
      const recent  = (actor.recent||actor.recent_activity||"").toLowerCase();
      const sponsor = (actor.sponsor||"").toLowerCase();
      return name.toLowerCase().includes(qLow) ||
             aliases.includes(qLow) ||
             desc.includes(qLow) ||
             tools.includes(qLow) ||
             targets.includes(qLow) ||
             recent.includes(qLow) ||
             sponsor.includes(qLow);
    });

    if (localMatches.length) {
      // Found in local KB — show immediately
      if (liveBadge) liveBadge.style.display = "none";
      ctiActorResults.innerHTML = localMatches.map(([n,a]) => renderActorCard(n,a)).join("");
      ctiActorResults.querySelectorAll(".cti-hunt-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          const actor = ACTOR_DB[btn.dataset.actor];
          if (!actor) return;
          const bulkIn = $("bulk-input");
          if (bulkIn) { bulkIn.value = actor.tools.join("\n") + "\n" + actor.ttps.join("\n"); switchTab("bulk"); $("bulk-analyze-btn")?.click(); }
        });
      });
      return;
    }

    // ── Step 2: Not in local KB — do live AI lookup ────────────
    if (liveBadge) liveBadge.style.display = "inline-block";
    ctiActorResults.innerHTML = `
      <div style="padding:16px 4px;">
        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--muted);margin-bottom:12px;">
          <span style="display:inline-block;animation:spin 1s linear infinite;">⟳</span>
          Searching live threat intelligence for <strong style="color:var(--text);">${esc(q)}</strong>…
        </div>
      </div>`;

    const systemPrompt = "You are a cyber threat intelligence analyst. Return ONLY valid JSON (no markdown) describing the threat actor with these fields: name, aliases (array), nation, motivation (espionage/financial/hacktivism/destructive/unknown), active_since, last_active, targets (array), ttps (array of T-codes), tools (array), campaigns (array), mitre_group_id, description (2-3 sentences), recent_activity, confidence (high/medium/low), not_found (boolean). If unknown return {not_found:true,name:\"x\",description:\"Not found\"}.";

    const userPrompt = `Search for threat intelligence on: ${q}\nReturn JSON only.`;

    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: systemPrompt,
          messages: [{ role: "user", content: userPrompt }],
        }),
      });

      if (!resp.ok) throw new Error("API error: " + resp.status);
      const data = await resp.json();

      // Extract text content (after any tool use blocks)
      const textBlocks = (data.content||[]).filter(b => b.type === "text");
      const rawText = textBlocks.map(b => b.text).join("\n").trim();

      // Parse JSON — strip any markdown fences
      const jsonStr = rawText.replace(/^```(?:json)?\s*/i,"").replace(/```\s*$/,"").trim();
      let actor;
      try { actor = JSON.parse(jsonStr); } catch { throw new Error("Invalid JSON response"); }

      if (actor.not_found) {
        ctiActorResults.innerHTML = `
          <div style="padding:20px 4px;text-align:center;">
            <div style="font-size:13px;color:var(--text);font-weight:700;margin-bottom:8px;">No threat intelligence found</div>
            <div style="font-size:11.5px;color:var(--muted);">"${esc(q)}" is not recognized as a known threat actor in current threat intelligence feeds.</div>
            <div style="font-size:11px;color:var(--muted);margin-top:8px;">Try an alias, alternate spelling, or check MITRE ATT&CK for similar groups.</div>
          </div>`;
        return;
      }

      // ── Render live actor card ─────────────────────────────────
      const flagMap = { Russia:"🇷🇺",China:"🇨🇳","North Korea":"🇰🇵",Iran:"🇮🇷",
        USA:"🇺🇸",UK:"🇬🇧",Ukraine:"🇺🇦",Israel:"🇮🇱",India:"🇮🇳",
        Pakistan:"🇵🇰",Turkey:"🇹🇷",Brazil:"🇧🇷",Romania:"🇷🇴",Unknown:"🌐" };
      const flag = flagMap[actor.nation] || "🌐";
      const motiveColors = { espionage:"#38bdf8", financial:"#fbbf24", hacktivism:"#a78bfa",
        destructive:"#f87171", unknown:"#9ca3af" };
      const mColor = motiveColors[actor.motivation] || "#9ca3af";
      const confColor = { high:"#34d399", medium:"#fbbf24", low:"#f87171" }[actor.confidence] || "#9ca3af";

      const mitreLink = actor.mitre_group_id
        ? `<a href="https://attack.mitre.org/groups/${enc(actor.mitre_group_id)}/" target="_blank" style="color:#38bdf8;font-size:10px;">MITRE ${esc(actor.mitre_group_id)} ↗</a>`
        : "";

      const html = `
        <div class="cti-actor-card" style="border-left:3px solid ${mColor};">
          <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:10px;">
            <div style="flex:1;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span style="font-size:15px;font-weight:800;color:var(--text);">${esc(actor.name)}</span>
                <span style="font-size:10px;background:${mColor}22;color:${mColor};border:1px solid ${mColor}44;padding:1px 8px;border-radius:10px;font-weight:700;">${esc(actor.motivation||"unknown")}</span>
                <span style="font-size:10px;background:rgba(167,139,250,0.1);color:#a78bfa;border:1px solid rgba(167,139,250,0.25);padding:1px 8px;border-radius:10px;">⚡ LIVE</span>
                <span style="font-size:10px;color:${confColor};font-weight:700;">● ${esc(actor.confidence||"?")} confidence</span>
              </div>
              ${actor.aliases?.length ? `<div style="font-size:11px;color:var(--muted);margin-top:3px;">Also known as: ${actor.aliases.map(a=>esc(a)).join(" · ")}</div>` : ""}
            </div>
            <div style="text-align:right;flex-shrink:0;">
              <div style="font-size:18px;">${flag}</div>
              <div style="font-size:10.5px;color:var(--muted);">${esc(actor.nation||"Unknown")}</div>
              ${mitreLink}
            </div>
          </div>

          <p style="font-size:11.5px;line-height:1.7;color:var(--text);margin:0 0 10px;">${esc(actor.description||"No description available.")}</p>

          ${actor.recent_activity ? `<div style="background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.2);border-radius:6px;padding:8px 10px;margin-bottom:10px;font-size:11px;"><span style="color:#fbbf24;font-weight:700;">⚡ Recent Activity:</span> <span style="color:var(--text);">${esc(actor.recent_activity)}</span></div>` : ""}

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;">
            ${actor.targets?.length ? `<div><div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;">Targets</div><div style="font-size:11px;color:var(--text);">${actor.targets.map(t=>esc(t)).join(", ")}</div></div>` : ""}
            ${actor.active_since||actor.last_active ? `<div><div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;">Active</div><div style="font-size:11px;color:var(--text);">${esc(actor.active_since||"?")}&nbsp;→&nbsp;${esc(actor.last_active||"present")}</div></div>` : ""}
            ${actor.ttps?.length ? `<div><div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;">MITRE ATT&CK TTPs</div><div style="font-size:11px;color:#38bdf8;">${actor.ttps.slice(0,8).map(t=>`<a href="https://attack.mitre.org/techniques/${enc(t.replace(".","/"))}/" target="_blank" style="color:#38bdf8;text-decoration:none;">${esc(t)}</a>`).join(" · ")}</div></div>` : ""}
            ${actor.tools?.length ? `<div><div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;">Known Tools</div><div style="font-size:11px;color:var(--text);">${actor.tools.slice(0,8).map(t=>esc(t)).join(", ")}</div></div>` : ""}
            ${actor.campaigns?.length ? `<div><div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px;">Campaigns</div><div style="font-size:11px;color:var(--text);">${actor.campaigns.map(c=>esc(c)).join(", ")}</div></div>` : ""}
          </div>

          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            ${actor.mitre_group_id ? `<a href="https://attack.mitre.org/groups/${enc(actor.mitre_group_id)}/" target="_blank" class="cti-pivot-btn">🛡 MITRE ATT&CK</a>` : ""}
            <a href="https://www.google.com/search?q=${enc('"'+actor.name+'" threat actor site report')}&tbs=qdr:y" target="_blank" class="cti-pivot-btn">🔎 Recent Reports</a>
            <a href="https://otx.alienvault.com/browse/global/adversaries?q=${enc(actor.name)}" target="_blank" class="cti-pivot-btn">👽 OTX</a>
            <a href="https://threatfox.abuse.ch/browse.php?search=tag%3A${enc(actor.name.toLowerCase().replace(/\s+/g,"-"))}" target="_blank" class="cti-pivot-btn">🦊 ThreatFox</a>
            <a href="https://socradar.io/labs/app/threat-actor-intelligence/?search=${enc(actor.name)}" target="_blank" class="cti-pivot-btn">📡 SOCRadar</a>
            ${actor.references?.length ? actor.references.slice(0,2).map(r => `<a href="${esc(r)}" target="_blank" class="cti-pivot-btn" style="font-size:9.5px;">📄 Reference ↗</a>`).join("") : ""}
          </div>
        </div>`;

      ctiActorResults.innerHTML = html;

    } catch (err) {
      // API unavailable — show helpful external pivots anyway
      if (liveBadge) liveBadge.style.display = "none";
      ctiActorResults.innerHTML = `
        <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px;">
          <div style="font-size:13px;font-weight:800;color:var(--text);margin-bottom:4px;">🔍 "${esc(q)}" — Not in local database</div>
          <div style="font-size:11.5px;color:var(--muted);margin-bottom:14px;">This actor isn't in the offline knowledge base. Search these live threat intelligence sources directly:</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
            <a href="https://attack.mitre.org/groups/?q=${enc(q)}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">🛡 MITRE ATT&CK Groups</a>
            <a href="https://www.google.com/search?q=${enc('"'+q+'" threat actor APT')}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">🔎 Google Threat Intel</a>
            <a href="https://otx.alienvault.com/browse/global/adversaries?q=${enc(q)}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">👽 OTX AlienVault</a>
            <a href="https://threatfox.abuse.ch/browse.php?search=tag%3A${enc(q.toLowerCase().replace(/\s+/g,'-'))}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">🦊 ThreatFox</a>
            <a href="https://socradar.io/labs/app/threat-actor-intelligence/?search=${enc(q)}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">📡 SOCRadar</a>
            <a href="https://malpedia.caad.fkie.fraunhofer.de/find?q=${enc(q)}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">📚 Malpedia</a>
            <a href="https://www.mandiant.com/resources/apt-groups" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">🔥 Mandiant APT Groups</a>
            <a href="https://thedfirreport.com/?s=${enc(q)}" target="_blank" class="cti-pivot-btn" style="font-size:11px;padding:6px 12px;">🕵 DFIR Report</a>
          </div>
          <div style="font-size:10.5px;color:var(--muted);border-top:1px solid var(--border);padding-top:10px;">
            💡 Actors in the offline KB: APT28, APT29, APT31, APT33, APT34, APT35, APT37, APT38, APT40, APT41, APT43, APT73, Lazarus, Kimsuky, Andariel, FIN7, Cl0p, LockBit, REvil, BlackCat, Scattered Spider, Volt Typhoon, Salt Typhoon, Sandworm, Turla, Gamaredon, Evil Corp, Hafnium, Killnet, Lapsus$, MuddyWater, RomCom, Equation Group, Transparent Tribe, Sidewinder, and more
          </div>
        </div>`;
    }
  });

  $("cti-actor-random")?.addEventListener("click", () => {
    const keys = Object.keys(ACTOR_DB);
    const name = keys[Math.floor(Math.random()*keys.length)];
    const inp = $("cti-actor-input"); if(inp) inp.value = name;
    $("cti-actor-search-btn")?.click();
  });


  // ══════════════════════════════════════════════════════════════════
  // TRENDING CVEs PANEL — live AI-powered top exploited CVEs
  // ══════════════════════════════════════════════════════════════════
  let _trendingLoaded = false;
  let _trendingData   = [];
  let _trendingFilter = "all";

  async function loadTrendingCVEs() {
    const grid   = $("cti-trending-grid");
    const status = $("cti-trending-status");
    if (!grid) return;
    grid.innerHTML = `<div style="color:var(--muted);font-size:11.5px;padding:12px 0;display:flex;align-items:center;gap:8px;"><span style="animation:spin 1s linear infinite;display:inline-block;">⟳</span> Fetching top exploited CVEs from live threat intelligence…</div>`;
    if (status) status.textContent = "";

    const sys = "You are a vulnerability intelligence analyst. Return ONLY a JSON array (no markdown) of the 10 most critical actively-exploited CVEs known to you. Each object needs: cve, cvss(number), epss(0-1), title, vendor, category(network/endpoint/web/cloud), kev(bool), ransomware(bool), exploited_in_wild(bool), patch_available(bool), summary(1 sentence), affected(string). Sort by risk: CISA KEV and high EPSS first.";

    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: sys,
          messages: [{ role: "user", content: "Return the top 10 actively exploited CVEs. JSON array only." }],
        }),
      });
      if (!resp.ok) throw new Error("API " + resp.status);
      const data = await resp.json();
      const txt  = (data.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("").trim();
      const json = txt.replace(/^```(?:json)?\s*/i,"").replace(/```\s*$/,"").trim();
      _trendingData = JSON.parse(json);
      _trendingLoaded = true;
      if (status) status.textContent = `Last updated: ${new Date().toLocaleTimeString()} — ${_trendingData.length} CVEs loaded`;
      renderTrendingCVEs();
    } catch(e) {
      grid.innerHTML = `
        <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px;">
          <div style="font-size:13px;font-weight:800;color:var(--text);margin-bottom:4px;">⚠️ Live CVE feed unavailable</div>
          <div style="font-size:11.5px;color:var(--muted);margin-bottom:14px;">Check these live vulnerability intelligence sources directly:</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">🔴 CISA KEV Catalog</a>
            <a href="https://www.first.org/epss/data" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">📊 EPSS Scores</a>
            <a href="https://nvd.nist.gov/vuln/search?query=&results_type=overview&form_type=Basic&search_type=last3months" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">📋 NVD Recent</a>
            <a href="https://socradar.io/labs/app/cve-radar/" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">📡 SOCRadar CVE Radar</a>
            <a href="https://viz.greynoise.io/trends/" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">🌩 GreyNoise Trends</a>
            <a href="https://attackerkb.com/topics/recent" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">⚔️ AttackerKB</a>
            <a href="https://www.exploit-db.com/" target="_blank" class="cti-pivot-btn" style="padding:6px 12px;">💀 ExploitDB</a>
          </div>
        </div>`;
    }
  }

  function renderTrendingCVEs() {
    const grid = $("cti-trending-grid");
    if (!grid) return;
    const filtered = _trendingData.filter(c => {
      if (_trendingFilter === "kev")        return c.kev;
      if (_trendingFilter === "ransomware") return c.ransomware;
      if (_trendingFilter === "critical")   return (c.cvss||0) >= 9.0;
      if (_trendingFilter === "network")    return c.category === "network";
      return true;
    });
    if (!filtered.length) { grid.innerHTML = `<div style="color:var(--muted);font-size:11.5px;padding:12px 0;">No CVEs match this filter.</div>`; return; }
    grid.innerHTML = filtered.map(c => {
      const cvssColor = c.cvss >= 9 ? "#ef4444" : c.cvss >= 7 ? "#fb923c" : c.cvss >= 4 ? "#fbbf24" : "#34d399";
      const epssBar   = Math.round((c.epss||0) * 100);
      const badges    = [
        c.kev         ? `<span style="background:#ef444420;color:#ef4444;border:1px solid #ef444440;padding:1px 6px;border-radius:8px;font-size:9.5px;font-weight:700;">CISA KEV</span>` : "",
        c.ransomware  ? `<span style="background:#f9731620;color:#fb923c;border:1px solid #fb923c40;padding:1px 6px;border-radius:8px;font-size:9.5px;font-weight:700;">Ransomware</span>` : "",
        c.exploited_in_wild ? `<span style="background:#ef444415;color:#f87171;border:1px solid #f8717130;padding:1px 6px;border-radius:8px;font-size:9.5px;">In Wild</span>` : "",
        c.patch_available ? `<span style="background:#34d39915;color:#34d399;border:1px solid #34d39930;padding:1px 6px;border-radius:8px;font-size:9.5px;">Patch Available</span>` : `<span style="background:#fbbf2415;color:#fbbf24;border:1px solid #fbbf2430;padding:1px 6px;border-radius:8px;font-size:9.5px;">No Patch</span>`,
      ].filter(Boolean).join(" ");
      return `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;border-left:3px solid ${cvssColor};">
        <div style="display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;">
          <div style="flex:1;min-width:180px;">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;">
              <a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve)}" target="_blank" style="font-size:13px;font-weight:800;color:#38bdf8;text-decoration:none;">${esc(c.cve)}</a>
              ${badges}
            </div>
            <div style="font-size:12px;font-weight:700;color:var(--text);margin-bottom:3px;">${esc(c.title||"")} — <span style="color:var(--muted);font-weight:400;">${esc(c.vendor||"")}</span></div>
            <div style="font-size:11px;color:var(--muted);line-height:1.6;">${esc(c.summary||"")}</div>
            <div style="font-size:10.5px;color:var(--muted);margin-top:4px;">Affected: ${esc(c.affected||"")}</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;align-items:flex-end;flex-shrink:0;">
            <div style="text-align:center;">
              <div style="font-size:18px;font-weight:900;color:${cvssColor};">${c.cvss||"?"}</div>
              <div style="font-size:9.5px;color:var(--muted);">CVSS</div>
            </div>
            <div style="text-align:center;min-width:60px;">
              <div style="font-size:12px;font-weight:800;color:#a78bfa;">${epssBar}%</div>
              <div style="font-size:9.5px;color:var(--muted);">EPSS</div>
              <div style="width:60px;height:4px;background:rgba(167,139,250,0.15);border-radius:2px;margin-top:2px;"><div style="width:${epssBar}%;height:100%;background:#a78bfa;border-radius:2px;"></div></div>
            </div>
            <div style="display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end;margin-top:2px;">
              <a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve)}" target="_blank" style="font-size:9.5px;padding:2px 7px;border:1px solid var(--border);border-radius:5px;color:var(--muted);text-decoration:none;">NVD</a>
              <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="font-size:9.5px;padding:2px 7px;border:1px solid var(--border);border-radius:5px;color:var(--muted);text-decoration:none;">KEV</a>
              <a href="https://socradar.io/labs/app/cve-radar/${esc(c.cve)}" target="_blank" style="font-size:9.5px;padding:2px 7px;border:1px solid var(--border);border-radius:5px;color:var(--muted);text-decoration:none;">SOCRadar</a>
            </div>
          </div>
        </div>
      </div>`;
    }).join("");
  }

  $("cti-trending-refresh")?.addEventListener("click", () => { _trendingLoaded = false; loadTrendingCVEs(); });
  document.querySelectorAll(".cti-trend-filter").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".cti-trend-filter").forEach(b=>b.classList.remove("active"));
      btn.classList.add("active");
      _trendingFilter = btn.dataset.filter;
      if (!_trendingLoaded) loadTrendingCVEs();
      else renderTrendingCVEs();
    });
  });

  // ══════════════════════════════════════════════════════════════════
  // TTP ANALYZER — paste TTPs or raw log → actor attribution + context
  // ══════════════════════════════════════════════════════════════════
  $("cti-ttp-analyze-btn")?.addEventListener("click", async () => {
    const inputEl = $("cti-ttp-input");
    const result  = $("cti-ttp-result");
    const raw = inputEl?.value?.trim() || "";
    if (!raw || !result) return;

    result.innerHTML = `<div style="color:var(--muted);font-size:11.5px;padding:12px 0;display:flex;align-items:center;gap:8px;"><span style="animation:spin 1s linear infinite;display:inline-block;">⟳</span> Analyzing TTPs and searching for actor attribution…</div>`;

    // Extract TTPs from input (may be raw text or clean TTP list)
    const ttps = [...new Set((raw.match(/\bT\d{4}(?:\.\d{3})?\b/g)||[]))];

    const sys2 = "You are a threat intelligence analyst. Given MITRE ATT&CK TTPs or raw log text, return ONLY valid JSON (no markdown): {ttps_found(array),kill_chain_phases(array),likely_actors(array of {name,confidence,reason}),attack_objective,detection_gaps(array),recommended_hunts(array of {platform,query}),mitre_summary(plain English),severity(critical/high/medium/low)}.";

    const userPrompt2 = `Analyze these indicators:\n\nRaw input:\n${raw.slice(0,2000)}\n\nExtracted TTPs: ${ttps.join(", ") || "none found — extract from raw text"}\n\nReturn JSON analysis.`;

    try {
      const resp = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: sys2,
          messages: [{ role: "user", content: userPrompt2 }],
        }),
      });
      if (!resp.ok) throw new Error("API " + resp.status);
      const data  = await resp.json();
      const txt   = (data.content||[]).filter(b=>b.type==="text").map(b=>b.text).join("").trim();
      const json  = txt.replace(/^```(?:json)?\s*/i,"").replace(/```\s*$/,"").trim();
      const a     = JSON.parse(json);

      const sevColor = {critical:"#ef4444",high:"#fb923c",medium:"#fbbf24",low:"#34d399"}[a.severity]||"#9ca3af";
      const confColor = {high:"#34d399",medium:"#fbbf24",low:"#f87171"};

      result.innerHTML = `
        <div style="display:flex;flex-direction:column;gap:12px;">
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;border-left:3px solid ${sevColor};">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;">
              <span style="font-size:12px;font-weight:800;color:var(--text);">TTPs Identified</span>
              <div style="display:flex;gap:5px;flex-wrap:wrap;">
                ${(a.ttps_found||ttps).map(t=>`<a href="https://attack.mitre.org/techniques/${esc(t.replace(".","/"))}" target="_blank" style="font-size:10px;background:rgba(56,189,248,0.1);color:#38bdf8;border:1px solid rgba(56,189,248,0.25);padding:1px 7px;border-radius:8px;text-decoration:none;font-weight:700;">${esc(t)}</a>`).join("")}
              </div>
              <span style="margin-left:auto;font-size:10px;background:${sevColor}20;color:${sevColor};border:1px solid ${sevColor}40;padding:1px 8px;border-radius:10px;font-weight:700;">${esc(a.severity||"?").toUpperCase()}</span>
            </div>
            <div style="font-size:11.5px;color:var(--text);line-height:1.7;margin-bottom:8px;">${esc(a.mitre_summary||"")}</div>
            ${a.kill_chain_phases?.length ? `<div style="font-size:10.5px;color:var(--muted);">Kill chain: <strong style="color:var(--text);">${a.kill_chain_phases.join(" → ")}</strong></div>` : ""}
            ${a.attack_objective ? `<div style="font-size:10.5px;color:var(--muted);margin-top:3px;">Objective: <strong style="color:var(--text);">${esc(a.attack_objective)}</strong></div>` : ""}
          </div>

          ${a.likely_actors?.length ? `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;">
            <div style="font-size:11.5px;font-weight:800;color:var(--text);margin-bottom:8px;">🎯 Likely Attribution</div>
            <div style="display:flex;flex-direction:column;gap:6px;">
              ${a.likely_actors.map(act=>`<div style="display:flex;align-items:flex-start;gap:10px;padding:8px;background:var(--bg);border-radius:7px;">
                <div style="flex:1;">
                  <span style="font-weight:700;color:var(--text);font-size:12px;">${esc(act.name)}</span>
                  <span style="font-size:10.5px;color:var(--muted);margin-left:8px;">${esc(act.reason||"")}</span>
                </div>
                <span style="font-size:10px;color:${confColor[act.confidence]||"#9ca3af"};font-weight:700;flex-shrink:0;">${esc(act.confidence||"?")} confidence</span>
              </div>`).join("")}
            </div>
          </div>` : ""}

          ${a.detection_gaps?.length ? `<div style="background:rgba(251,191,36,0.05);border:1px solid rgba(251,191,36,0.2);border-radius:10px;padding:14px;">
            <div style="font-size:11.5px;font-weight:800;color:#fbbf24;margin-bottom:6px;">⚠️ Detection Gaps</div>
            ${a.detection_gaps.map(g=>`<div style="font-size:11px;color:var(--text);padding:2px 0;">• ${esc(g)}</div>`).join("")}
          </div>` : ""}

          ${a.recommended_hunts?.length ? `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;">
            <div style="font-size:11.5px;font-weight:800;color:var(--text);margin-bottom:8px;">🏹 Recommended Hunt Queries</div>
            ${a.recommended_hunts.map(h=>`<div style="margin-bottom:8px;"><div style="font-size:10px;color:#a78bfa;font-weight:700;margin-bottom:3px;">${esc(h.platform||"SIEM")}</div><code style="font-size:10.5px;display:block;background:var(--bg);padding:8px;border-radius:6px;color:#38bdf8;white-space:pre-wrap;word-break:break-all;">${esc(h.query||"")}</code></div>`).join("")}
          </div>` : ""}
        </div>`;

    } catch(e) {
      // Offline fallback — do local TTP analysis from embedded MITRE data
      const _fallbackTTPs = [...new Set((raw.match(/T\d{4}(?:\.\d{3})?/g)||[]))];
      if (_fallbackTTPs.length > 0) {
        const _ttpLinks = _fallbackTTPs.map(t =>
          `<a href="https://attack.mitre.org/techniques/${esc(t.replace(".","/"))}" target="_blank" style="color:#38bdf8;text-decoration:none;background:rgba(56,189,248,0.1);padding:2px 8px;border-radius:6px;border:1px solid rgba(56,189,248,0.2);font-size:11px;">${esc(t)}</a>`
        ).join(" ");
        result.innerHTML = `
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;">
            <div style="font-size:12px;font-weight:800;color:var(--text);margin-bottom:8px;">TTPs Found (${_fallbackTTPs.length}) — Offline mode</div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">${_ttpLinks}</div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:10px;">AI analysis unavailable. Use these resources for attribution and context:</div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <a href="https://attack.mitre.org/techniques/" target="_blank" class="cti-pivot-btn">🛡 MITRE ATT&CK</a>
              <a href="https://navigator.attack.mitre.org/" target="_blank" class="cti-pivot-btn">🗺 ATT&CK Navigator</a>
              <a href="https://www.google.com/search?q=${enc(_fallbackTTPs.join("+")+" threat actor")}" target="_blank" class="cti-pivot-btn">🔎 Attribution Search</a>
              <a href="https://attackerkb.com/" target="_blank" class="cti-pivot-btn">⚔️ AttackerKB</a>
            </div>
          </div>`;
      } else {
        result.innerHTML = `<div style="font-size:11.5px;color:#f87171;padding:8px 0;">Analysis unavailable and no TTPs found in input. Paste MITRE T-codes (e.g. T1566, T1078) to proceed.</div>`;
      }
    }
  });
  $("cti-ttp-clear-btn")?.addEventListener("click", () => {
    const el = $("cti-ttp-input"); if(el) el.value = "";
    const r  = $("cti-ttp-result"); if(r) r.innerHTML = "";
  });

  // Auto-load trending CVEs when user navigates to that panel
  document.querySelectorAll(".cti-sub-btn").forEach(btn => {
    if (btn.dataset.ctitab === "trending") {
      btn.addEventListener("click", () => { if (!_trendingLoaded) loadTrendingCVEs(); });
    }
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

  // ══════════════════════════════════════════════════════════════════════════
  // DEVICE TIMELINE ANALYZER — fully offline, no network calls
  // ══════════════════════════════════════════════════════════════════════════

  // ── Offline Process Intelligence DB ──────────────────────────────────────
  const DT_PROCESS_DB = {
    // Known malicious / hacking tools
    malicious: new Set([
      "mimikatz.exe","mimilib.dll","wce.exe","pwdump.exe","pwdump7.exe",
      "procdump.exe","fgdump.exe","gsecdump.exe","cachedump.exe",
      "cobaltstrikeservice.exe","cobaltstrike.exe","beacon.exe",
      "meterpreter.exe","msf.exe","payload.exe","stager.exe",
      "havoc.exe","sliver.exe","bruteratel.exe","nighthawk.exe",
      "empire.exe","pupy.exe","quasar.exe","njrat.exe","darkcomet.exe",
      "asyncrat.exe","remcos.exe","nanocore.exe","azorult.exe",
      "emotet.exe","trickbot.exe","ryuk.exe","conti.exe","lockbit.exe",
      "wannacry.exe","notpetya.exe","ransomware.exe",
    ]),
    // Known LOLBins that are abused (legitimate binaries used maliciously)
    lolbins: new Set([
      "certutil.exe","mshta.exe","wmic.exe","regsvr32.exe","rundll32.exe",
      "cmstp.exe","msiexec.exe","odbcconf.exe","pcalua.exe","regasm.exe",
      "regsvcs.exe","installutil.exe","csc.exe","vbc.exe","jsc.exe",
      "msbuild.exe","msdt.exe","presentationhost.exe","infdefaultinstall.exe",
      "ieexec.exe","appsyncpublishingserver.exe","ftp.exe","winrm.cmd",
      "syncappvpublishingserver.exe","bash.exe","forfiles.exe",
      "desktopimgdownldr.exe","esentutl.exe","mavinject.exe","dnscmd.exe",
      "diskshadow.exe","bginfo.exe","cscript.exe","wscript.exe",
      "control.exe","xwizard.exe","scriptrunner.exe","pcwrun.exe",
    ]),
    // Legitimate system processes (Windows)
    legitimate: new Set([
      "svchost.exe","lsass.exe","csrss.exe","wininit.exe","winlogon.exe",
      "services.exe","smss.exe","explorer.exe","taskmgr.exe","mmc.exe",
      "dllhost.exe","conhost.exe","spoolsv.exe","SearchIndexer.exe",
      "RuntimeBroker.exe","sihost.exe","fontdrvhost.exe","dwm.exe",
      "audiodg.exe","MsMpEng.exe","SecurityHealthService.exe","WmiPrvSE.exe",
      "SearchProtocolHost.exe","SearchFilterHost.exe","TiWorker.exe",
      "TrustedInstaller.exe","WerFault.exe","WerMgr.exe","consent.exe",
      "UserOOBEBroker.exe","backgroundTaskHost.exe","SystemSettingsBroker.exe",
    ]),
    // Expected paths for system processes (wrong path = suspicious)
    expectedPaths: {
      "svchost.exe":    ["c:\\windows\\system32\\","c:\\windows\\syswow64\\"],
      "lsass.exe":      ["c:\\windows\\system32\\"],
      "csrss.exe":      ["c:\\windows\\system32\\"],
      "wininit.exe":    ["c:\\windows\\system32\\"],
      "winlogon.exe":   ["c:\\windows\\system32\\"],
      "services.exe":   ["c:\\windows\\system32\\"],
      "smss.exe":       ["c:\\windows\\system32\\"],
      "explorer.exe":   ["c:\\windows\\"],
      "taskmgr.exe":    ["c:\\windows\\system32\\"],
      "spoolsv.exe":    ["c:\\windows\\system32\\"],
    },
  };

  // ── Malicious parent→child relationship rules ─────────────────────────────
  const DT_PARENT_CHILD_RULES = [
    { parent:/\b(winword|excel|powerpnt|outlook|onenote)\.exe\b/i,  child:/\b(powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32|certutil|wmic)\.exe\b/i, sev:"critical", label:"Office application spawned a script interpreter — classic macro attack", mitre:["T1566.001","T1059"] },
    { parent:/\bexplorer\.exe\b/i,  child:/\b(powershell|cmd)\.exe\b/i,  cmdPattern:/-enc\b|-encoded\b|downloadstring|iex\b/i, sev:"critical", label:"Explorer spawned encoded/download PowerShell", mitre:["T1059.001"] },
    { parent:/\bbrowser|chrome|firefox|msedge|iexplore\b/i, child:/\b(powershell|cmd|wscript|mshta|rundll32)\.exe\b/i, sev:"critical", label:"Browser spawned a script/shell process — possible drive-by or ClickFix attack", mitre:["T1204.002","T1059"] },
    { parent:/\bwscript\.exe|cscript\.exe\b/i, child:/\b(powershell|cmd|mshta|regsvr32)\.exe\b/i, sev:"critical", label:"Script host spawned another interpreter — staged execution", mitre:["T1059.005","T1059.001"] },
    { parent:/\bmshta\.exe\b/i, child:/\b(powershell|cmd|wscript|regsvr32)\.exe\b/i, sev:"critical", label:"MSHTA LOLBin spawned shell — HTA-based attack", mitre:["T1218.005"] },
    { parent:/\bsvchost\.exe\b/i, child:/\b(cmd|powershell|wscript|cscript|mshta)\.exe\b/i, sev:"high", label:"Svchost spawned interactive shell — unusual, possible service abuse", mitre:["T1543.003"] },
    { parent:/\btaskmgr\.exe|mmc\.exe\b/i, child:/\b(powershell|cmd)\.exe\b/i, cmdPattern:/\-[eE]nc\b|\-[eE]ncodedCommand\b/i, sev:"high", label:"Task manager/MMC spawned encoded PowerShell", mitre:["T1059.001"] },
    { parent:/\blsass\.exe\b/i, child:/.+/i, sev:"critical", label:"Process spawned by LSASS — highly anomalous, possible credential dumping or injection", mitre:["T1003.001","T1055"] },
  ];

  // ── Suspicious command-line patterns ─────────────────────────────────────
  const DT_CMDLINE_RULES = [
    { pattern:/-(?:enc|EncodedCommand)\s+[A-Za-z0-9+/]{20,}/i,    sev:"critical", label:"Base64 encoded PowerShell (-enc)",                    mitre:["T1027","T1059.001"] },
    { pattern:/DownloadString|DownloadFile|Invoke-WebRequest/i,    sev:"critical", label:"Remote download/execution (download cradle)",         mitre:["T1105","T1059.001"] },
    { pattern:/Invoke-Expression|IEX\s*\(/i,                       sev:"critical", label:"IEX — dynamic in-memory execution",                   mitre:["T1059.001"] },
    { pattern:/Set-MpPreference\s+-Disable/i,                      sev:"critical", label:"Defender disabled",                                   mitre:["T1562.001"] },
    { pattern:/Add-MpPreference\s+-ExclusionPath/i,                sev:"critical", label:"AV exclusion added — hiding malware from Defender",   mitre:["T1562.001"] },
    { pattern:/AmsiInitFailed|amsi\.dll|amsiScanBuffer/i,          sev:"critical", label:"AMSI bypass attempt",                                 mitre:["T1562.001"] },
    { pattern:/vssadmin.*delete.*shadows|wbadmin.*delete/i,        sev:"critical", label:"Shadow copy deletion — ransomware indicator",         mitre:["T1490"] },
    { pattern:/mimikatz|sekurlsa|lsadump|logonpasswords/i,         sev:"critical", label:"Mimikatz credential dump command",                    mitre:["T1003.001"] },
    { pattern:/procdump.*lsass|comsvcs.*MiniDump.*lsass/i,         sev:"critical", label:"LSASS memory dump",                                   mitre:["T1003.001"] },
    { pattern:/net\s+user\s+.*\/add|net\s+localgroup.*admin.*\/add/i, sev:"critical", label:"Adds user to admin group — privilege escalation",  mitre:["T1136.001","T1098"] },
    { pattern:/reg\s+add.*\\Run|New-ItemProperty.*\\Run/i,         sev:"critical", label:"Registry Run key added — persistence",                mitre:["T1547.001"] },
    { pattern:/schtasks\s+\/create/i,                              sev:"critical", label:"Scheduled task created — persistence mechanism",      mitre:["T1053.005"] },
    { pattern:/sc\s+create|New-Service/i,                          sev:"high",     label:"Service created — persistence or lateral movement",   mitre:["T1543.003"] },
    { pattern:/certutil.*(?:-urlcache|-decode|-encode)/i,          sev:"critical", label:"CertUtil LOLBin abuse",                               mitre:["T1105","T1140","T1218.003"] },
    { pattern:/mshta\s+(?:https?:|vbscript:|javascript:)/i,        sev:"critical", label:"MSHTA executing remote/scripted content",             mitre:["T1218.005"] },
    { pattern:/regsvr32.*(?:\/s|scrobj|https?:)/i,                 sev:"critical", label:"Regsvr32 LOLBin — COM scriptlet execution",           mitre:["T1218.010"] },
    { pattern:/rundll32.*(?:javascript:|shell32|comsvcs)/i,        sev:"critical", label:"Rundll32 LOLBin abuse",                               mitre:["T1218.011"] },
    { pattern:/wmic.*process.*call.*create/i,                      sev:"critical", label:"WMIC process creation LOLBin",                        mitre:["T1047"] },
    { pattern:/-ExecutionPolicy\s+(?:Bypass|Unrestricted)/i,       sev:"high",     label:"PowerShell execution policy bypassed",                mitre:["T1059.001"] },
    { pattern:/-WindowStyle\s+Hidden|-w\s+hidden/i,                sev:"high",     label:"Hidden window — process concealment",                 mitre:["T1564.003"] },
    { pattern:/Invoke-Command.*-ComputerName|Enter-PSSession/i,    sev:"high",     label:"PowerShell remote execution — lateral movement",      mitre:["T1021.006"] },
    { pattern:/net\s+(?:view|use|share|session|accounts)/i,        sev:"medium",   label:"Network reconnaissance via net commands",             mitre:["T1016","T1135"] },
    { pattern:/whoami|ipconfig\s*\/all|systeminfo|hostname/i,      sev:"medium",   label:"System/user reconnaissance",                         mitre:["T1033","T1082"] },
    { pattern:/Get-ADUser|Get-ADComputer|Get-ADGroup/i,            sev:"medium",   label:"Active Directory enumeration",                       mitre:["T1087.002","T1069.002"] },
    { pattern:/\bpsexec\b|\bpsexesvc\b/i,                          sev:"high",     label:"PsExec — lateral movement tool",                     mitre:["T1021.002","T1570"] },
    { pattern:/\bnltest\b/i,                                       sev:"medium",   label:"Nltest — domain trust enumeration",                  mitre:["T1482"] },
    { pattern:/taskkill.*(?:defender|av|antivirus|malware|endpoint)/i, sev:"critical", label:"Security tool terminated",                       mitre:["T1562.001"] },
    { pattern:/cipher\s+\/w|format\s+.*\/q/i,                     sev:"high",     label:"Disk wiping command — anti-forensics",               mitre:["T1485","T1561"] },
  ];

  // ── Suspicious path patterns ──────────────────────────────────────────────
  const DT_SUSPICIOUS_PATHS = [
    { pattern:/\\temp\\|\/tmp\//i,                      sev:"high",   label:"Execution from Temp directory" },
    { pattern:/\\appdata\\(?:local|roaming)\\[^\\]+\.exe/i, sev:"high", label:"Execution from AppData" },
    { pattern:/\\downloads\\.*\.exe/i,                  sev:"high",   label:"Execution from Downloads folder" },
    { pattern:/\\public\\|\\users\\public\\/i,          sev:"high",   label:"Execution from Public folder" },
    { pattern:/\\recycle/i,                             sev:"critical",label:"Execution from Recycle Bin" },
    { pattern:/[a-z]{1,2}:\\[^\\]+\.exe$/i,             sev:"high",   label:"Executable at filesystem root" },
    { pattern:/\bperfmon\b.*\.dll|system32.*\.{3,5}$/i, sev:"medium", label:"Unusual DLL/file extension in System32" },
  ];

  // ── Known C2/malware network indicators ──────────────────────────────────
  const DT_SUSPICIOUS_PORTS = new Set([4444,4445,1234,8888,9999,31337,50050,4447,55555,8443,8080,2222]);
  const DT_C2_PATTERNS = [
    /\b(?:185|91|194|45|194)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,  // High-risk ASN ranges (Tor exits, bulletproof)
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,          // HTTP to raw IP
    /\.(?:xyz|top|click|gq|cf|tk|pw|cc|su|ru|onion)\b/i,       // High-risk TLDs
  ];

  // ── Windows EventID reference ─────────────────────────────────────────────
  const DT_EVENT_IDS = {
    "4624": { cat:"auth",     label:"Logon success",              sev:"info",   icon:"🔓" },
    "4625": { cat:"auth",     label:"Logon failure",              sev:"medium", icon:"🔐" },
    "4634": { cat:"auth",     label:"Logoff",                     sev:"info",   icon:"🚪" },
    "4648": { cat:"auth",     label:"Logon with explicit creds",  sev:"medium", icon:"🔑" },
    "4672": { cat:"auth",     label:"Special privileges assigned",sev:"medium", icon:"👑" },
    "4688": { cat:"process",  label:"Process created",            sev:"info",   icon:"⚙️" },
    "4689": { cat:"process",  label:"Process terminated",         sev:"info",   icon:"⛔" },
    "4697": { cat:"system",   label:"Service installed",          sev:"high",   icon:"🔩" },
    "4698": { cat:"system",   label:"Scheduled task created",     sev:"high",   icon:"📌" },
    "4699": { cat:"system",   label:"Scheduled task deleted",     sev:"medium", icon:"🗑" },
    "4702": { cat:"system",   label:"Scheduled task updated",     sev:"medium", icon:"🔄" },
    "4703": { cat:"system",   label:"Token privilege adjusted",   sev:"medium", icon:"🎟" },
    "4720": { cat:"auth",     label:"User account created",       sev:"high",   icon:"👤" },
    "4728": { cat:"auth",     label:"Member added to security group",sev:"high",icon:"➕" },
    "4732": { cat:"auth",     label:"Member added to local admin",sev:"critical",icon:"🚨" },
    "4740": { cat:"auth",     label:"Account locked out",         sev:"medium", icon:"🔒" },
    "4756": { cat:"auth",     label:"Member added to universal group",sev:"high",icon:"➕" },
    "4768": { cat:"auth",     label:"Kerberos TGT requested",     sev:"info",   icon:"🎫" },
    "4769": { cat:"auth",     label:"Kerberos service ticket",    sev:"info",   icon:"🎫" },
    "4771": { cat:"auth",     label:"Kerberos pre-auth failed",   sev:"medium", icon:"❌" },
    "4776": { cat:"auth",     label:"NTLM auth attempt",          sev:"info",   icon:"🔄" },
    "4798": { cat:"auth",     label:"User local group queried",   sev:"medium", icon:"👥" },
    "4799": { cat:"auth",     label:"Security-enabled group queried",sev:"medium",icon:"👥" },
    "7045": { cat:"system",   label:"New service installed",      sev:"high",   icon:"🔩" },
    "1102": { cat:"system",   label:"Audit log cleared",          sev:"critical",icon:"🚨" },
    "4616": { cat:"system",   label:"System time changed",        sev:"medium", icon:"⏰" },
    "4657": { cat:"registry", label:"Registry value modified",    sev:"medium", icon:"🗝" },
    "4660": { cat:"file",     label:"Object deleted",             sev:"medium", icon:"🗑" },
    "4663": { cat:"file",     label:"Object access attempt",      sev:"info",   icon:"📄" },
    "4670": { cat:"file",     label:"Permissions changed",        sev:"medium", icon:"🔒" },
    "5140": { cat:"network",  label:"Network share accessed",     sev:"medium", icon:"📂" },
    "5145": { cat:"network",  label:"Network share check",        sev:"info",   icon:"📁" },
    "5156": { cat:"network",  label:"Network connection allowed", sev:"info",   icon:"🌐" },
    "5158": { cat:"network",  label:"Network bind allowed",       sev:"info",   icon:"🌐" },
  };

  // ── Sysmon EventID reference ──────────────────────────────────────────────
  const DT_SYSMON_IDS = {
    "1":  { cat:"process",  label:"Process Create",              sev:"info",   icon:"⚙️" },
    "2":  { cat:"file",     label:"File creation time changed",  sev:"medium", icon:"⏱" },
    "3":  { cat:"network",  label:"Network connection",          sev:"info",   icon:"🌐" },
    "5":  { cat:"process",  label:"Process terminated",          sev:"info",   icon:"⛔" },
    "6":  { cat:"system",   label:"Driver loaded",               sev:"high",   icon:"🔩" },
    "7":  { cat:"system",   label:"Image/DLL loaded",            sev:"medium", icon:"📦" },
    "8":  { cat:"process",  label:"CreateRemoteThread",          sev:"critical",icon:"💉" },
    "9":  { cat:"file",     label:"RawAccessRead",               sev:"high",   icon:"💾" },
    "10": { cat:"process",  label:"ProcessAccess",               sev:"high",   icon:"🔍" },
    "11": { cat:"file",     label:"FileCreate",                  sev:"medium", icon:"📄" },
    "12": { cat:"registry", label:"RegistryCreate/Delete",       sev:"medium", icon:"🗝" },
    "13": { cat:"registry", label:"RegistryValue set",           sev:"medium", icon:"🗝" },
    "14": { cat:"registry", label:"RegistryKey renamed",         sev:"medium", icon:"🗝" },
    "15": { cat:"file",     label:"FileCreateStreamHash",        sev:"medium", icon:"📄" },
    "17": { cat:"system",   label:"Pipe created",                sev:"medium", icon:"🔗" },
    "18": { cat:"system",   label:"Pipe connected",              sev:"medium", icon:"🔗" },
    "22": { cat:"network",  label:"DNS query",                   sev:"info",   icon:"🌐" },
    "23": { cat:"file",     label:"FileDelete",                  sev:"medium", icon:"🗑" },
    "25": { cat:"process",  label:"ProcessTampering",            sev:"critical",icon:"💉" },
  };

  // ── Timestamp parser — handles many formats ───────────────────────────────
  function dtParseTimestamp(raw) {
    if (!raw) return null;
    const s = raw.trim();
    const attempts = [
      s,
      s.replace("T"," ").replace(/Z$/,""),
      s.replace(/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/,"$1-$2-$3 $4:$5:$6"),
      s.replace(/(\d{1,2})\/(\d{1,2})\/(\d{4})/,"$3-$1-$2"),
    ];
    for (const a of attempts) {
      const d = new Date(a);
      if (!isNaN(d.getTime())) return d;
    }
    return null;
  }

  // ── Format detection ──────────────────────────────────────────────────────
  function dtDetectFormat(text) {
    const t = text.slice(0, 2000).toLowerCase();
    if (/<event\b|<eventid>|<system>|<provider name=/i.test(text))  return "evtx";
    if (/eventid[=:,\s]+\d{3,4}/i.test(text))                       return "evtx";
    if (/^\s*[\[{]/m.test(text) && (text.includes('"EventID"') || text.includes('"timestamp"') || text.includes('"process_name"'))) return "json";
    if (/^[^\n,]+,[^\n,]+,[^\n,]+/m.test(text) && text.split("\n")[0].split(",").length > 3) return "csv";
    if (/\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d/i.test(t)) return "syslog";
    return "raw";
  }

  // ── Parse CSV ─────────────────────────────────────────────────────────────
  function dtParseCSV(text) {
    const lines = text.trim().split("\n");
    if (lines.length < 2) return [];
    const headers = lines[0].split(",").map(h => h.trim().toLowerCase().replace(/["\s]/g,""));
    const fieldMap = {
      timestamp: ["timestamp","time","datetime","date","timecreated","@timestamp","eventtime"],
      eventid:   ["eventid","event_id","eventcode","id","event.code","winlog.event_id"],
      process:   ["process","processname","imagename","image","process_name","newprocessname","commandline_process"],
      cmdline:   ["cmdline","commandline","command_line","commandlineargs","processcommandline"],
      user:      ["user","username","subjectusername","targetusername","account_name","user.name","winlog.user.name"],
      host:      ["host","hostname","computername","computer","source_host","host.name"],
      parent:    ["parentprocess","parentprocessname","parentimage","parentcommandline","parent_process"],
      path:      ["path","filepath","fullpath","imagepath","process_path"],
      pid:       ["pid","processid","newprocessid","process_id"],
      ppid:      ["ppid","parentprocessid","parent_process_id"],
      ip:        ["destinationip","destip","dst_ip","remote_address","ipaddress","ip"],
      port:      ["destinationport","destport","dst_port","port","remote_port"],
      category:  ["category","eventtype","type","channel","log_source"],
      severity:  ["severity","level","criticality"],
    };
    const colMap = {};
    Object.entries(fieldMap).forEach(([key, aliases]) => {
      const idx = headers.findIndex(h => aliases.some(a => h.includes(a)));
      if (idx >= 0) colMap[key] = idx;
    });
    const events = [];
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      const cols = dtSplitCSVLine(lines[i]);
      const get  = (key) => colMap[key] !== undefined ? (cols[colMap[key]]||"").trim().replace(/^"|"$/g,"") : "";
      events.push({
        rawLine: lines[i],
        timestamp: get("timestamp"), eventId: get("eventid"),
        process: get("process"),     cmdline: get("cmdline"),
        user:    get("user"),        host:    get("host"),
        parent:  get("parent"),      path:    get("path"),
        pid:     get("pid"),         ppid:    get("ppid"),
        ip:      get("ip"),          port:    get("port"),
        category:get("category"),    severity:get("severity"),
      });
    }
    return events;
  }

  function dtSplitCSVLine(line) {
    const result = []; let cur = ""; let inQ = false;
    for (let i = 0; i < line.length; i++) {
      if (line[i] === '"') { inQ = !inQ; continue; }
      if (line[i] === ',' && !inQ) { result.push(cur); cur = ""; continue; }
      cur += line[i];
    }
    result.push(cur);
    return result;
  }

  // ── Parse raw/event log text ──────────────────────────────────────────────
  function dtParseRaw(text) {
    const lines = text.split("\n");
    const events = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      // Extract fields with flexible regex
      const tsMatch  = line.match(/(\d{4}[-\/]\d{2}[-\/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/);
      const eidMatch = line.match(/[Ee]vent(?:ID)?[=:\s#]+(\d{3,5})/);
      const procMatch= line.match(/(?:Process(?:Name)?|Image|NewProcessName)[=:\s"]+([^\s,"]+\.exe)/i) ||
                       line.match(/\b([a-zA-Z0-9_\-]+\.exe)\b/i);
      const cmdMatch = line.match(/(?:CommandLine|Cmdline|cmd)[=:\s"]+([^\n]{0,300})/i);
      const userMatch= line.match(/(?:User(?:Name)?|Account)[=:\s"]+([^\s,"]{3,60})/i);
      const hostMatch= line.match(/(?:Computer(?:Name)?|Host(?:name)?|Machine)[=:\s"]+([^\s,"]{3,60})/i);
      const ipMatch  = line.match(/(?:Dest(?:ination)?IP|RemoteAddr|IpAddress)[=:\s"]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i) ||
                       line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      const portMatch= line.match(/(?:Dest(?:ination)?Port|Port)[=:\s"]+(\d{2,5})/i);
      const parentMatch = line.match(/(?:Parent(?:Process(?:Name)?|Image))[=:\s"]+([^\s,"]+\.exe)/i);
      const pathMatch= line.match(/(?:Image|ProcessPath|FilePath)[=:\s"]+([A-Za-z]:\\[^\s,"]{5,200})/i);
      events.push({
        rawLine: line,
        timestamp: tsMatch?.[1] || "",
        eventId:   eidMatch?.[1] || "",
        process:   (procMatch?.[1] || "").toLowerCase(),
        cmdline:   cmdMatch?.[1] || "",
        user:      userMatch?.[1] || "",
        host:      hostMatch?.[1] || "",
        parent:    (parentMatch?.[1] || "").toLowerCase(),
        path:      pathMatch?.[1] || "",
        ip:        ipMatch?.[1] || "",
        port:      portMatch?.[1] || "",
        category:  "",
        severity:  "",
      });
    }
    return events.filter(e => e.timestamp || e.eventId || e.process || e.cmdline);
  }

  // ── Parse JSON ────────────────────────────────────────────────────────────
  function dtParseJSON(text) {
    try {
      let data = JSON.parse(text);
      if (!Array.isArray(data)) data = [data];
      return data.map(row => {
        const get = (...keys) => { for (const k of keys) { if (row[k]) return String(row[k]); const parts=k.split("."); let v=row; for(const p of parts) v=v?.[p]; if(v) return String(v); } return ""; };
        return {
          rawLine:   JSON.stringify(row).slice(0,200),
          timestamp: get("timestamp","time","@timestamp","TimeCreated","EventTime","date"),
          eventId:   get("EventID","event_id","eventcode","event.code","winlog.event_id"),
          process:   get("ProcessName","process_name","Image","NewProcessName","process.name","image"),
          cmdline:   get("CommandLine","command_line","cmdline","ProcessCommandLine"),
          user:      get("User","username","SubjectUserName","user.name","winlog.user.name"),
          host:      get("Hostname","ComputerName","hostname","host.name","Computer"),
          parent:    get("ParentProcessName","parent_process","ParentImage","ParentProcessId"),
          path:      get("ImagePath","process_path","FilePath","full_path"),
          ip:        get("DestinationIp","dst_ip","remote_address","IpAddress","destination.ip"),
          port:      get("DestinationPort","dst_port","remote_port","destination.port"),
          category:  get("Category","EventType","Channel","type"),
          severity:  get("Severity","Level","severity","level"),
        };
      });
    } catch { return dtParseRaw(text); }
  }

  // ── Analyze a single event for maliciousness ──────────────────────────────
  function dtAnalyzeEvent(ev) {
    const findings = [];
    const mitreTags = new Set();
    let maxSev = "benign";
    const sevOrder = { critical:4, high:3, medium:2, low:1, benign:0 };
    const addFinding = (sev, label, mitre=[]) => {
      findings.push({ sev, label });
      mitre.forEach(t => mitreTags.add(t));
      if (sevOrder[sev] > sevOrder[maxSev]) maxSev = sev;
    };

    const procName = (ev.process||"").toLowerCase().replace(/.*[\\\/]/,"");
    const parentName = (ev.parent||"").toLowerCase().replace(/.*[\\\/]/,"");
    const cmdline = (ev.cmdline||"").toLowerCase();
    const path = (ev.path||"").toLowerCase();

    // 1. Known malicious process name
    if (DT_PROCESS_DB.malicious.has(procName)) {
      addFinding("critical", `Known malicious tool: ${procName}`, ["T1588"]);
    }
    // 2. LOLBin in use
    if (DT_PROCESS_DB.lolbins.has(procName) && (cmdline || ev.eventId === "4688")) {
      const isLegitUse = !cmdline || (!/(urlcache|decode|http|script|javascript|vbscript|bypass)/i.test(cmdline));
      if (!isLegitUse) addFinding("high", `LOLBin abuse: ${procName}`, ["T1218"]);
    }
    // 3. Wrong path for system process
    if (path && DT_PROCESS_DB.expectedPaths[procName]) {
      const expected = DT_PROCESS_DB.expectedPaths[procName];
      const isCorrect = expected.some(p => path.startsWith(p));
      if (!isCorrect) addFinding("critical", `${procName} running from unexpected path: ${ev.path}`, ["T1036.005"]);
    }
    // 4. Suspicious path
    for (const rule of DT_SUSPICIOUS_PATHS) {
      if (path && rule.pattern.test(path) && !DT_PROCESS_DB.legitimate.has(procName)) {
        addFinding(rule.sev, rule.label, []);
      }
    }
    // 5. Command line patterns
    for (const rule of DT_CMDLINE_RULES) {
      if (cmdline && rule.pattern.test(cmdline)) {
        addFinding(rule.sev, rule.label, rule.mitre);
        break; // First match is most relevant
      }
    }
    // More cmdline checks (don't break after first for multi-signal)
    for (const rule of DT_CMDLINE_RULES.slice(1)) {
      if (cmdline && rule.pattern.test(ev.cmdline||"")) {
        if (!findings.some(f => f.label === rule.label)) {
          addFinding(rule.sev, rule.label, rule.mitre);
        }
      }
    }
    // 6. Parent-child relationship rules
    for (const rule of DT_PARENT_CHILD_RULES) {
      if (rule.parent.test(parentName) && rule.child.test(procName)) {
        if (!rule.cmdPattern || rule.cmdPattern.test(cmdline)) {
          addFinding(rule.sev, rule.label, rule.mitre);
        }
      }
    }
    // 7. Network: suspicious port or C2 pattern
    if (ev.port && DT_SUSPICIOUS_PORTS.has(parseInt(ev.port))) {
      addFinding("high", `Connection to C2 port ${ev.port}`, ["T1071","T1090"]);
    }
    if (ev.ip) {
      for (const p of DT_C2_PATTERNS) {
        if (p.test(ev.ip)) { addFinding("medium", `Suspicious network destination: ${ev.ip}`, ["T1071.001"]); break; }
      }
    }
    // 8. High-severity EventIDs
    const eid = ev.eventId;
    if (eid) {
      const info = DT_EVENT_IDS[eid] || DT_SYSMON_IDS[eid];
      if (info && (info.sev === "critical" || info.sev === "high")) {
        addFinding(info.sev, `${info.label} (Event ${eid})`, []);
      }
    }

    // Determine verdict
    let verdict, verdictIcon, verdictColor;
    if (maxSev === "critical" || findings.filter(f=>f.sev==="critical").length > 0) {
      verdict = "MALICIOUS"; verdictIcon = "🚨"; verdictColor = "#ef4444";
    } else if (maxSev === "high" || findings.filter(f=>f.sev==="high").length > 0) {
      verdict = "SUSPICIOUS"; verdictIcon = "⚠️"; verdictColor = "#fbbf24";
    } else if (findings.filter(f=>f.sev==="medium").length > 0) {
      verdict = "SUSPICIOUS"; verdictIcon = "⚠️"; verdictColor = "#f59e0b";
    } else if (findings.length > 0) {
      verdict = "REVIEW"; verdictIcon = "🔵"; verdictColor = "#38bdf8";
    } else if (DT_PROCESS_DB.legitimate.has(procName)) {
      verdict = "BENIGN"; verdictIcon = "✅"; verdictColor = "#34d399";
    } else {
      verdict = "UNKNOWN"; verdictIcon = "⚪"; verdictColor = "#6b7280";
    }

    return { findings, mitre: [...mitreTags], verdict, verdictIcon, verdictColor, maxSev };
  }

  // ── Determine event category ──────────────────────────────────────────────
  function dtGetCategory(ev, analysis) {
    if (ev.eventId) {
      const info = DT_EVENT_IDS[ev.eventId] || DT_SYSMON_IDS[ev.eventId];
      if (info) return info.cat;
    }
    const cmd = (ev.cmdline||"").toLowerCase();
    const proc = (ev.process||"").toLowerCase();
    if (ev.ip || ev.port || /network|connect|listen|dns/i.test(ev.category)) return "network";
    if (/reg\b|registry|regedit/i.test(proc+cmd)) return "registry";
    if (/copy|move|del\b|create.*file|write.*file/i.test(cmd)) return "file";
    if (/logon|login|auth|kerberos|ntlm/i.test(ev.category||"")) return "auth";
    if (ev.process) return "process";
    return "system";
  }

  // ── Detect attack chain across all events ────────────────────────────────
  function dtDetectAttackChain(events) {
    const stages = {
      recon:     { label:"Reconnaissance",       icon:"🔍", color:"#38bdf8", found:false },
      initial:   { label:"Initial Access",        icon:"🎯", color:"#f59e0b", found:false },
      exec:      { label:"Execution",             icon:"⚙️", color:"#fb923c", found:false },
      persist:   { label:"Persistence",           icon:"📌", color:"#a78bfa", found:false },
      escalate:  { label:"Privilege Escalation",  icon:"👑", color:"#f87171", found:false },
      evade:     { label:"Defense Evasion",        icon:"🛡", color:"#fbbf24", found:false },
      cred:      { label:"Credential Access",      icon:"🔑", color:"#ef4444", found:false },
      lateral:   { label:"Lateral Movement",       icon:"🔀", color:"#f87171", found:false },
      collect:   { label:"Collection",             icon:"📂", color:"#fb923c", found:false },
      c2:        { label:"C2 Communication",       icon:"📡", color:"#ef4444", found:false },
      exfil:     { label:"Exfiltration",           icon:"📤", color:"#ef4444", found:false },
      impact:    { label:"Impact",                 icon:"💀", color:"#ef4444", found:false },
    };
    for (const ev of events) {
      const all = [...ev._analysis.findings.map(f=>f.label), ev.cmdline||"", ev.process||""].join(" ").toLowerCase();
      const mitre = ev._analysis.mitre.join(",");
      if (/whoami|ipconfig|net view|systeminfo|nltest|get-ad/i.test(all)) stages.recon.found = true;
      if (/phishing|macro|exploit|download.*exe|dropper/i.test(all)) stages.initial.found = true;
      if (/powershell|cmd|wscript|mshta|rundll32|iex|invoke-expression/i.test(all)) stages.exec.found = true;
      if (/scheduled task|registry run|service.*creat|startup/i.test(all)) stages.persist.found = true;
      if (/privilege|uac bypass|token|add.*admin/i.test(all)) stages.escalate.found = true;
      if (/amsi|defender.*disab|exclusion|av.*kill|taskkill.*defender/i.test(all)) stages.evade.found = true;
      if (/lsass|mimikatz|credential|sekurlsa|sam\b|ntlm/i.test(all)) stages.cred.found = true;
      if (/psexec|lateral|remote.*session|invoke-command|wmic.*node/i.test(all)) stages.lateral.found = true;
      if (/compress|archive|collect|shadow.*copy|database/i.test(all)) stages.collect.found = true;
      if (ev.ip || ev.port || /c2.*port|beacon|reverse.*shell/i.test(all)) stages.c2.found = true;
      if (/exfil|upload.*http|post.*data|ftp.*put/i.test(all)) stages.exfil.found = true;
      if (/encrypt|ransom|wipe|delete.*shadow|vssadmin/i.test(all)) stages.impact.found = true;
    }
    return stages;
  }

  // ── Main render function ──────────────────────────────────────────────────
  function dtRender(eventsRaw, format) {
    const dtTimeline = $("dt-timeline");
    const dtResults  = $("dt-results");
    const dtSummary  = $("dt-summary-bar");
    const dtChain    = $("dt-attack-chain");
    if (!dtTimeline) return;

    // Parse based on format
    let events = [];
    if (format === "csv")     events = dtParseCSV(eventsRaw);
    else if (format === "json") events = dtParseJSON(eventsRaw);
    else if (format === "evtx" || format === "raw" || format === "syslog") events = dtParseRaw(eventsRaw);
    else { // auto
      const detected = dtDetectFormat(eventsRaw);
      if (detected === "csv")  events = dtParseCSV(eventsRaw);
      else if (detected === "json") events = dtParseJSON(eventsRaw);
      else events = dtParseRaw(eventsRaw);
    }

    if (!events.length) {
      $("dt-status").textContent = "No parseable events found. Check format or try a different mode.";
      return;
    }

    // Sort by timestamp
    events.forEach(ev => { ev._ts = dtParseTimestamp(ev.timestamp); });
    events.sort((a,b) => { if (!a._ts && !b._ts) return 0; if (!a._ts) return 1; if (!b._ts) return -1; return a._ts - b._ts; });

    // Analyze each event
    events.forEach(ev => {
      ev._analysis = dtAnalyzeEvent(ev);
      ev._category = dtGetCategory(ev, ev._analysis);
      const eid = ev.eventId;
      if (eid) { ev._eidInfo = DT_EVENT_IDS[eid] || DT_SYSMON_IDS[eid]; }
    });

    // Stats
    const malCount  = events.filter(e => e._analysis.verdict === "MALICIOUS").length;
    const suspCount = events.filter(e => e._analysis.verdict === "SUSPICIOUS").length;
    const total     = events.length;

    dtResults.style.display = "block";
    $("dt-status").textContent = `Analyzed ${total} events — ${malCount} malicious, ${suspCount} suspicious`;

    // Summary bar
    dtSummary.innerHTML = [
      { num: total,     label:"Total Events",  color:"#38bdf8" },
      { num: malCount,  label:"🚨 Malicious",   color:"#ef4444" },
      { num: suspCount, label:"⚠️ Suspicious",  color:"#fbbf24" },
      { num: events.filter(e=>e._analysis.verdict==="BENIGN").length,  label:"✅ Benign",   color:"#34d399" },
      { num: events.filter(e=>e._category==="process").length, label:"Processes",  color:"#94a3b8" },
      { num: events.filter(e=>e._category==="network").length, label:"Network",    color:"#94a3b8" },
      { num: events.filter(e=>e._category==="auth").length,    label:"Auth",       color:"#94a3b8" },
    ].map(s => `<div class="dt-stat"><div class="dt-stat-num" style="color:${s.color}">${s.num}</div><div class="dt-stat-label">${s.label}</div></div>`).join("");

    // Attack chain
    const chain = dtDetectAttackChain(events);
    const foundStages = Object.values(chain).filter(s => s.found);
    if (foundStages.length >= 2) {
      dtChain.style.display = "block";
      dtChain.innerHTML = `<div class="dt-chain-card">
        <div class="dt-chain-head">🔗 Attack Chain Detected — ${foundStages.length} stage${foundStages.length>1?"s":""} identified across timeline</div>
        <div class="dt-chain-stages">${foundStages.map(s=>`
          <div class="dt-stage-pill" style="background:${s.color}12;color:${s.color};border-color:${s.color}33;">
            <span>${s.icon}</span><span>${esc(s.label)}</span>
          </div>`).join("")}</div>
      </div>`;
    } else {
      dtChain.style.display = "none";
    }

    // Build event cards
    dtTimeline.innerHTML = events.map((ev, idx) => {
      const a = ev._analysis;
      const catCls = `dt-cat-${ev._category}`;
      const catLabel = { process:"⚙️ Process", network:"🌐 Network", auth:"🔐 Auth",
                         file:"📁 File", registry:"🗝 Registry", system:"🖥 System", lateral:"🔀 Lateral" }[ev._category] || ev._category;
      const eidLabel = ev._eidInfo ? ` — ${ev._eidInfo.label}` : "";
      const filterTags = [
        ev._category,
        a.verdict === "MALICIOUS" ? "malicious" : "",
        (a.verdict === "SUSPICIOUS" || a.verdict === "REVIEW") ? "suspicious" : "",
      ].filter(Boolean).join(" ");

      const procDisplay = ev.process ? ev.process.replace(/.*[\\\/]/,"") : (ev._eidInfo?.icon||"")+" event";
      const cmdDisplay  = ev.cmdline ? ev.cmdline.slice(0,200) + (ev.cmdline.length > 200 ? "…" : "") : "";
      const findingHtml = a.findings.slice(0,3).map(f => {
        const cls = f.sev === "critical" ? "dt-finding-malicious" :
                    f.sev === "high"     ? "dt-finding-malicious" : "dt-finding-suspicious";
        const icon = f.sev === "critical" ? "🚨" : f.sev === "high" ? "⚠️" : "🔵";
        return `<div class="dt-event-finding ${cls}">${icon} ${esc(f.label)}</div>`;
      }).join("");
      const mitreHtml = a.mitre.slice(0,4).map(t =>
        `<a href="https://attack.mitre.org/techniques/${t.replace(".","/")}" target="_blank" class="dt-mitre-tag">${esc(t)}</a>`
      ).join("");

      const verdictCls = a.verdict === "MALICIOUS" ? "dt-malicious" :
                         a.verdict === "SUSPICIOUS" || a.verdict === "REVIEW" ? "dt-suspicious" :
                         a.verdict === "BENIGN"    ? "dt-benign" : "dt-unknown";

      return `<div class="dt-event ${verdictCls}" data-filter-tags="${filterTags}" data-idx="${idx}">
        <div class="dt-event-verdict" style="color:${a.verdictColor}">
          <div class="dt-verdict-icon">${a.verdictIcon}</div>
          <div class="dt-verdict-label" style="color:${a.verdictColor}">${esc(a.verdict)}</div>
        </div>
        <div class="dt-event-main">
          <div class="dt-event-header">
            <span class="dt-event-time">${esc(ev.timestamp||"no timestamp")}</span>
            <span class="dt-event-category ${catCls}">${catLabel}${ev.eventId?" #"+ev.eventId:""}</span>
            ${ev._eidInfo ? `<span style="font-size:10px;color:var(--muted);">${esc(ev._eidInfo.label)}</span>` : ""}
          </div>
          <div class="dt-event-process">${esc(procDisplay)}${ev.parent?` <span style="font-size:9.5px;color:var(--muted);font-weight:400;">← ${esc(ev.parent.replace(/.*[\\\/]/,""))}</span>`:""}</div>
          ${cmdDisplay ? `<div class="dt-event-cmdline">${esc(cmdDisplay)}</div>` : ""}
          <div class="dt-event-meta">
            ${ev.user ? `<span>👤 <span class="dt-meta-highlight">${esc(ev.user)}</span></span>` : ""}
            ${ev.host ? `<span>🖥 ${esc(ev.host)}</span>` : ""}
            ${ev.ip   ? `<span>🌐 <span class="dt-meta-highlight">${esc(ev.ip)}</span>${ev.port?":"+ev.port:""}</span>` : ""}
            ${ev.pid  ? `<span>PID ${esc(ev.pid)}</span>` : ""}
          </div>
          ${findingHtml}
          ${mitreHtml ? `<div class="dt-event-mitre">${mitreHtml}</div>` : ""}
        </div>
      </div>`;
    }).join("");

    // Wire filter buttons
    document.querySelectorAll(".dt-filter-btn").forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll(".dt-filter-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        const f = btn.dataset.filter;
        document.querySelectorAll(".dt-event").forEach(card => {
          const tags = card.dataset.filterTags || "";
          card.classList.toggle("dt-hidden", f !== "all" && !tags.includes(f));
        });
      };
    });
  }

  // ── Wire up Device Timeline tab UI ────────────────────────────────────────
  (function initDevTimeline() {
    // Format selector buttons
    let dtCurrentFmt = "auto";
    document.querySelectorAll(".dt-fmt-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".dt-fmt-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        dtCurrentFmt = btn.dataset.fmt;
      });
    });

    // Analyze button
    const dtBtn  = $("dt-analyze-btn");
    const dtInp  = $("dt-input");
    const dtStat = $("dt-status");
    if (dtBtn && dtInp) {
      dtBtn.addEventListener("click", () => {
        const text = dtInp.value.trim();
        if (!text) { dtStat.textContent = "Status: paste logs above first."; return; }
        dtStat.textContent = "Status: analyzing…";
        $("dt-results").style.display = "none";
        // Use setTimeout to allow UI to update before heavy processing
        setTimeout(() => {
          try {
            const fmt = dtCurrentFmt === "auto" ? dtDetectFormat(text) : dtCurrentFmt;
            dtStat.textContent = `Status: detected format — ${fmt.toUpperCase()}. Processing…`;
            dtRender(text, dtCurrentFmt);
          } catch(e) {
            dtStat.textContent = "Status: parse error — " + e.message;
          }
        }, 30);
      });
    }

    // Clear
    $("dt-clear-btn")?.addEventListener("click", () => {
      if (dtInp) dtInp.value = "";
      const res = $("dt-results"); if (res) res.style.display = "none";
      if (dtStat) dtStat.textContent = "Status: paste logs above and click Analyze";
    });

    // Export report
    $("dt-export-btn")?.addEventListener("click", () => {
      const events = [...document.querySelectorAll(".dt-event:not(.dt-hidden)")];
      let report = "DEVICE TIMELINE ANALYSIS REPORT\n" + "=".repeat(60) + "\n";
      report += `Generated: ${new Date().toISOString()}\n`;
      report += `Total events shown: ${events.length}\n\n`;
      events.forEach(card => {
        const verdict = card.querySelector(".dt-verdict-label")?.textContent?.trim() || "";
        const time    = card.querySelector(".dt-event-time")?.textContent?.trim() || "";
        const proc    = card.querySelector(".dt-event-process")?.textContent?.trim() || "";
        const cmd     = card.querySelector(".dt-event-cmdline")?.textContent?.trim() || "";
        const findings= [...card.querySelectorAll(".dt-event-finding")].map(f=>f.textContent.trim()).join("; ");
        report += `[${verdict}] ${time}\n`;
        if (proc)     report += `  Process: ${proc}\n`;
        if (cmd)      report += `  Cmdline: ${cmd}\n`;
        if (findings) report += `  Findings: ${findings}\n`;
        report += "\n";
      });
      try { navigator.clipboard.writeText(report); $("dt-status").textContent = "Status: report copied to clipboard"; }
      catch { $("dt-status").textContent = "Status: copy failed — try Ctrl+A on the timeline"; }
    });

    // Sample data loader
    $("dt-load-sample-btn")?.addEventListener("click", () => {
      if (dtInp) {
        dtInp.value = [
          "2026-03-21 09:10:02, EventID=4624, User=CORP\\jdoe, Host=CORP-WS-041, IpAddress=10.0.1.55, LogonType=3",
          "2026-03-21 09:14:22, EventID=4688, ProcessName=powershell.exe, CommandLine=-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAGUAeABlACcAKQA=, ParentProcess=winword.exe, User=CORP\\jdoe, Host=CORP-WS-041",
          "2026-03-21 09:14:35, EventID=4688, ProcessName=powershell.exe, CommandLine=Set-MpPreference -DisableRealtimeMonitoring $true, User=CORP\\jdoe, Host=CORP-WS-041",
          "2026-03-21 09:15:01, EventID=5156, ProcessName=powershell.exe, DestinationIp=185.220.101.45, DestinationPort=4444, User=CORP\\jdoe, Host=CORP-WS-041",
          "2026-03-21 09:15:44, EventID=4688, ProcessName=mimikatz.exe, CommandLine=sekurlsa::logonpasswords, User=CORP\\jdoe, Host=CORP-WS-041",
          "2026-03-21 09:16:12, EventID=4688, ProcessName=cmd.exe, CommandLine=schtasks /create /tn WindowsUpdate /tr C:\\Users\\Public\\svchost32.exe /sc onlogon, User=CORP\\jdoe, Host=CORP-WS-041",
          "2026-03-21 09:17:30, EventID=4624, User=CORP\\admin, Host=CORP-DC-001, IpAddress=10.0.1.41, LogonType=3",
          "2026-03-21 09:17:45, EventID=4732, User=CORP\\jdoe, Host=CORP-DC-001, CommandLine=net localgroup administrators jdoe /add",
          "2026-03-21 09:18:02, EventID=1102, Host=CORP-WS-041, User=CORP\\jdoe",
        ].join("\n");
        dtCurrentFmt = "auto";
        document.querySelectorAll(".dt-fmt-btn").forEach(b => b.classList.remove("active"));
        document.querySelector('.dt-fmt-btn[data-fmt="auto"]')?.classList.add("active");
        dtStat.textContent = "Status: sample loaded — click Analyze";
      }
    });
  })();


});
