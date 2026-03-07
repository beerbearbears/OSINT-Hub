document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  const $ = (id) => document.getElementById(id);
  const enc = encodeURIComponent;

  const setHref = (id, href) => {
    const el = $(id);
    if (el) el.href = href;
  };

  const setStatus = (msg) => {
    if (statusText) statusText.textContent = msg;
  };

  // ─── Searchbox UI ───────────────────────────────────────────
  const searchbox = document.getElementById("searchbox");
  const clearBtn = document.getElementById("clear-input");

  function syncSearchboxState() {
    if (!searchbox || !input) return;
    searchbox.classList.toggle("has-value", !!(input.value && input.value.trim()));
  }

  if (input) input.addEventListener("input", syncSearchboxState);
  if (clearBtn && input) {
    clearBtn.addEventListener("click", () => { input.value = ""; syncSearchboxState(); input.focus(); });
  }

  // ─── Helpers ────────────────────────────────────────────────
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
      try { v = new URL(v).hostname; }
      catch { v = v.replace(/^[a-z]+:\/\//i, ""); }
    }
    v = v.replace(/^\[|\]$/g, "");
    v = v.replace(/[,;]+$/g, "");
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  // ─── Email header parser ─────────────────────────────────────
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

  // ─── Type detection ──────────────────────────────────────────
  function detectType(raw, pastedText) {
    const r = (raw || "").trim();
    const p = (pastedText || "").trim();

    if (looksLikeHeaders(p) || looksLikeHeaders(r)) return { type: "header", q: "" };

    const v = normalize(r);

    // Raw URL detection (before normalization strips path)
    const rawTrimmed = r.replace(/^hxxps?:\/\//i, "https://").replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    if (/^https?:\/\/.{4,}/i.test(rawTrimmed)) return { type: "url", q: rawTrimmed };

    if (/^T\d{4,5}$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v.toLowerCase() };
    if (/^\d{3,5}$/.test(v)) return { type: "eventid", q: v };
    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9._-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  // ─── Session History ─────────────────────────────────────────
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
    if (!sessionHistory.length) {
      list.innerHTML = '<div class="history-empty">No searches yet.</div>';
      return;
    }
    list.innerHTML = sessionHistory.map((e, i) => {
      const t = e.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      const typeColor = {
        ip: "#38bdf8", domain: "#34d399", hash: "#f59e0b", email: "#a78bfa",
        url: "#fb923c", cve: "#f87171", username: "#e879f9", header: "#67e8f9",
        eventid: "#86efac", mitre: "#fbbf24"
      }[e.type] || "#9ca3af";
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
        if (entry && input) {
          input.value = entry.value;
          syncSearchboxState();
          switchTab("single");
          doSearch({ silent: false });
        }
      });
    });
  }

  // ─── Export History ──────────────────────────────────────────
  const exportHistoryBtn = $("export-history");
  if (exportHistoryBtn) {
    exportHistoryBtn.addEventListener("click", () => {
      if (!sessionHistory.length) return alert("No history to export yet.");
      const lines = ["OSINT Session History Export", `Exported: ${new Date().toISOString()}`, "─".repeat(50)];
      sessionHistory.forEach(e => {
        lines.push(`[${e.time.toISOString()}] ${e.type.toUpperCase().padEnd(10)} ${e.value}`);
      });
      const blob = new Blob([lines.join("\n")], { type: "text/plain" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `osint-session-${Date.now()}.txt`;
      a.click();
    });
  }

  // ─── Tab Switcher ────────────────────────────────────────────
  function switchTab(name) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.id === `tab-${name}`));
  }

  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // ─── Landing links ───────────────────────────────────────────
  const landing = {
    ip_vt: "https://www.virustotal.com/", ip_abuseipdb: "https://www.abuseipdb.com/",
    ip_talos: "https://talosintelligence.com/", ip_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    ip_otx: "https://otx.alienvault.com/", ip_anyrun: "https://intelligence.any.run/",
    ip_mxtoolbox: "https://mxtoolbox.com/", ip_blacklistchecker: "https://blacklistchecker.com/",
    ip_cleantalk: "https://cleantalk.org/blacklists", ip_shodan: "https://www.shodan.io/",
    ip_censys: "https://search.censys.io/", ip_greynoise: "https://viz.greynoise.io/",
    ip_iplocation: "https://iplocation.io/", ip_ipinfo: "https://ipinfo.io/",
    ip_whatismyipaddress: "https://whatismyipaddress.com/", ip_myip: "https://myip.ms/",
    ip_spur: "https://spur.us/", ip_clickfix: "https://clickfix.carsonww.com/",
    ip_ripestat: "https://stat.ripe.net/", ip_bgphe: "https://bgp.he.net/",
    ip_nitter: "https://nitter.net/", ip_threatminer: "https://www.threatminer.org/",
    ip_urlscan: "https://urlscan.io/", ip_viewdns: "https://viewdns.info/",
    ip_scamalytics: "https://scamalytics.com/",

    dom_vt: "https://www.virustotal.com/", dom_talos: "https://talosintelligence.com/",
    dom_ibmxf: "https://exchange.xforce.ibmcloud.com/", dom_otx: "https://otx.alienvault.com/",
    dom_urlscan: "https://urlscan.io/", dom_mxtoolbox: "https://mxtoolbox.com/",
    dom_blacklistchecker: "https://blacklistchecker.com/", dom_cleantalk_bl: "https://cleantalk.org/blacklists",
    dom_cleantalk_malware: "https://cleantalk.org/malware", dom_sucuri: "https://sitecheck.sucuri.net/",
    dom_urlvoid: "https://www.urlvoid.com/", dom_urlhaus: "https://urlhaus.abuse.ch/",
    dom_whois: "https://www.whois.com/whois/", dom_dnslytics: "https://dnslytics.com/",
    dom_netcraft: "https://www.netcraft.com/", dom_webcheck: "https://webcheck.spiderlabs.io/",
    dom_securitytrails: "https://securitytrails.com/", dom_hudsonrock_info: "https://intel.hudsonrock.com/",
    dom_hudsonrock_urls: "https://cavalier.hudsonrock.com/", dom_socradar: "https://socradar.io/",
    dom_wayback: "https://web.archive.org/", dom_wayback_save: "https://web.archive.org/",
    dom_browserling: "https://www.browserling.com/", dom_anyrun: "https://intelligence.any.run/",
    dom_anyrun_safe: "https://any.run/submit/", dom_phishing_checker: "https://phishing.finsin.cl/list.php",
    dom_clickfix: "https://clickfix.carsonww.com/", dom_nitter: "https://nitter.net/",
    dom_netlas: "https://netlas.io/", dom_censys: "https://search.censys.io/",
    dom_shodan: "https://www.shodan.io/", dom_dnstools: "https://whois.domaintools.com/",
    dom_crtsh: "https://crt.sh/", dom_dnsdumpster: "https://dnsdumpster.com/",

    url_vt: "https://www.virustotal.com/", url_urlscan: "https://urlscan.io/",
    url_urlvoid: "https://www.urlvoid.com/", url_urlhaus: "https://urlhaus.abuse.ch/",
    url_phishtank: "https://www.phishtank.com/", url_checkphish: "https://checkphish.ai/",
    url_safebrowsing: "https://transparencyreport.google.com/safe-browsing/search",
    url_sucuri: "https://sitecheck.sucuri.net/", url_browserling: "https://www.browserling.com/",
    url_wayback: "https://web.archive.org/", url_anyrun: "https://any.run/submit/",
    url_otx: "https://otx.alienvault.com/",

    em_hunter: "https://hunter.io/", em_hibp: "https://haveibeenpwned.com/",
    em_intelbase: "https://intelbase.is/", em_emailrep: "https://emailrep.io/",
    em_epieos: "https://epieos.com/", em_intelx: "https://intelx.io/",
    em_phonebook: "https://phonebook.cz/", em_dehashed: "https://dehashed.com/",

    hdr_mha: "https://mha.azurewebsites.net/pages/mha.html",
    hdr_google: "https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    hdr_mxtoolbox: "https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx",
    hdr_traceemail: "https://whatismyipaddress.com/trace-email",
    hdr_dnschecker: "https://dnschecker.org/email-header-analyzer.php",

    usr_namechk: "https://namechk.com/", usr_whatsmyname: "https://whatsmyname.app/",
    usr_sherlock: "https://github.com/sherlock-project/sherlock",
    usr_socialsearcher: "https://www.social-searcher.com/",
    usr_dehashed: "https://dehashed.com/", usr_intelx: "https://intelx.io/",

    h_vt: "https://www.virustotal.com/", h_hybrid: "https://www.hybrid-analysis.com/",
    h_joesandbox: "https://www.joesandbox.com/", h_triage: "https://tria.ge/",
    h_malshare: "https://malshare.com/", h_malwarebazaar: "https://bazaar.abuse.ch/",
    h_ibmxf: "https://exchange.xforce.ibmcloud.com/", h_talos: "https://talosintelligence.com/",
    h_otx: "https://otx.alienvault.com/", h_anyrun: "https://intelligence.any.run/",
    h_threatminer: "https://www.threatminer.org/", h_intezer: "https://analyze.intezer.com/",
    h_cyberchef: "https://gchq.github.io/CyberChef/", h_nitter: "https://nitter.net/",

    cve_nvd: "https://nvd.nist.gov/", cve_cveorg: "https://www.cve.org/",
    cve_cisa: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cve_exploitdb: "https://www.exploit-db.com/", cve_vulners: "https://vulners.com/",
    cve_github: "https://github.com/search",

    cvep_cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss: "https://www.first.org/epss/",

    emart_msgid_search: "https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    emart_dkim_domain: "https://www.virustotal.com/",
    emart_spf_domain: "https://www.virustotal.com/",

    lb_lolbas: "https://lolbas-project.github.io/",
    lb_gtfobins: "https://gtfobins.github.io/",
    lb_hijacklibs: "https://hijacklibs.net/",

    ev_eventidnet: "https://www.eventid.net/",
    ev_mslearn: "https://learn.microsoft.com/",
    ev_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    sysmon_mslearn: "https://learn.microsoft.com/",
    sysmon_swift: "https://github.com/SwiftOnSecurity/sysmon-config",
    sysmon_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    soc_ruler: "https://ruler-project.github.io/ruler-project/RULER/remote/",
    soc_hackthelogs: "https://www.hackthelogs.com/mainpage.html",
    soc_explainshell: "https://explainshell.com/",
    soc_sigma: "https://github.com/SigmaHQ/sigma",
    soc_uncoder: "https://uncoder.io/",
  };

  function setLandingLinks() {
    Object.entries(landing).forEach(([id, href]) => setHref(id, href));
  }

  function renderCardMeta() {
    document.querySelectorAll(".meta[data-meta]").forEach(m => {
      const id = m.getAttribute("data-meta");
      const a = $(id);
      if (a && a.href) m.textContent = a.href;
    });
  }

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

  // ─── MITRE ATT&CK auto-suggest ───────────────────────────────
  const mitreByType = {
    ip:       ["T1071", "T1095", "T1041", "T1105", "T1046"],
    domain:   ["T1071", "T1583", "T1584", "T1566", "T1041"],
    url:      ["T1566", "T1071", "T1204", "T1190"],
    hash:     ["T1204", "T1059", "T1027", "T1055", "T1036"],
    email:    ["T1566", "T1114", "T1078"],
    header:   ["T1566", "T1078", "T1557", "T1114"],
    cve:      ["T1190", "T1068", "T1055"],
    username: ["T1078", "T1110", "T1003"],
    eventid:  ["T1059", "T1047", "T1053", "T1078"],
  };

  function suggestMitreTactics(type) {
    const suggestions = mitreByType[type] || [];
    const panel = $("mitre-suggested");
    const tagsEl = $("mitre-suggested-tags");
    if (!panel || !tagsEl) return;

    if (!suggestions.length) { panel.style.display = "none"; return; }

    panel.style.display = "block";
    tagsEl.innerHTML = suggestions.map(tid => {
      const lbl = document.querySelector(`#mitre-panel input[value="${tid}"]`)
        ?.closest("label")?.textContent?.trim() || tid;
      return `<button class="mitre-suggest-tag" data-tid="${tid}" type="button">${lbl}</button>`;
    }).join("");

    tagsEl.querySelectorAll(".mitre-suggest-tag").forEach(btn => {
      btn.addEventListener("click", () => {
        const cb = document.querySelector(`#mitre-panel input[value="${btn.dataset.tid}"]`);
        if (cb) { cb.checked = true; btn.classList.add("applied"); btn.textContent = "✅ " + btn.textContent; }
      });
    });
  }

  // ─── MITRE copy / clear ──────────────────────────────────────
  const mitreCopyBtn = $("mitre-copy-btn");
  if (mitreCopyBtn) {
    mitreCopyBtn.addEventListener("click", async () => {
      const checked = [...document.querySelectorAll("#mitre-panel input[type=checkbox]:checked")];
      if (!checked.length) return setStatus("No TTPs tagged.");
      const lines = checked.map(cb => {
        const lbl = cb.closest("label")?.textContent?.trim() || cb.value;
        return `${lbl} — https://attack.mitre.org/techniques/${cb.value.replace(".", "/")}/`;
      });
      const text = "Tagged TTPs:\n" + lines.join("\n");
      try { await navigator.clipboard.writeText(text); } catch { /* fallback */ }
      setStatus(`Copied ${checked.length} tagged TTPs`);
    });
  }

  const mitreClearBtn = $("mitre-clear-btn");
  if (mitreClearBtn) {
    mitreClearBtn.addEventListener("click", () => {
      document.querySelectorAll("#mitre-panel input[type=checkbox]").forEach(cb => cb.checked = false);
      const panel = $("mitre-suggested");
      if (panel) panel.style.display = "none";
      setStatus("TTPs cleared");
    });
  }

  // ─── Verdict Banner ──────────────────────────────────────────
  function showVerdict(type, q) {
    const banner = $("verdict-banner");
    if (!banner) return;

    const verdictMap = {
      ip:       { icon: "🛡", label: "IP Address", color: "#38bdf8" },
      domain:   { icon: "🌐", label: "Domain", color: "#34d399" },
      url:      { icon: "🔗", label: "URL", color: "#fb923c" },
      hash:     { icon: "🔒", label: "File Hash", color: "#f59e0b" },
      email:    { icon: "📧", label: "Email Address", color: "#a78bfa" },
      header:   { icon: "📨", label: "Email Headers Detected", color: "#67e8f9" },
      cve:      { icon: "💥", label: "CVE / Vulnerability", color: "#f87171" },
      username: { icon: "👤", label: "Username", color: "#e879f9" },
      eventid:  { icon: "🪟", label: "Windows Event ID", color: "#86efac" },
      mitre:    { icon: "🧩", label: "MITRE ATT&CK Technique", color: "#fbbf24" },
    };

    const v = verdictMap[type];
    if (!v) { banner.style.display = "none"; return; }

    banner.style.display = "flex";
    banner.style.borderColor = v.color + "44";
    banner.style.background = v.color + "11";
    banner.innerHTML = `
      <span class="verdict-icon" style="color:${v.color}">${v.icon}</span>
      <div>
        <span class="verdict-type" style="color:${v.color}">${v.label}</span>
        <span class="verdict-value">${q || "detected from pasted text"}</span>
      </div>
    `;
  }

  // ─── Defang / Refang ─────────────────────────────────────────
  function defangSmart(text) {
    let t = (text || "");
    t = t.replace(/\bhttps?:\/\/[^\s<>"')]+/gi, (m) => {
      let x = m.replace(/^https:\/\//i, "hxxps://").replace(/^http:\/\//i, "hxxp://");
      x = x.replace(/\./g, "[.]");
      return x;
    });
    t = t.replace(/\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, (m, u, d) =>
      `${u}[@]${String(d).replace(/\./g, "[.]")}`
    );
    t = t.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, (m) =>
      isValidIPv4(m) ? m.replace(/\./g, "[.]") : m
    );
    t = t.replace(/(\[?[0-9A-Fa-f:]{2,}\]?)/g, (token) => {
      if (!token.includes(":")) return token;
      const trail = token.match(/[),.;]+$/)?.[0] || "";
      const core = token.slice(0, token.length - trail.length);
      const cleaned = core.replace(/^\[|\]$/g, "");
      if (!isValidIPv6(cleaned)) return token;
      return core.replace(/:/g, "[:]") + trail;
    });
    t = t.replace(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi, (m) => {
      if (m.includes("[.]")) return m;
      if (/\.(exe|dll|sys|bat|cmd|ps1|js|vbs)$/i.test(m)) return m;
      if (!/\.[a-z]{2,}$/i.test(m)) return m;
      return m.replace(/\./g, "[.]");
    });
    return t;
  }

  function refangSmart(text) {
    let t = (text || "");
    t = t.replace(/hxxps:\/\//gi, "https://").replace(/hxxp:\/\//gi, "http://");
    t = t.replace(/\[@\]/g, "@").replace(/\[\.\]/g, ".").replace(/\[:\]/g, ":");
    return t;
  }

  // ─── Smart IOC Extractor ─────────────────────────────────────
  function extractSmartIOCs(text) {
    const now = new Date().toISOString();
    const t = (text || "").replace(/\r\n/g, "\n");
    const headerDetected = looksLikeHeaders(t);
    const h = headerDetected ? parseEmailHeaders(t) : null;

    const originLink = h?.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}` : "-";
    const dkimLink = h?.dkimDomain ? `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}` : "-";
    const spfLink = h?.spfMailfromDomain ? `https://www.virustotal.com/gui/domain/${enc(h.spfMailfromDomain)}` : "-";
    const returnPathLink = h?.returnPathDomain ? `https://www.virustotal.com/gui/domain/${enc(h.returnPathDomain)}` : "-";

    if (headerDetected) {
      return `SMART IOC EXTRACTOR
Extracted At (UTC): ${now}

EMAIL HEADER INTEL:
- Sender (From): ${h?.senderEmail || "-"}
- Receiver (To): ${h?.receiverEmail || "-"}
- Subject: ${h?.subject || "-"}
- Date: ${h?.date || "-"}
- Message-ID: ${h?.messageId || "-"}
- Return-Path: ${h?.returnPath || "-"}
- Return-Path Domain: ${h?.returnPathDomain || "-"}
- Origin IP (heuristic): ${h?.originIp || "-"}
- SPF Result: ${h?.spfResult || "-"}   (smtp.mailfrom: ${h?.spfMailfrom || "-"})
- DKIM Result: ${h?.dkimResult || "-"} (d=${h?.dkimDomain || "-"}; s=${h?.dkimSelector || "-"})

QUICK PIVOTS:
- Return-Path Domain Pivot: ${returnPathLink}
- Origin IP Pivot: ${originLink}
- SPF Domain Pivot: ${spfLink}
- DKIM Domain Pivot: ${dkimLink}
`;
    }

    // Generic IOC extraction from raw text
    const refanged = refangSmart(t);
    const ips = [...new Set((refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g) || []).filter(isValidIPv4))];
    const domains = [...new Set((refanged.match(/\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\b/g) || [])
      .filter(d => !/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(d)))];
    const hashes = [...new Set((refanged.match(/\b[a-fA-F0-9]{32,64}\b/g) || []).filter(h => [32,40,64].includes(h.length)))];
    const cves = [...new Set((refanged.match(/CVE-\d{4}-\d{4,}/gi) || []).map(c => c.toUpperCase()))];
    const emails = [...new Set((refanged.match(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || []))];
    const urls = [...new Set((refanged.match(/https?:\/\/[^\s<>"']+/gi) || []))];

    const lines = [`SMART IOC EXTRACTOR`, `Extracted At (UTC): ${now}`, ""];
    if (ips.length) lines.push(`IPs (${ips.length}):\n${ips.map(v => "  " + v).join("\n")}`);
    if (domains.length) lines.push(`\nDomains (${domains.length}):\n${domains.map(v => "  " + v).join("\n")}`);
    if (urls.length) lines.push(`\nURLs (${urls.length}):\n${urls.map(v => "  " + v).join("\n")}`);
    if (emails.length) lines.push(`\nEmails (${emails.length}):\n${emails.map(v => "  " + v).join("\n")}`);
    if (hashes.length) lines.push(`\nHashes (${hashes.length}):\n${hashes.map(v => "  " + v).join("\n")}`);
    if (cves.length) lines.push(`\nCVEs (${cves.length}):\n${cves.map(v => "  " + v).join("\n")}`);
    if (!ips.length && !domains.length && !hashes.length && !cves.length && !emails.length && !urls.length) {
      lines.push("No recognizable IOCs found.");
    }
    return lines.join("\n");
  }

  // ─── Link builders ───────────────────────────────────────────
  function buildLinksForIP(ip) {
    setHref("ip_vt",              `https://www.virustotal.com/gui/ip-address/${enc(ip)}`);
    setHref("ip_abuseipdb",       `https://www.abuseipdb.com/check/${enc(ip)}`);
    setHref("ip_talos",           `https://talosintelligence.com/reputation_center/lookup?search=${enc(ip)}`);
    setHref("ip_ibmxf",           `https://exchange.xforce.ibmcloud.com/ip/${enc(ip)}`);
    setHref("ip_otx",             `https://otx.alienvault.com/indicator/ip/${enc(ip)}`);
    setHref("ip_anyrun",          anyrunLookupGeneral(ip));
    setHref("ip_mxtoolbox",       `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${enc(ip)}&run=toolpage`);
    setHref("ip_blacklistchecker",`https://blacklistchecker.com/ip/${enc(ip)}`);
    setHref("ip_cleantalk",       `https://cleantalk.org/blacklists/${enc(ip)}`);
    setHref("ip_shodan",          `https://www.shodan.io/host/${enc(ip)}`);
    setHref("ip_censys",          `https://search.censys.io/hosts/${enc(ip)}`);
    setHref("ip_greynoise",       `https://viz.greynoise.io/ip/${enc(ip)}`);
    setHref("ip_iplocation",      `https://iplocation.io/ip/${enc(ip)}`);
    setHref("ip_ipinfo",          `https://ipinfo.io/${enc(ip)}`);
    setHref("ip_whatismyipaddress",`https://whatismyipaddress.com/ip/${enc(ip)}`);
    setHref("ip_myip",            `https://myip.ms/info/whois/${enc(ip)}`);
    setHref("ip_spur",            `https://spur.us/context/${enc(ip)}`);
    setHref("ip_clickfix",        `https://clickfix.carsonww.com/?q=${enc(ip)}`);
    setHref("ip_ripestat",        `https://stat.ripe.net/${enc(ip)}`);
    setHref("ip_bgphe",           `https://bgp.he.net/ip/${enc(ip)}`);
    setHref("ip_nitter",          `https://nitter.net/search?q=${enc(ip)}`);
    setHref("ip_threatminer",     `https://www.threatminer.org/host.php?q=${enc(ip)}`);
    setHref("ip_urlscan",         `https://urlscan.io/search/#ip:${enc(ip)}`);
    setHref("ip_viewdns",         `https://viewdns.info/reverseip/?host=${enc(ip)}&t=1`);
    setHref("ip_scamalytics",     `https://scamalytics.com/ip/${enc(ip)}`);
  }

  function buildLinksForDomain(domain) {
    setHref("dom_vt",             `https://www.virustotal.com/gui/domain/${enc(domain)}`);
    setHref("dom_talos",          `https://talosintelligence.com/reputation_center/lookup?search=${enc(domain)}`);
    setHref("dom_ibmxf",          `https://exchange.xforce.ibmcloud.com/url/${enc(domain)}`);
    setHref("dom_otx",            `https://otx.alienvault.com/indicator/domain/${enc(domain)}`);
    setHref("dom_urlscan",        `https://urlscan.io/search/#domain:${enc(domain)}`);
    setHref("dom_mxtoolbox",      `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${enc(domain)}&run=toolpage`);
    setHref("dom_blacklistchecker",`https://blacklistchecker.com/domain/${enc(domain)}`);
    setHref("dom_cleantalk_bl",   `https://cleantalk.org/blacklists/${enc(domain)}`);
    setHref("dom_cleantalk_malware",`https://cleantalk.org/website/${enc(domain)}`);
    setHref("dom_sucuri",         `https://sitecheck.sucuri.net/results/${enc(domain)}`);
    setHref("dom_urlvoid",        `https://www.urlvoid.com/scan/${enc(domain)}/`);
    setHref("dom_urlhaus",        `https://urlhaus.abuse.ch/browse.php?search=${enc(domain)}`);
    setHref("dom_whois",          `https://www.whois.com/whois/${enc(domain)}`);
    setHref("dom_dnslytics",      `https://dnslytics.com/domain/${enc(domain)}`);
    setHref("dom_netcraft",       `https://searchdns.netcraft.com/?host=${enc(domain)}`);
    setHref("dom_webcheck",       `https://webcheck.spiderlabs.io/?q=${enc(domain)}`);
    setHref("dom_securitytrails", `https://securitytrails.com/domain/${enc(domain)}`);
    setHref("dom_hudsonrock_info",`https://intel.hudsonrock.com/?q=${enc(domain)}`);
    setHref("dom_hudsonrock_urls",`https://cavalier.hudsonrock.com/?q=${enc(domain)}`);
    setHref("dom_socradar",       gsearch(`SOCRadar dark web report ${domain}`));
    setHref("dom_wayback",        `https://web.archive.org/web/*/${enc(domain)}`);
    setHref("dom_wayback_save",   `https://web.archive.org/save/${enc(domain)}`);
    setHref("dom_browserling",    `https://www.browserling.com/browse/${enc(domain)}`);
    setHref("dom_anyrun",         anyrunLookupGeneral(domain));
    setHref("dom_anyrun_safe",    `https://any.run/submit/?url=${enc("http://" + domain)}`);
    setHref("dom_phishing_checker",`https://phishing.finsin.cl/list.php?search=${enc(domain)}`);
    setHref("dom_clickfix",       `https://clickfix.carsonww.com/?q=${enc(domain)}`);
    setHref("dom_nitter",         `https://nitter.net/search?q=${enc(domain)}`);
    setHref("dom_netlas",         `https://app.netlas.io/domains/?q=${enc(domain)}`);
    setHref("dom_censys",         `https://search.censys.io/search?resource=hosts&q=${enc(domain)}`);
    setHref("dom_shodan",         `https://www.shodan.io/search?query=${enc(domain)}`);
    setHref("dom_dnstools",       `https://whois.domaintools.com/${enc(domain)}`);
    setHref("dom_crtsh",          `https://crt.sh/?q=${enc(domain)}`);
    setHref("dom_dnsdumpster",    `https://dnsdumpster.com/`); // requires form submit
  }

  function buildLinksForURL(url) {
    setHref("url_vt",           `https://www.virustotal.com/gui/url/${btoa(url).replace(/=/g,'')}`);
    setHref("url_urlscan",      `https://urlscan.io/search/#page.url:${enc(url)}`);
    setHref("url_urlvoid",      `https://www.urlvoid.com/scan/${enc(url)}/`);
    setHref("url_urlhaus",      `https://urlhaus.abuse.ch/browse.php?search=${enc(url)}`);
    setHref("url_phishtank",    `https://www.phishtank.com/`);
    setHref("url_checkphish",   `https://checkphish.ai/?url=${enc(url)}`);
    setHref("url_safebrowsing", `https://transparencyreport.google.com/safe-browsing/search?url=${enc(url)}`);
    setHref("url_sucuri",       `https://sitecheck.sucuri.net/results/${enc(url)}`);
    setHref("url_browserling",  `https://www.browserling.com/browse/${enc(url)}`);
    setHref("url_wayback",      `https://web.archive.org/web/*/${enc(url)}`);
    setHref("url_anyrun",       `https://any.run/submit/?url=${enc(url)}`);
    setHref("url_otx",          `https://otx.alienvault.com/indicator/url/${enc(url)}`);
  }

  function buildLinksForHash(hash) {
    setHref("h_vt",           `https://www.virustotal.com/gui/file/${enc(hash)}`);
    setHref("h_hybrid",       `https://www.hybrid-analysis.com/search?query=${enc(hash)}`);
    setHref("h_joesandbox",   `https://www.joesandbox.com/search?q=${enc(hash)}`);
    setHref("h_triage",       `https://tria.ge/s?q=${enc(hash)}`);
    setHref("h_malshare",     `https://malshare.com/sample.php?action=detail&hash=${enc(hash)}`);
    setHref("h_malwarebazaar",`https://bazaar.abuse.ch/browse.php?search=${enc(hash)}`);
    setHref("h_ibmxf",        `https://exchange.xforce.ibmcloud.com/malware/${enc(hash)}`);
    setHref("h_talos",        `https://talosintelligence.com/talos_file_reputation?s=${enc(hash)}`);
    setHref("h_otx",          `https://otx.alienvault.com/indicator/file/${enc(hash)}`);
    setHref("h_anyrun",       anyrunLookupGeneral(hash));
    setHref("h_threatminer",  `https://www.threatminer.org/sample.php?q=${enc(hash)}`);
    setHref("h_intezer",      `https://analyze.intezer.com/`);
    setHref("h_cyberchef",    `https://gchq.github.io/CyberChef/`);
    setHref("h_nitter",       `https://nitter.net/search?q=${enc(hash)}`);
  }

  function buildLinksForEmail(email) {
    setHref("em_hunter",   `https://hunter.io/email-verifier/${enc(email)}`);
    setHref("em_hibp",     `https://haveibeenpwned.com/account/${enc(email)}`);
    setHref("em_intelbase",`https://intelbase.is/search?q=${enc(email)}`);
    setHref("em_emailrep", `https://emailrep.io/${enc(email)}`);
    setHref("em_epieos",   `https://epieos.com/?q=${enc(email)}&t=email`);
    setHref("em_intelx",   `https://intelx.io/?s=${enc(email)}`);
    setHref("em_phonebook",`https://phonebook.cz/`);
    setHref("em_dehashed", `https://dehashed.com/search?query=${enc(email)}`);
  }

  function buildLinksForUsername(user) {
    setHref("usr_namechk",       `https://namechk.com/?q=${enc(user)}`);
    setHref("usr_whatsmyname",   `https://whatsmyname.app/?q=${enc(user)}`);
    setHref("usr_sherlock",      `https://github.com/sherlock-project/sherlock`);
    setHref("usr_socialsearcher",`https://www.social-searcher.com/social-buzz/?q5=${enc(user)}`);
    setHref("usr_dehashed",      `https://dehashed.com/search?query=${enc(user)}`);
    setHref("usr_intelx",        `https://intelx.io/?s=${enc(user)}`);
  }

  function buildLinksForCVE(cve) {
    setHref("cve_nvd",       `https://nvd.nist.gov/vuln/detail/${enc(cve)}`);
    setHref("cve_cveorg",    `https://www.cve.org/CVERecord?id=${enc(cve)}`);
    setHref("cve_cisa",      gsearch(`site:cisa.gov "Known Exploited Vulnerabilities" ${cve}`));
    setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${enc(cve)}`);
    setHref("cve_vulners",   `https://vulners.com/search?query=${enc(cve)}`);
    setHref("cve_github",    `https://github.com/search?q=${enc(cve)}`);
    setHref("cvep_cisa_kev", gsearch(`CISA KEV ${cve}`));
    setHref("cvep_epss",     `https://www.first.org/epss/?q=${enc(cve)}`);
  }

  function buildLinksForEventID(id) {
    setHref("ev_eventidnet",`https://www.eventid.net/display.asp?eventid=${enc(id)}`);
    setHref("ev_mslearn",   `https://learn.microsoft.com/en-us/search/?terms=${enc("Event ID " + id)}`);
    setHref("ev_hackthelogs",gsearch(`HackTheLogs Event ID ${id}`));
  }

  function buildLinksForHeaders(headerText) {
    setHref("hdr_dnschecker", "https://dnschecker.org/email-header-analyzer.php");
    setHref("hdr_mxtoolbox",  "https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx");
    setHref("hdr_mha",        "https://mha.azurewebsites.net/pages/mha.html");
    setHref("hdr_google",     "https://toolbox.googleapps.com/apps/messageheader/analyzeheader");
    const h = parseEmailHeaders(headerText);
    setHref("emart_msgid_search", h.messageId ? gsearch(`"${h.messageId}"`) : landing.emart_msgid_search);
    if (h.dkimDomain) setHref("emart_dkim_domain", `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}`);
    else setHref("emart_dkim_domain", landing.emart_dkim_domain);
    const spfDom = h.spfMailfromDomain || (h.spfMailfrom.split("@")[1] || "");
    if (spfDom) setHref("emart_spf_domain", `https://www.virustotal.com/gui/domain/${enc(spfDom)}`);
    else setHref("emart_spf_domain", landing.emart_spf_domain);
    return h;
  }

  // ─── Main search ─────────────────────────────────────────────
  function doSearch({ silent = false } = {}) {
    const raw = (input?.value || "").trim();
    const pasted = (output?.value || "").trim();
    syncSearchboxState();

    if (!raw && !pasted) {
      setSearchMode(false); showRelevantTools([]);
      setLandingLinks(); renderCardMeta();
      setStatus("Status: ready (landing page)");
      const banner = $("verdict-banner");
      if (banner) banner.style.display = "none";
      const sp = $("mitre-suggested");
      if (sp) sp.style.display = "none";
      if (!silent && output) output.value = "";
      return;
    }

    const { type, q } = detectType(raw, pasted);

    if (!type) {
      setSearchMode(false); showRelevantTools([]);
      setLandingLinks(); renderCardMeta();
      setStatus("Status: unknown type (landing page)");
      if (!silent && output && raw) output.value = raw;
      return;
    }

    setSearchMode(true);

    let sections = [];
    if (type === "header") sections = ["header", "emailartifacts"];
    else if (type === "cve") sections = ["cve", "cveplus"];
    else sections = [type];

    showRelevantTools(sections);
    setLandingLinks();
    showVerdict(type, q);
    suggestMitreTactics(type);

    // Update MITRE ATT&CK link with technique if applicable
    if (type === "mitre" && q) {
      setHref("mitre-attack-link", `https://attack.mitre.org/techniques/${q.replace(".", "/")}/`);
    } else {
      setHref("mitre-attack-link", "https://attack.mitre.org/");
    }

    if (type === "ip") {
      buildLinksForIP(q);
      const privateNote = (isValidIPv4(q) && isPrivateIPv4(q)) || (isValidIPv6(q) && isPrivateIPv6(q));
      if (!silent && output) output.value = privateNote
        ? `IP detected (PRIVATE): ${q}\nNote: external OSINT may not return results for private IPs.`
        : `IP detected: ${q}`;
      setStatus(`Status: detected IP → ${q}`);
    }
    if (type === "domain") { buildLinksForDomain(q); if (!silent && output) output.value = `Domain detected: ${q}`; setStatus(`Status: detected DOMAIN → ${q}`); }
    if (type === "url")    { buildLinksForURL(q);    if (!silent && output) output.value = `URL detected: ${q}`;    setStatus(`Status: detected URL → ${q}`); }
    if (type === "hash")   { buildLinksForHash(q);   if (!silent && output) output.value = `Hash detected: ${q}`;   setStatus(`Status: detected HASH → ${q}`); }
    if (type === "email")  { buildLinksForEmail(q);  if (!silent && output) output.value = `Email detected: ${q}`;  setStatus(`Status: detected EMAIL → ${q}`); }
    if (type === "username") { buildLinksForUsername(q); if (!silent && output) output.value = `Username detected: ${q}`; setStatus(`Status: detected USERNAME → ${q}`); }
    if (type === "cve")    { buildLinksForCVE(q);    if (!silent && output) output.value = `CVE detected: ${q}`;    setStatus(`Status: detected CVE → ${q}`); }
    if (type === "eventid"){ buildLinksForEventID(q);if (!silent && output) output.value = `Event ID detected: ${q}`; setStatus(`Status: detected EVENT ID → ${q}`); }

    if (type === "header") {
      const headerText = pasted || raw;
      const h = buildLinksForHeaders(headerText);
      if (!silent && output) {
        output.value =
`EMAIL HEADERS DETECTED ✅

Sender (From): ${h.senderEmail || "-"}
Receiver (To): ${h.receiverEmail || "-"}
Return-Path: ${h.returnPath || "-"}
Return-Path Domain: ${h.returnPathDomain || "-"}
Origin IP: ${h.originIp || "-"}
SPF: ${h.spfResult || "-"} (smtp.mailfrom: ${h.spfMailfrom || "-"})
DKIM: ${h.dkimResult || "-"} (d=${h.dkimDomain || "-"}; s=${h.dkimSelector || "-"})

Quick Pivots:
- Return-Path Domain Pivot: ${h.returnPathDomain ? `https://www.virustotal.com/gui/domain/${enc(h.returnPathDomain)}` : "-"}
- Origin IP Pivot: ${h.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}` : "-"}
- SPF Domain Pivot: ${h.spfMailfromDomain ? `https://www.virustotal.com/gui/domain/${enc(h.spfMailfromDomain)}` : "-"}
- DKIM Domain Pivot: ${h.dkimDomain ? `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}` : "-"}

Tip: Use Extract IOCs for an investigation-ready summary.`;
      }
      setStatus("Status: detected EMAIL HEADERS → header tools + email artifacts");
    }

    // Log to history (avoid logging header body, just mark it)
    if (type && q !== undefined) {
      const histVal = type === "header" ? "(email headers)" : (q || raw.slice(0, 60));
      addToHistory(type, histVal);
    }

    renderCardMeta();
  }

  // Rebuild links before user clicks a tool link
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    const raw = (input?.value || "").trim();
    const pasted = (output?.value || "").trim();
    if (raw || pasted) doSearch({ silent: true });
  }, true);

  // ─── Keyboard shortcuts ──────────────────────────────────────
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey) {
      if (e.key === "k" || e.key === "K") { e.preventDefault(); input?.focus(); input?.select(); }
      if (e.key === "d" || e.key === "D") { e.preventDefault(); const src = (output?.value||"").trim() ? output.value : (input?.value||""); if(output) output.value = defangSmart(src); setStatus("Status: defanged"); }
      if (e.key === "e" || e.key === "E") { e.preventDefault(); const text=(output?.value||"").trim()||(input?.value||""); if(output) output.value = extractSmartIOCs(text); setStatus("Status: Smart IOC extraction complete"); }
    }
  });

  // ─── Buttons ─────────────────────────────────────────────────
  const searchBtn = $("search-btn");
  if (searchBtn) searchBtn.addEventListener("click", () => doSearch({ silent: false }));
  if (input) input.addEventListener("keydown", e => { if (e.key === "Enter") doSearch({ silent: false }); });

  const defangBtn = $("defang-btn");
  if (defangBtn) defangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() ? output.value : (input?.value || "");
    if (output) output.value = defangSmart(src);
    setStatus("Status: defanged (smart IOC-only, IPv6 supported)");
  });

  const refangBtn = $("refang-btn");
  if (refangBtn) refangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() ? output.value : (input?.value || "");
    if (output) output.value = refangSmart(src);
    setStatus("Status: refanged (IPv6 supported)");
  });

  const extractBtn = $("extract-btn");
  if (extractBtn) extractBtn.addEventListener("click", () => {
    const text = (output?.value || "").trim() || (input?.value || "");
    if (output) output.value = extractSmartIOCs(text);
    setStatus("Status: Smart IOC extraction complete");
  });

  const copyBtn = $("copy-btn");
  if (copyBtn) copyBtn.addEventListener("click", async () => {
    if (!output) return;
    try { await navigator.clipboard.writeText(output.value || ""); }
    catch { output.focus(); output.select(); document.execCommand("copy"); }
    setStatus("Status: copied to clipboard");
  });

  const clearAll = $("clear-all");
  if (clearAll) clearAll.addEventListener("click", () => {
    if (input) input.value = "";
    if (output) output.value = "";
    syncSearchboxState();
    setSearchMode(false); showRelevantTools([]);
    setLandingLinks(); renderCardMeta();
    setStatus("Status: ready (landing page)");
    const banner = $("verdict-banner");
    if (banner) banner.style.display = "none";
    const sp = $("mitre-suggested");
    if (sp) sp.style.display = "none";
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

    // Also scan the full blob for embedded IOCs not on their own line
    const ips = (refanged.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g) || []).filter(isValidIPv4);
    ips.forEach(ip => { if (!iocs.find(i => i.q === ip)) iocs.push({ raw: ip, type: "ip", q: ip }); });

    const hashes = (refanged.match(/\b[a-fA-F0-9]{64}\b/g) || []);
    hashes.forEach(h => { if (!iocs.find(i => i.q === h)) iocs.push({ raw: h, type: "hash", q: h }); });

    const cves = (refanged.match(/CVE-\d{4}-\d{4,}/gi) || []).map(c => c.toUpperCase());
    cves.forEach(c => { if (!iocs.find(i => i.q === c)) iocs.push({ raw: c, type: "cve", q: c }); });

    // Deduplicate by q
    const seen = new Set();
    return iocs.filter(i => { if (seen.has(i.q)) return false; seen.add(i.q); return true; });
  }

  function getBulkLinks(type, q) {
    const e = encodeURIComponent;
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

  // ── Mode switcher ──
  document.querySelectorAll(".sa-mode-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".sa-mode-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      saCurrentMode = btn.dataset.mode;
      const badge = $("sa-mode-badge");
      if (badge) badge.textContent = saCurrentMode.toUpperCase();
    });
  });

  // ── Shannon entropy ──
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

  // ── Base64 decode (handles PS unicode base64 too) ──
  function tryDecodeBase64(str) {
    const clean = str.replace(/[\s\r\n]/g, "");
    if (clean.length < 8) return null;
    try {
      // Try standard base64
      const raw = atob(clean);
      // Check if it looks like UTF-16LE (PowerShell -EncodedCommand)
      const isUtf16 = raw.split("").every((c, i) => i % 2 === 1 ? c === "\0" : true);
      if (isUtf16) {
        return raw.split("").filter((_, i) => i % 2 === 0).join("");
      }
      // Check if printable enough
      const printable = raw.split("").filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
      if (printable / raw.length > 0.6) return raw;
      return null;
    } catch { return null; }
  }

  // ── Deep decode: strip layers of encoding ──
  function deepDecode(text) {
    let current = text;
    const layers = [];
    let maxLayers = 6;
    while (maxLayers-- > 0) {
      // Find base64 blobs (min 20 chars)
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

  // ── Char array decoder: [char]72+[char]101+... ──
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

  // ── String reverse detection ──
  function findReversedStrings(text) {
    const results = [];
    const pattern = /['"]([\w\-./:\\]{8,})['"]\s*[-|]\s*(?:split\s*''|ForEach|%)/gi;
    const matches = [...text.matchAll(/\[string\]::join\(.*?(-join|-split)/gi)];
    // Simpler: detect -join after split
    const rev = text.match(/-split\s+''[^']*''.*?-join\s+''[^']*''/gi) || [];
    rev.forEach(m => results.push({ hint: "Possible string reversal/join obfuscation", snippet: m.slice(0, 80) }));
    return results;
  }

  // ── Threat indicator DB ──
  const THREAT_INDICATORS = {
    powershell: [
      // Download & Execute
      { pattern: /\bDownloadString\b/gi,          sev: "critical", label: "Downloads & executes remote string",         mitre: ["T1059.001","T1105"] },
      { pattern: /\bDownloadFile\b/gi,             sev: "high",    label: "Downloads file from remote URL",             mitre: ["T1105"] },
      { pattern: /\bDownloadData\b/gi,             sev: "high",    label: "Downloads raw data from remote",             mitre: ["T1105"] },
      { pattern: /\bWebClient\b/gi,                sev: "medium",  label: "Creates WebClient object (network activity)",mitre: ["T1071","T1105"] },
      { pattern: /\bInvoke-WebRequest\b|\biwr\b/gi,sev: "medium",  label: "Web request via Invoke-WebRequest",          mitre: ["T1105","T1071"] },
      { pattern: /\bcurl\b|\bwget\b/gi,            sev: "low",     label: "curl/wget download attempt",                 mitre: ["T1105"] },
      // Execution
      { pattern: /\bIEX\b|\bInvoke-Expression\b/gi,sev: "critical",label: "IEX — executes arbitrary string as code",    mitre: ["T1059.001"] },
      { pattern: /\bInvoke-Command\b|\bicm\b/gi,   sev: "high",    label: "Remote command execution",                   mitre: ["T1059.001","T1021"] },
      { pattern: /\bStart-Process\b/gi,            sev: "medium",  label: "Spawns a new process",                       mitre: ["T1059","T1204"] },
      { pattern: /\bShellExecute\b/gi,             sev: "high",    label: "ShellExecute — launches external process",   mitre: ["T1059","T1204"] },
      { pattern: /\bcmd\.exe\b|\bcmd\s*\/[ck]/gi,  sev: "medium",  label: "Spawns cmd.exe subprocess",                  mitre: ["T1059.003"] },
      { pattern: /\bwscript\b|\bcscript\b/gi,      sev: "high",    label: "Executes via WScript/CScript host",          mitre: ["T1059.005"] },
      { pattern: /\bmshta\.exe\b|\bmshta\b/gi,     sev: "critical",label: "mshta — HTML Application host abuse (LOLBin)",mitre: ["T1218.005"] },
      { pattern: /\bregsvr32\b/gi,                 sev: "high",    label: "regsvr32 — COM scriptlet abuse",             mitre: ["T1218.010"] },
      { pattern: /\brundll32\b/gi,                 sev: "high",    label: "rundll32 — DLL proxy execution",             mitre: ["T1218.011"] },
      // Obfuscation
      { pattern: /\-enc\b|\-EncodedCommand\b/gi,   sev: "high",    label: "Base64-encoded command (-enc)",              mitre: ["T1027","T1059.001"] },
      { pattern: /\-w\s*hidden|\-WindowStyle\s*[Hh]idden/gi, sev: "high", label: "Hidden window — anti-visibility",    mitre: ["T1564.003"] },
      { pattern: /\-nop\b|\-NonInteractive\b/gi,   sev: "medium",  label: "-nop/-NonInteractive — evasion flag",        mitre: ["T1059.001"] },
      { pattern: /\-ExecutionPolicy\s*[Bb]ypass/gi,sev: "critical",label: "Execution policy bypass",                    mitre: ["T1059.001","T1562"] },
      { pattern: /\[Convert\]::FromBase64String/gi, sev: "high",   label: "Manual Base64 decode",                       mitre: ["T1027"] },
      { pattern: /\[char\]\s*\d+/gi,               sev: "medium",  label: "Char-array obfuscation",                     mitre: ["T1027"] },
      { pattern: /\$env:/gi,                       sev: "low",     label: "References environment variables",           mitre: ["T1082"] },
      // Persistence
      { pattern: /\bNew-ScheduledTask\b|\bRegister-ScheduledTask\b/gi, sev: "high", label: "Creates scheduled task (persistence)", mitre: ["T1053.005"] },
      { pattern: /\bSet-ItemProperty.*Run\b/gi,    sev: "critical",label: "Writes to Run registry key (autostart)",     mitre: ["T1547.001"] },
      { pattern: /HKCU:\\|HKLM:\\/gi,             sev: "medium",  label: "Modifies registry keys",                     mitre: ["T1547","T1112"] },
      { pattern: /\bNew-Service\b|\bsc\.exe\b/gi,  sev: "high",    label: "Creates or modifies a Windows service",      mitre: ["T1543.003"] },
      // Defense evasion
      { pattern: /\bAdd-MpPreference\s+-Exclusion/gi,sev:"critical",label:"Adds AV/Defender exclusion (disables protection)",mitre:["T1562.001"] },
      { pattern: /\bSet-MpPreference.*Disable/gi,  sev: "critical",label: "Disables Windows Defender",                  mitre: ["T1562.001"] },
      { pattern: /\bDisable-WindowsOptionalFeature\b/gi,sev:"high",label:"Disables Windows security feature",           mitre: ["T1562"] },
      { pattern: /\bwevtutil\b.*cl\b/gi,           sev: "critical",label: "Clears Windows event logs",                  mitre: ["T1070.001"] },
      { pattern: /\bClear-EventLog\b/gi,           sev: "critical",label: "Clears event log (covers tracks)",           mitre: ["T1070.001"] },
      { pattern: /\bSleep\b|\bStart-Sleep\b/gi,    sev: "low",     label: "Sleep delay — possible sandbox evasion",     mitre: ["T1497"] },
      // Credential access
      { pattern: /\bMimikatz\b|\bInvoke-Mimikatz\b/gi, sev:"critical",label:"Mimikatz credential dumping tool",        mitre:["T1003"] },
      { pattern: /\blsass\b/gi,                    sev: "critical",label: "References lsass (credential dump target)",  mitre: ["T1003.001"] },
      { pattern: /\bGet-Credential\b/gi,           sev: "medium",  label: "Credential harvesting attempt",              mitre: ["T1056"] },
      { pattern: /\bSecureString\b/gi,             sev: "low",     label: "Uses SecureString (credential handling)",    mitre: ["T1078"] },
      // Discovery
      { pattern: /\bGet-Process\b|\bGet-Service\b/gi,sev:"low",    label: "Process/service enumeration",                mitre: ["T1057","T1007"] },
      { pattern: /\bGet-NetAdapter\b|\bipconfig\b/gi,sev:"low",    label: "Network interface discovery",                mitre: ["T1016"] },
      { pattern: /\bGet-ADUser\b|\bGet-ADComputer\b/gi,sev:"medium",label:"Active Directory enumeration",              mitre: ["T1087.002"] },
      { pattern: /\bnet\s+user\b|\bnet\s+group\b/gi,sev:"medium", label: "User/group enumeration",                     mitre: ["T1087"] },
      // Lateral movement / C2
      { pattern: /\bEnter-PSSession\b|\bNew-PSSession\b/gi,sev:"high",label:"PS remoting — lateral movement",          mitre:["T1021.006"] },
      { pattern: /\bInvoke-WMIMethod\b|\bGet-WMIObject\b/gi,sev:"high",label:"WMI execution",                         mitre:["T1047"] },
      { pattern: /\bwmic\b/gi,                     sev: "high",    label: "WMIC — WMI command-line abuse",              mitre: ["T1047"] },
      // Exfiltration
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

  // Auto-detect script type
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

  // ── Extract IOCs from script ──
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

  // ── Run indicators against text ──
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

  // ── Severity order ──
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const SEV_CONFIG = {
    critical: { color: "#f87171", bg: "rgba(248,113,113,0.10)", label: "CRITICAL", icon: "🔴" },
    high:     { color: "#fb923c", bg: "rgba(251,146,60,0.10)",  label: "HIGH",     icon: "🟠" },
    medium:   { color: "#fbbf24", bg: "rgba(251,191,36,0.10)",  label: "MEDIUM",   icon: "🟡" },
    low:      { color: "#34d399", bg: "rgba(52,211,153,0.10)",  label: "LOW",      icon: "🟢" },
  };

  // ── Overall verdict from hits ──
  function calcVerdict(hits) {
    if (!hits.length) return { label: "✅ CLEAN", color: "#34d399", score: 0 };
    if (hits.some(h => h.sev === "critical")) return { label: "🔴 MALICIOUS", color: "#f87171", score: hits.length };
    if (hits.some(h => h.sev === "high"))     return { label: "🟠 HIGH RISK",  color: "#fb923c", score: hits.length };
    if (hits.some(h => h.sev === "medium"))   return { label: "🟡 SUSPICIOUS", color: "#fbbf24", score: hits.length };
    return { label: "🟢 LOW RISK", color: "#34d399", score: hits.length };
  }

  // ── Render full analysis result ──
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
    <!-- VERDICT HEADER -->
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

    // THREAT INDICATORS
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

    // MITRE ATT&CK MAPPING
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

    // DECODED LAYERS
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

    // EXTRACTED IOCs
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

    // ENTROPY NOTE
    if (entropy > 5.5) {
      html += `<div class="sa-section sa-entropy-warn">
        <div class="sa-section-head">⚠️ High Entropy Detected (${entropy.toFixed(2)})</div>
        <p style="margin:8px 14px 14px;font-size:13px;color:var(--muted);">
          Entropy above 5.5 typically indicates encoded, compressed, or encrypted content. This script likely contains obfuscated payloads. Use <strong>Deep Decode</strong> to attempt extraction.
        </p>
      </div>`;
    }

    saResults.innerHTML = html;

    // Auto-check MITRE checkboxes in main panel
    mitre.forEach(t => {
      const tid = t.split(".")[0]; // parent technique
      const cb = document.querySelector(`#mitre-panel input[value="${tid}"]`);
      if (cb) cb.checked = true;
    });
  }

  // ── MITRE technique name lookup ──
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

  // ── Report generator ──
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

  // ── Wire up Script Analyzer buttons ──
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

  // Also trigger on Enter in sa-input with Ctrl
  if (saInput) {
    saInput.addEventListener("keydown", e => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        saAnalyzeBtn?.click();
      }
    });
  }

  // ─── Startup ─────────────────────────────────────────────────
  syncSearchboxState();
  setSearchMode(false);
  setLandingLinks();
  renderCardMeta();
  setStatus("Status: ready (landing page)");
  renderHistory();
});
