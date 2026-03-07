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

  // ─── Startup ─────────────────────────────────────────────────
  syncSearchboxState();
  setSearchMode(false);
  setLandingLinks();
  renderCardMeta();
  setStatus("Status: ready (landing page)");
  renderHistory();
});
