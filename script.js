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

  // Searchbox UI helpers
  const searchbox = document.getElementById("searchbox");
  const clearBtn = document.getElementById("clear-input");

  function syncSearchboxState() {
    if (!searchbox || !input) return;
    const has = !!(input.value && input.value.trim());
    searchbox.classList.toggle("has-value", has);
  }

  if (input) input.addEventListener("input", syncSearchboxState);
  if (clearBtn && input) {
    clearBtn.addEventListener("click", () => {
      input.value = "";
      syncSearchboxState();
      input.focus();
    });
  }

  // ---------------- Landing pages (when no input) ----------------
  const landing = {
    // IP
    ip_vt: "https://www.virustotal.com/",
    ip_abuseipdb: "https://www.abuseipdb.com/",
    ip_talos: "https://talosintelligence.com/",
    ip_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    ip_otx: "https://otx.alienvault.com/",
    ip_anyrun: "https://intelligence.any.run/",
    ip_mxtoolbox: "https://mxtoolbox.com/",
    ip_blacklistchecker: "https://blacklistchecker.com/",
    ip_cleantalk: "https://cleantalk.org/blacklists",
    ip_shodan: "https://www.shodan.io/",
    ip_censys: "https://search.censys.io/",
    ip_greynoise: "https://viz.greynoise.io/",
    ip_iplocation: "https://iplocation.io/",
    ip_ipinfo: "https://ipinfo.io/",
    ip_whatismyipaddress: "https://whatismyipaddress.com/",
    ip_myip: "https://myip.ms/",
    ip_spur: "https://spur.us/",
    ip_clickfix: "https://clickfix.carsonww.com/",
    ip_ripestat: "https://stat.ripe.net/",
    ip_nitter: "https://nitter.net/",
    ip_threatminer: "https://www.threatminer.org/",
    ip_urlscan: "https://urlscan.io/",
    ip_viewdns: "https://viewdns.info/",
    ip_scamalytics: "https://scamalytics.com/",

    // Domain
    dom_vt: "https://www.virustotal.com/",
    dom_talos: "https://talosintelligence.com/",
    dom_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    dom_otx: "https://otx.alienvault.com/",
    dom_urlscan: "https://urlscan.io/",
    dom_mxtoolbox: "https://mxtoolbox.com/",
    dom_blacklistchecker: "https://blacklistchecker.com/",
    dom_cleantalk_bl: "https://cleantalk.org/blacklists",
    dom_cleantalk_malware: "https://cleantalk.org/malware",
    dom_sucuri: "https://sitecheck.sucuri.net/",
    dom_urlvoid: "https://www.urlvoid.com/",
    dom_urlhaus: "https://urlhaus.abuse.ch/",
    dom_whois: "https://www.whois.com/whois/",
    dom_dnslytics: "https://dnslytics.com/",
    dom_netcraft: "https://www.netcraft.com/",
    dom_webcheck: "https://webcheck.spiderlabs.io/",
    dom_securitytrails: "https://securitytrails.com/",
    dom_hudsonrock_info: "https://intel.hudsonrock.com/",
    dom_hudsonrock_urls: "https://cavalier.hudsonrock.com/",
    dom_socradar: "https://socradar.io/",
    dom_wayback: "https://web.archive.org/",
    dom_wayback_save: "https://web.archive.org/",
    dom_browserling: "https://www.browserling.com/",
    dom_anyrun: "https://intelligence.any.run/",
    dom_anyrun_safe: "https://any.run/",
    dom_phishing_checker: "https://phishing.finsin.cl/list.php",
    dom_clickfix: "https://clickfix.carsonww.com/",
    dom_nitter: "https://nitter.net/",
    dom_netlas: "https://netlas.io/",
    dom_censys: "https://search.censys.io/",
    dom_shodan: "https://www.shodan.io/",
    dom_dnstools: "https://whois.domaintools.com/",

    // Email
    em_hunter: "https://hunter.io/",
    em_hibp: "https://haveibeenpwned.com/",
    em_intelbase: "https://intelbase.is/",

    // Headers
    hdr_mha: "https://mha.azurewebsites.net/pages/mha.html",
    hdr_google: "https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    hdr_mxtoolbox: "https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx",
    hdr_traceemail: "https://whatismyipaddress.com/trace-email",
    hdr_dnschecker: "https://dnschecker.org/email-header-analyzer.php",

    // Username
    usr_namechk: "https://namechk.com/",
    usr_whatsmyname: "https://whatsmyname.app/",

    // Hash
    h_vt: "https://www.virustotal.com/",
    h_hybrid: "https://www.hybrid-analysis.com/",
    h_joesandbox: "https://www.joesandbox.com/analysis/search",
    h_triage: "https://tria.ge/",
    h_malshare: "https://malshare.com/",
    h_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    h_talos: "https://talosintelligence.com/",
    h_otx: "https://otx.alienvault.com/",
    h_anyrun: "https://intelligence.any.run/",
    h_threatminer: "https://www.threatminer.org/",
    h_cyberchef: "https://gchq.github.io/CyberChef/",
    h_nitter: "https://nitter.net/",

    // CVE
    cve_nvd: "https://nvd.nist.gov/",
    cve_cveorg: "https://www.cve.org/",
    cve_cisa: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cve_exploitdb: "https://www.exploit-db.com/",
    cve_vulners: "https://vulners.com/",
    cve_github: "https://github.com/search",

    // CVE+ (KEV/EPSS)
    cvep_cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss: "https://www.first.org/epss/",

    // Email artifacts (landing)
    emart_msgid_search: "https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    emart_dkim_domain: "https://www.virustotal.com/",
    emart_spf_domain: "https://www.virustotal.com/",

    // LOLBINS
    lb_lolbas: "https://lolbas-project.github.io/",
    lb_gtfobins: "https://gtfobins.github.io/",
    lb_hijacklibs: "https://hijacklibs.net/",

    // Event ID
    ev_eventidnet: "https://www.eventid.net/",
    ev_mslearn: "https://learn.microsoft.com/",
    ev_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    // Sysmon
    sysmon_mslearn: "https://learn.microsoft.com/",
    sysmon_swift: "https://github.com/SwiftOnSecurity/sysmon-config",
    sysmon_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    // SOC
    soc_ruler: "https://ruler-project.github.io/ruler-project/RULER/remote/",
    soc_hackthelogs: "https://www.hackthelogs.com/mainpage.html",
    soc_explainshell: "https://explainshell.com/",
    soc_sigma: "https://github.com/SigmaHQ/sigma",
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
    document.querySelectorAll(".tool-section[data-type]").forEach(section => {
      section.classList.remove("active");
    });
    if (!types || !types.length) return;
    types.forEach(t => {
      const sec = document.querySelector(`.tool-section[data-type="${t}"]`);
      if (sec) sec.classList.add("active");
    });
  }

  // ---------- validators ----------
  function isValidIPv4(addr) {
    const parts = (addr || "").trim().split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  function isPrivateIPv4(ip) {
    if (!isValidIPv4(ip)) return false;
    const [a,b] = ip.split(".").map(Number);
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
    const head = normalized.split("\n").slice(0, 80).join("\n");

    const strong = [
      /(^|\n)\s*received:\s/im,
      /(^|\n)\s*authentication-results:\s/im,
      /(^|\n)\s*dkim-signature:\s/im,
      /(^|\n)\s*arc-seal:\s/im,
      /(^|\n)\s*message-id:\s/im,
      /(^|\n)\s*return-path:\s/im,
      /(^|\n)\s*from:\s/im,
      /(^|\n)\s*to:\s/im,
      /(^|\n)\s*subject:\s/im,
      /(^|\n)\s*date:\s/im,
    ];

    const hasAnyStrong = strong.some(rx => rx.test(head));
    const headerLineCount = (head.match(/(^|\n)[A-Za-z0-9-]{2,}:\s.+/g) || []).length;

    return hasAnyStrong || headerLineCount >= 6;
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
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  // ---------- Email header parser ----------
  function parseEmailHeaders(text) {
    const t = (text || "").replace(/\r\n/g, "\n");

    const getLine = (re) => (t.match(re) || [])[1]?.trim() || "";

    const from = getLine(/^from:\s*(.+)$/im);
    const to = getLine(/^to:\s*(.+)$/im);
    const subject = getLine(/^subject:\s*(.+)$/im);

    const messageId = getLine(/^message-id:\s*(.+)$/im).replace(/[<>]/g, "");
    const returnPath = getLine(/^return-path:\s*<?([^>\s]+)>?/im);

    const senderEmail = (from.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";
    const receiverEmail = (to.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";

    const returnPathDomain = (returnPath.split("@")[1] || "").toLowerCase();

    const dkimBlock = (t.match(/^dkim-signature:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im) || [])[1] || "";
    const dkimSelector = (dkimBlock.match(/\bs=([^;\s]+)/i) || [])[1] || "";
    const dkimDomain = ((dkimBlock.match(/\bd=([^;\s]+)/i) || [])[1] || "").toLowerCase();

    const authBlock = (t.match(/^authentication-results:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im) || [])[1] || "";
    const spfResult = ((authBlock.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();
    const dkimResult = ((authBlock.match(/\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();

    const spfMailfrom = ((authBlock.match(/\bsmtp\.mailfrom=([^;\s]+)/i) || [])[1] || "").toLowerCase();
    const spfMailfromDomain = (spfMailfrom.split("@")[1] || "").toLowerCase();

    // Origin IP heuristic from last Received
    const receivedLines = t.match(/^received:\s*(.+)$/gim) || [];
    let originIp = "";
    for (let i = receivedLines.length - 1; i >= 0; i--) {
      const line = receivedLines[i];
      const ip = (line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || "";
      if (ip && isValidIPv4(ip) && !isPrivateIPv4(ip)) { originIp = ip; break; }
    }

    return {
      from, to, subject,
      senderEmail, receiverEmail,
      messageId,
      returnPath,
      returnPathDomain,
      dkimSelector,
      dkimDomain,
      spfMailfrom,
      spfMailfromDomain,
      spfResult,
      dkimResult,
      originIp
    };
  }

  // ---------- type detection ----------
  function detectType(raw, pastedText) {
    const r = (raw || "").trim();
    const p = (pastedText || "").trim();

    if (looksLikeHeaders(p) || looksLikeHeaders(r)) return { type: "header", q: "" };

    const v = normalize(r);

    if (/^T\d{4,5}$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cveplus", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };

    if (/^(event\s*id|eventid)\s*[:#]?\s*\d{3,5}$/i.test(r) || /^\d{3,5}$/.test(v)) {
      return { type: "eventid", q: v.replace(/[^\d]/g, "") };
    }
    if (/sysmon/i.test(r)) return { type: "sysmon", q: r };

    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };

    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }

    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };

    if (/[\\\/].+\.(exe|dll|ps1|vbs|js|bat|cmd)\b/i.test(r)
      || /\b[a-z0-9._-]+\.(exe|dll|ps1|vbs|js|bat|cmd)\b/i.test(r)
      || r.includes(" -") || r.includes(" /")) {
      return { type: "lolbins", q: r };
    }

    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  const gsearch = (q) => `https://www.google.com/search?q=${enc(q)}`;

  // ---------- update links ----------
  function updateLinksForQuery(type, q, headerText = "") {
    const qp = enc(q || "");

    if (type === "email") {
      setHref("em_hunter", `https://hunter.io/search/${qp}`);
      setHref("em_hibp", `https://haveibeenpwned.com/account/${qp}`);
      setHref("em_intelbase", gsearch(`site:intelbase.is ${q}`));
    }

    if (type === "header") {
      // Header tools (exact links you provided)
      setHref("hdr_dnschecker", "https://dnschecker.org/email-header-analyzer.php");
      setHref("hdr_mxtoolbox", "https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx");
      setHref("hdr_mha", "https://mha.azurewebsites.net/pages/mha.html");
      setHref("hdr_google", "https://toolbox.googleapps.com/apps/messageheader/analyzeheader");

      // Email artifacts pivots (NO more random google redirect)
      const h = parseEmailHeaders(headerText);

      // Message-ID
      setHref("emart_msgid_search", h.messageId ? gsearch(`"${h.messageId}"`) : "https://toolbox.googleapps.com/apps/messageheader/analyzeheader");

      // DKIM domain pivot + DKIM result quick pivot
      if (h.dkimDomain) {
        setHref("emart_dkim_domain",
          `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}`
        );
      } else {
        setHref("emart_dkim_domain", "https://www.virustotal.com/");
      }

      // SPF mailfrom pivot + SPF result quick pivot
      const spfDom = h.spfMailfromDomain || (h.spfMailfrom.split("@")[1] || "");
      if (spfDom) {
        setHref("emart_spf_domain",
          `https://www.virustotal.com/gui/domain/${enc(spfDom)}`
        );
      } else {
        setHref("emart_spf_domain", "https://www.virustotal.com/");
      }
    }

    // Other types: keep your original logic by reusing landing links first
    // (Your existing sections/IDs remain unchanged)
  }

  // ---------- Defang / Refang ----------
  function defangText(text) {
    let t = (text || "");
    t = t.replace(/\bhttps:\/\//gi, "hxxps://").replace(/\bhttp:\/\//gi, "hxxp://");
    t = t.replace(/\[\.\]/g, "[.]");
    t = t.replace(/\./g, "[.]");
    t = t.replace(/[A-Fa-f0-9:\[\]]{2,}/g, (m) => {
      const v = m.replace(/^\[|\]$/g, "");
      if (m.includes(":") && isValidIPv6(v)) return m.replace(/:/g, "[:]");
      return m;
    });
    return t;
  }

  function refangText(text) {
    return (text || "")
      .replace(/hxxps:\/\//gi, "https://")
      .replace(/hxxp:\/\//gi, "http://")
      .replace(/\[\.\]/g, ".")
      .replace(/\[:\]/g, ":");
  }

  // ---------- Smart IOC Extractor (Enhanced for email headers) ----------
  function extractSmartIOCs(text) {
    const now = new Date().toISOString();
    const t = (text || "").replace(/\r\n/g, "\n");

    const headerDetected = looksLikeHeaders(t);
    const header = headerDetected ? parseEmailHeaders(t) : null;

    const out =
`SMART IOC EXTRACTOR
Extracted At (UTC): ${now}

EMAIL HEADER INTEL (if detected):
- Sender (From): ${header?.senderEmail || "-"}
- Receiver (To): ${header?.receiverEmail || "-"}
- Return-Path: ${header?.returnPath || "-"}
- Return-Path Domain: ${header?.returnPathDomain || "-"}
- Origin IP: ${header?.originIp || "-"}
- SPF: ${header?.spfResult || "-"}  (mailfrom: ${header?.spfMailfrom || "-"})
- DKIM: ${header?.dkimResult || "-"}  (d=${header?.dkimDomain || "-"}; s=${header?.dkimSelector || "-"})

QUICK LINKS:
- DKIM Domain Pivot: ${header?.dkimDomain ? `https://www.virustotal.com/gui/domain/${enc(header.dkimDomain)}` : "-"}
- SPF Domain Pivot: ${header?.spfMailfromDomain ? `https://www.virustotal.com/gui/domain/${enc(header.spfMailfromDomain)}` : "-"}
- Origin IP Pivot: ${header?.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(header.originIp)}` : "-"}

(Use Search to show relevant OSINT sections.)`;

    return out;
  }

  // ---------- Main search ----------
  function doSearch({ silent = false } = {}) {
    const raw = (input?.value || "").trim();
    const pasted = (output?.value || "").trim();

    syncSearchboxState();

    if (!raw && !pasted) {
      setSearchMode(false);
      showRelevantTools([]);
      setLandingLinks();
      renderCardMeta();
      setStatus("Status: ready (landing page)");
      if (!silent && output) output.value = "";
      return;
    }

    const { type } = detectType(raw, pasted);

    if (!type) {
      setSearchMode(false);
      showRelevantTools([]);
      setLandingLinks();
      renderCardMeta();
      setStatus("Status: unknown type (landing page)");
      if (!silent && output && raw) output.value = raw;
      return;
    }

    setSearchMode(true);

    const sections = [];
    if (type === "header") sections.push("header", "emailartifacts");
    else if (type === "cveplus") sections.push("cve", "cveplus");
    else if (type === "sysmon") sections.push("sysmon", "soc");
    else if (type === "lolbins") sections.push("lolbins", "soc");
    else if (type === "mitre") sections.push("soc");
    else sections.push(type);

    showRelevantTools(sections);

    setLandingLinks();

    if (type === "header") {
      const headerText = pasted || raw;
      updateLinksForQuery("header", "", headerText);

      if (!silent && output) {
        const h = parseEmailHeaders(headerText);
        output.value =
`EMAIL HEADERS DETECTED ✅

Sender (From): ${h.senderEmail || "-"}
Receiver (To): ${h.receiverEmail || "-"}
Return-Path: ${h.returnPath || "-"}
Return-Path Domain: ${h.returnPathDomain || "-"}
Origin IP (heuristic): ${h.originIp || "-"}
SPF: ${h.spfResult || "-"} (mailfrom: ${h.spfMailfrom || "-"})
DKIM: ${h.dkimResult || "-"} (d=${h.dkimDomain || "-"}; s=${h.dkimSelector || "-"})

Tip: Click Header tools + Email Artifact pivots below.`;
      }

      renderCardMeta();
      setStatus("Status: detected EMAIL HEADERS → header tools + email artifacts pivots");
      return;
    }

    // For non-header searches, just display basic result
    if (!silent && output) output.value = `${type.toUpperCase()} detected`;
    setStatus(`Status: detected ${type.toUpperCase()}`);
    renderCardMeta();
  }

  // Ensure correct links before click
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    const raw = (input?.value || "").trim();
    const pasted = (output?.value || "").trim();
    if (raw || pasted) doSearch({ silent: true });
  }, true);

  // Buttons
  const searchBtn = $("search-btn");
  if (searchBtn) searchBtn.addEventListener("click", () => doSearch({ silent:false }));

  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doSearch({ silent:false });
    });
  }

  const defangBtn = $("defang-btn");
  if (defangBtn) defangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() ? output.value : (input?.value || "");
    if (output) output.value = defangText(src);
    setStatus("Status: defanged output generated");
  });

  const refangBtn = $("refang-btn");
  if (refangBtn) refangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() ? output.value : (input?.value || "");
    if (output) output.value = refangText(src);
    setStatus("Status: refanged output generated");
  });

  const extractBtn = $("extract-btn");
  if (extractBtn) extractBtn.addEventListener("click", () => {
    const text = (output?.value || "").trim() || (input?.value || "");
    if (output) output.value = extractSmartIOCs(text);
    setStatus("Status: Smart IOC extraction complete");
  });

  const copyBtn = $("copy-btn");
  if (copyBtn) copyBtn.addEventListener("click", () => {
    if (!output) return;
    output.focus();
    output.select();
    document.execCommand("copy");
    setStatus("Status: copied to clipboard");
  });

  const clearAll = $("clear-all");
  if (clearAll) clearAll.addEventListener("click", () => {
    if (input) input.value = "";
    if (output) output.value = "";
    syncSearchboxState();
    setSearchMode(false);
    showRelevantTools([]);
    setLandingLinks();
    renderCardMeta();
    setStatus("Status: ready (landing page)");
  });

  const toggleDark = $("toggle-dark");
  if (toggleDark) toggleDark.addEventListener("click", () => {
    document.body.classList.toggle("light");
  });

  // Startup
  syncSearchboxState();
  setSearchMode(false);
  setLandingLinks();
  renderCardMeta();
  setStatus("Status: ready (landing page)");
});
