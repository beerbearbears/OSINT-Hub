document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  const $ = (id) => document.getElementById(id);
  const setHref = (id, href) => { const el = $(id); if (el) el.href = href; };
  const setStatus = (msg) => { if (statusText) statusText.textContent = msg; };

  // ---------- landing links ----------
  const landing = {
    // SOC
    soc_mitre: "https://attack.mitre.org/",
    soc_sigma: "https://github.com/SigmaHQ/sigma",
    soc_cyberchef: "https://gchq.github.io/CyberChef/",
    soc_malapi: "https://malapi.io/",
    soc_intelbase: "https://intelbase.is/",

    // Sysmon
    sysmon_mslearn: "https://learn.microsoft.com/",
    sysmon_hackthelogs: "https://www.hackthelogs.com/mainpage.html",
    sysmon_splunk: "https://docs.splunk.com/",

    // Event ID
    ev_uws: "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
    ev_eventidnet: "https://www.eventid.net/",
    ev_mslearn: "https://learn.microsoft.com/",
    ev_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    // MITRE technique detector
    mitre_tech: "https://attack.mitre.org/",
    mitre_search: "https://attack.mitre.org/",

    // CVE+KEV+EPSS
    cvep_nvd: "https://nvd.nist.gov/",
    cvep_cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss: "https://www.first.org/epss/",
    cvep_github: "https://github.com/search",
    cvep_exploitdb: "https://www.exploit-db.com/",

    // Email artifacts
    emart_hdr_mha: "https://mha.azurewebsites.net/pages/mha.html",
    emart_google: "https://toolbox.googleapps.com/apps/messageheader/",
    emart_msgid_search: "https://www.google.com/",
    emart_dkim_domain: "https://www.google.com/",
    emart_spf_domain: "https://www.google.com/",

    // Cmdline tools
    cmd_sigma: "https://github.com/SigmaHQ/sigma",
    cmd_lolbas: "https://lolbas-project.github.io/",
    cmd_gtfobins: "https://gtfobins.github.io/",
    cmd_splunk: "https://docs.splunk.com/",
    cmd_explainshell: "https://explainshell.com/",
    cmd_ruler: "https://ruler-project.github.io/ruler-project/RULER/remote/",
    cmd_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    // LOLBins
    lb_lolbas: "https://lolbas-project.github.io/",
    lb_lolbas_home: "https://lolbas-project.github.io/",
    lb_gtfobins: "https://gtfobins.github.io/",
    lb_hijacklibs: "https://hijacklibs.net/",

    // IP
    ip_vt: "https://www.virustotal.com/",
    ip_abuseipdb: "https://www.abuseipdb.com/",
    ip_talos: "https://talosintelligence.com/",
    ip_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    ip_otx: "https://otx.alienvault.com/",
    ip_shodan: "https://www.shodan.io/",
    ip_censys: "https://search.censys.io/",
    ip_greynoise: "https://viz.greynoise.io/",
    ip_ipinfo: "https://ipinfo.io/",
    ip_urlscan: "https://urlscan.io/",

    // Domain
    dom_vt: "https://www.virustotal.com/",
    dom_talos: "https://talosintelligence.com/",
    dom_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    dom_otx: "https://otx.alienvault.com/",
    dom_urlscan: "https://urlscan.io/",
    dom_whois: "https://www.whois.com/whois/",
    dom_dnstools: "https://whois.domaintools.com/",

    // Email
    em_hunter: "https://hunter.io/",
    em_hibp: "https://haveibeenpwned.com/",

    // Headers
    hdr_mha: "https://mha.azurewebsites.net/pages/mha.html",
    hdr_google: "https://toolbox.googleapps.com/apps/messageheader/",
    hdr_mxtoolbox: "https://mxtoolbox.com/EmailHeaders.aspx",
    hdr_traceemail: "https://whatismyipaddress.com/trace-email",

    // Username
    usr_namechk: "https://namechk.com/",
    usr_whatsmyname: "https://whatsmyname.app/",

    // Hash
    h_vt: "https://www.virustotal.com/",
    h_hybrid: "https://www.hybrid-analysis.com/",
    h_triage: "https://tria.ge/",
    h_otx: "https://otx.alienvault.com/",

    // CVE
    cve_nvd: "https://nvd.nist.gov/",
    cve_cveorg: "https://www.cve.org/",
    cve_exploitdb: "https://www.exploit-db.com/",
    cve_github: "https://github.com/search"
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

  // Landing: show all. Detected: show only relevant data-type. Sections without data-type (MITRE tagging) stay visible.
  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      const secType = section.dataset.type;
      if (!type) { section.style.display = "block"; return; }
      if (!secType) { section.style.display = "block"; return; }
      section.style.display = (secType === type) ? "block" : "none";
    });
  }

  function scrollToType(type) {
    if (!type) return;
    document.querySelector(`.tool-section[data-type="${type}"]`)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---------- parsing helpers ----------
  function looksLikeHeaders(text) {
    const t = (text || "").trim();
    if (!t || !t.includes("\n")) return false;
    const signals = [
      /^received:/im,
      /^authentication-results:/im,
      /^dkim-signature:/im,
      /^arc-seal:/im,
      /^message-id:/im,
      /^return-path:/im,
      /^from:/im,
      /^to:/im,
      /^subject:/im
    ];
    return signals.some(rx => rx.test(t));
  }

  function isValidIPv6(addr) {
    const v = (addr || "").trim().replace(/^\[|\]$/g, "");
    try { new URL(`http://[${v}]/`); return true; } catch { return false; }
  }

  function isValidIPv4(addr) {
    const parts = (addr || "").trim().split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
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

  function extractEmailArtifacts(text) {
    const t = text || "";
    const messageId = (t.match(/^message-id:\s*(.+)$/im) || [])[1]?.trim() || "";
    const returnPath = (t.match(/^return-path:\s*<?([^>\s]+)>?/im) || [])[1]?.trim() || "";
    const from = (t.match(/^from:\s*(.+)$/im) || [])[1]?.trim() || "";

    // DKIM selector (s=) and d= domain
    const dkimSig = (t.match(/^dkim-signature:\s*([\s\S]+?)(?:\n\S|$)/im) || [])[1] || "";
    const dkimSelector = (dkimSig.match(/\bs=([^;\s]+)/i) || [])[1] || "";
    const dkimDomain = (dkimSig.match(/\bd=([^;\s]+)/i) || [])[1] || "";

    // SPF domain: usually appears in Authentication-Results: spf=pass ... smtp.mailfrom=domain
    const authRes = (t.match(/^authentication-results:\s*([\s\S]+?)(?:\n\S|$)/im) || [])[1] || "";
    const spfDomain = (authRes.match(/\bsmtp\.mailfrom=([^;\s]+)/i) || [])[1] || "";

    const fromDomain = (() => {
      const m = from.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
      if (m && m[1]) return m[1].toLowerCase();
      const m2 = from.match(/<[^>]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})>/);
      return (m2 && m2[1]) ? m2[1].toLowerCase() : "";
    })();

    return {
      messageId,
      returnPath,
      from,
      fromDomain,
      dkimSelector,
      dkimDomain: dkimDomain.toLowerCase(),
      spfDomain: spfDomain.toLowerCase()
    };
  }

  // ---------- detection ----------
  function detectType(raw) {
    const t = (raw || "").trim();
    const v = normalize(t);

    // headers (preferred)
    if (looksLikeHeaders(t)) return { type: "header", q: "" };

    // MITRE technique id
    const tech = t.match(/\bT\d{4}(?:\.\d{3})?\b/i);
    if (tech) return { type: "mitre", q: tech[0].toUpperCase() };

    // CVE (send to cveplus section by default)
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cveplus", q: v.toUpperCase() };

    // email
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };

    // ip
    if (isValidIPv6(v) || isValidIPv4(v)) return { type: "ip", q: v };

    // hash
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }

    // Sysmon event id pattern: "Sysmon Event ID 1" or "Event ID 1" with sysmon keyword
    const sys = t.match(/\b(?:sysmon)\b[\s\S]{0,40}\b(?:event\s*id|eventid)\s*[:#-]?\s*(\d{1,3})\b/i);
    if (sys && sys[1]) return { type: "sysmon", q: sys[1] };

    // Windows event id
    const ev = t.match(/\b(?:event\s*id|eventid)\s*[:#-]?\s*(\d{3,5})\b/i) || t.match(/^\s*(\d{3,5})\s*$/);
    if (ev && ev[1]) return { type: "eventid", q: ev[1] };

    // command line / file path / process
    if (/[A-Za-z]:\\/.test(t) || /\b[a-z0-9._-]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)\b/i.test(t) || /--?[a-z]/.test(t)) {
      return { type: "cmdline", q: t };
    }

    // lolbin keyword
    const lol2 = t.match(/\b(powershell|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|wmic|schtasks|cmd)\b/i);
    if (lol2 && lol2[1]) return { type: "lolbin", q: lol2[1].toLowerCase() };

    // domain
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };

    // username
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  // ---------- link updates ----------
  function updateLinks(type, q, rawTextForContext = "") {
    if (!type) return;

    // helper: google search
    const g = (query) => `https://www.google.com/search?q=${encodeURIComponent(query)}`;

    if (type === "soc") {
      setHref("soc_mitre", g(`site:attack.mitre.org ${q}`));
      setHref("soc_sigma", `https://github.com/SigmaHQ/sigma/search?q=${encodeURIComponent(q)}`);
      setHref("soc_cyberchef", "https://gchq.github.io/CyberChef/");
      setHref("soc_malapi", g(`site:malapi.io ${q}`));
      setHref("soc_intelbase", "https://intelbase.is/");
    }

    if (type === "sysmon") {
      // Event IDs common: 1,3,7,11,13, but allow any number
      const eid = String(q || "").trim();
      setHref("sysmon_mslearn", g(`site:learn.microsoft.com sysmon event id ${eid}`));
      setHref("sysmon_hackthelogs", g(`site:hackthelogs.com sysmon event id ${eid}`));
      setHref("sysmon_splunk", g(`site:docs.splunk.com sysmon EventCode=${eid} OR "Sysmon Event ID ${eid}"`));
    }

    if (type === "eventid") {
      const eid = String(q || "").trim();
      setHref("ev_uws", `https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=${encodeURIComponent(eid)}`);
      setHref("ev_eventidnet", `https://www.eventid.net/search.asp?search=${encodeURIComponent(eid)}&submit=search`);
      setHref("ev_mslearn", g(`site:learn.microsoft.com "Event ID ${eid}"`));
      setHref("ev_hackthelogs", g(`site:hackthelogs.com event id ${eid}`));
    }

    if (type === "mitre") {
      const tid = String(q || "").toUpperCase();
      setHref("mitre_tech", `https://attack.mitre.org/techniques/${encodeURIComponent(tid)}/`);
      setHref("mitre_search", g(`site:attack.mitre.org ${tid}`));
    }

    if (type === "cveplus") {
      const cve = String(q || "").toUpperCase();
      setHref("cvep_nvd", `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`);
      setHref("cvep_cisa_kev", g(`site:cisa.gov "Known Exploited Vulnerabilities" ${cve}`));
      // EPSS site is not always a simple URL param; use search so it always works.
      setHref("cvep_epss", g(`site:first.org epss ${cve}`));
      setHref("cvep_github", `https://github.com/search?q=${encodeURIComponent(cve + " poc exploit")}&type=repositories`);
      setHref("cvep_exploitdb", `https://www.exploit-db.com/search?cve=${encodeURIComponent(cve)}`);
    }

    if (type === "emailart") {
      const art = extractEmailArtifacts(rawTextForContext);
      setHref("emart_hdr_mha", "https://mha.azurewebsites.net/pages/mha.html");
      setHref("emart_google", "https://toolbox.googleapps.com/apps/messageheader/");

      setHref("emart_msgid_search", art.messageId ? g(`"${art.messageId}"`) : g("message-id header"));
      setHref("emart_dkim_domain", art.dkimDomain ? g(`DKIM d=${art.dkimDomain}`) : g("DKIM signature d="));
      setHref("emart_spf_domain", art.spfDomain ? g(`SPF smtp.mailfrom=${art.spfDomain}`) : g("SPF smtp.mailfrom="));
    }

    if (type === "cmdline") {
      const text = String(q || "").trim();
      const file = (text.match(/\b([a-z0-9._-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr))\b/i) || [])[1] || "";
      const base = (file || (text.match(/\b(powershell|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|wmic|schtasks|cmd)\b/i) || [])[1] || "").toLowerCase();

      setHref("cmd_sigma", `https://github.com/SigmaHQ/sigma/search?q=${encodeURIComponent(file || text)}`);
      setHref("cmd_lolbas", base ? g(`site:lolbas-project.github.io ${base}`) : g(`site:lolbas-project.github.io ${text}`));
      setHref("cmd_gtfobins", base ? g(`site:gtfobins.github.io ${base}`) : g(`site:gtfobins.github.io ${text}`));
      setHref("cmd_splunk", g(`site:docs.splunk.com ${file || base || text} command line`));

      // ExplainShell expects query in URL fragment; use direct only if it looks like a shell command
      const explainQ = encodeURIComponent(text.replace(/\s+/g, " ").trim()).slice(0, 2000);
      setHref("cmd_explainshell", `https://explainshell.com/explain?cmd=${explainQ}`);

      setHref("cmd_ruler", "https://ruler-project.github.io/ruler-project/RULER/remote/");
      setHref("cmd_hackthelogs", "https://www.hackthelogs.com/mainpage.html");
    }

    if (type === "lolbin") {
      const s = encodeURIComponent(q || "");
      setHref("lb_lolbas", `https://www.google.com/search?q=${encodeURIComponent("site:lolbas-project.github.io " + (q || ""))}`);
      setHref("lb_lolbas_home", "https://lolbas-project.github.io/");
      setHref("lb_gtfobins", `https://www.google.com/search?q=${encodeURIComponent("site:gtfobins.github.io " + (q || ""))}`);
      setHref("lb_hijacklibs", `https://www.google.com/search?q=${encodeURIComponent("site:hijacklibs.net " + (q || ""))}`);
    }

    if (type === "ip") {
      const qp = encodeURIComponent(q);
      setHref("ip_vt", `https://www.virustotal.com/gui/ip-address/${qp}`);
      setHref("ip_abuseipdb", `https://www.abuseipdb.com/check/${qp}`);
      setHref("ip_talos", `https://talosintelligence.com/reputation_center/lookup?search=${qp}`);
      setHref("ip_ibmxf", `https://exchange.xforce.ibmcloud.com/ip/${qp}`);
      setHref("ip_otx", `https://otx.alienvault.com/indicator/ip/${qp}`);
      setHref("ip_shodan", `https://www.shodan.io/host/${qp}`);
      setHref("ip_censys", `https://search.censys.io/hosts/${qp}`);
      setHref("ip_greynoise", `https://viz.greynoise.io/ip/${qp}`);
      setHref("ip_ipinfo", `https://ipinfo.io/${qp}`);
      setHref("ip_urlscan", `https://urlscan.io/ip/${qp}`);
    }

    if (type === "domain") {
      const qp = encodeURIComponent(q);
      setHref("dom_vt", `https://www.virustotal.com/gui/domain/${qp}`);
      setHref("dom_talos", `https://talosintelligence.com/reputation_center/lookup?search=${qp}`);
      setHref("dom_ibmxf", `https://exchange.xforce.ibmcloud.com/url/${qp}`);
      setHref("dom_otx", `https://otx.alienvault.com/indicator/domain/${qp}`);
      setHref("dom_urlscan", `https://urlscan.io/search/#page.domain:${qp}`);
      setHref("dom_whois", `https://www.whois.com/whois/${qp}`);
      setHref("dom_dnstools", `https://whois.domaintools.com/${qp}`);
    }

    if (type === "email") {
      const qp = encodeURIComponent(q);
      setHref("em_hunter", `https://hunter.io/search/${qp}`);
      setHref("em_hibp", `https://haveibeenpwned.com/account/${qp}`);
    }

    if (type === "hash") {
      const qp = encodeURIComponent(q);
      setHref("h_vt", `https://www.virustotal.com/gui/file/${qp}`);
      setHref("h_hybrid", `https://www.hybrid-analysis.com/sample/${qp}`);
      setHref("h_triage", `https://tria.ge/s?q=${qp}`);
      setHref("h_otx", `https://otx.alienvault.com/indicator/file/${qp}`);
    }

    if (type === "cve") {
      const qp = encodeURIComponent(q);
      setHref("cve_nvd", `https://nvd.nist.gov/vuln/detail/${qp}`);
      setHref("cve_cveorg", `https://www.cve.org/CVERecord?id=${qp}`);
      setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${qp}`);
      setHref("cve_github", `https://github.com/search?q=${encodeURIComponent(q + " poc exploit")}&type=repositories`);
    }
  }

  // ---------- defang/refang ----------
  function defangText(text) {
    let t = (text || "");
    t = t
      .replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://")
      .replace(/\./g, "[.]");

    // defang IPv6 tokens
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

  // ---------- IOC Extractor ----------
  function uniq(arr) { return Array.from(new Set(arr)); }

  function extractIOCs() {
    // Use output (logs pasted) first, else input
    const text = (output?.value || "").trim() || (input?.value || "");
    const extractedAt = new Date().toISOString();

    const timestamps = [
      ...(text.match(/\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g) || []),
      ...(text.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\b/gi) || []),
      ...(text.match(/\b\d{1,2}\/\d{1,2}\/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}\b/g) || []),
    ];

    const emails = text.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || [];
    const urls = text.match(/\b(?:https?|hxxps?|ftp):\/\/[^\s"'<>]+/gi) || [];

    const ipv4Raw = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
    const ipv4 = ipv4Raw.filter(isValidIPv4);

    const ipv6Candidates = text.match(/\b[0-9A-Fa-f:]{2,}\b/g) || [];
    const ipv6 = ipv6Candidates.filter(x => x.includes(":") && isValidIPv6(x));

    const domains = (text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || []).filter(d => !d.includes("@"));
    const hashes = text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || [];
    const cves = (text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(x => x.toUpperCase());

    const mitreTechs = (text.match(/\bT\d{4}(?:\.\d{3})?\b/gi) || []).map(x => x.toUpperCase());

    const eventIds = (text.match(/\b(?:event\s*id|eventid)\s*[:#-]?\s*\d{1,5}\b/gi) || [])
      .map(s => (s.match(/\d{1,5}/) || [""])[0])
      .filter(Boolean);

    const sysmonEventIds = (text.match(/\bsysmon\b[\s\S]{0,40}\b(?:event\s*id|eventid)\s*[:#-]?\s*\d{1,3}\b/gi) || [])
      .map(s => (s.match(/\d{1,3}/) || [""])[0])
      .filter(Boolean);

    const usernames = [
      ...(text.match(/\b[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+\b/g) || []),
      ...(text.match(/\buser(?:name)?\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
      ...(text.match(/\baccount\s*name\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
    ].filter(Boolean);

    const hostnames = [
      ...(text.match(/\b(?:host|hostname|computer|device)\s*(?:name)?\s*[:=]\s*([A-Za-z0-9._-]{2,})\b/gi) || [])
        .map(s => s.split(/[:=]/)[1].trim()),
    ].filter(Boolean);

    const paths = text.match(/\b[A-Za-z]:\\[^\s"'<>]+/g) || [];
    const procs = text.match(/\b[a-zA-Z0-9._-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)\b/gi) || [];

    // Email artifacts (if present in the text)
    const emailArt = extractEmailArtifacts(text);

    const report =
`IOC EXTRACTOR
Extracted At (UTC): ${extractedAt}

Timestamps:
${uniq(timestamps).join("\n") || "-"}

MITRE Techniques:
${uniq(mitreTechs).join("\n") || "-"}

Sysmon Event IDs:
${uniq(sysmonEventIds).join("\n") || "-"}

Windows Event IDs:
${uniq(eventIds).join("\n") || "-"}

Usernames:
${uniq(usernames).join("\n") || "-"}

Hostnames:
${uniq(hostnames).join("\n") || "-"}

Emails:
${uniq(emails).join("\n") || "-"}

IPv4:
${uniq(ipv4).join("\n") || "-"}

IPv6:
${uniq(ipv6).join("\n") || "-"}

Domains:
${uniq(domains).join("\n") || "-"}

URLs:
${uniq(urls).join("\n") || "-"}

Hashes (MD5/SHA1/SHA256):
${uniq(hashes).join("\n") || "-"}

CVEs:
${uniq(cves).join("\n") || "-"}

Processes:
${uniq(procs.map(p => p.toLowerCase())).join("\n") || "-"}

File Paths:
${uniq(paths).join("\n") || "-"}

EMAIL ARTIFACTS (if found):
Message-ID: ${emailArt.messageId || "-"}
DKIM selector (s=): ${emailArt.dkimSelector || "-"}
DKIM domain (d=): ${emailArt.dkimDomain || "-"}
SPF domain (smtp.mailfrom=): ${emailArt.spfDomain || "-"}
Return-Path: ${emailArt.returnPath || "-"}
From domain: ${emailArt.fromDomain || "-"}`;

    if (output) output.value = report;
  }

  // ---------- main search ----------
  function doSearch({ silent = false } = {}) {
    const raw = (input?.value || "").trim();

    if (!raw) {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: ready (landing page)");
      if (!silent && output) output.value = "";
      return;
    }

    const { type, q } = detectType(raw);

    // If headers pasted: show header tools AND also prep email artifacts links
    if (type === "header") {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools("header");
      setStatus("Status: detected EMAIL HEADERS → open analyzer + paste");
      if (!silent && output) output.value = raw;

      // also update Email Artifacts section links using the header text
      updateLinks("emailart", "", raw);
      renderCardMeta();
      // keep header visible (user asked), but also let them scroll to email artifacts if desired manually

      scrollToType("header");
      return;
    }

    if (!type) {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: unknown IOC type (landing page)");
      if (!silent && output) output.value = raw;
      return;
    }

    showRelevantTools(type);
    updateLinks(type, q, raw);
    renderCardMeta();
    setStatus(`Status: detected ${type.toUpperCase()} → ${String(q).slice(0, 120)}`);
    if (!silent && output) output.value = `${type.toUpperCase()} Query: ${q}`;

    scrollToType(type);
  }

  // Ensure tool links are updated right before click (prevents landing links when input exists)
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    if ((input?.value || "").trim()) doSearch({ silent: true });
  }, true);

  // ---------- wire up buttons ----------
  $("search-btn")?.addEventListener("click", () => doSearch({ silent: false }));
  input?.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch({ silent: false }); });

  $("defang-btn")?.addEventListener("click", () => {
    if (!output) return;
    const src = (output.value || "").trim() ? output.value : (input?.value || "");
    output.value = defangText(src);
    setStatus("Status: defanged output generated");
  });

  $("refang-btn")?.addEventListener("click", () => {
    if (!output) return;
    const src = output.value || input?.value || "";
    output.value = refangText(src);
    setStatus("Status: refanged output generated");
  });

  $("extract-btn")?.addEventListener("click", () => {
    extractIOCs();
    setStatus("Status: IOC extraction complete");
  });

  $("copy-btn")?.addEventListener("click", () => {
    if (!output) return;
    output.focus();
    output.select();
    document.execCommand("copy");
    setStatus("Status: copied to clipboard");
  });

  $("clear-all")?.addEventListener("click", () => {
    if (input) input.value = "";
    if (output) output.value = "";
    setLandingLinks();
    renderCardMeta();
    showRelevantTools(null);
    setStatus("Status: ready (landing page)");
  });

  $("toggle-dark")?.addEventListener("click", () => document.body.classList.toggle("light"));

  // Startup
  setLandingLinks();
  renderCardMeta();
  showRelevantTools(null);
  setStatus("Status: ready (landing page)");
});
