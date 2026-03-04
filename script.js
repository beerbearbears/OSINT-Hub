document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  const $ = (id) => document.getElementById(id);
  const setHref = (id, href) => { const el = $(id); if (el) el.href = href; };
  const setStatus = (msg) => { if (statusText) statusText.textContent = msg; };

  // -------- landing links --------
  const landing = {
    // SOC
    soc_mitre: "https://attack.mitre.org/",
    soc_sigma: "https://github.com/SigmaHQ/sigma",
    soc_cyberchef: "https://gchq.github.io/CyberChef/",
    soc_malapi: "https://malapi.io/",

    // EventID
    ev_uws: "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
    ev_eventidnet: "https://www.eventid.net/",
    ev_mslearn: "https://learn.microsoft.com/",
    ev_splunk: "https://docs.splunk.com/",

    // LOLBINS
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

  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      const secType = section.dataset.type;
      if (!type) { section.style.display = "block"; return; }  // landing
      if (!secType) { section.style.display = "block"; return; } // MITRE always visible
      section.style.display = (secType === type) ? "block" : "none";
    });
  }

  function scrollToType(type) {
    if (!type) return;
    document.querySelector(`.tool-section[data-type="${type}"]`)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---------- detection helpers ----------
  function looksLikeHeaders(text) {
    const t = (text || "").trim();
    if (!t || !t.includes("\n")) return false;
    return [
      /^received:/im,
      /^authentication-results:/im,
      /^dkim-signature:/im,
      /^arc-seal:/im,
      /^message-id:/im,
      /^return-path:/im,
      /^from:/im,
      /^to:/im,
      /^subject:/im
    ].some(rx => rx.test(t));
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

  function detectType(raw) {
    const t = (raw || "").trim();
    const v = normalize(t);

    // headers
    if (looksLikeHeaders(t)) return { type: "header", q: "" };

    // CVE
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };

    // email
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };

    // IP (v4/v6)
    if (isValidIPv6(v) || isValidIPv4(v)) return { type: "ip", q: v };

    // hash
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }

    // Event ID (accept "4625" or "Event ID: 4625")
    const ev = t.match(/\b(?:event\s*id|eventid)\s*[:#-]?\s*(\d{3,5})\b/i) || t.match(/^\s*(\d{3,5})\s*$/);
    if (ev && ev[1]) return { type: "eventid", q: ev[1] };

    // LOLBIN / process / binary
    // common Windows LOL binaries or anything ending with .exe/.dll/.ps1 etc
    const lol = t.match(/\b([a-z0-9._-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr))\b/i);
    if (lol && lol[1]) return { type: "lolbin", q: lol[1].toLowerCase() };
    const lol2 = t.match(/\b(powershell|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|wmic|schtasks|cmd)\b/i);
    if (lol2 && lol2[1]) return { type: "lolbin", q: lol2[1].toLowerCase() };

    // domain
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };

    // username
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  // ---------- link updates ----------
  function updateLinks(type, q) {
    if (!type || !q) return;
    const qp = encodeURIComponent(q);

    if (type === "soc") {
      setHref("soc_mitre", `https://www.google.com/search?q=${encodeURIComponent("site:attack.mitre.org " + q)}`);
      setHref("soc_sigma", `https://github.com/SigmaHQ/sigma/search?q=${qp}`);
      setHref("soc_cyberchef", "https://gchq.github.io/CyberChef/");
      setHref("soc_malapi", `https://www.google.com/search?q=${encodeURIComponent("site:malapi.io " + q)}`);
    }

    if (type === "eventid") {
      setHref("ev_uws", `https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=${qp}`);
      setHref("ev_eventidnet", `https://www.eventid.net/search.asp?search=${qp}&submit=search`);
      setHref("ev_mslearn", `https://www.google.com/search?q=${encodeURIComponent('site:learn.microsoft.com "Event ID ' + q + '"')}`);
      setHref("ev_splunk", `https://www.google.com/search?q=${encodeURIComponent('site:docs.splunk.com "EventCode=' + q + '" OR "Event ID ' + q + '"')}`);
    }

    if (type === "lolbin") {
      setHref("lb_lolbas", `https://www.google.com/search?q=${encodeURIComponent("site:lolbas-project.github.io " + q)}`);
      setHref("lb_lolbas_home", "https://lolbas-project.github.io/");
      setHref("lb_gtfobins", `https://www.google.com/search?q=${encodeURIComponent("site:gtfobins.github.io " + q)}`);
      setHref("lb_hijacklibs", `https://www.google.com/search?q=${encodeURIComponent("site:hijacklibs.net " + q)}`);
    }

    if (type === "ip") {
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
      setHref("dom_vt", `https://www.virustotal.com/gui/domain/${qp}`);
      setHref("dom_talos", `https://talosintelligence.com/reputation_center/lookup?search=${qp}`);
      setHref("dom_ibmxf", `https://exchange.xforce.ibmcloud.com/url/${qp}`);
      setHref("dom_otx", `https://otx.alienvault.com/indicator/domain/${qp}`);
      setHref("dom_urlscan", `https://urlscan.io/search/#page.domain:${qp}`);
      setHref("dom_whois", `https://www.whois.com/whois/${qp}`);
      setHref("dom_dnstools", `https://whois.domaintools.com/${qp}`);
    }

    if (type === "email") {
      setHref("em_hunter", `https://hunter.io/search/${qp}`);
      setHref("em_hibp", `https://haveibeenpwned.com/account/${qp}`);
    }

    if (type === "hash") {
      setHref("h_vt", `https://www.virustotal.com/gui/file/${qp}`);
      setHref("h_hybrid", `https://www.hybrid-analysis.com/sample/${qp}`);
      setHref("h_triage", `https://tria.ge/s?q=${qp}`);
      setHref("h_otx", `https://otx.alienvault.com/indicator/file/${qp}`);
    }

    if (type === "cve") {
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

  // ---------- IOC Extractor (FIXED) ----------
  function uniq(arr) { return Array.from(new Set(arr)); }

  function extractIOCs() {
    // ✅ Use output textarea if user pasted logs there; fallback to input
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

    // collect potential IPv6 tokens then validate strictly
    const ipv6Candidates = text.match(/\b[0-9A-Fa-f:]{2,}\b/g) || [];
    const ipv6 = ipv6Candidates.filter(x => x.includes(":") && isValidIPv6(x));

    const domains = (text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [])
      .filter(d => !d.includes("@"));

    const hashes = text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || [];
    const cves = (text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(x => x.toUpperCase());

    const eventIds = (text.match(/\b(?:event\s*id|eventid)\s*[:#-]?\s*\d{3,5}\b/gi) || [])
      .map(s => (s.match(/\d{3,5}/) || [""])[0])
      .filter(Boolean);

    // usernames: domain\user, user@domain, "user: xxx", "account name: xxx"
    const usernames = [
      ...(text.match(/\b[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+\b/g) || []), // domain\user
      ...(text.match(/\buser(?:name)?\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
      ...(text.match(/\baccount\s*name\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
    ].filter(Boolean);

    // hostnames
    const hostnames = [
      ...(text.match(/\b(?:host|hostname|computer|device)\s*(?:name)?\s*[:=]\s*([A-Za-z0-9._-]{2,})\b/gi) || [])
        .map(s => s.split(/[:=]/)[1].trim()),
    ].filter(Boolean);

    // file paths + process names
    const paths = text.match(/\b[A-Za-z]:\\[^\s"'<>]+/g) || [];
    const procs = text.match(/\b[a-zA-Z0-9._-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)\b/gi) || [];

    const report =
`IOC EXTRACTOR
Extracted At (UTC): ${extractedAt}

Timestamps:
${uniq(timestamps).join("\n") || "-"}

Event IDs:
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
${uniq(paths).join("\n") || "-"}`;

    if (output) output.value = report;
  }

  // ---------- Search ----------
  function doSearch({ silent = false } = {}) {
    const raw = (input?.value || "").trim();

    // landing
    if (!raw) {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: ready (landing page)");
      if (!silent && output) output.value = "";
      return;
    }

    const { type, q } = detectType(raw);

    if (type === "header") {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools("header");
      setStatus("Status: detected EMAIL HEADERS → open analyzer + paste");
      if (!silent && output) output.value = raw;
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
    updateLinks(type, q);
    renderCardMeta();
    setStatus(`Status: detected ${type.toUpperCase()} → ${q}`);
    if (!silent && output) output.value = `${type.toUpperCase()} Query: ${q}`;
    scrollToType(type);
  }

  // ---------- Events ----------
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

  // ✅ FIXED: Extract IOCs now extracts from output textarea OR input
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
