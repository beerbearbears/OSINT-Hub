document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

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

    // Headers
    hdr_mha: "https://mha.azurewebsites.net/pages/mha.html",
    hdr_google: "https://toolbox.googleapps.com/apps/messageheader/",
    hdr_mxtoolbox: "https://mxtoolbox.com/EmailHeaders.aspx",
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
    cve_github: "https://github.com/search"
  };

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
    const signals = [
      /^received:/im,
      /^authentication-results:/im,
      /^dkim-signature:/im,
      /^arc-seal:/im,
      /^message-id:/im,
      /^return-path:/im,
    ];
    return signals.some(rx => rx.test(t));
  }

  // Robust IPv6 validator using URL parsing (handles :: compression)
  function isValidIPv6(addr) {
    const v = (addr || "").trim().replace(/^\[|\]$/g, "");
    try {
      // URL requires bracketed IPv6 host
      new URL(`http://[${v}]/`);
      return true;
    } catch {
      return false;
    }
  }

  function isValidIPv4(addr) {
    const parts = (addr || "").trim().split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => {
      if (!/^\d{1,3}$/.test(p)) return false;
      const n = Number(p);
      return n >= 0 && n <= 255;
    });
  }

  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";

    // Refang common patterns for detection only
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");

    // If URL, reduce to hostname (works for IPv6 too)
    if (/^(https?:\/\/)/i.test(v)) {
      try { v = new URL(v).hostname; } catch { v = v.replace(/^[a-z]+:\/\//i, ""); }
    }

    // Strip brackets from IPv6 literals (e.g. [2001:db8::1])
    v = v.replace(/^\[|\]$/g, "");

    // Strip path/query/fragment if user pasted something like "domain.com/path"
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  function detectType(raw) {
    const t = (raw || "").trim();
    const v = normalize(t);

    if (looksLikeHeaders(t)) return { type: "header", q: "" };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };

    // ✅ IPv6 support
    if (isValidIPv6(v)) return { type: "ip", q: v };
    if (isValidIPv4(v)) return { type: "ip", q: v };

    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  // Landing page: show all. Detected: show only that section. MITRE always visible.
  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      const secType = section.dataset.type;
      if (!type) { section.style.display = "block"; return; }
      if (!secType) { section.style.display = "block"; return; }
      section.style.display = (secType === type) ? "block" : "none";
    });
  }

  function updateLinks(type, q) {
    if (!type || !q) return;
    const qp = encodeURIComponent(q);

    if (type === "ip") {
      // Use encode where possible for IPv6 safety
      document.getElementById("ip_vt").href = `https://www.virustotal.com/gui/ip-address/${qp}`;
      document.getElementById("ip_abuseipdb").href = `https://www.abuseipdb.com/check/${qp}`;
      document.getElementById("ip_talos").href = `https://talosintelligence.com/reputation_center/lookup?search=${qp}`;
      document.getElementById("ip_ibmxf").href = `https://exchange.xforce.ibmcloud.com/ip/${qp}`;
      document.getElementById("ip_otx").href = `https://otx.alienvault.com/indicator/ip/${qp}`;
      document.getElementById("ip_anyrun").href = `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`;
      document.getElementById("ip_mxtoolbox").href = `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${qp}`;
      document.getElementById("ip_blacklistchecker").href = `https://blacklistchecker.com/check?input=${qp}`;
      document.getElementById("ip_cleantalk").href = `https://cleantalk.org/blacklists/${qp}`;
      document.getElementById("ip_shodan").href = `https://www.shodan.io/host/${qp}`;
      document.getElementById("ip_censys").href = `https://search.censys.io/hosts/${qp}`;
      document.getElementById("ip_greynoise").href = `https://viz.greynoise.io/ip/${qp}`;
      document.getElementById("ip_iplocation").href = `https://iplocation.io/ip/${qp}`;
      document.getElementById("ip_ipinfo").href = `https://ipinfo.io/${qp}`;
      document.getElementById("ip_whatismyipaddress").href = `https://whatismyipaddress.com/ip/${qp}`;
      document.getElementById("ip_myip").href = `https://myip.ms/info/whois/${qp}`;
      document.getElementById("ip_spur").href = `https://spur.us/context/${qp}`;
      document.getElementById("ip_clickfix").href = `https://clickfix.carsonww.com/domains?query=${qp}`;
      document.getElementById("ip_ripestat").href = `https://stat.ripe.net/resource/${qp}?tab=database`;
      document.getElementById("ip_nitter").href = `https://nitter.net/search?f=tweets&q=${qp}`;
      document.getElementById("ip_threatminer").href = `https://www.threatminer.org/host.php?q=${qp}`;
      document.getElementById("ip_urlscan").href = `https://urlscan.io/ip/${qp}`;
      document.getElementById("ip_viewdns").href = `https://viewdns.info/iphistory/?domain=${qp}`;
      document.getElementById("ip_scamalytics").href = `https://scamalytics.com/ip/${qp}`;
    }

    if (type === "domain") {
      document.getElementById("dom_vt").href = `https://www.virustotal.com/gui/domain/${qp}`;
      document.getElementById("dom_talos").href = `https://talosintelligence.com/reputation_center/lookup?search=${qp}`;
      document.getElementById("dom_ibmxf").href = `https://exchange.xforce.ibmcloud.com/url/${qp}`;
      document.getElementById("dom_otx").href = `https://otx.alienvault.com/indicator/domain/${qp}`;
      document.getElementById("dom_urlscan").href = `https://urlscan.io/search/#page.domain:${qp}`;
      document.getElementById("dom_mxtoolbox").href = `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${qp}`;
      document.getElementById("dom_blacklistchecker").href = `https://blacklistchecker.com/check?input=${qp}`;
      document.getElementById("dom_cleantalk_bl").href = `https://cleantalk.org/blacklists/${qp}`;
      document.getElementById("dom_cleantalk_malware").href = `https://cleantalk.org/website-malware-scanner?url=${qp}`;
      document.getElementById("dom_sucuri").href = `https://sitecheck.sucuri.net/results/${qp}`;
      document.getElementById("dom_urlvoid").href = `https://urlvoid.com/scan/${qp}/`;
      document.getElementById("dom_urlhaus").href = `https://urlhaus.abuse.ch/browse.php?search=${qp}`;
      document.getElementById("dom_whois").href = `https://www.whois.com/whois/${qp}`;
      document.getElementById("dom_dnslytics").href = `https://search.dnslytics.com/search?q=${qp}`;
      document.getElementById("dom_netcraft").href = `https://sitereport.netcraft.com/?url=${qp}`;
      document.getElementById("dom_webcheck").href = `https://web-check.xyz/check/${qp}`;
      document.getElementById("dom_securitytrails").href = `https://securitytrails.com/domain/${qp}`;
      document.getElementById("dom_hudsonrock_info").href = `https://www.hudsonrock.com/search/domain/${qp}`;
      document.getElementById("dom_hudsonrock_urls").href = `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=${qp}`;
      document.getElementById("dom_socradar").href = `https://socradar.io/labs/app/dark-web-report?domain=${qp}`;
      document.getElementById("dom_wayback").href = `https://web.archive.org/web/*/${qp}`;
      document.getElementById("dom_wayback_save").href = `https://web.archive.org/save/${qp}`;
      document.getElementById("dom_browserling").href = `https://www.browserling.com/browse/win10/chrome138/${qp}`;
      document.getElementById("dom_anyrun").href = `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`;
      document.getElementById("dom_anyrun_safe").href = `https://app.any.run/safe/${qp}`;
      document.getElementById("dom_phishing_checker").href = `https://phishing.finsin.cl/list.php?search=${qp}`;
      document.getElementById("dom_clickfix").href = `https://clickfix.carsonww.com/domains?query=${qp}`;
      document.getElementById("dom_nitter").href = `https://nitter.net/search?f=tweets&q=${qp}`;
      document.getElementById("dom_netlas").href = `https://netlas.io/search?query=${qp}`;
      document.getElementById("dom_censys").href = `https://search.censys.io/search?resource=hosts&q=${qp}`;
      document.getElementById("dom_shodan").href = `https://www.shodan.io/search?query=${qp}`;
      document.getElementById("dom_dnstools").href = `https://whois.domaintools.com/${qp}`;
    }

    if (type === "email") {
      document.getElementById("em_hunter").href = `https://hunter.io/search/${qp}`;
      document.getElementById("em_hibp").href = `https://haveibeenpwned.com/account/${qp}`;
    }

    if (type === "hash") {
      document.getElementById("h_vt").href = `https://www.virustotal.com/gui/file/${qp}`;
      document.getElementById("h_hybrid").href = `https://www.hybrid-analysis.com/sample/${qp}`;
      document.getElementById("h_joesandbox").href = `https://www.joesandbox.com/analysis/search?q=${qp}`;
      document.getElementById("h_triage").href = `https://tria.ge/s?q=${qp}`;
      document.getElementById("h_malshare").href = `https://malshare.com/sample.php?action=detail&hash=${qp}`;
      document.getElementById("h_ibmxf").href = `https://exchange.xforce.ibmcloud.com/malware/${qp}`;
      document.getElementById("h_talos").href = `https://talosintelligence.com/talos_file_reputation?s=${qp}`;
      document.getElementById("h_otx").href = `https://otx.alienvault.com/indicator/file/${qp}`;
      document.getElementById("h_anyrun").href = `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`;
      document.getElementById("h_threatminer").href = `https://www.threatminer.org/file.php?q=${qp}`;
      document.getElementById("h_cyberchef").href = `https://gchq.github.io/CyberChef/#input=${btoa(q)}`;
      document.getElementById("h_nitter").href = `https://nitter.net/search?f=tweets&q=${qp}`;
    }

    if (type === "cve") {
      document.getElementById("cve_nvd").href = `https://nvd.nist.gov/vuln/detail/${qp}`;
      document.getElementById("cve_cveorg").href = `https://www.cve.org/CVERecord?id=${qp}`;
      document.getElementById("cve_cisa").href = `https://www.google.com/search?q=${encodeURIComponent(`site:cisa.gov ${q} known exploited vulnerabilities`)}`;
      document.getElementById("cve_exploitdb").href = `https://www.exploit-db.com/search?cve=${qp}`;
      document.getElementById("cve_vulners").href = `https://vulners.com/search?query=${qp}`;
      document.getElementById("cve_github").href = `https://github.com/search?q=${encodeURIComponent(q + " poc exploit")}&type=repositories`;
    }
  }

  // ✅ Defang includes IPv6 ":" -> "[:]"
  function defangText(text) {
    let t = (text || "");
    t = t
      .replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://")
      .replace(/\./g, "[.]");

    // Replace IPv6 colons inside IPv6 tokens only
    // Find long hex/colon runs, validate as IPv6, then defang colons
    t = t.replace(/[A-Fa-f0-9:]{2,}/g, (m) => {
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

  function uniq(arr) { return Array.from(new Set(arr)); }

  function extractIOCs() {
    const text = input.value || "";
    const extractedAt = new Date().toISOString();

    const timestamps = [
      ...(text.match(/\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g) || []),
      ...(text.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\b/gi) || []),
      ...(text.match(/\b\d{1,2}\/\d{1,2}\/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}\b/g) || []),
    ];

    const ipv4 = (text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []).filter(isValidIPv4);

    // ✅ Better IPv6 extraction: grab candidates then validate
    const ipv6Candidates = text.match(/[A-Fa-f0-9:]{2,}/g) || [];
    const ipv6 = ipv6Candidates
      .map(x => x.replace(/^\[|\]$/g, ""))
      .filter(x => x.includes(":") && isValidIPv6(x));

    const emails = text.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || [];
    const urls = text.match(/\b(?:https?|hxxps?|ftp):\/\/[^\s"'<>]+/gi) || [];
    const domains = (text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || []).filter(d => !d.includes("@"));
    const hashes = text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || [];
    const cves = (text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(x => x.toUpperCase());

    const usernames = [
      ...(text.match(/\bby\s+([a-zA-Z0-9._-]{3,})\b/g) || []).map(s => s.replace(/^by\s+/i, "")),
      ...(text.match(/\buser(?:name)?\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
      ...(text.match(/\baccount\s*name\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
    ].filter(Boolean);

    output.value =
`IOC EXTRACTOR
Extracted At (UTC): ${extractedAt}

Timestamps:
${uniq(timestamps).join("\n") || "-"}

Usernames:
${uniq(usernames).join("\n") || "-"}

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
${uniq(cves).join("\n") || "-"}`;
  }

  // Keep current detection so clicks always open correct link
  let current = { type: null, q: "" };

  function doSearch({ silent = false } = {}) {
    const raw = input.value || "";
    const trimmed = raw.trim();

    // No input => LANDING PAGE
    if (!trimmed) {
      current = { type: null, q: "" };
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: ready (landing page)");
      if (!silent) output.value = "";
      return;
    }

    const { type, q } = detectType(trimmed);
    current = { type, q };

    if (type === "header") {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools("header");
      setStatus("Status: detected EMAIL HEADERS → open analyzer + paste");
      if (!silent) output.value = trimmed;
      return;
    }

    if (!type) {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: unknown IOC type (landing page)");
      if (!silent) output.value = trimmed;
      return;
    }

    showRelevantTools(type);
    updateLinks(type, q);
    renderCardMeta();
    setStatus(`Status: detected ${type.toUpperCase()} → ${q}`);
    if (!silent) output.value = `${type.toUpperCase()} Query: ${q}`;
  }

  function copyOutput() {
    output.focus();
    output.select();
    document.execCommand("copy");
  }

  function clearAll() {
    input.value = "";
    output.value = "";
    current = { type: null, q: "" };
    setLandingLinks();
    renderCardMeta();
    showRelevantTools(null);
    setStatus("Status: ready (landing page)");
  }

  function toggleTheme() {
    document.body.classList.toggle("light");
  }

  // ✅ Auto-update links while typing (debounced)
  let tmr = null;
  input.addEventListener("input", () => {
    clearTimeout(tmr);
    tmr = setTimeout(() => doSearch({ silent: true }), 180);
  });

  // ✅ If user clicks a tool card while input is present, force-update links first
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;

    const hasInput = (input.value || "").trim().length > 0;
    if (!hasInput) return;

    // If still on landing links, refresh detection and links before navigation
    // (prevents landing-page redirects)
    doSearch({ silent: true });
  }, true);

  // Events
  document.getElementById("search-btn").addEventListener("click", () => doSearch({ silent: false }));
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") doSearch({ silent: false });
  });

  document.getElementById("defang-btn").addEventListener("click", () => {
    output.value = defangText(input.value || "");
    setStatus("Status: defanged output generated");
  });

  document.getElementById("refang-btn").addEventListener("click", () => {
    output.value = refangText(output.value || input.value || "");
    setStatus("Status: refanged output generated");
  });

  document.getElementById("extract-btn").addEventListener("click", () => {
    extractIOCs();
    setStatus("Status: IOC extraction complete");
  });

  document.getElementById("copy-btn").addEventListener("click", () => {
    copyOutput();
    setStatus("Status: copied to clipboard");
  });

  document.getElementById("clear-all").addEventListener("click", clearAll);
  document.getElementById("toggle-dark").addEventListener("click", toggleTheme);

  // Startup (landing page)
  setLandingLinks();
  renderCardMeta();
  showRelevantTools(null);
  setStatus("Status: ready (landing page)");
});
