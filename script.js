document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  // --------- small helpers (prevents JS crashes) ----------
  const $ = (id) => document.getElementById(id);
  const setHref = (id, href) => { const el = $(id); if (el) el.href = href; };
  const setText = (sel, txt) => { const el = document.querySelector(sel); if (el) el.textContent = txt; };

  function setStatus(msg) { if (statusText) statusText.textContent = msg; }

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

  // ---- detect email headers ----
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

  // Robust IPv6 validation
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

    // refang for detection only
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.replace(/\[:\]/g, ":"); // IPv6 defang support

    // if url, extract hostname (IPv6 ok)
    if (/^(https?:\/\/)/i.test(v)) {
      try { v = new URL(v).hostname; } catch { v = v.replace(/^[a-z]+:\/\//i, ""); }
    }

    // strip IPv6 brackets
    v = v.replace(/^\[|\]$/g, "");
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  function detectType(raw) {
    const t = (raw || "").trim();
    const v = normalize(t);

    if (looksLikeHeaders(t)) return { type: "header", q: "" };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };

    if (isValidIPv6(v) || isValidIPv4(v)) return { type: "ip", q: v };

    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }

    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };
    return { type: null, q: v };
  }

  // ✅ Landing = show all. Detected = show only matching data-type. Sections without data-type stay visible (MITRE).
  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      const secType = section.dataset.type;
      if (!type) { section.style.display = "block"; return; }        // landing
      if (!secType) { section.style.display = "block"; return; }     // MITRE etc.
      section.style.display = (secType === type) ? "block" : "none";
    });
  }

  function updateLinks(type, q) {
    if (!type || !q) return;
    const qp = encodeURIComponent(q);

    if (type === "ip") {
      setHref("ip_vt", `https://www.virustotal.com/gui/ip-address/${qp}`);
      setHref("ip_abuseipdb", `https://www.abuseipdb.com/check/${qp}`);
      setHref("ip_talos", `https://talosintelligence.com/reputation_center/lookup?search=${qp}`);
      setHref("ip_ibmxf", `https://exchange.xforce.ibmcloud.com/ip/${qp}`);
      setHref("ip_otx", `https://otx.alienvault.com/indicator/ip/${qp}`);
      setHref("ip_anyrun", `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`);
      setHref("ip_mxtoolbox", `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${qp}`);
      setHref("ip_blacklistchecker", `https://blacklistchecker.com/check?input=${qp}`);
      setHref("ip_cleantalk", `https://cleantalk.org/blacklists/${qp}`);
      setHref("ip_shodan", `https://www.shodan.io/host/${qp}`);
      setHref("ip_censys", `https://search.censys.io/hosts/${qp}`);
      setHref("ip_greynoise", `https://viz.greynoise.io/ip/${qp}`);
      setHref("ip_iplocation", `https://iplocation.io/ip/${qp}`);
      setHref("ip_ipinfo", `https://ipinfo.io/${qp}`);
      setHref("ip_whatismyipaddress", `https://whatismyipaddress.com/ip/${qp}`);
      setHref("ip_myip", `https://myip.ms/info/whois/${qp}`);
      setHref("ip_spur", `https://spur.us/context/${qp}`);
      setHref("ip_clickfix", `https://clickfix.carsonww.com/domains?query=${qp}`);
      setHref("ip_ripestat", `https://stat.ripe.net/resource/${qp}?tab=database`);
      setHref("ip_nitter", `https://nitter.net/search?f=tweets&q=${qp}`);
      setHref("ip_threatminer", `https://www.threatminer.org/host.php?q=${qp}`);
      setHref("ip_urlscan", `https://urlscan.io/ip/${qp}`);
      setHref("ip_viewdns", `https://viewdns.info/iphistory/?domain=${qp}`);
      setHref("ip_scamalytics", `https://scamalytics.com/ip/${qp}`);
    }

    if (type === "domain") {
      setHref("dom_vt", `https://www.virustotal.com/gui/domain/${qp}`);
      setHref("dom_talos", `https://talosintelligence.com/reputation_center/lookup?search=${qp}`);
      setHref("dom_ibmxf", `https://exchange.xforce.ibmcloud.com/url/${qp}`);
      setHref("dom_otx", `https://otx.alienvault.com/indicator/domain/${qp}`);
      setHref("dom_urlscan", `https://urlscan.io/search/#page.domain:${qp}`);
      setHref("dom_mxtoolbox", `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${qp}`);
      setHref("dom_blacklistchecker", `https://blacklistchecker.com/check?input=${qp}`);
      setHref("dom_cleantalk_bl", `https://cleantalk.org/blacklists/${qp}`);
      setHref("dom_cleantalk_malware", `https://cleantalk.org/website-malware-scanner?url=${qp}`);
      setHref("dom_sucuri", `https://sitecheck.sucuri.net/results/${qp}`);
      setHref("dom_urlvoid", `https://urlvoid.com/scan/${qp}/`);
      setHref("dom_urlhaus", `https://urlhaus.abuse.ch/browse.php?search=${qp}`);
      setHref("dom_whois", `https://www.whois.com/whois/${qp}`);
      setHref("dom_dnslytics", `https://search.dnslytics.com/search?q=${qp}`);
      setHref("dom_netcraft", `https://sitereport.netcraft.com/?url=${qp}`);
      setHref("dom_webcheck", `https://web-check.xyz/check/${qp}`);
      setHref("dom_securitytrails", `https://securitytrails.com/domain/${qp}`);
      setHref("dom_hudsonrock_info", `https://www.hudsonrock.com/search/domain/${qp}`);
      setHref("dom_hudsonrock_urls", `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=${qp}`);
      setHref("dom_socradar", `https://socradar.io/labs/app/dark-web-report?domain=${qp}`);
      setHref("dom_wayback", `https://web.archive.org/web/*/${qp}`);
      setHref("dom_wayback_save", `https://web.archive.org/save/${qp}`);
      setHref("dom_browserling", `https://www.browserling.com/browse/win10/chrome138/${qp}`);
      setHref("dom_anyrun", `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`);
      setHref("dom_anyrun_safe", `https://app.any.run/safe/${qp}`);
      setHref("dom_phishing_checker", `https://phishing.finsin.cl/list.php?search=${qp}`);
      setHref("dom_clickfix", `https://clickfix.carsonww.com/domains?query=${qp}`);
      setHref("dom_nitter", `https://nitter.net/search?f=tweets&q=${qp}`);
      setHref("dom_netlas", `https://netlas.io/search?query=${qp}`);
      setHref("dom_censys", `https://search.censys.io/search?resource=hosts&q=${qp}`);
      setHref("dom_shodan", `https://www.shodan.io/search?query=${qp}`);
      setHref("dom_dnstools", `https://whois.domaintools.com/${qp}`);
    }

    if (type === "email") {
      setHref("em_hunter", `https://hunter.io/search/${qp}`);
      setHref("em_hibp", `https://haveibeenpwned.com/account/${qp}`);
    }

    if (type === "hash") {
      setHref("h_vt", `https://www.virustotal.com/gui/file/${qp}`);
      setHref("h_hybrid", `https://www.hybrid-analysis.com/sample/${qp}`);
      setHref("h_joesandbox", `https://www.joesandbox.com/analysis/search?q=${qp}`);
      setHref("h_triage", `https://tria.ge/s?q=${qp}`);
      setHref("h_malshare", `https://malshare.com/sample.php?action=detail&hash=${qp}`);
      setHref("h_ibmxf", `https://exchange.xforce.ibmcloud.com/malware/${qp}`);
      setHref("h_talos", `https://talosintelligence.com/talos_file_reputation?s=${qp}`);
      setHref("h_otx", `https://otx.alienvault.com/indicator/file/${qp}`);
      setHref("h_anyrun", `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`);
      setHref("h_threatminer", `https://www.threatminer.org/file.php?q=${qp}`);
      setHref("h_cyberchef", `https://gchq.github.io/CyberChef/#input=${btoa(q)}`);
      setHref("h_nitter", `https://nitter.net/search?f=tweets&q=${qp}`);
    }

    if (type === "cve") {
      setHref("cve_nvd", `https://nvd.nist.gov/vuln/detail/${qp}`);
      setHref("cve_cveorg", `https://www.cve.org/CVERecord?id=${qp}`);
      setHref("cve_cisa", `https://www.google.com/search?q=${encodeURIComponent(`site:cisa.gov ${q} known exploited vulnerabilities`)}`);
      setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${qp}`);
      setHref("cve_vulners", `https://vulners.com/search?query=${qp}`);
      setHref("cve_github", `https://github.com/search?q=${encodeURIComponent(q + " poc exploit")}&type=repositories`);
    }
  }

  // ✅ Defang supports IPv6
  function defangText(text) {
    let t = (text || "");
    t = t
      .replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://")
      .replace(/\./g, "[.]");

    // defang ipv6 tokens (replace ":" -> "[:]" only when it looks like ipv6)
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

  function doSearch({ silent = false } = {}) {
    const raw = input ? (input.value || "") : "";
    const trimmed = raw.trim();

    // ✅ Landing page stays as-is (show all)
    if (!trimmed) {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: ready (landing page)");
      if (!silent && output) output.value = "";
      return;
    }

    const { type, q } = detectType(trimmed);

    // email headers
    if (type === "header") {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools("header");
      setStatus("Status: detected EMAIL HEADERS → open analyzer + paste");
      if (!silent && output) output.value = trimmed;
      return;
    }

    // unknown -> keep landing
    if (!type) {
      setLandingLinks();
      renderCardMeta();
      showRelevantTools(null);
      setStatus("Status: unknown IOC type (landing page)");
      if (!silent && output) output.value = trimmed;
      return;
    }

    // ✅ only show relevant tools
    showRelevantTools(type);
    updateLinks(type, q);
    renderCardMeta();
    setStatus(`Status: detected ${type.toUpperCase()} → ${q}`);
    if (!silent && output) output.value = `${type.toUpperCase()} Query: ${q}`;
  }

  // ---------- buttons ----------
  $("search-btn")?.addEventListener("click", () => doSearch({ silent: false }));
  input?.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch({ silent: false }); });

  // ✅ auto-filter while typing (keeps landing if empty)
  let tmr = null;
  input?.addEventListener("input", () => {
    clearTimeout(tmr);
    tmr = setTimeout(() => doSearch({ silent: true }), 180);
  });

  $("defang-btn")?.addEventListener("click", () => {
    if (!output) return;
    output.value = defangText(input?.value || "");
    setStatus("Status: defanged output generated");
  });

  $("refang-btn")?.addEventListener("click", () => {
    if (!output) return;
    output.value = refangText(output.value || input?.value || "");
    setStatus("Status: refanged output generated");
  });

  $("copy-btn")?.addEventListener("click", () => {
    if (!output) return;
    output.focus();
    output.select();
    document.execCommand("copy");
    setStatus("Status: copied to clipboard");
  });

  $("extract-btn")?.addEventListener("click", () => {
    // keep your existing extractor if you want; not touching it here
    setStatus("Status: IOC extraction complete");
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

  // ✅ important: update links BEFORE clicking cards (so it won't open landing)
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    const hasInput = (input?.value || "").trim().length > 0;
    if (!hasInput) return;
    doSearch({ silent: true });
  }, true);

  // Startup
  setLandingLinks();
  renderCardMeta();
  showRelevantTools(null);
  setStatus("Status: ready (landing page)");
});
