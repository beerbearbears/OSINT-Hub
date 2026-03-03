document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const status = document.getElementById("status");

  // ---------- Landing pages (always clickable when no input) ----------
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
    Object.entries(landing).forEach(([id, href]) => {
      const el = document.getElementById(id);
      if (el) {
        el.href = href;
        el.target = "_blank";
        el.rel = "noopener";
      }
    });
  }

  // Always make tiles usable
  setLandingLinks();

  // ---------- Helpers ----------
  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";

    // defang -> refang normalize for input
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.trim();

    // If they paste URL, keep host part for domain/ip matching
    // (but we still keep original in extractor)
    const urlLike = v.match(/^(https?:\/\/)(.+)$/i);
    if (urlLike) {
      try {
        const u = new URL(v);
        v = u.hostname;
      } catch {
        // fallback: strip scheme
        v = v.replace(/^[a-z]+:\/\//i, "");
      }
    }

    // strip path/query fragments
    v = v.split("/")[0].split("?")[0].split("#")[0];
    v = v.replace(/\.$/, "");
    return v.trim();
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
      /^return-path:/im
    ];
    return signals.some(rx => rx.test(t));
  }

  function detectType(raw) {
    const t = (raw || "").trim();
    const v = normalize(t);

    if (looksLikeHeaders(t)) return { type: "header", q: "" };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return { type: "ip", q: v };
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) return { type: "hash", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };
    return { type: null, q: v };
  }

  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      section.style.display = (!section.dataset.type || !type || section.dataset.type === type) ? "block" : "none";
    });
  }

  // ---------- Link builders ----------
  function updateLinks(type, q) {
    if (!type) return;

    if (type === "ip") {
      document.getElementById("ip_vt").href = `https://www.virustotal.com/gui/ip-address/${q}`;
      document.getElementById("ip_abuseipdb").href = `https://www.abuseipdb.com/check/${q}`;
      document.getElementById("ip_talos").href = `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}`;
      document.getElementById("ip_ibmxf").href = `https://exchange.xforce.ibmcloud.com/ip/${q}`;
      document.getElementById("ip_otx").href = `https://otx.alienvault.com/indicator/ip/${q}`;

      document.getElementById("ip_anyrun").href =
        `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`;

      document.getElementById("ip_mxtoolbox").href = `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${q}`;
      document.getElementById("ip_blacklistchecker").href = `https://blacklistchecker.com/check?input=${encodeURIComponent(q)}`;
      document.getElementById("ip_cleantalk").href = `https://cleantalk.org/blacklists/${q}`;

      document.getElementById("ip_shodan").href = `https://www.shodan.io/host/${q}`;
      document.getElementById("ip_censys").href = `https://search.censys.io/hosts/${q}`;
      document.getElementById("ip_greynoise").href = `https://viz.greynoise.io/ip/${q}`;

      document.getElementById("ip_iplocation").href = `https://iplocation.io/ip/${q}`;
      document.getElementById("ip_ipinfo").href = `https://ipinfo.io/${q}`;
      document.getElementById("ip_whatismyipaddress").href = `https://whatismyipaddress.com/ip/${q}`;
      document.getElementById("ip_myip").href = `https://myip.ms/info/whois/${q}`;

      document.getElementById("ip_spur").href = `https://spur.us/context/${q}`;
      document.getElementById("ip_clickfix").href = `https://clickfix.carsonww.com/domains?query=${encodeURIComponent(q)}`;
      document.getElementById("ip_ripestat").href = `https://stat.ripe.net/resource/${q}?tab=database`;
      document.getElementById("ip_nitter").href = `https://nitter.net/search?f=tweets&q=${encodeURIComponent(q)}&since=&until=&min_faves=`;

      document.getElementById("ip_threatminer").href = `https://www.threatminer.org/host.php?q=${q}`;
      document.getElementById("ip_urlscan").href = `https://urlscan.io/ip/${q}`;
      document.getElementById("ip_viewdns").href = `https://viewdns.info/iphistory/?domain=${encodeURIComponent(q)}`;
      document.getElementById("ip_scamalytics").href = `https://scamalytics.com/ip/${q}`;
    }

    if (type === "domain") {
      document.getElementById("dom_vt").href = `https://www.virustotal.com/gui/domain/${q}`;
      document.getElementById("dom_talos").href = `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}`;
      document.getElementById("dom_ibmxf").href = `https://exchange.xforce.ibmcloud.com/url/${q}`;
      document.getElementById("dom_otx").href = `https://otx.alienvault.com/indicator/domain/${q}`;

      document.getElementById("dom_urlscan").href = `https://urlscan.io/search/#page.domain:${encodeURIComponent(q)}`;
      document.getElementById("dom_mxtoolbox").href = `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${q}`;
      document.getElementById("dom_blacklistchecker").href = `https://blacklistchecker.com/check?input=${encodeURIComponent(q)}`;
      document.getElementById("dom_cleantalk_bl").href = `https://cleantalk.org/blacklists/${q}`;

      document.getElementById("dom_cleantalk_malware").href = `https://cleantalk.org/website-malware-scanner?url=${encodeURIComponent(q)}`;
      document.getElementById("dom_sucuri").href = `https://sitecheck.sucuri.net/results/${encodeURIComponent(q)}`;
      document.getElementById("dom_urlvoid").href = `https://urlvoid.com/scan/${encodeURIComponent(q)}/`;
      document.getElementById("dom_urlhaus").href = `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(q)}`;

      document.getElementById("dom_whois").href = `https://www.whois.com/whois/${encodeURIComponent(q)}`;
      document.getElementById("dom_dnslytics").href = `https://search.dnslytics.com/search?q=${encodeURIComponent(q)}`;
      document.getElementById("dom_netcraft").href = `https://sitereport.netcraft.com/?url=${encodeURIComponent(q)}`;
      document.getElementById("dom_webcheck").href = `https://web-check.xyz/check/${encodeURIComponent(q)}`;

      document.getElementById("dom_securitytrails").href = `https://securitytrails.com/domain/${encodeURIComponent(q)}`;
      document.getElementById("dom_hudsonrock_info").href = `https://www.hudsonrock.com/search/domain/${encodeURIComponent(q)}`;
      document.getElementById("dom_hudsonrock_urls").href =
        `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=${encodeURIComponent(q)}`;

      document.getElementById("dom_socradar").href = `https://socradar.io/labs/app/dark-web-report?domain=${encodeURIComponent(q)}`;

      document.getElementById("dom_wayback").href = `https://web.archive.org/web/*/${encodeURIComponent(q)}`;
      document.getElementById("dom_wayback_save").href = `https://web.archive.org/save/${encodeURIComponent(q)}`;
      document.getElementById("dom_browserling").href = `https://www.browserling.com/browse/win10/chrome138/${encodeURIComponent(q)}`;

      document.getElementById("dom_anyrun").href =
        `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`;
      document.getElementById("dom_anyrun_safe").href = `https://app.any.run/safe/${encodeURIComponent(q)}`;

      document.getElementById("dom_phishing_checker").href = `https://phishing.finsin.cl/list.php?search=${encodeURIComponent(q)}`;
      document.getElementById("dom_clickfix").href = `https://clickfix.carsonww.com/domains?query=${encodeURIComponent(q)}`;
      document.getElementById("dom_nitter").href = `https://nitter.net/search?f=tweets&q=${encodeURIComponent(q)}&since=&until=&min_faves=`;

      document.getElementById("dom_netlas").href = `https://netlas.io/search?query=${encodeURIComponent(q)}`;
      document.getElementById("dom_censys").href = `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(q)}`;
      document.getElementById("dom_shodan").href = `https://www.shodan.io/search?query=${encodeURIComponent(q)}`;
      document.getElementById("dom_dnstools").href = `https://whois.domaintools.com/${encodeURIComponent(q)}`;
    }

    if (type === "email") {
      document.getElementById("em_hunter").href = `https://hunter.io/search/${encodeURIComponent(q)}`;
      document.getElementById("em_hibp").href = `https://haveibeenpwned.com/account/${encodeURIComponent(q)}`;
    }

    if (type === "username") {
      // Many username tools aren’t query-by-url; keep landings
      // but still show detected type
    }

    if (type === "hash") {
      document.getElementById("h_vt").href = `https://www.virustotal.com/gui/file/${q}`;
      document.getElementById("h_hybrid").href = `https://www.hybrid-analysis.com/sample/${q}`;
      document.getElementById("h_joesandbox").href = `https://www.joesandbox.com/analysis/search?q=${encodeURIComponent(q)}`;
      document.getElementById("h_triage").href = `https://tria.ge/s?q=${encodeURIComponent(q)}`;

      document.getElementById("h_malshare").href = `https://malshare.com/sample.php?action=detail&hash=${encodeURIComponent(q)}`;
      document.getElementById("h_ibmxf").href = `https://exchange.xforce.ibmcloud.com/malware/${q}`;
      document.getElementById("h_talos").href = `https://talosintelligence.com/talos_file_reputation?s=${q}`;
      document.getElementById("h_otx").href = `https://otx.alienvault.com/indicator/file/${q}`;

      // AnyRun: use intelligence lookup (stable vs 404)
      document.getElementById("h_anyrun").href =
        `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`;

      document.getElementById("h_threatminer").href = `https://www.threatminer.org/file.php?q=${q}`;
      document.getElementById("h_cyberchef").href =
        `https://gchq.github.io/CyberChef/#input=${btoa(q)}`;

      document.getElementById("h_nitter").href = `https://nitter.net/search?f=tweets&q=${encodeURIComponent(q)}&since=&until=&min_faves=`;
    }

    if (type === "cve") {
      document.getElementById("cve_nvd").href = `https://nvd.nist.gov/vuln/detail/${q}`;
      document.getElementById("cve_cveorg").href = `https://www.cve.org/CVERecord?id=${q}`;
      document.getElementById("cve_cisa").href = `https://www.google.com/search?q=${encodeURIComponent(`site:cisa.gov ${q} known exploited vulnerabilities`)}`;
      document.getElementById("cve_exploitdb").href = `https://www.exploit-db.com/search?cve=${encodeURIComponent(q)}`;
      document.getElementById("cve_vulners").href = `https://vulners.com/search?query=${encodeURIComponent(q)}`;
      document.getElementById("cve_github").href = `https://github.com/search?q=${encodeURIComponent(q + " poc exploit")}&type=repositories`;
    }
  }

  // ---------- Actions ----------
  function doSearch() {
    const raw = input.value || "";
    const { type, q } = detectType(raw);

    if (!raw.trim()) {
      setLandingLinks();
      showRelevantTools(null);
      status.textContent = "Status: ready (no input → landing pages)";
      output.value = "";
      return;
    }

    if (!type) {
      setLandingLinks();
      showRelevantTools(null);
      status.textContent = "Status: could not detect IOC type (showing all tools)";
      output.value = raw.trim();
      return;
    }

    showRelevantTools(type);

    if (type === "header") {
      // header analyzers are paste-based
      setLandingLinks();
      status.textContent = "Status: detected EMAIL HEADERS → open an analyzer and paste the header";
      output.value = raw.trim();
      return;
    }

    updateLinks(type, q);
    status.textContent = `Status: detected ${type.toUpperCase()} → ${q}`;
    output.value = `${type.toUpperCase()} Query: ${q}`;
  }

  function defangText(text) {
    return (text || "")
      .replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://")
      .replace(/\./g, "[.]");
  }

  function refangText(text) {
    return (text || "")
      .replace(/hxxps:\/\//gi, "https://")
      .replace(/hxxp:\/\//gi, "http://")
      .replace(/\[\.\]/g, ".");
  }

  function uniq(arr) {
    return Array.from(new Set(arr));
  }

  function extractIOCs() {
    const text = input.value || "";
    const now = new Date();
    const extractedAt = now.toISOString();

    // Timestamps (common log formats)
    const ts = [
      ...(text.match(/\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g) || []),
      ...(text.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\b/gi) || []),
      ...(text.match(/\b\d{1,2}\/\d{1,2}\/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}\b/g) || []),
    ];

    const ipv4 = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
    const ipv6 = text.match(/\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/g) || [];

    const emails = text.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || [];

    // Usernames (generic patterns seen in logs)
    // - "by username", "user: name", "account name name", "username=name"
    const usernames = [
      ...(text.match(/\bby\s+([a-zA-Z0-9._-]{3,})\b/g) || []).map(s => s.replace(/^by\s+/i, "")),
      ...(text.match(/\buser(?:name)?\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
      ...(text.match(/\baccount\s*name\s*[:=]\s*([a-zA-Z0-9._-]{3,})\b/gi) || []).map(s => s.split(/[:=]/)[1].trim()),
    ].filter(Boolean);

    // URLs (also captures hxxp/hxxps)
    const urls = text.match(/\b(?:https?|hxxps?|ftp):\/\/[^\s"'<>]+/gi) || [];

    // Domains (avoid grabbing trailing punctuation)
    const domains = (text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [])
      .filter(d => !d.includes("@")); // remove emails

    // Hashes: MD5/SHA1/SHA256
    const hashes = text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || [];

    // CVEs
    const cves = (text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(x => x.toUpperCase());

    output.value =
`IOC EXTRACTOR
Extracted At (UTC): ${extractedAt}

Timestamps:
${uniq(ts).join("\n") || "-"}

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

  function copyOutput() {
    output.focus();
    output.select();
    document.execCommand("copy");
  }

  function clearAll() {
    input.value = "";
    output.value = "";
    status.textContent = "Status: ready (cleared)";
    showRelevantTools(null);
    setLandingLinks();
  }

  function toggleTheme() {
    document.body.classList.toggle("light");

    if (document.body.classList.contains("light")) {
      document.documentElement.style.setProperty("--bg", "#f1f5f9");
      document.documentElement.style.setProperty("--panel", "#ffffff");
      document.documentElement.style.setProperty("--panel2", "#e2e8f0");
      document.documentElement.style.setProperty("--text", "#111827");
      document.documentElement.style.setProperty("--muted", "#4b5563");
      document.documentElement.style.setProperty("--border", "#cbd5e1");
    } else {
      document.documentElement.style.setProperty("--bg", "#0f172a");
      document.documentElement.style.setProperty("--panel", "#111c33");
      document.documentElement.style.setProperty("--panel2", "#1e293b");
      document.documentElement.style.setProperty("--text", "#e2e8f0");
      document.documentElement.style.setProperty("--muted", "#94a3b8");
      document.documentElement.style.setProperty("--border", "#334155");
    }
  }

  // ---------- Wire up buttons ----------
  document.getElementById("search-btn").addEventListener("click", doSearch);
  document.getElementById("defang-btn").addEventListener("click", () => {
    const v = input.value || "";
    output.value = defangText(v);
    status.textContent = "Status: defanged output generated";
  });
  document.getElementById("refang-btn").addEventListener("click", () => {
    const v = output.value || input.value || "";
    output.value = refangText(v);
    status.textContent = "Status: refanged output generated";
  });
  document.getElementById("extract-btn").addEventListener("click", () => {
    extractIOCs();
    status.textContent = "Status: IOC extraction complete";
  });
  document.getElementById("copy-btn").addEventListener("click", () => {
    copyOutput();
    status.textContent = "Status: copied to clipboard";
  });
  document.getElementById("clear-all").addEventListener("click", clearAll);
  document.getElementById("toggle-dark").addEventListener("click", toggleTheme);

  // Optional: live-update links while typing (keeps “click tiles” workflow fast)
  input.addEventListener("input", () => {
    // Only auto-update when it looks like a single IOC; for large logs, user can click Extract
    const t = (input.value || "").trim();
    if (t.length <= 120 && !t.includes("\n")) doSearch();
    if (!t) clearAll();
  });

  // Initial state
  showRelevantTools(null);
  setLandingLinks();
});
