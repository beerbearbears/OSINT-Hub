document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const status = document.getElementById("status");

  // Landing pages used when input is blank OR type not detected
  const defaultLinks = {
    // IP
    virustotal: "https://www.virustotal.com/",
    abuseipdb: "https://www.abuseipdb.com/",
    talos: "https://talosintelligence.com/",
    ibmxf: "https://exchange.xforce.ibmcloud.com/",
    alienotx: "https://otx.alienvault.com/",
    anyrun_ip: "https://intelligence.any.run/",
    mxtoolbox_ip: "https://mxtoolbox.com/",
    blacklistchecker_ip: "https://blacklistchecker.com/",
    cleantalk_ip: "https://cleantalk.org/blacklists",
    shodan_ip: "https://www.shodan.io/",
    censys_ip: "https://search.censys.io/",
    greynoise: "https://viz.greynoise.io/",
    iplocation: "https://iplocation.io/",
    ipinfo: "https://ipinfo.io/",
    whatismyipaddress_ip: "https://whatismyipaddress.com/",
    myip_ms: "https://myip.ms/",
    ripestat: "https://stat.ripe.net/",
    spur: "https://spur.us/",
    scamalytics: "https://scamalytics.com/",
    threatminer: "https://www.threatminer.org/",
    urlscan: "https://urlscan.io/",
    viewdns_iphistory: "https://viewdns.info/",

    // Domain
    passivedns: "https://www.passivedns.io/",
    securitytrails: "https://securitytrails.com/",
    censys: "https://censys.io/",
    shodan: "https://www.shodan.io/",
    netlas: "https://netlas.io/",
    virustotal_domain: "https://www.virustotal.com/",
    talos_domain: "https://talosintelligence.com/",
    ibmxf_domain: "https://exchange.xforce.ibmcloud.com/",
    alienotx_domain: "https://otx.alienvault.com/",
    urlscan_domain: "https://urlscan.io/",
    mxtoolbox: "https://mxtoolbox.com/",
    blacklistchecker: "https://www.blacklistchecker.com/",
    cleantalk_bl: "https://cleantalk.org/blacklists",
    cleantalk_malware: "https://cleantalk.org/malware",
    sucuri: "https://sitecheck.sucuri.net/",
    urlvoid: "https://www.urlvoid.com/",
    urlhaus: "https://urlhaus.abuse.ch/",
    whois_domaintools: "https://whois.domaintools.com/",
    dnSlytics: "https://dnslytics.com/",
    netcraft: "https://www.netcraft.com/",
    webcheck: "https://webcheck.spiderlabs.io/",
    hudsonrock_info: "https://intel.hudsonrock.com/",
    hudsonrock_urls: "https://intel.hudsonrock.com/",
    socradar: "https://www.socradar.io/",
    wayback: "https://web.archive.org/",
    wayback_save: "https://web.archive.org/",
    browserling: "https://www.browserling.com/",
    anyrun_domain: "https://any.run/",
    anyrun_safe: "https://any.run/",
    phishing_checker: "https://phishingchecker.org/",
    clickfix: "https://clickfix.carsonww.com/",
    nitter: "https://nitter.net/",

    // Email
    hunter: "https://hunter.io/",
    haveibeenpwned: "https://haveibeenpwned.com/",

    // Username
    namechk: "https://namechk.com/",
    whatsmyname: "https://whatsmyname.app/",

    // Hash
    virustotalhash: "https://www.virustotal.com/",
    threatminerhash: "https://www.threatminer.org/",
    anyrun: "https://intelligence.any.run/",
    alienhash: "https://otx.alienvault.com/",
    taloshash: "https://talosintelligence.com/",
    ibmhash: "https://exchange.xforce.ibmcloud.com/",
    triage: "https://tria.ge/",
    joesandbox: "https://www.joesandbox.com/",
    hybrid: "https://www.hybrid-analysis.com/",

    // CVE
    nvd_cve: "https://nvd.nist.gov/",
    cve_org: "https://www.cve.org/",
    cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    exploitdb: "https://www.exploit-db.com/",
    vulners: "https://vulners.com/",
    github_poc: "https://github.com/search"
  };

  function setDefaultHrefs() {
    Object.entries(defaultLinks).forEach(([id, href]) => {
      const el = document.getElementById(id);
      if (el) {
        el.href = href;
        el.target = "_blank";
        el.rel = "noopener";
      }
    });
  }

  // Call once so links work even if input is empty
  setDefaultHrefs();

  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";

    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.trim();

    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return v.toUpperCase();
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return v;

    v = v.replace(/^[a-z]+:\/\//i, "");
    v = v.split("/")[0].split("?")[0].split("#")[0];
    v = v.replace(/\.$/, "");
    return v.trim();
  }

  function detectType(v) {
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return "cve";
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return "email";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) return "hash";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return "domain";
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return "username";
    return null;
  }

  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      section.style.display = (section.dataset.type === type || !section.dataset.type) ? "block" : "none";
    });
  }

  const links = {
    ip: {
      virustotal: (q) => `https://www.virustotal.com/gui/ip-address/${q}/detection`,
      abuseipdb: (q) => `https://www.abuseipdb.com/check/${q}`,
      talos: (q) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}`,
      ibmxf: (q) => `https://exchange.xforce.ibmcloud.com/ip/${q}`,
      alienotx: (q) => `https://otx.alienvault.com/indicator/ip/${q}`,

      anyrun_ip: (q) =>
        `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`,

      mxtoolbox_ip: (q) => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${q}`,
      blacklistchecker_ip: (q) => `https://blacklistchecker.com/check?input=${encodeURIComponent(q)}`,
      cleantalk_ip: (q) => `https://cleantalk.org/blacklists/${q}`,

      shodan_ip: (q) => `https://www.shodan.io/host/${q}`,
      censys_ip: (q) => `https://search.censys.io/hosts/${q}`,
      greynoise: (q) => `https://viz.greynoise.io/ip/${q}`,

      iplocation: (q) => `https://iplocation.io/ip/${q}`,
      ipinfo: (q) => `https://ipinfo.io/${q}`,
      whatismyipaddress_ip: (q) => `https://whatismyipaddress.com/ip/${q}`,
      myip_ms: (q) => `https://myip.ms/info/whois/${q}`,
      ripestat: (q) => `https://stat.ripe.net/resource/${q}?tab=database`,

      spur: (q) => `https://spur.us/context/${q}`,
      scamalytics: (q) => `https://scamalytics.com/ip/${q}`,
      threatminer: (q) => `https://www.threatminer.org/host.php?q=${q}`,
      urlscan: (q) => `https://urlscan.io/ip/${q}`,

      // ✅ NEW: ViewDNS (uses your exact format)
      viewdns_iphistory: (q) => `https://viewdns.info/iphistory/?domain=${encodeURIComponent(q)}`
    },

    domain: {
      passivedns: (q) => `https://www.passivedns.io/?q=${encodeURIComponent(q)}`,
      securitytrails: (q) => `https://securitytrails.com/domain/${q}`,
      censys: (q) => `https://censys.io/domain/${q}`,
      shodan: (q) => `https://www.shodan.io/search?query=${encodeURIComponent(q)}`,
      netlas: (q) => `https://netlas.io/search?query=${encodeURIComponent(q)}`,
      virustotal_domain: (q) => `https://www.virustotal.com/gui/domain/${q}/detection`,
      talos_domain: (q) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}`,
      ibmxf_domain: (q) => `https://exchange.xforce.ibmcloud.com/url/${q}`,
      alienotx_domain: (q) => `https://otx.alienvault.com/indicator/domain/${q}`,
      urlscan_domain: (q) => `https://urlscan.io/domain/${q}`,
      mxtoolbox: (q) => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${q}`,
      blacklistchecker: (q) => `https://www.blacklistchecker.com/check?query=${encodeURIComponent(q)}`,
      cleantalk_bl: (q) => `https://cleantalk.org/blacklists/${q}`,
      cleantalk_malware: (q) => `https://cleantalk.org/malware/${q}`,
      sucuri: (q) => `https://sitecheck.sucuri.net/results/${q}`,
      urlvoid: (q) => `https://www.urlvoid.com/scan/${q}`,
      urlhaus: (q) => `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(q)}`,
      whois_domaintools: (q) => `https://whois.domaintools.com/${q}`,
      dnSlytics: (q) => `https://dnslytics.com/domain/${q}`,
      netcraft: (q) => `https://searchdns.netcraft.com/?host=${encodeURIComponent(q)}`,
      webcheck: (q) => `https://webcheck.spiderlabs.io/${q}`,
      hudsonrock_info: (q) => `https://intel.hudsonrock.com/?q=${encodeURIComponent(q)}`,
      hudsonrock_urls: (q) => `https://intel.hudsonrock.com/?q=${encodeURIComponent(q)}`,
      socradar: (q) => `https://www.socradar.io/labs/dark-web-search/?query=${encodeURIComponent(q)}`,
      wayback: (q) => `https://web.archive.org/web/*/${q}`,
      wayback_save: (q) => `https://web.archive.org/save/${q}`,
      browserling: (q) => `https://www.browserling.com/browse/${q}`,
      anyrun_domain: (q) => `https://any.run/search/?q=${encodeURIComponent(q)}`,
      anyrun_safe: (q) => `https://any.run/search/?q=${encodeURIComponent(q)}`,
      phishing_checker: (q) => `https://phishingchecker.org/?q=${encodeURIComponent(q)}`,
      clickfix: (q) => `https://clickfix.carsonww.com/domains?query=${encodeURIComponent(q)}`,
      nitter: (q) => `https://nitter.net/search?f=tweets&q=${encodeURIComponent(q)}&since=&until=&near=`,
    },

    email: {
      hunter: (q) => `https://hunter.io/search/${encodeURIComponent(q)}`,
      haveibeenpwned: (q) => `https://haveibeenpwned.com/account/${encodeURIComponent(q)}`
    },

    username: {
      namechk: (q) => `https://namechk.com/`,
      whatsmyname: (q) => `https://whatsmyname.app/`
    },

    hash: {
      virustotalhash: (q) => `https://www.virustotal.com/gui/file/${q}/detection`,
      threatminerhash: (q) => `https://www.threatminer.org/sample.php?q=${q}`,

      // ✅ FIX: AnyRun hash uses Intelligence lookup (no 404)
      anyrun: (q) =>
        `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({ query: q, dateRange: 180 }))}`,

      alienhash: (q) => `https://otx.alienvault.com/indicator/file/${q}`,
      taloshash: (q) => `https://talosintelligence.com/talos_file_reputation?s=${q}`,
      ibmhash: (q) => `https://exchange.xforce.ibmcloud.com/malware/${q}`,
      triage: (q) => `https://tria.ge/s?q=${encodeURIComponent(q)}`,

      // ✅ FIX: JoeSandbox link = broader site search (better hit rate)
      joesandbox: (q) => `https://www.google.com/search?q=${encodeURIComponent(`site:joesandbox.com ${q}`)}`,

      hybrid: (q) => `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(q)}`
    },

    cve: {
      nvd_cve: (q) => `https://nvd.nist.gov/vuln/detail/${q}`,
      cve_org: (q) => `https://www.cve.org/CVERecord?id=${q}`,
      cisa_kev: (q) => `https://www.google.com/search?q=${encodeURIComponent(`site:cisa.gov known exploited vulnerabilities ${q}`)}`,
      exploitdb: (q) => `https://www.exploit-db.com/search?cve=${encodeURIComponent(q)}`,
      vulners: (q) => `https://vulners.com/search?query=${encodeURIComponent(q)}`,
      github_poc: (q) => `https://github.com/search?q=${encodeURIComponent(q + " poc exploit")}&type=repositories`
    }
  };

  function updateAllLinks(q, type) {
    if (!links[type]) return;
    Object.keys(links[type]).forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.href = links[type][id](q);
      el.target = "_blank";
      el.rel = "noopener";
    });
  }

  function runSearch() {
    const norm = normalize(input.value);

    // If blank: keep landing pages; show all sections
    if (!norm) {
      status.textContent = "Status: waiting… (links open landing pages)";
      output.value = "";
      document.querySelectorAll(".tool-section").forEach(s => (s.style.display = "block"));
      setDefaultHrefs();
      return;
    }

    const type = detectType(norm);
    if (!type) {
      status.textContent = `Status: Could not detect IOC type → ${norm} (links remain landing pages)`;
      output.value = "";
      document.querySelectorAll(".tool-section").forEach(s => (s.style.display = "block"));
      setDefaultHrefs();
      return;
    }

    showRelevantTools(type);
    updateAllLinks(norm, type);
    status.textContent = `Status: Detected ${type.toUpperCase()} → ${norm}`;
    output.value = `${type.toUpperCase()} Query: ${norm}`;
  }

  function defang() {
    const v = input.value || "";
    output.value = v.replace(/\./g, "[.]").replace(/http/gi, "hxxp");
  }

  function refang() {
    output.value = (output.value || "").replace(/\[\.\]/g, ".").replace(/hxxp/gi, "http");
  }

  function extractIOCs() {
    const text = input.value || "";
    const ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
    const domains = text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [];
    const emails = text.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || [];
    const hashes = text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || [];
    const cves = text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || [];

    output.value =
      `IPs:\n${ips.join("\n")}\n\nDomains:\n${domains.join("\n")}\n\nEmails:\n${emails.join("\n")}\n\nHashes:\n${hashes.join("\n")}\n\nCVEs:\n${cves.map(x => x.toUpperCase()).join("\n")}`;
  }

  function copyOutput() {
    output.select();
    document.execCommand("copy");
  }

  function clearAll() {
    input.value = "";
    output.value = "";
    status.textContent = "Status: waiting… (links open landing pages)";
    document.querySelectorAll(".tool-section").forEach(s => (s.style.display = "block"));
    setDefaultHrefs();
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

  document.getElementById("search-btn").addEventListener("click", runSearch);
  document.getElementById("defang-btn").addEventListener("click", defang);
  document.getElementById("refang-btn").addEventListener("click", refang);
  document.getElementById("extract-btn").addEventListener("click", extractIOCs);
  document.getElementById("copy-btn").addEventListener("click", copyOutput);
  document.getElementById("clear-all").addEventListener("click", clearAll);
  document.getElementById("toggle-dark").addEventListener("click", toggleTheme);

  // Live update while typing + Enter key
  input.addEventListener("input", runSearch);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });

  // Initial state
  runSearch();
});
