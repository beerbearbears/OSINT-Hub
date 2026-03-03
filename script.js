document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const status = document.getElementById("status");

  // 1) Normalize common SOC formats: hxxp, [.] , full URLs with paths, etc.
  function normalize(raw) {
    let v = (raw || "").trim();

    // convert hxxp(s) -> http(s)
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");

    // refang [.] and (.) patterns
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");

    // remove surrounding brackets/spaces
    v = v.replace(/^\[|\]$/g, "").trim();

    // if it's a URL, keep only host (and maybe query for some tools we don't need)
    // remove protocol
    v = v.replace(/^[a-z]+:\/\//i, "");
    // cut at first slash
    v = v.split("/")[0];
    // cut at first ? or #
    v = v.split("?")[0].split("#")[0];

    // remove trailing dot
    v = v.replace(/\.$/, "");

    return v.trim();
  }

  // 2) Detect IOC type (after normalization)
  function detectType(val) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return "ip";
    if (/^[a-fA-F0-9]{32}$/.test(val) || /^[a-fA-F0-9]{40}$/.test(val) || /^[a-fA-F0-9]{64}$/.test(val)) return "hash";
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(val)) return "email";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return "domain";
    if (/^[a-zA-Z0-9_-]{3,}$/.test(val)) return "username";
    return null;
  }

  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      section.style.display = (section.dataset.type === type || !section.dataset.type) ? "block" : "none";
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const status = document.getElementById("status");

  // 1) Normalize common SOC formats: hxxp, [.] , full URLs with paths, etc.
  function normalize(raw) {
    let v = (raw || "").trim();

    // convert hxxp(s) -> http(s)
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");

    // refang [.] and (.) patterns
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");

    // remove surrounding brackets/spaces
    v = v.replace(/^\[|\]$/g, "").trim();

    // if it's a URL, keep only host (and maybe query for some tools we don't need)
    // remove protocol
    v = v.replace(/^[a-z]+:\/\//i, "");
    // cut at first slash
    v = v.split("/")[0];
    // cut at first ? or #
    v = v.split("?")[0].split("#")[0];

    // remove trailing dot
    v = v.replace(/\.$/, "");

    return v.trim();
  }

  // 2) Detect IOC type (after normalization)
  function detectType(val) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return "ip";
    if (/^[a-fA-F0-9]{32}$/.test(val) || /^[a-fA-F0-9]{40}$/.test(val) || /^[a-fA-F0-9]{64}$/.test(val)) return "hash";
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(val)) return "email";
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return "domain";
    if (/^[a-zA-Z0-9_-]{3,}$/.test(val)) return "username";
    return null;
  }

  function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
      section.style.display = (section.dataset.type === type || !section.dataset.type) ? "block" : "none";
    });
  }

  // 3) ALL SOURCES mapping (IDs must match your <a id="...">)
const links = {
  ip: {
    virustotal: (q) => `https://www.virustotal.com/gui/ip-address/${q}/detection`,
    abuseipdb: (q) => `https://www.abuseipdb.com/check/${q}`,

    // ✅ FIXED: Spur context URL format
    spur: (q) => `https://spur.us/context/${q}`,

    ipinfo: (q) => `https://ipinfo.io/${q}`,
    threatminer: (q) => `https://www.threatminer.org/host.php?q=${q}`,
    urlscan: (q) => `https://urlscan.io/ip/${q}`,
    ibmxf: (q) => `https://exchange.xforce.ibmcloud.com/ip/${q}`,
    talos: (q) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(q)}`,
    alienotx: (q) => `https://otx.alienvault.com/indicator/ip/${q}`,
    scamalytics: (q) => `https://scamalytics.com/ip/${q}`,
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
    clickfix: (q) => `https://www.google.com/search?q=${encodeURIComponent("ClickFix " + q)}`,
    nitter: (q) => `https://nitter.net/search?q=${encodeURIComponent(q)}`,
  },

  email: {
    hunter: (q) => `https://hunter.io/search/${encodeURIComponent(q)}`,
    haveibeenpwned: (q) => `https://haveibeenpwned.com/account/${encodeURIComponent(q)}`,
  },

  username: {
    namechk: (q) => `https://namechk.com/`,
    whatsmyname: (q) => `https://whatsmyname.app/`,
  },

  hash: {
    virustotalhash: (q) => `https://www.virustotal.com/gui/file/${q}/detection`,

    // ✅ FIXED: ThreatMiner hash view uses sample.php (file.php can 404)
    threatminerhash: (q) => `https://www.threatminer.org/sample.php?q=${q}`,

    anyrun: (q) => `https://any.run/search/?q=${encodeURIComponent(q)}`,
    alienhash: (q) => `https://otx.alienvault.com/indicator/file/${q}`,
    taloshash: (q) => `https://talosintelligence.com/talos_file_reputation?s=${q}`,
    ibmhash: (q) => `https://exchange.xforce.ibmcloud.com/malware/${q}`,
    triage: (q) => `https://tria.ge/s?q=${encodeURIComponent(q)}`,

    // ✅ FIXED: JoeSandbox /search often rejects hashes → use reliable site search
    joesandbox: (q) =>
      `https://www.google.com/search?q=${encodeURIComponent(`site:joesandbox.com/analysis ${q}`)}`,

    hybrid: (q) => `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(q)}`,
  },
};
