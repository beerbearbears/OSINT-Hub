document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const status = document.getElementById("status");

  // Normalize IOC input (supports hxxp, [.] and full URLs)
  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";

    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.replace(/^\s+|\s+$/g, "");

    // If email, keep as-is
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return v;

    // Strip protocol
    v = v.replace(/^[a-z]+:\/\//i, "");
    // Remove path/query/fragment
    v = v.split("/")[0].split("?")[0].split("#")[0];
    // Remove trailing dot
    v = v.replace(/\.$/, "");

    return v.trim();
  }

  function detectType(v) {
    // Order matters
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
      spur: (q) => `https://spur.us/context/${q}`, // ✅ FIXED
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
      threatminerhash: (q) => `https://www.threatminer.org/sample.php?q=${q}`, // ✅ FIXED
      anyrun: (q) => `https://any.run/search/?q=${encodeURIComponent(q)}`,
      alienhash: (q) => `https://otx.alienvault.com/indicator/file/${q}`,
      taloshash: (q) => `https://talosintelligence.com/talos_file_reputation?s=${q}`,
      ibmhash: (q) => `https://exchange.xforce.ibmcloud.com/malware/${q}`,
      triage: (q) => `https://tria.ge/s?q=${encodeURIComponent(q)}`,
      joesandbox: (q) => `https://www.google.com/search?q=${encodeURIComponent(`site:joesandbox.com/analysis ${q}`)}`, // ✅ FIXED
      hybrid: (q) => `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(q)}`,
    },
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
    const raw = input.value;
    const norm = normalize(raw);

    if (!norm) {
      status.textContent = "Status: waiting…";
      return;
    }

    const type = detectType(norm);
    if (!type) {
      status.textContent = `Status: Could not detect IOC type → ${norm}`;
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

    output.value =
      `IPs:\n${ips.join("\n")}\n\nDomains:\n${domains.join("\n")}\n\nEmails:\n${emails.join("\n")}\n\nHashes:\n${hashes.join("\n")}`;
  }

  function copyOutput() {
    output.select();
    document.execCommand("copy");
  }

  function clearAll() {
    input.value = "";
    output.value = "";
    status.textContent = "Status: waiting…";
    document.querySelectorAll(".tool-section").forEach(s => (s.style.display = "block"));
  }

  function toggleTheme() {
    // simple invert-like theme
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

  // Events
  document.getElementById("search-btn").addEventListener("click", runSearch);
  document.getElementById("defang-btn").addEventListener("click", defang);
  document.getElementById("refang-btn").addEventListener("click", refang);
  document.getElementById("extract-btn").addEventListener("click", extractIOCs);
  document.getElementById("copy-btn").addEventListener("click", copyOutput);
  document.getElementById("clear-all").addEventListener("click", clearAll);
  document.getElementById("toggle-dark").addEventListener("click", toggleTheme);

  // Optional: auto-generate links while typing
  input.addEventListener("input", runSearch);

  // Enter = search
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runSearch();
  });
});
