document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const statusEl = document.getElementById("status");
  const statusText = statusEl ? statusEl.querySelector("span") : null;

  const $ = (id) => document.getElementById(id);
  const setHref = (id, href) => { const el = $(id); if (el) el.href = href; };
  const setStatus = (msg) => { if (statusText) statusText.textContent = msg; };
  const enc = encodeURIComponent;

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
    cve_github: "https://github.com/search",

    // CVE+ (KEV/EPSS)
    cvep_cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss: "https://www.first.org/epss/",

    // Email artifacts
    emart_msgid_search: "https://www.google.com/",
    emart_dkim_domain: "https://www.google.com/",
    emart_spf_domain: "https://www.google.com/",

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
    // fc00::/7 (ULA) or fe80::/10 (link-local) or ::1
    return v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v === "::1";
  }

  function looksLikeHeaders(text) {
    const t = (text || "").trim();
    if (!t) return false;
    const head = t.split("\n").slice(0, 60).join("\n");

    const strong = [
      /(^|\n)\s*received:\s/im,
      /(^|\n)\s*authentication-results:\s/im,
      /(^|\n)\s*dkim-signature:\s/im,
      /(^|\n)\s*arc-seal:\s/im,
      /(^|\n)\s*message-id:\s/im,
      /(^|\n)\s*return-path:\s/im,
      /(^|\n)\s*mime-version:\s/im,
      /(^|\n)\s*content-type:\s/im,
    ];
    const hasAnyStrong = strong.some(rx => rx.test(head));
    const colonLines = (head.match(/(^|\n)[A-Za-z0-9-]{2,}:\s.+/g) || []).length;
    return hasAnyStrong || colonLines >= 4;
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

    // DKIM selector/domain
    const dkimBlock = (t.match(/^dkim-signature:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im) || [])[1] || "";
    const dkimSelector = (dkimBlock.match(/\bs=([^;\s]+)/i) || [])[1] || "";
    const dkimDomain = (dkimBlock.match(/\bd=([^;\s]+)/i) || [])[1] || "";

    // SPF mailfrom is often in Authentication-Results
    const auth = (t.match(/^authentication-results:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im) || [])[1] || "";
    const spfMailfrom = (auth.match(/\bsmtp\.mailfrom=([^;\s]+)/i) || [])[1] || "";

    return {
      messageId,
      returnPath,
      dkimSelector,
      dkimDomain: (dkimDomain || "").toLowerCase(),
      spfMailfrom: (spfMailfrom || "").toLowerCase(),
    };
  }

  function detectType(raw, pastedText) {
    const r = (raw || "").trim();
    const p = (pastedText || "").trim();

    if (looksLikeHeaders(p) || looksLikeHeaders(r)) return { type: "header", q: "" };

    const v = normalize(r);

    // MITRE technique id
    if (/^T\d{4,5}$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };

    // CVE
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cveplus", q: v.toUpperCase() };

    // email
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v };

    // event id / sysmon hints
    if (/^(event\s*id|eventid)\s*[:#]?\s*\d{3,5}$/i.test(r) || /^\d{3,5}$/.test(v)) return { type: "eventid", q: v.replace(/[^\d]/g, "") };
    if (/sysmon/i.test(r)) return { type: "sysmon", q: r };

    // ip
    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };

    // hash
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }

    // domain
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };

    // commandline / file
    if (/[\\\/].+\.(exe|dll|ps1|vbs|js|bat|cmd)\b/i.test(r) || /\b[a-z0-9_-]+\.(exe|dll|ps1|vbs|js|bat|cmd)\b/i.test(r) || r.includes(" -") || r.includes(" /")) {
      return { type: "lolbins", q: r };
    }

    // username
    if (/^[a-zA-Z0-9_-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  // ---------- link builders ----------
  const gsearch = (q) => `https://www.google.com/search?q=${enc(q)}`;

  function updateLinksForQuery(type, q, headerText="") {
    const qp = enc(q || "");

    if (type === "ip") {
      setHref("ip_vt", `https://www.virustotal.com/gui/ip-address/${qp}`);
      setHref("ip_abuseipdb", `https://www.abuseipdb.com/check/${qp}`);
      setHref("ip_talos", `https://talosintelligence.com/reputation_center/lookup?search=${qp}`);
      setHref("ip_ibmxf", `https://exchange.xforce.ibmcloud.com/ip/${qp}`);
      setHref("ip_otx", `https://otx.alienvault.com/indicator/ip/${qp}`);
      setHref("ip_anyrun", `https://intelligence.any.run/analysis/lookup#${enc(JSON.stringify({ query: q, dateRange: 180 }))}`);
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
      setHref("dom_anyrun", `https://intelligence.any.run/analysis/lookup#${enc(JSON.stringify({ query: q, dateRange: 180 }))}`);
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

      // ✅ intelbase 404 fix: stable site-search
      setHref("em_intelbase", gsearch(`site:intelbase.is ${q}`));
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
      setHref("h_anyrun", `https://intelligence.any.run/analysis/lookup#${enc(JSON.stringify({ query: q, dateRange: 180 }))}`);
      setHref("h_threatminer", `https://www.threatminer.org/file.php?q=${qp}`);
      setHref("h_cyberchef", `https://gchq.github.io/CyberChef/#input=${btoa(q)}`);
      setHref("h_nitter", `https://nitter.net/search?f=tweets&q=${qp}`);
    }

    if (type === "username") {
      setHref("usr_namechk", `https://namechk.com/${enc(q)}`);
      setHref("usr_whatsmyname", `https://whatsmyname.app/?q=${enc(q)}`);
    }

    if (type === "cveplus") {
      setHref("cve_nvd", `https://nvd.nist.gov/vuln/detail/${enc(q)}`);
      setHref("cve_cveorg", `https://www.cve.org/CVERecord?id=${enc(q)}`);
      setHref("cve_cisa", gsearch(`site:cisa.gov ${q} known exploited vulnerabilities`));
      setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${enc(q)}`);
      setHref("cve_vulners", `https://vulners.com/search?query=${enc(q)}`);
      setHref("cve_github", `https://github.com/search?q=${enc(q + " poc exploit")}&type=repositories`);

      setHref("cvep_cisa_kev", gsearch(`site:cisa.gov "Known Exploited Vulnerabilities" ${q}`));
      setHref("cvep_epss", gsearch(`site:first.org EPSS ${q}`));
    }

    if (type === "eventid") {
      setHref("ev_eventidnet", `https://www.eventid.net/search.asp?search=${enc(q)}&submit=search`);
      setHref("ev_mslearn", gsearch(`site:learn.microsoft.com "Event ID ${q}"`));
      setHref("ev_hackthelogs", `https://www.hackthelogs.com/?s=${enc(q)}`);
    }

    if (type === "sysmon") {
      setHref("sysmon_mslearn", gsearch(`site:learn.microsoft.com sysmon event id ${q}`));
    }

    if (type === "mitre") {
      // Not a section, but give user a useful result in output
      // (MITRE checkbox section always visible)
    }

    if (type === "header") {
      const art = extractEmailArtifacts(headerText);
      setHref("emart_msgid_search", art.messageId ? gsearch(`"${art.messageId}"`) : gsearch("message-id header"));
      setHref("emart_dkim_domain", art.dkimDomain ? gsearch(`DKIM d=${art.dkimDomain}`) : gsearch("DKIM signature d="));
      setHref("emart_spf_domain", art.spfMailfrom ? gsearch(`SPF smtp.mailfrom=${art.spfMailfrom}`) : gsearch("SPF smtp.mailfrom="));
    }

    if (type === "lolbins") {
      // Use google searches against LOLBAS + Sigma
      setHref("lb_lolbas", gsearch(`site:lolbas-project.github.io ${q}`));
      setHref("soc_sigma", gsearch(`site:github.com SigmaHQ sigma ${q}`));
      setHref("soc_explainshell", "https://explainshell.com/");
    }
  }

  // ---------- Defang / Refang ----------
  function defangText(text) {
    let t = (text || "");

    // URLs
    t = t.replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://");

    // dots
    t = t.replace(/\./g, "[.]");

    // IPv6 (replace : with [:] only for real IPv6 tokens)
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

  // ---------- Smart IOC Extractor ----------
  function uniq(arr) { return Array.from(new Set(arr)); }

  const suspiciousTlds = new Set(["zip","mov","top","xyz","click","cam","gq","tk","work","life","rest","fit","quest"]);
  const urlShorteners = ["bit.ly","t.co","tinyurl.com","goo.gl","is.gd","cutt.ly","rebrand.ly","ow.ly","buff.ly","rb.gy"];

  function scoreUrl(u) {
    let s = 25;
    const lower = u.toLowerCase();

    if (lower.includes("@")) s += 10;
    if (lower.includes("xn--")) s += 10;
    if (/\b\d{1,3}(\.\d{1,3}){3}\b/.test(lower)) s += 10; // IP in URL
    if (/:([0-9]{2,5})\b/.test(lower) && !/:(80|443)\b/.test(lower)) s += 8;

    const extHit = lower.match(/\.(exe|dll|scr|js|jse|vbs|vbe|ps1|bat|cmd|msi|iso|img|zip|rar|7z|one|lnk)(\?|$|#|\/)/);
    if (extHit) s += 18;

    const kw = ["invoice","payment","update","security","verify","login","reset","password","mfa","urgent","doc","sharepoint","onedrive","dropbox"];
    if (kw.some(k => lower.includes(k))) s += 8;

    try {
      const url = new URL(lower.replace(/^hxxp/, "http"));
      const host = url.hostname;
      if (urlShorteners.includes(host)) s += 15;
      const tld = host.split(".").pop();
      if (tld && suspiciousTlds.has(tld)) s += 10;
    } catch {}

    return s;
  }

  function scoreDomain(d) {
    let s = 18;
    const lower = d.toLowerCase();
    if (lower.startsWith("xn--")) s += 10;
    const tld = lower.split(".").pop();
    if (tld && suspiciousTlds.has(tld)) s += 10;
    if (lower.includes("-")) s += 2;
    return s;
  }

  function scoreIp(ip) {
    if (isValidIPv4(ip)) {
      if (isPrivateIPv4(ip)) return 6;
      return 30;
    }
    if (isValidIPv6(ip)) {
      if (isPrivateIPv6(ip)) return 6;
      return 30;
    }
    return 0;
  }

  function extractSmartIOCs(text) {
    const now = new Date().toISOString();
    const t = text || "";

    // Core artifacts
    const timestamps = [
      ...(t.match(/\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g) || []),
      ...(t.match(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\b/gi) || []),
      ...(t.match(/\b\d{1,2}\/\d{1,2}\/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}\b/g) || []),
    ];

    const ipv4Raw = t.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
    const ipv4 = uniq(ipv4Raw.filter(isValidIPv4));

    const ipv6Candidates = t.match(/\b[0-9A-Fa-f:]{2,}\b/g) || [];
    const ipv6 = uniq(ipv6Candidates.filter(x => x.includes(":") && isValidIPv6(x)));

    const emails = uniq(t.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || []);
    const urls = uniq(t.match(/\b(?:https?|hxxps?|ftp):\/\/[^\s"'<>]+/gi) || []);
    const domains = uniq((t.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || []).filter(d => !d.includes("@")));

    const hashes = uniq(t.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || []).map(x => x.toLowerCase());
    const cves = uniq((t.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(x => x.toUpperCase()));
    const mitre = uniq((t.match(/\bT\d{4,5}\b/gi) || []).map(x => x.toUpperCase()));

    // Windows Event IDs + Sysmon IDs
    const eventIds = uniq([
      ...((t.match(/\bEvent\s*ID\s*[:#]?\s*(\d{3,5})\b/gi) || []).map(x => x.replace(/[^\d]/g, ""))),
      ...((t.match(/\b(?:^|\s)(\d{3,5})(?:\s|$)\b/g) || []).filter(x => /^\d{3,5}$/.test(x.trim())).map(x => x.trim()))
    ]).filter(Boolean);

    const sysmonIds = uniq((t.match(/\bSysmon\s*(?:Event\s*)?ID\s*[:#]?\s*(\d{1,2})\b/gi) || []).map(x => x.replace(/[^\d]/g, ""))).filter(Boolean);

    // file/process/command line (simple but useful)
    const filePaths = uniq(t.match(/\b[A-Za-z]:\\[^\r\n"']+\b/g) || []);
    const executables = uniq(t.match(/\b[a-zA-Z0-9._-]+\.(exe|dll|ps1|vbs|js|bat|cmd|msi)\b/gi) || []).map(x => x.toLowerCase());
    const commandLines = [];
    const cmdLineMatch = t.match(/\bcommand\s*line\s*[:=]\s*([^\r\n]+)/i);
    if (cmdLineMatch && cmdLineMatch[1]) commandLines.push(cmdLineMatch[1].trim());

    // Email header artifacts (if present)
    const emailArtifacts = looksLikeHeaders(t) ? extractEmailArtifacts(t) : { messageId:"", returnPath:"", dkimSelector:"", dkimDomain:"", spfMailfrom:"" };

    // Score items
    const scored = [];

    hashes.forEach(h => scored.push({ type:"HASH", value:h, score:50, note:"High-value file pivot" }));
    cves.forEach(c => scored.push({ type:"CVE", value:c, score:42, note:"Vulnerability pivot (check KEV/EPSS)" }));
    mitre.forEach(m => scored.push({ type:"MITRE", value:m, score:28, note:"Technique pivot (ATT&CK)" }));

    ipv4.forEach(ip => scored.push({ type:"IP", value:ip, score:scoreIp(ip), note:isPrivateIPv4(ip) ? "Private/loopback/link-local" : "Public IP pivot" }));
    ipv6.forEach(ip => scored.push({ type:"IPV6", value:ip, score:scoreIp(ip), note:isPrivateIPv6(ip) ? "ULA/link-local/loopback" : "Public IPv6 pivot" }));

    urls.forEach(u => scored.push({ type:"URL", value:u, score:scoreUrl(u), note:"URL pivot" }));
    domains.forEach(d => scored.push({ type:"DOMAIN", value:d, score:scoreDomain(d), note:"Domain pivot" }));
    emails.forEach(e => scored.push({ type:"EMAIL", value:e, score:20, note:"Identity/Breach pivot" }));

    eventIds.slice(0, 30).forEach(eid => scored.push({ type:"EVENT_ID", value:eid, score:16, note:"Windows event lookup" }));
    sysmonIds.forEach(sid => scored.push({ type:"SYSMON_ID", value:sid, score:18, note:"Sysmon ID pivot" }));

    executables.forEach(exe => scored.push({ type:"EXECUTABLE", value:exe, score:22, note:"Possible LOLBIN / process pivot" }));
    filePaths.slice(0, 50).forEach(p => scored.push({ type:"FILEPATH", value:p, score:10, note:"Host artifact" }));
    commandLines.forEach(c => scored.push({ type:"CMDLINE", value:c, score:26, note:"Command line pivot" }));

    if (emailArtifacts.messageId) scored.push({ type:"MESSAGE-ID", value:emailArtifacts.messageId, score:22, note:"Email artifact pivot" });
    if (emailArtifacts.dkimDomain) scored.push({ type:"DKIM d=", value:emailArtifacts.dkimDomain, score:20, note:"Sender DKIM domain pivot" });
    if (emailArtifacts.dkimSelector) scored.push({ type:"DKIM s=", value:emailArtifacts.dkimSelector, score:14, note:"DKIM selector" });
    if (emailArtifacts.spfMailfrom) scored.push({ type:"SPF mailfrom", value:emailArtifacts.spfMailfrom, score:20, note:"SPF mailfrom pivot" });
    if (emailArtifacts.returnPath) scored.push({ type:"Return-Path", value:emailArtifacts.returnPath, score:18, note:"Return-Path pivot" });

    // Sort high to low and dedupe by type+value
    const key = (o) => `${o.type}::${o.value}`.toLowerCase();
    const seen = new Set();
    const deduped = [];
    scored.sort((a,b) => b.score - a.score).forEach(o => {
      const k = key(o);
      if (!seen.has(k)) { seen.add(k); deduped.push(o); }
    });

    const high = deduped.filter(x => x.score >= 30).slice(0, 20);
    const medium = deduped.filter(x => x.score >= 18 && x.score < 30).slice(0, 40);

    // Build investigation-ready quick pivot links for top items
    const pivots = [];
    high.forEach(item => {
      if (item.type === "IP" || item.type === "IPV6") {
        pivots.push(`VT IP: https://www.virustotal.com/gui/ip-address/${enc(item.value)}`);
        pivots.push(`AbuseIPDB: https://www.abuseipdb.com/check/${enc(item.value)}`);
        pivots.push(`GreyNoise: https://viz.greynoise.io/ip/${enc(item.value)}`);
      }
      if (item.type === "DOMAIN") {
        pivots.push(`VT Domain: https://www.virustotal.com/gui/domain/${enc(item.value)}`);
        pivots.push(`urlscan: https://urlscan.io/search/#page.domain:${enc(item.value)}`);
        pivots.push(`WHOIS: https://www.whois.com/whois/${enc(item.value)}`);
      }
      if (item.type === "HASH") {
        pivots.push(`VT File: https://www.virustotal.com/gui/file/${enc(item.value)}`);
        pivots.push(`Triage: https://tria.ge/s?q=${enc(item.value)}`);
        pivots.push(`OTX File: https://otx.alienvault.com/indicator/file/${enc(item.value)}`);
      }
      if (item.type === "CVE") {
        pivots.push(`NVD: https://nvd.nist.gov/vuln/detail/${enc(item.value)}`);
        pivots.push(`Exploit-DB: https://www.exploit-db.com/search?cve=${enc(item.value)}`);
      }
      if (item.type === "URL") {
        pivots.push(`urlscan: https://urlscan.io/search/#${enc(item.value)}`);
        pivots.push(`VT URL search: ${gsearch(`site:virustotal.com ${item.value}`)}`);
      }
    });

    const out =
`SMART IOC EXTRACTOR
Extracted At (UTC): ${now}

INVESTIGATION-READY (Top priority):
${high.map(x => `- [${x.score}] ${x.type}: ${x.value}${x.note ? `  (${x.note})` : ""}`).join("\n") || "- None"}

USEFUL (Medium priority):
${medium.map(x => `- [${x.score}] ${x.type}: ${x.value}${x.note ? `  (${x.note})` : ""}`).join("\n") || "- None"}

EMAIL ARTIFACTS (if detected):
- Message-ID: ${emailArtifacts.messageId || "-"}
- Return-Path: ${emailArtifacts.returnPath || "-"}
- DKIM selector (s=): ${emailArtifacts.dkimSelector || "-"}
- DKIM domain (d=): ${emailArtifacts.dkimDomain || "-"}
- SPF mailfrom: ${emailArtifacts.spfMailfrom || "-"}

TIMESTAMPS:
${uniq(timestamps).join("\n") || "-"}

QUICK PIVOT LINKS (Top items):
${uniq(pivots).slice(0, 25).join("\n") || "-"}

ALL EXTRACTED (Raw lists):
Emails:
${emails.join("\n") || "-"}

IPv4:
${ipv4.join("\n") || "-"}

IPv6:
${ipv6.join("\n") || "-"}

Domains:
${domains.join("\n") || "-"}

URLs:
${urls.join("\n") || "-"}

Hashes:
${hashes.join("\n") || "-"}

CVEs:
${cves.join("\n") || "-"}

MITRE Technique IDs:
${mitre.join("\n") || "-"}

Windows Event IDs:
${eventIds.join("\n") || "-"}

Sysmon IDs:
${sysmonIds.join("\n") || "-"}

Executables:
${executables.join("\n") || "-"}

File Paths:
${filePaths.join("\n") || "-"}

Command Lines:
${commandLines.join("\n") || "-"}`;

    return out;
  }

  // ---------- Main search ----------
  function doSearch({ silent = false } = {}) {
    const raw = (input.value || "").trim();
    const pasted = (output.value || "").trim();

    if (!raw && !pasted) {
      setSearchMode(false);
      setLandingLinks();
      renderCardMeta();
      setStatus("Status: ready (landing page)");
      if (!silent) output.value = "";
      return;
    }

    const { type, q } = detectType(raw, pasted);

    // unknown -> keep landing visible
    if (!type) {
      setSearchMode(false);
      setLandingLinks();
      renderCardMeta();
      setStatus("Status: unknown type (landing page)");
      if (!silent && raw) output.value = raw;
      return;
    }

    // enable search mode
    setSearchMode(true);

    // determine which sections to show
    const sections = [];
    if (type === "header") { sections.push("header","emailartifacts"); }
    else if (type === "cveplus") { sections.push("cve","cveplus"); }
    else if (type === "sysmon") { sections.push("sysmon","soc"); }
    else if (type === "lolbins") { sections.push("lolbins","soc"); }
    else if (type === "mitre") { sections.push("soc"); }
    else sections.push(type);

    showRelevantTools(sections);

    // start from landing then build query links
    setLandingLinks();

    if (type === "header") {
      const headerText = pasted || raw;
      updateLinksForQuery("header", "", headerText);
      if (!silent && !pasted) output.value = raw;
      renderCardMeta();
      setStatus("Status: detected EMAIL HEADERS → header tools + email artifacts pivots");
      return;
    }

    updateLinksForQuery(type, q);

    if (type === "mitre") {
      if (!silent) output.value = `MITRE Technique: ${q}\nATT&CK: https://attack.mitre.org/techniques/${q}/`;
      setStatus(`Status: detected MITRE technique → ${q}`);
      renderCardMeta();
      return;
    }

    if (!silent) output.value = `${type.toUpperCase()} Query: ${q}`;
    setStatus(`Status: detected ${type.toUpperCase()} → ${q}`);
    renderCardMeta();
  }

  // Ensure tools clicked after input use query links (prevents landing redirects)
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    const raw = (input.value || "").trim();
    const pasted = (output.value || "").trim();
    if (raw || pasted) doSearch({ silent: true });
  }, true);

  // ---------- Buttons ----------
  document.getElementById("search-btn").addEventListener("click", () => doSearch({ silent:false }));
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch({ silent:false }); });

  document.getElementById("defang-btn").addEventListener("click", () => {
    const src = (output.value || "").trim() ? output.value : (input.value || "");
    output.value = defangText(src);
    setStatus("Status: defanged output generated");
  });

  document.getElementById("refang-btn").addEventListener("click", () => {
    const src = output.value || input.value || "";
    output.value = refangText(src);
    setStatus("Status: refanged output generated");
  });

  document.getElementById("extract-btn").addEventListener("click", () => {
    const text = (output.value || "").trim() || (input.value || "");
    output.value = extractSmartIOCs(text);
    setStatus("Status: Smart IOC extraction complete");
  });

  document.getElementById("copy-btn").addEventListener("click", () => {
    output.focus();
    output.select();
    document.execCommand("copy");
    setStatus("Status: copied to clipboard");
  });

  document.getElementById("clear-all").addEventListener("click", () => {
    input.value = "";
    output.value = "";
    setSearchMode(false);
    showRelevantTools([]);
    setLandingLinks();
    renderCardMeta();
    setStatus("Status: ready (landing page)");
  });

  document.getElementById("toggle-dark").addEventListener("click", () => {
    document.body.classList.toggle("light");
  });

  // Startup (landing page)
  setSearchMode(false);
  setLandingLinks();
  renderCardMeta();
  setStatus("Status: ready (landing page)");
});
