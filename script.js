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

  // ---------------- Searchbox UI helpers ----------------
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

  // ---------------- Helpers ----------------
  const gsearch = (q) => `https://www.google.com/search?q=${enc(q)}`;
  const anyrunLookupHash = (q) =>
    `https://intelligence.any.run/analysis/lookup#${enc(JSON.stringify({ query: q, dateRange: 180 }))}`;

  const anyrunLookupGeneral = (q) =>
    `https://intelligence.any.run/analysis/lookup#${enc(JSON.stringify({ query: q, dateRange: 180 }))}`;

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
    const head = normalized.split("\n").slice(0, 120).join("\n");

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

    return hasAnyStrong || headerLineCount >= 8;
  }

  function normalize(raw) {
    let v = (raw || "").trim();
    if (!v) return "";

    // Refang basics first
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.replace(/\[:\]/g, ":");

    // If URL, take hostname
    if (/^(https?:\/\/)/i.test(v)) {
      try { v = new URL(v).hostname; }
      catch { v = v.replace(/^[a-z]+:\/\//i, ""); }
    }

    v = v.replace(/^\[|\]$/g, "");
    v = v.replace(/[,;]+$/g, "");
    v = v.split("/")[0].split("?")[0].split("#")[0].replace(/\.$/, "");
    return v.trim();
  }

  // ---------------- Email header parser ----------------
  function parseEmailHeaders(text) {
    const t = (text || "").replace(/\r\n/g, "\n");

    const getLine = (re) => (t.match(re) || [])[1]?.trim() || "";

    const from = getLine(/^from:\s*(.+)$/im);
    const to = getLine(/^to:\s*(.+)$/im);
    const subject = getLine(/^subject:\s*(.+)$/im);
    const date = getLine(/^date:\s*(.+)$/im);

    const messageId = getLine(/^message-id:\s*(.+)$/im).replace(/[<>]/g, "");
    const returnPath = getLine(/^return-path:\s*<?([^>\s]+)>?/im);

    const senderEmail = (from.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";
    const receiverEmail = (to.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";

    const returnPathDomain = (returnPath.split("@")[1] || "").toLowerCase();

    // DKIM (handle folded header lines)
    const dkimMatch = t.match(/^dkim-signature:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im);
    const dkimBlock = (dkimMatch && dkimMatch[1]) ? dkimMatch[1].replace(/\n\s+/g, " ") : "";
    const dkimSelector = (dkimBlock.match(/\bs=([^;\s]+)/i) || [])[1] || "";
    const dkimDomain = ((dkimBlock.match(/\bd=([^;\s]+)/i) || [])[1] || "").toLowerCase();

    // Authentication-Results (folded)
    const authMatch = t.match(/^authentication-results:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im);
    const authBlock = (authMatch && authMatch[1]) ? authMatch[1].replace(/\n\s+/g, " ") : "";

    const spfResult = ((authBlock.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();
    const dkimResult = ((authBlock.match(/\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();

    const spfMailfrom = ((authBlock.match(/\bsmtp\.mailfrom=([^;\s]+)/i) || [])[1] || "").toLowerCase();
    const spfMailfromDomain = (spfMailfrom.split("@")[1] || "").toLowerCase();

    // Origin IP heuristic: use the LAST Received header that contains a PUBLIC IPv4
    const receivedAll = t.match(/^received:\s*[\s\S]*?(?=\n[A-Za-z0-9-]{2,}:\s|$)/gim) || [];
    let originIp = "";
    for (let i = receivedAll.length - 1; i >= 0; i--) {
      const block = receivedAll[i];
      const ip = (block.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || "";
      if (ip && isValidIPv4(ip) && !isPrivateIPv4(ip)) { originIp = ip; break; }
    }

    return {
      from, to, subject, date,
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

  // ---------------- Type detection ----------------
  function detectType(raw, pastedText) {
    const r = (raw || "").trim();
    const p = (pastedText || "").trim();

    // Email headers detection
    if (looksLikeHeaders(p) || looksLikeHeaders(r)) return { type: "header", q: "" };

    const v = normalize(r);

    // MITRE
    if (/^T\d{4,5}$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };

    // CVE
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };

    // Email
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v.toLowerCase() };

    // EventID
    if (/^\d{3,5}$/.test(v)) return { type: "eventid", q: v };

    // IP
    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };

    // Hash
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }

    // Domain
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v)) return { type: "domain", q: v.toLowerCase() };

    // Username
    if (/^[a-zA-Z0-9._-]{3,}$/.test(v)) return { type: "username", q: v };

    return { type: null, q: v };
  }

  // ---------------- Landing links (no input) ----------------
  const landing = {
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

    em_hunter: "https://hunter.io/",
    em_hibp: "https://haveibeenpwned.com/",
    em_intelbase: "https://intelbase.is/",

    hdr_mha: "https://mha.azurewebsites.net/pages/mha.html",
    hdr_google: "https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    hdr_mxtoolbox: "https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx",
    hdr_traceemail: "https://whatismyipaddress.com/trace-email",
    hdr_dnschecker: "https://dnschecker.org/email-header-analyzer.php",

    usr_namechk: "https://namechk.com/",
    usr_whatsmyname: "https://whatsmyname.app/",

    h_vt: "https://www.virustotal.com/",
    h_hybrid: "https://www.hybrid-analysis.com/",
    h_joesandbox: "https://www.joesandbox.com/",
    h_triage: "https://tria.ge/",
    h_malshare: "https://malshare.com/",
    h_ibmxf: "https://exchange.xforce.ibmcloud.com/",
    h_talos: "https://talosintelligence.com/",
    h_otx: "https://otx.alienvault.com/",
    h_anyrun: "https://intelligence.any.run/",
    h_threatminer: "https://www.threatminer.org/",
    h_cyberchef: "https://gchq.github.io/CyberChef/",
    h_nitter: "https://nitter.net/",

    cve_nvd: "https://nvd.nist.gov/",
    cve_cveorg: "https://www.cve.org/",
    cve_cisa: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cve_exploitdb: "https://www.exploit-db.com/",
    cve_vulners: "https://vulners.com/",
    cve_github: "https://github.com/search",

    cvep_cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cvep_epss: "https://www.first.org/epss/",

    emart_msgid_search: "https://toolbox.googleapps.com/apps/messageheader/analyzeheader",
    emart_dkim_domain: "https://www.virustotal.com/",
    emart_spf_domain: "https://www.virustotal.com/",

    lb_lolbas: "https://lolbas-project.github.io/",
    lb_gtfobins: "https://gtfobins.github.io/",
    lb_hijacklibs: "https://hijacklibs.net/",

    ev_eventidnet: "https://www.eventid.net/",
    ev_mslearn: "https://learn.microsoft.com/",
    ev_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

    sysmon_mslearn: "https://learn.microsoft.com/",
    sysmon_swift: "https://github.com/SwiftOnSecurity/sysmon-config",
    sysmon_hackthelogs: "https://www.hackthelogs.com/mainpage.html",

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

  // ---------------- Defang / Refang (FIXED) ----------------
  // Defang only IOCs (URLs/domains/IPs/emails), not the whole paragraph.
  function defangSmart(text) {
    let t = (text || "");

    // URLs
    t = t.replace(/\bhttps?:\/\/[^\s<>"')]+/gi, (m) => {
      let x = m.replace(/^https:\/\//i, "hxxps://").replace(/^http:\/\//i, "hxxp://");
      x = x.replace(/\./g, "[.]");
      return x;
    });

    // Emails
    t = t.replace(/\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, (m, u, d) => {
      return `${u}[@]${d.replace(/\./g, "[.]")}`;
    });

    // IPv4
    t = t.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, (m) => {
      if (!isValidIPv4(m)) return m;
      return m.replace(/\./g, "[.]");
    });

    // Domains (standalone)
    t = t.replace(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi, (m) => {
      // avoid already-defanged or obvious file extensions like .exe
      if (m.includes("[.]")) return m;
      if (/\.(exe|dll|sys|bat|cmd|ps1|js|vbs)$/i.test(m)) return m;
      // must contain TLD-ish
      if (!/\.[a-z]{2,}$/i.test(m)) return m;
      return m.replace(/\./g, "[.]");
    });

    return t;
  }

  function refangSmart(text) {
    let t = (text || "");
    t = t.replace(/hxxps:\/\//gi, "https://").replace(/hxxp:\/\//gi, "http://");
    t = t.replace(/\[@\]/g, "@");
    t = t.replace(/\[\.\]/g, ".");
    t = t.replace(/\[:\]/g, ":");
    return t;
  }

  // ---------------- Tool link builders (FIXED) ----------------
  function buildLinksForIP(ip) {
    setHref("ip_vt", `https://www.virustotal.com/gui/ip-address/${enc(ip)}`);
    setHref("ip_abuseipdb", `https://www.abuseipdb.com/check/${enc(ip)}`);
    setHref("ip_talos", `https://talosintelligence.com/reputation_center/lookup?search=${enc(ip)}`);
    setHref("ip_ibmxf", `https://exchange.xforce.ibmcloud.com/ip/${enc(ip)}`);
    setHref("ip_otx", `https://otx.alienvault.com/indicator/ip/${enc(ip)}`);
    setHref("ip_anyrun", anyrunLookupGeneral(ip));
    setHref("ip_mxtoolbox", `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${enc(ip)}&run=toolpage`);
    setHref("ip_blacklistchecker", `https://blacklistchecker.com/ip/${enc(ip)}`);
    setHref("ip_cleantalk", `https://cleantalk.org/blacklists/${enc(ip)}`);
    setHref("ip_shodan", `https://www.shodan.io/host/${enc(ip)}`);
    setHref("ip_censys", `https://search.censys.io/hosts/${enc(ip)}`);
    setHref("ip_greynoise", `https://viz.greynoise.io/ip/${enc(ip)}`);
    setHref("ip_iplocation", `https://iplocation.io/ip/${enc(ip)}`);
    setHref("ip_ipinfo", `https://ipinfo.io/${enc(ip)}`);
    setHref("ip_whatismyipaddress", `https://whatismyipaddress.com/ip/${enc(ip)}`);
    setHref("ip_myip", `https://myip.ms/info/whois/${enc(ip)}`);
    setHref("ip_spur", `https://spur.us/context/${enc(ip)}`);
    setHref("ip_clickfix", `https://clickfix.carsonww.com/?q=${enc(ip)}`);
    setHref("ip_ripestat", `https://stat.ripe.net/${enc(ip)}`);
    setHref("ip_nitter", `https://nitter.net/search?q=${enc(ip)}`);
    setHref("ip_threatminer", `https://www.threatminer.org/host.php?q=${enc(ip)}`);
    setHref("ip_urlscan", `https://urlscan.io/search/#ip:${enc(ip)}`);
    setHref("ip_viewdns", `https://viewdns.info/reverseip/?host=${enc(ip)}&t=1`);
    setHref("ip_scamalytics", `https://scamalytics.com/ip/${enc(ip)}`);
  }

  function buildLinksForDomain(domain) {
    setHref("dom_vt", `https://www.virustotal.com/gui/domain/${enc(domain)}`);
    setHref("dom_talos", `https://talosintelligence.com/reputation_center/lookup?search=${enc(domain)}`);
    setHref("dom_ibmxf", `https://exchange.xforce.ibmcloud.com/url/${enc(domain)}`);
    setHref("dom_otx", `https://otx.alienvault.com/indicator/domain/${enc(domain)}`);
    setHref("dom_urlscan", `https://urlscan.io/search/#domain:${enc(domain)}`);
    setHref("dom_mxtoolbox", `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${enc(domain)}&run=toolpage`);
    setHref("dom_blacklistchecker", `https://blacklistchecker.com/domain/${enc(domain)}`);
    setHref("dom_cleantalk_bl", `https://cleantalk.org/blacklists/${enc(domain)}`);
    setHref("dom_cleantalk_malware", `https://cleantalk.org/website/${enc(domain)}`);
    setHref("dom_sucuri", `https://sitecheck.sucuri.net/results/${enc(domain)}`);
    setHref("dom_urlvoid", `https://www.urlvoid.com/scan/${enc(domain)}/`);
    setHref("dom_urlhaus", `https://urlhaus.abuse.ch/browse.php?search=${enc(domain)}`);
    setHref("dom_whois", `https://www.whois.com/whois/${enc(domain)}`);
    setHref("dom_dnslytics", `https://dnslytics.com/domain/${enc(domain)}`);
    setHref("dom_netcraft", `https://searchdns.netcraft.com/?host=${enc(domain)}`);
    setHref("dom_webcheck", `https://webcheck.spiderlabs.io/?q=${enc(domain)}`);
    setHref("dom_securitytrails", `https://securitytrails.com/domain/${enc(domain)}`);
    setHref("dom_hudsonrock_info", `https://intel.hudsonrock.com/?q=${enc(domain)}`);
    setHref("dom_hudsonrock_urls", `https://cavalier.hudsonrock.com/?q=${enc(domain)}`);
    setHref("dom_socradar", gsearch(`SOCRadar dark web report ${domain}`));
    setHref("dom_wayback", `https://web.archive.org/web/*/${enc(domain)}`);
    setHref("dom_wayback_save", `https://web.archive.org/save/${enc(domain)}`);
    setHref("dom_browserling", `https://www.browserling.com/browse/${enc(domain)}`);
    setHref("dom_anyrun", anyrunLookupGeneral(domain));
    setHref("dom_anyrun_safe", `https://any.run/`);
    setHref("dom_phishing_checker", `https://phishing.finsin.cl/list.php?search=${enc(domain)}`);
    setHref("dom_clickfix", `https://clickfix.carsonww.com/?q=${enc(domain)}`);
    setHref("dom_nitter", `https://nitter.net/search?q=${enc(domain)}`);
    setHref("dom_netlas", `https://app.netlas.io/domains/?q=${enc(domain)}`);
    setHref("dom_censys", `https://search.censys.io/search?resource=hosts&q=${enc(domain)}`);
    setHref("dom_shodan", `https://www.shodan.io/search?query=${enc(domain)}`);
    setHref("dom_dnstools", `https://whois.domaintools.com/${enc(domain)}`);
  }

  function buildLinksForHash(hash) {
    setHref("h_vt", `https://www.virustotal.com/gui/file/${enc(hash)}`);
    setHref("h_hybrid", `https://www.hybrid-analysis.com/search?query=${enc(hash)}`);
    setHref("h_joesandbox", `https://www.joesandbox.com/search?q=${enc(hash)}`);
    setHref("h_triage", `https://tria.ge/s?q=${enc(hash)}`);
    setHref("h_malshare", `https://malshare.com/sample.php?action=detail&hash=${enc(hash)}`);
    setHref("h_ibmxf", `https://exchange.xforce.ibmcloud.com/malware/${enc(hash)}`);
    setHref("h_talos", `https://talosintelligence.com/talos_file_reputation?s=${enc(hash)}`);
    setHref("h_otx", `https://otx.alienvault.com/indicator/file/${enc(hash)}`);
    setHref("h_anyrun", anyrunLookupHash(hash));
    setHref("h_threatminer", `https://www.threatminer.org/sample.php?q=${enc(hash)}`);
    setHref("h_cyberchef", `https://gchq.github.io/CyberChef/`);
    setHref("h_nitter", `https://nitter.net/search?q=${enc(hash)}`);
  }

  function buildLinksForEmail(email) {
    setHref("em_hunter", `https://hunter.io/email-verifier/${enc(email)}`);
    setHref("em_hibp", `https://haveibeenpwned.com/account/${enc(email)}`);
    // ✅ intelbase fix (no 404)
    setHref("em_intelbase", `https://intelbase.is/search?q=${enc(email)}`);
  }

  function buildLinksForUsername(user) {
    setHref("usr_namechk", `https://namechk.com/?q=${enc(user)}`);
    setHref("usr_whatsmyname", `https://whatsmyname.app/?q=${enc(user)}`);
  }

  function buildLinksForCVE(cve) {
    setHref("cve_nvd", `https://nvd.nist.gov/vuln/detail/${enc(cve)}`);
    setHref("cve_cveorg", `https://www.cve.org/CVERecord?id=${enc(cve)}`);
    setHref("cve_cisa", gsearch(`site:cisa.gov "Known Exploited Vulnerabilities" ${cve}`));
    setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${enc(cve)}`);
    setHref("cve_vulners", `https://vulners.com/search?query=${enc(cve)}`);
    setHref("cve_github", `https://github.com/search?q=${enc(cve)}`);
    setHref("cvep_cisa_kev", gsearch(`CISA KEV ${cve}`));
    setHref("cvep_epss", `https://www.first.org/epss/?q=${enc(cve)}`);
  }

  function buildLinksForEventID(id) {
    setHref("ev_eventidnet", `https://www.eventid.net/display.asp?eventid=${enc(id)}`);
    setHref("ev_mslearn", `https://learn.microsoft.com/en-us/search/?terms=${enc("Event ID " + id)}`);
    setHref("ev_hackthelogs", gsearch(`HackTheLogs Event ID ${id}`));
  }

  function buildLinksForHeaders(headerText) {
    // Header tools
    setHref("hdr_dnschecker", "https://dnschecker.org/email-header-analyzer.php");
    setHref("hdr_mxtoolbox", "https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx");
    setHref("hdr_mha", "https://mha.azurewebsites.net/pages/mha.html");
    setHref("hdr_google", "https://toolbox.googleapps.com/apps/messageheader/analyzeheader");

    // Artifacts
    const h = parseEmailHeaders(headerText);

    setHref("emart_msgid_search", h.messageId ? gsearch(`"${h.messageId}"`) : landing.emart_msgid_search);

    if (h.dkimDomain) setHref("emart_dkim_domain", `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}`);
    else setHref("emart_dkim_domain", landing.emart_dkim_domain);

    const spfDom = h.spfMailfromDomain || (h.spfMailfrom.split("@")[1] || "");
    if (spfDom) setHref("emart_spf_domain", `https://www.virustotal.com/gui/domain/${enc(spfDom)}`);
    else setHref("emart_spf_domain", landing.emart_spf_domain);

    return h;
  }

  // ---------------- Smart IOC extractor output (UPGRADED) ----------------
  function extractSmartIOCs(text) {
    const now = new Date().toISOString();
    const t = (text || "").replace(/\r\n/g, "\n");

    const headerDetected = looksLikeHeaders(t);
    const h = headerDetected ? parseEmailHeaders(t) : null;

    const originLink = h?.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}` : "-";
    const dkimLink = h?.dkimDomain ? `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}` : "-";
    const spfLink = h?.spfMailfromDomain ? `https://www.virustotal.com/gui/domain/${enc(h.spfMailfromDomain)}` : "-";
    const returnPathLink = h?.returnPathDomain ? `https://www.virustotal.com/gui/domain/${enc(h.returnPathDomain)}` : "-";

    return `SMART IOC EXTRACTOR
Extracted At (UTC): ${now}

EMAIL HEADER INTEL:
- Sender (From): ${h?.senderEmail || "-"}
- Receiver (To): ${h?.receiverEmail || "-"}
- Subject: ${h?.subject || "-"}
- Date: ${h?.date || "-"}
- Message-ID: ${h?.messageId || "-"}
- Return-Path: ${h?.returnPath || "-"}
- Return-Path Domain: ${h?.returnPathDomain || "-"}
- Origin IP (heuristic): ${h?.originIp || "-"}
- SPF Result: ${h?.spfResult || "-"}   (smtp.mailfrom: ${h?.spfMailfrom || "-"})
- DKIM Result: ${h?.dkimResult || "-"} (d=${h?.dkimDomain || "-"}; s=${h?.dkimSelector || "-"})

QUICK PIVOTS:
- Return-Path Domain Pivot: ${returnPathLink}
- Origin IP Pivot: ${originLink}
- SPF Domain Pivot: ${spfLink}
- DKIM Domain Pivot: ${dkimLink}

NOTE:
- Origin IP is best-effort based on last public IPv4 seen in Received headers.
`;
  }

  // ---------------- Main search flow ----------------
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

    const { type, q } = detectType(raw, pasted);

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

    // Decide visible sections
    let sections = [];
    if (type === "header") sections = ["header", "emailartifacts"];
    else if (type === "cve") sections = ["cve", "cveplus"];
    else sections = [type];

    showRelevantTools(sections);

    // Reset to landing first then build query links
    setLandingLinks();

    if (type === "ip") {
      buildLinksForIP(q);
      const privateNote = (isValidIPv4(q) && isPrivateIPv4(q)) || (isValidIPv6(q) && isPrivateIPv6(q));
      if (!silent && output) {
        output.value = privateNote
          ? `IP detected (PRIVATE/RFC1918): ${q}\nNote: tools will still open, but results may be empty for private IPs.`
          : `IP detected: ${q}`;
      }
      setStatus(`Status: detected IP`);
    }

    if (type === "domain") {
      buildLinksForDomain(q);
      if (!silent && output) output.value = `Domain detected: ${q}`;
      setStatus(`Status: detected DOMAIN`);
    }

    if (type === "hash") {
      buildLinksForHash(q);
      if (!silent && output) output.value = `Hash detected: ${q}`;
      setStatus(`Status: detected HASH`);
    }

    if (type === "email") {
      buildLinksForEmail(q);
      if (!silent && output) output.value = `Email detected: ${q}`;
      setStatus(`Status: detected EMAIL`);
    }

    if (type === "username") {
      buildLinksForUsername(q);
      if (!silent && output) output.value = `Username detected: ${q}`;
      setStatus(`Status: detected USERNAME`);
    }

    if (type === "cve") {
      buildLinksForCVE(q);
      if (!silent && output) output.value = `CVE detected: ${q}`;
      setStatus(`Status: detected CVE`);
    }

    if (type === "eventid") {
      buildLinksForEventID(q);
      if (!silent && output) output.value = `Event ID detected: ${q}`;
      setStatus(`Status: detected EVENT ID`);
    }

    if (type === "header") {
      const headerText = pasted || raw;
      const h = buildLinksForHeaders(headerText);

      if (!silent && output) {
        output.value =
`EMAIL HEADERS DETECTED ✅

Sender (From): ${h.senderEmail || "-"}
Receiver (To): ${h.receiverEmail || "-"}
Return-Path: ${h.returnPath || "-"}
Return-Path Domain: ${h.returnPathDomain || "-"}
Origin IP: ${h.originIp || "-"}
SPF: ${h.spfResult || "-"} (smtp.mailfrom: ${h.spfMailfrom || "-"})
DKIM: ${h.dkimResult || "-"} (d=${h.dkimDomain || "-"}; s=${h.dkimSelector || "-"})

Quick Pivots:
- Return-Path Domain Pivot: ${h.returnPathDomain ? `https://www.virustotal.com/gui/domain/${enc(h.returnPathDomain)}` : "-"}
- Origin IP Pivot: ${h.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}` : "-"}
- SPF Domain Pivot: ${h.spfMailfromDomain ? `https://www.virustotal.com/gui/domain/${enc(h.spfMailfromDomain)}` : "-"}
- DKIM Domain Pivot: ${h.dkimDomain ? `https://www.virustotal.com/gui/domain/${enc(h.dkimDomain)}` : "-"}

Tip: Use Extract IOCs for a full investigation-ready summary.`;
      }

      setStatus("Status: detected EMAIL HEADERS → header tools + email artifacts");
    }

    renderCardMeta();
  }

  // Ensure links are built before user clicks
  document.addEventListener("click", (e) => {
    const a = e.target.closest(".tool-grid a");
    if (!a) return;
    const raw = (input?.value || "").trim();
    const pasted = (output?.value || "").trim();
    if (raw || pasted) doSearch({ silent: true });
  }, true);

  // ---------------- Buttons ----------------
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
    if (output) output.value = defangSmart(src);
    setStatus("Status: defanged (smart IOC-only)");
  });

  const refangBtn = $("refang-btn");
  if (refangBtn) refangBtn.addEventListener("click", () => {
    const src = (output?.value || "").trim() ? output.value : (input?.value || "");
    if (output) output.value = refangSmart(src);
    setStatus("Status: refanged");
  });

  const extractBtn = $("extract-btn");
  if (extractBtn) extractBtn.addEventListener("click", () => {
    const text = (output?.value || "").trim() || (input?.value || "");
    if (output) output.value = extractSmartIOCs(text);
    setStatus("Status: Smart IOC extraction complete");
  });

  const copyBtn = $("copy-btn");
  if (copyBtn) copyBtn.addEventListener("click", async () => {
    if (!output) return;
    try {
      await navigator.clipboard.writeText(output.value || "");
      setStatus("Status: copied to clipboard");
    } catch {
      output.focus();
      output.select();
      document.execCommand("copy");
      setStatus("Status: copied to clipboard (fallback)");
    }
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
