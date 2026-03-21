document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);
  const enc = encodeURIComponent;
  const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

  const input = $("input");
  const output = $("output");
  const statusEl = $("status");
  const searchbox = $("searchbox");
  const bulkInput = $("bulk-input");
  const bulkOutput = $("bulk-output");
  const landingNote = $("landing-note");

  const ALL_SECTION_TYPES = ["ip", "domain", "url", "hash", "email", "header", "cve", "mitre"];

  function setStatus(text) {
    const span = statusEl ? statusEl.querySelector("span") : null;
    if (span) span.textContent = text;
  }

  function gsearch(q) {
    return `https://www.google.com/search?q=${enc(q)}`;
  }

  function syncSearchboxState() {
    if (!searchbox || !input) return;
    searchbox.classList.toggle("has-value", !!input.value.trim());
  }

  function setHref(id, href) {
    const el = $(id);
    if (!el) return;
    const meta = el.querySelector(".meta");

    if (href && String(href).trim()) {
      el.href = href;
      el.dataset.hrefActive = "1";
      el.classList.remove("is-disabled");
      el.removeAttribute("aria-disabled");
      if (meta) meta.textContent = href;
    } else {
      el.removeAttribute("href");
      el.dataset.hrefActive = "0";
      el.classList.add("is-disabled");
      el.setAttribute("aria-disabled", "true");
      if (meta) meta.textContent = "URL not configured";
    }
  }

  function clearAllLinks() {
    document.querySelectorAll(".tool-grid a").forEach((a) => {
      setHref(a.id, null);
    });
  }

  function showOnlySections(types = []) {
    document.querySelectorAll(".tool-section").forEach((section) => {
      const type = section.getAttribute("data-type");
      section.classList.toggle("hidden-section", !types.includes(type));
    });
    if (landingNote) landingNote.style.display = types.length ? "none" : "block";
  }

  function showAllSections() {
    document.querySelectorAll(".tool-section").forEach((section) => {
      section.classList.remove("hidden-section");
    });
    if (landingNote) landingNote.style.display = "block";
  }

  function isValidIPv4(addr) {
    const parts = String(addr || "").trim().split(".");
    if (parts.length !== 4) return false;
    return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  function isPrivateIPv4(ip) {
    if (!isValidIPv4(ip)) return false;
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  function isValidIPv6(addr) {
    const v = String(addr || "").trim().replace(/^\[|\]$/g, "");
    if (!v.includes(":")) return false;
    try {
      new URL(`http://[${v}]/`);
      return true;
    } catch {
      return false;
    }
  }

  function isPrivateIPv6(ip) {
    const v = String(ip || "").toLowerCase();
    return v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v === "::1";
  }

  function normalize(raw) {
    let v = String(raw || "").trim();
    if (!v) return "";
    v = v.replace(/^hxxps:\/\//i, "https://").replace(/^hxxp:\/\//i, "http://");
    v = v.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    v = v.replace(/^\[|\]$/g, "");
    v = v.replace(/[,;]+$/g, "");
    return v.trim();
  }

  function looksLikeHeaders(text) {
    const t = String(text || "").trim();
    if (!t) return false;
    const normalized = t.replace(/\r\n/g, "\n");
    const head = normalized.split("\n").slice(0, 120).join("\n");

    const strong = [
      /(^|\n)\s*received:\s/im,
      /(^|\n)\s*authentication-results:\s/im,
      /(^|\n)\s*dkim-signature:\s/im,
      /(^|\n)\s*arc-seal:\s/im,
      /(^|\n)\s*message-id:\s/im,
      /(^|\n)\s*return-path:\s/im
    ];

    if (strong.some((rx) => rx.test(head))) return true;

    const weak = [
      /(^|\n)\s*from:\s/im,
      /(^|\n)\s*to:\s/im,
      /(^|\n)\s*subject:\s/im,
      /(^|\n)\s*date:\s/im
    ];
    const weakCount = weak.filter((rx) => rx.test(head)).length;
    const lineCount = (head.match(/(^|\n)[A-Za-z0-9-]{2,}:\s.+/g) || []).length;
    return weakCount >= 3 && lineCount >= 6;
  }

  function parseEmailHeaders(text) {
    const t = String(text || "").replace(/\r\n/g, "\n");
    const getLine = (re) => (t.match(re) || [])[1]?.trim() || "";

    const from = getLine(/^from:\s*(.+)$/im);
    const to = getLine(/^to:\s*(.+)$/im);
    const subject = getLine(/^subject:\s*(.+)$/im);
    const date = getLine(/^date:\s*(.+)$/im);
    const messageId = getLine(/^message-id:\s*(.+)$/im).replace(/[<>]/g, "");
    const returnPath = getLine(/^return-path:\s*<?([^>\s]+)>?/im);

    const senderEmail = (from.match(/\b([^@\s<"]+@[^@\s>"]+)\b/i) || [])[1] || "";
    const returnPathDomain = (returnPath.split("@")[1] || "").toLowerCase();

    const authMatch = t.match(/^authentication-results:\s*([\s\S]+?)(?:\n[A-Za-z0-9-]{2,}:\s|$)/im);
    const authBlock = authMatch?.[1] ? authMatch[1].replace(/\n\s+/g, " ") : "";
    const spfResult = ((authBlock.match(/\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();
    const dkimResult = ((authBlock.match(/\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b/i) || [])[1] || "").toLowerCase();

    const receivedAll = t.match(/^received:\s*[\s\S]*?(?=\n[A-Za-z0-9-]{2,}:\s|$)/gim) || [];
    let originIp = "";

    for (let i = receivedAll.length - 1; i >= 0; i--) {
      const block = receivedAll[i];
      const ipv4 = (block.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || "";
      if (ipv4 && isValidIPv4(ipv4) && !isPrivateIPv4(ipv4)) {
        originIp = ipv4;
        break;
      }
    }

    return {
      from,
      to,
      subject,
      date,
      messageId,
      returnPath,
      senderEmail,
      returnPathDomain,
      spfResult,
      dkimResult,
      originIp
    };
  }

  function detectType(raw, pasted = "") {
    const r = String(raw || "").trim();
    const p = String(pasted || "").trim();

    if (looksLikeHeaders(r) || looksLikeHeaders(p)) return { type: "header", q: "", raw: p || r };

    const v = normalize(r);

    const rawFixed = r.replace(/^hxxps?:\/\//i, "https://").replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
    if (/^https?:\/\/.{4,}/i.test(rawFixed)) return { type: "url", q: rawFixed };

    if (/^T\d{4,5}(\.\d{3})?$/i.test(v)) return { type: "mitre", q: v.toUpperCase() };
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return { type: "cve", q: v.toUpperCase() };
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return { type: "email", q: v.toLowerCase() };
    if (isValidIPv4(v) || isValidIPv6(v)) return { type: "ip", q: v };
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v) || /^[a-fA-F0-9]{96}$/.test(v) || /^[a-fA-F0-9]{128}$/.test(v)) {
      return { type: "hash", q: v.toLowerCase() };
    }
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(v) && v.includes(".") && !/\s/.test(v)) return { type: "domain", q: v.toLowerCase() };

    return { type: null, q: v };
  }

  function defangText(s) {
    return String(s || "")
      .replace(/https?:\/\//gi, (m) => m.toLowerCase() === "https://" ? "hxxps://" : "hxxp://")
      .replace(/\./g, "[.]");
  }

  function refangText(s) {
    return String(s || "")
      .replace(/^hxxps:\/\//gi, "https://")
      .replace(/^hxxp:\/\//gi, "http://")
      .replace(/\[\.\]/g, ".")
      .replace(/\(\.\)/g, ".");
  }

  function extractAllIOCsFromText(text) {
    const src = String(text || "");
    const found = [];
    const push = (type, q) => {
      if (!q) return;
      if (!found.some((x) => x.type === type && x.q === q)) found.push({ type, q });
    };

    (src.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).forEach((m) => push("cve", m.toUpperCase()));
    (src.match(/\bT\d{4,5}(?:\.\d{3})?\b/gi) || []).forEach((m) => push("mitre", m.toUpperCase()));
    (src.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).forEach((m) => { if (isValidIPv4(m)) push("ip", m); });
    (src.match(/\b(?:[A-Fa-f0-9]{1,4}:){2,}[A-Fa-f0-9:]+\b/g) || []).forEach((m) => { if (isValidIPv6(m)) push("ip", m); });
    (src.match(/\bhttps?:\/\/[^\s<>"']+/gi) || []).forEach((m) => push("url", m));
    (src.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []).forEach((m) => push("email", m.toLowerCase()));
    (src.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{96}\b|\b[a-fA-F0-9]{128}\b/g) || []).forEach((m) => push("hash", m.toLowerCase()));

    (src.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g) || []).forEach((m) => {
      const lower = m.toLowerCase();
      if (!found.some((x) => x.q === lower) && !/^[0-9.]+$/.test(lower)) push("domain", lower);
    });

    return found;
  }

  function analystPill(label, level) {
    return `<span class="analyst-pill ${level}">${esc(label)}</span>`;
  }

  function hideAnalystTriage() {
    const panel = $("analyst-triage-panel");
    const body = $("analyst-triage-body");
    if (panel) panel.style.display = "none";
    if (body) body.innerHTML = "";
  }

  function renderAnalystTriage(type, q, context = {}) {
    const panel = $("analyst-triage-panel");
    const body = $("analyst-triage-body");
    const copyBtn = $("analyst-triage-copy");
    if (!panel || !body || !type) return;

    let verdict = "";
    let assessment = "";
    let why = "";
    let next = "";
    let pill = analystPill("Informational", "info");

    if (type === "ip") {
      const isPriv = (isValidIPv4(q) && isPrivateIPv4(q)) || (isValidIPv6(q) && isPrivateIPv6(q));
      if (isPriv) {
        verdict = "Likely internal or non-routable address";
        assessment = "This IP is private or local scope. External reputation tools will usually add little value unless the alert specifically concerns internal movement.";
        why = "Private IP space is common in normal enterprise traffic, VPN segments, NAT, and server-to-server communications.";
        next = "Validate the asset owner, host role, VLAN, and traffic direction. Correlate with DHCP, EDR, firewall, and proxy logs before escalating.";
        pill = analystPill("Low Risk", "low");
      } else {
        verdict = "External IP requiring validation";
        assessment = "This appears to be a public IP and should be treated as suspicious until validated through reputation, ASN type, exposure, and event context.";
        why = "A public IP is not automatically malicious, but hosting providers, scanners, VPN exits, and compromised infrastructure frequently appear in real alerts.";
        next = "Check VT, AbuseIPDB, Talos, OTX, ASN, and GreyNoise. Correlate with the detection: login attempts, downloads, callbacks, or beaconing.";
        pill = analystPill("Medium Risk", "medium");
      }
    } else if (type === "domain") {
      verdict = "Domain requires infrastructure validation";
      assessment = "The domain should be reviewed for age, registrar, passive DNS, certificate history, and whether it fits the business context of the alert.";
      why = "Malicious domains often stand out through recent registration, odd naming, suspicious TLDs, or infrastructure overlap with other campaigns.";
      next = "Check WHOIS, passive DNS, VT, urlscan, and certificate transparency. Compare naming pattern against the alert theme or sender context.";
      pill = analystPill("Medium Risk", "medium");
    } else if (type === "url") {
      verdict = "URL requires path-level review";
      assessment = "A URL is higher value than a bare domain because the path, filename, parameters, and redirects may directly indicate phishing or malware delivery.";
      why = "Attackers often hide malicious intent in the full path, file names, or redirect chains even when the parent domain looks familiar.";
      next = "Review the full path, decode parameters if present, check urlscan and VT, then compare it with the original email or web event.";
      pill = analystPill("High Attention", "high");
    } else if (type === "hash") {
      const hashAlgo = q.length === 32 ? "MD5" : q.length === 40 ? "SHA-1" : q.length === 64 ? "SHA-256" : "Unknown";
      verdict = "File artifact with high investigation value";
      assessment = `This is a ${hashAlgo} indicator. Hashes are strong pivots because they map to a specific file and can confirm whether the file has known malicious history.`;
      why = "Unlike domains or IPs, a hash often allows direct validation through sandboxes, malware repositories, and EDR prevalence data.";
      next = "Check VT, MalwareBazaar, Hybrid Analysis, Triage, Joe Sandbox, and EDR prevalence. Confirm filename, signer, path, and parent process.";
      pill = analystPill("High Risk", "high");
    } else if (type === "email") {
      verdict = "Possible phishing or sender-validation case";
      assessment = "An email address alone is not enough to classify as malicious, but it becomes high value when tied to spoofing, lookalike domains, or suspicious mail flow.";
      why = "Phishing often relies on deceptive sender identity, mismatched domains, reply-to abuse, or recently created infrastructure.";
      next = "Search the sender, validate the domain, review any headers, and compare the theme against current business activity or user report.";
      pill = analystPill("Medium Risk", "medium");
    } else if (type === "header") {
      const h = parseEmailHeaders(context.raw || "");
      const findings = [];
      if (h.spfResult && h.spfResult !== "pass") findings.push(`SPF=${h.spfResult}`);
      if (h.dkimResult && h.dkimResult !== "pass") findings.push(`DKIM=${h.dkimResult}`);
      if (h.senderEmail && h.returnPathDomain && !h.senderEmail.toLowerCase().endsWith("@" + h.returnPathDomain)) findings.push("sender vs return-path mismatch");
      if (h.originIp) findings.push(`origin IP ${h.originIp}`);

      verdict = findings.length ? "Header anomalies observed" : "Headers parsed successfully";
      assessment = findings.length
        ? `Potential concerns were found: ${findings.join(", ")}. This does not prove phishing by itself, but it raises priority for deeper validation.`
        : "No obvious single header indicator proves maliciousness yet. Continue validation using sender alignment, mail flow, and content context.";
      why = "Email headers are strong for identifying sender infrastructure, authentication outcomes, and mismatches between visible sender and real sending path.";
      next = "Validate SPF, DKIM, and alignment. Compare From vs Return-Path, pivot on sending domains and the origin IP, and review the email body/theme.";
      pill = findings.length ? analystPill("High Attention", "high") : analystPill("Medium Risk", "medium");
    } else if (type === "cve") {
      verdict = "Known vulnerability requiring exploitability context";
      assessment = "A CVE alone does not confirm compromise, but it raises risk if the asset is vulnerable, exposed, unpatched, and internet-facing.";
      why = "Security operations value comes from answering whether the environment is actually affected and whether exploitation evidence exists.";
      next = "Check NVD, KEV, Vulners, AttackerKB, and patch status. Confirm product exposure, internet accessibility, and matching exploitation telemetry.";
      pill = analystPill("High Risk", "high");
    } else if (type === "mitre") {
      verdict = "MITRE ATT&CK technique reference";
      assessment = "This is a knowledge pivot, not an IOC. It helps classify behavior and align detections, playbooks, and write-ups.";
      why = "Technique IDs are useful for contextualizing alerts and linking them to known attacker behavior patterns.";
      next = "Open the ATT&CK page, review detection guidance, and map the observable or event to related tactics and procedures.";
      pill = analystPill("Informational", "info");
    } else {
      verdict = "Indicator parsed";
      assessment = "The observable was detected, but it needs source-event context before a confident verdict can be made.";
      why = "Most observables become meaningful only when correlated with alert type, user behavior, asset criticality, and surrounding telemetry.";
      next = "Validate the IOC type, pivot in the relevant tools, and correlate it with the original detection details.";
      pill = analystPill("Informational", "info");
    }

    const textSummary =
`Assessment: ${verdict}

Why it matters:
${assessment}

Analyst view:
${why}

Recommended next checks:
${next}`;

    body.innerHTML = `
      <div class="analyst-triage-card">
        <div class="analyst-triage-label">Assessment</div>
        <div class="analyst-triage-value">${pill}<div style="margin-top:8px">${esc(verdict)}</div></div>
      </div>
      <div class="analyst-triage-card">
        <div class="analyst-triage-label">Why it matters</div>
        <div class="analyst-triage-value">${esc(assessment)}</div>
      </div>
      <div class="analyst-triage-card">
        <div class="analyst-triage-label">Analyst view</div>
        <div class="analyst-triage-value">${esc(why)}</div>
      </div>
      <div class="analyst-triage-card">
        <div class="analyst-triage-label">Recommended next checks</div>
        <div class="analyst-triage-value">${esc(next)}</div>
      </div>
    `;

    panel.style.display = "block";

    if (copyBtn) {
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(textSummary);
          setStatus("Status: analyst auto triage copied");
        } catch {
          setStatus("Status: copy failed");
        }
      };
    }
  }

  function setLandingState() {
    clearAllLinks();
    showAllSections();
    hideAnalystTriage();
    setStatus("Status: ready (landing page)");
    if (output) output.value = "";
  }

  function populateIpLinks(ip) {
    setHref("ip_vt", `https://www.virustotal.com/gui/ip-address/${enc(ip)}`);
    setHref("ip_abuseipdb", `https://www.abuseipdb.com/check/${enc(ip)}`);
    setHref("ip_otx", `https://otx.alienvault.com/indicator/ip/${enc(ip)}`);
    setHref("ip_talos", `https://talosintelligence.com/reputation_center/lookup?search=${enc(ip)}`);
    setHref("ip_xforce", `https://exchange.xforce.ibmcloud.com/ip/${enc(ip)}`);
    setHref("ip_shodan", `https://www.shodan.io/host/${enc(ip)}`);
    setHref("ip_greynoise", `https://viz.greynoise.io/ip/${enc(ip)}`);
    setHref("ip_mxtoolbox", `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${enc(ip)}&run=toolpage`);
  }

  function populateDomainLinks(domain) {
    setHref("dom_vt", `https://www.virustotal.com/gui/domain/${enc(domain)}`);
    setHref("dom_whois", `https://who.is/whois/${enc(domain)}`);
    setHref("dom_dnsdumpster", `https://dnsdumpster.com/`);
    setHref("dom_securitytrails", `https://securitytrails.com/domain/${enc(domain)}`);
    setHref("dom_otx", `https://otx.alienvault.com/indicator/domain/${enc(domain)}`);
    setHref("dom_urlscan", `https://urlscan.io/search/#domain:${enc(domain)}`);
    setHref("dom_crtsh", `https://crt.sh/?q=${enc(domain)}`);
    setHref("dom_shodan", `https://www.shodan.io/search?query=${enc(domain)}`);
  }

  function populateUrlLinks(url) {
    const b64 = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    setHref("url_vt", `https://www.virustotal.com/gui/url/${b64}`);
    setHref("url_urlscan", `https://urlscan.io/search/#page.url:${enc(url)}`);
    setHref("url_google", gsearch(`"${url}"`));
    setHref("url_wayback", `https://web.archive.org/web/*/${url}`);
    setHref("url_redirectdetective", `https://redirectdetective.com/?url=${enc(url)}`);
    setHref("url_browserling", `https://www.browserling.com/browse/win/7/chrome/127/${enc(url)}`);
  }

  function populateHashLinks(hash) {
    setHref("hash_vt", `https://www.virustotal.com/gui/file/${enc(hash)}`);
    setHref("hash_otx", `https://otx.alienvault.com/indicator/file/${enc(hash)}`);
    setHref("hash_triage", `https://tria.ge/s?q=${enc(hash)}`);
    setHref("hash_mbazaar", `https://bazaar.abuse.ch/browse.php?search=${enc(hash)}`);
    setHref("hash_hybrid", `https://www.hybrid-analysis.com/search?query=${enc(hash)}`);
    setHref("hash_joesandbox", `https://www.joesandbox.com/analysis/search?q=${enc(hash)}`);
  }

  function populateEmailLinks(email) {
    setHref("email_google", gsearch(`"${email}"`));
    setHref("email_hunter", `https://hunter.io/email-verifier/${enc(email)}`);
    setHref("email_intelx", `https://intelx.io/?s=${enc(email)}`);
    setHref("email_haveibeenpwned", `https://haveibeenpwned.com/`);
  }

  function populateHeaderLinks(headerText) {
    const h = parseEmailHeaders(headerText);
    const fromDomain = (h.senderEmail.split("@")[1] || "").toLowerCase();

    setHref("hdr_google_from", fromDomain ? gsearch(`"${fromDomain}"`) : null);
    setHref("hdr_google_ip", h.originIp ? gsearch(`"${h.originIp}"`) : null);
    setHref("hdr_vt_ip", h.originIp ? `https://www.virustotal.com/gui/ip-address/${enc(h.originIp)}` : null);
    setHref("hdr_otx_ip", h.originIp ? `https://otx.alienvault.com/indicator/ip/${enc(h.originIp)}` : null);

    const lines = [
      `Type: header`,
      `From: ${h.from || "-"}`,
      `To: ${h.to || "-"}`,
      `Subject: ${h.subject || "-"}`,
      `Date: ${h.date || "-"}`,
      `Sender Email: ${h.senderEmail || "-"}`,
      `Return-Path: ${h.returnPath || "-"}`,
      `SPF: ${h.spfResult || "-"}`,
      `DKIM: ${h.dkimResult || "-"}`,
      `Origin IP: ${h.originIp || "-"}`,
      `Message-ID: ${h.messageId || "-"}`
    ];
    if (output) output.value = lines.join("\n");
  }

  function populateCveLinks(cve) {
    setHref("cve_nvd", `https://nvd.nist.gov/vuln/detail/${enc(cve)}`);
    setHref("cve_cveorg", `https://www.cve.org/CVERecord?id=${enc(cve)}`);
    setHref("cve_cisa", gsearch(`site:cisa.gov "Known Exploited Vulnerabilities" ${cve}`));
    setHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${enc(cve)}`);
    setHref("cve_vulners", `https://vulners.com/search?query=${enc(cve)}`);
    setHref("cve_github", `https://github.com/search?q=${enc(cve)}`);
    setHref("cve_socradar", `https://socradar.io/labs/app/vulnerability-intelligence/${enc(cve)}`);
    setHref("cve_rapid7", `https://attackerkb.com/search?q=${enc(cve)}`);
    setHref("cve_snyk", `https://security.snyk.io/vuln?search=${enc(cve)}`);
    setHref("cve_nuclei", `https://github.com/search?q=${enc(cve)}+nuclei+template`);
  }

  function populateMitreLinks(technique) {
    setHref("mitre_attack", `https://attack.mitre.org/techniques/${enc(technique)}/`);
    setHref("mitre_google", gsearch(`"${technique}" MITRE ATT&CK`));
  }

  function doSearch() {
    const raw = String(input?.value || "").trim();
    const pasted = String(output?.value || "").trim();

    if (!raw && !pasted) {
      setLandingState();
      return;
    }

    clearAllLinks();

    const detected = detectType(raw, pasted);
    const type = detected.type;
    const q = detected.q;

    if (!type) {
      showAllSections();
      hideAnalystTriage();
      setStatus("Status: unknown type (landing page)");
      if (output && raw) output.value = `Unable to classify input:\n${raw}`;
      return;
    }

    if (type === "ip") {
      showOnlySections(["ip"]);
      populateIpLinks(q);
      if (output) output.value = `Type: ip\nIOC: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: IP pivots loaded");
      return;
    }

    if (type === "domain") {
      showOnlySections(["domain"]);
      populateDomainLinks(q);
      if (output) output.value = `Type: domain\nIOC: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: domain pivots loaded");
      return;
    }

    if (type === "url") {
      showOnlySections(["url"]);
      populateUrlLinks(q);
      if (output) output.value = `Type: url\nIOC: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: URL pivots loaded");
      return;
    }

    if (type === "hash") {
      showOnlySections(["hash"]);
      populateHashLinks(q);
      if (output) output.value = `Type: hash\nIOC: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: hash pivots loaded");
      return;
    }

    if (type === "email") {
      showOnlySections(["email"]);
      populateEmailLinks(q);
      if (output) output.value = `Type: email\nIOC: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: email pivots loaded");
      return;
    }

    if (type === "header") {
      showOnlySections(["header"]);
      populateHeaderLinks(detected.raw || pasted || raw);
      renderAnalystTriage(type, q, { raw: detected.raw || pasted || raw });
      setStatus("Status: email headers parsed");
      return;
    }

    if (type === "cve") {
      showOnlySections(["cve"]);
      populateCveLinks(q);
      if (output) output.value = `Type: cve\nIOC: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: CVE pivots loaded");
      return;
    }

    if (type === "mitre") {
      showOnlySections(["mitre"]);
      populateMitreLinks(q);
      if (output) output.value = `Type: mitre\nTechnique: ${q}`;
      renderAnalystTriage(type, q, { raw, pasted });
      setStatus("Status: MITRE pivots loaded");
    }
  }

  function runBulkExtract() {
    const text = String(bulkInput?.value || "").trim();
    if (!text) {
      if (bulkOutput) bulkOutput.value = "";
      return;
    }

    const iocs = extractAllIOCsFromText(text);
    if (!iocs.length) {
      if (bulkOutput) bulkOutput.value = "No IOCs found.";
      return;
    }

    const grouped = {};
    iocs.forEach((ioc) => {
      grouped[ioc.type] ??= [];
      grouped[ioc.type].push(ioc.q);
    });

    const order = ["ip", "domain", "url", "email", "hash", "cve", "mitre"];
    const lines = [];

    order.forEach((type) => {
      if (!grouped[type]?.length) return;
      lines.push(`[${type.toUpperCase()}]`);
      grouped[type].forEach((item) => lines.push(item));
      lines.push("");
    });

    if (bulkOutput) bulkOutput.value = lines.join("\n").trim();
  }

  // Events
  $("search-btn")?.addEventListener("click", doSearch);
  $("clear-input")?.addEventListener("click", () => {
    if (input) input.value = "";
    syncSearchboxState();
    input?.focus();
  });

  input?.addEventListener("input", syncSearchboxState);
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      doSearch();
    }
  });

  $("defang-btn")?.addEventListener("click", () => {
    const src = input?.value?.trim() || output?.value?.trim() || "";
    const out = defangText(src);
    if (input && input.value.trim()) input.value = out;
    else if (output) output.value = out;
    syncSearchboxState();
    setStatus("Status: defanged");
  });

  $("refang-btn")?.addEventListener("click", () => {
    const src = input?.value?.trim() || output?.value?.trim() || "";
    const out = refangText(src);
    if (input && input.value.trim()) input.value = out;
    else if (output) output.value = out;
    syncSearchboxState();
    setStatus("Status: refanged");
  });

  $("extract-btn")?.addEventListener("click", () => {
    const src = String(output?.value || input?.value || "").trim();
    const iocs = extractAllIOCsFromText(src);
    output.value = iocs.length
      ? iocs.map((x) => `[${x.type}] ${x.q}`).join("\n")
      : "No IOCs found.";
    setStatus("Status: IOC extraction complete");
  });

  $("copy-btn")?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(output?.value || "");
      setStatus("Status: output copied");
    } catch {
      setStatus("Status: copy failed");
    }
  });

  $("bulk-extract-btn")?.addEventListener("click", runBulkExtract);
  $("bulk-copy-btn")?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(bulkOutput?.value || "");
      setStatus("Status: bulk output copied");
    } catch {
      setStatus("Status: copy failed");
    }
  });
  $("bulk-clear-btn")?.addEventListener("click", () => {
    if (bulkInput) bulkInput.value = "";
    if (bulkOutput) bulkOutput.value = "";
  });

  $("clear-all")?.addEventListener("click", () => {
    if (input) input.value = "";
    if (output) output.value = "";
    if (bulkInput) bulkInput.value = "";
    if (bulkOutput) bulkOutput.value = "";
    syncSearchboxState();
    setLandingState();
  });

  $("toggle-dark")?.addEventListener("click", () => {
    document.body.classList.toggle("light");
    const isLight = document.body.classList.contains("light");
    try {
      localStorage.setItem("hawkeye_theme", isLight ? "light" : "dark");
    } catch {}
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b === btn));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${tab}`));
    });
  });

  // Init
  try {
    const saved = localStorage.getItem("hawkeye_theme");
    if (saved === "light") document.body.classList.add("light");
  } catch {}

  clearAllLinks();
  showAllSections();
  hideAnalystTriage();
  syncSearchboxState();
  setStatus("Status: ready");
});
