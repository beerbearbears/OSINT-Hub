document.addEventListener("DOMContentLoaded", () => {

  const input = document.getElementById("input");
  const output = document.getElementById("output");
  const triagePanel = document.getElementById("auto-triage");
  const triageBody = document.getElementById("triage-body");
  const copyTriageBtn = document.getElementById("copy-triage");

  const searchBtn = document.getElementById("search-btn");
  const defangBtn = document.getElementById("defang-btn");
  const refangBtn = document.getElementById("refang-btn");
  const extractBtn = document.getElementById("extract-btn");
  const copyBtn = document.getElementById("copy-btn");

  // ================= SAFE LINK HANDLER =================
  function safeSetHref(id, url) {
    const el = document.getElementById(id);
    if (!el) return;

    if (!url) {
      el.removeAttribute("href");
      el.classList.add("disabled-tool");
      el.title = "No link available";
    } else {
      el.href = url;
      el.classList.remove("disabled-tool");
      el.title = "";
    }
  }

  // ================= TYPE DETECTION =================
  function detectType(v) {
    if (/^CVE-\d{4}-\d+/i.test(v)) return "cve";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
    if (/^[a-f0-9]{32,64}$/i.test(v)) return "hash";
    if (/@/.test(v)) return "email";
    if (v.includes(".")) return "domain";
    return "unknown";
  }

  // ================= AUTO TRIAGE ENGINE =================
  function generateTriage(type, value) {

    let risk = "low";
    let verdict = "Likely Benign";
    let reason = "";
    let action = "";

    if (type === "ip") {
      if (value.startsWith("192.") || value.startsWith("10.") || value.startsWith("172.")) {
        risk = "low";
        verdict = "Internal Traffic";
        reason = "Private IP range";
        action = "No action needed";
      } else {
        risk = "medium";
        verdict = "Suspicious External IP";
        reason = "External communication observed";
        action = "Check user activity and destination reputation";
      }
    }

    if (type === "domain") {
      risk = "medium";
      verdict = "Suspicious Domain";
      reason = "Requires reputation validation";
      action = "Check domain age + passive DNS";
    }

    if (type === "hash") {
      risk = "high";
      verdict = "Potential Malware";
      reason = "File hash detected";
      action = "Check VT + isolate endpoint";
    }

    if (type === "cve") {
      risk = "high";
      verdict = "Vulnerability Detected";
      reason = "Known CVE";
      action = "Check patch status immediately";
    }

    if (type === "email") {
      risk = "medium";
      verdict = "Possible Phishing";
      reason = "Email IOC";
      action = "Check headers + sender reputation";
    }

    const badgeClass = risk;

    return `
      <div class="triage-card">
        <div class="triage-label">Assessment</div>
        <div class="triage-value">
          <span class="triage-badge ${badgeClass}">${verdict}</span>
        </div>
      </div>

      <div class="triage-card">
        <div class="triage-label">Why it matters</div>
        <div class="triage-value">${reason}</div>
      </div>

      <div class="triage-card">
        <div class="triage-label">Recommended Action</div>
        <div class="triage-value">${action}</div>
      </div>
    `;
  }

  // ================= SEARCH =================
  function doSearch() {

    const raw = input.value.trim();
    if (!raw) return;

    const type = detectType(raw);

    // Reset all links
    const links = document.querySelectorAll(".tool-grid a");
    links.forEach(a => safeSetHref(a.id, null));

    // ================= IP =================
    if (type === "ip") {
      safeSetHref("ip_vt", `https://www.virustotal.com/gui/ip-address/${raw}`);
      safeSetHref("ip_abuse", `https://www.abuseipdb.com/check/${raw}`);
      safeSetHref("ip_otx", `https://otx.alienvault.com/indicator/ip/${raw}`);
    }

    // ================= DOMAIN =================
    if (type === "domain") {
      safeSetHref("dom_vt", `https://www.virustotal.com/gui/domain/${raw}`);
      safeSetHref("dom_whois", `https://who.is/whois/${raw}`);
      safeSetHref("dom_dns", `https://dnsdumpster.com`);
    }

    // ================= HASH =================
    if (type === "hash") {
      safeSetHref("hash_vt", `https://www.virustotal.com/gui/file/${raw}`);
      safeSetHref("hash_otx", `https://otx.alienvault.com/indicator/file/${raw}`);
      safeSetHref("hash_triage", `https://tria.ge/s?q=${raw}`);
    }

    // ================= CVE =================
    if (type === "cve") {
      safeSetHref("cve_nvd", `https://nvd.nist.gov/vuln/detail/${raw}`);
      safeSetHref("cve_cveorg", `https://www.cve.org/CVERecord?id=${raw}`);
      safeSetHref("cve_cisa", `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`);
      safeSetHref("cve_exploitdb", `https://www.exploit-db.com/search?cve=${raw}`);
      safeSetHref("cve_vulners", `https://vulners.com/search?query=${raw}`);
      safeSetHref("cve_github", `https://github.com/search?q=${raw}+exploit`);

      safeSetHref("cve_socradar", `https://socradar.io/labs/?search=${raw}`);
      safeSetHref("cve_rapid7", `https://attackerkb.com/search?q=${raw}`);
      safeSetHref("cve_snyk", `https://security.snyk.io/vuln/?search=${raw}`);
      safeSetHref("cve_nuclei", `https://github.com/projectdiscovery/nuclei-templates/search?q=${raw}`);
    }

    // ================= AUTO TRIAGE =================
    triagePanel.style.display = "block";
    triageBody.innerHTML = generateTriage(type, raw);

    output.value = `Type: ${type}\nIOC: ${raw}`;
  }

  // ================= BUTTON EVENTS =================
  searchBtn.onclick = doSearch;

  input.addEventListener("keypress", (e) => {
    if (e.key === "Enter") doSearch();
  });

  defangBtn.onclick = () => {
    input.value = input.value.replace(/\./g, "[.]");
  };

  refangBtn.onclick = () => {
    input.value = input.value.replace(/\[\.\]/g, ".");
  };

  extractBtn.onclick = () => {
    const matches = input.value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
    output.value = matches ? matches.join("\n") : "No IOC found";
  };

  copyBtn.onclick = () => {
    navigator.clipboard.writeText(output.value);
  };

  copyTriageBtn.onclick = () => {
    navigator.clipboard.writeText(triageBody.innerText);
  };

});
