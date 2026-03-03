document.addEventListener("DOMContentLoaded", () => {

  const input = document.getElementById("input");
  const output = document.getElementById("output");

  // ===== DEFAULT LANDING PAGES =====
  const defaultLinks = {
    vt_ip: "https://www.virustotal.com",
    abuse: "https://www.abuseipdb.com",
    shodan: "https://www.shodan.io",
    censys: "https://search.censys.io",
    greynoise: "https://viz.greynoise.io",
    viewdns: "https://viewdns.info",

    vt_hash: "https://www.virustotal.com",
    anyrun: "https://intelligence.any.run",
    triage: "https://tria.ge",
    joesandbox: "https://www.joesandbox.com/analysis/search",

    mha: "https://mha.azurewebsites.net",
    google_header: "https://toolbox.googleapps.com/apps/messageheader/",
    mxtool_header: "https://mxtoolbox.com/EmailHeaders.aspx"
  };

  function resetLinks() {
    Object.keys(defaultLinks).forEach(id => {
      const el = document.getElementById(id);
      if (el) el.href = defaultLinks[id];
    });
  }

  resetLinks(); // always clickable

  function detectType(value) {

    if (value.includes("Received:") || value.includes("DKIM-Signature"))
      return "header";

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value))
      return "ip";

    if (/^[a-fA-F0-9]{32}$/.test(value) ||
        /^[a-fA-F0-9]{40}$/.test(value) ||
        /^[a-fA-F0-9]{64}$/.test(value))
      return "hash";

    return null;
  }

  function showSection(type) {
    document.querySelectorAll(".tool-section").forEach(sec => {
      if (!type) {
        sec.style.display = "block";
      } else {
        sec.style.display = sec.dataset.type === type ? "block" : "none";
      }
    });
  }

  function updateLinks(value, type) {

    if (type === "ip") {
      document.getElementById("vt_ip").href =
        `https://www.virustotal.com/gui/ip-address/${value}`;

      document.getElementById("abuse").href =
        `https://www.abuseipdb.com/check/${value}`;

      document.getElementById("shodan").href =
        `https://www.shodan.io/host/${value}`;

      document.getElementById("censys").href =
        `https://search.censys.io/hosts/${value}`;

      document.getElementById("greynoise").href =
        `https://viz.greynoise.io/ip/${value}`;

      document.getElementById("viewdns").href =
        `https://viewdns.info/iphistory/?domain=${value}`;
    }

    if (type === "hash") {
      document.getElementById("vt_hash").href =
        `https://www.virustotal.com/gui/file/${value}`;

      document.getElementById("anyrun").href =
        `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(JSON.stringify({query:value,dateRange:180}))}`;

      document.getElementById("triage").href =
        `https://tria.ge/s?q=${value}`;

      document.getElementById("joesandbox").href =
        `https://www.joesandbox.com/analysis/search?q=${value}`;
    }
  }

  function runSearch() {

    const value = input.value.trim();

    if (!value) {
      resetLinks();
      showSection(null);
      output.value = "";
      return;
    }

    const type = detectType(value);

    if (!type) {
      resetLinks();
      showSection(null);
      output.value = "Unknown type";
      return;
    }

    showSection(type);
    updateLinks(value, type);
    output.value = `Detected: ${type.toUpperCase()} → ${value}`;
  }

  document.getElementById("search-btn").addEventListener("click", runSearch);

  document.getElementById("clear-all").addEventListener("click", () => {
    input.value = "";
    output.value = "";
    resetLinks();
    showSection(null);
  });

  document.getElementById("toggle-dark").addEventListener("click", () => {
    document.body.classList.toggle("light");
  });

});
