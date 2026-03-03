let currentTab = "ip";

/* ---------------- TAB & THEME ---------------- */

function setTab(tab) {
  currentTab = tab;
  document.getElementById("results").innerHTML = "";
}

function toggleDark() {
  document.body.classList.toggle("dark");
  document.body.classList.toggle("light");
}

function clearAll() {
  document.getElementById("iocInput").value = "";
  document.getElementById("results").innerHTML = "";
}

/* ---------------- UTIL ---------------- */

function copyText(text) {
  navigator.clipboard.writeText(text);
  alert("Copied: " + text);
}

/* ---------------- OSINT GENERATOR ---------------- */

function generateLinks() {
  const input = document.getElementById("iocInput").value.trim();
  const resultsDiv = document.getElementById("results");
  const loader = document.getElementById("loader");

  if (!input) return;

  resultsDiv.innerHTML = "";
  loader.classList.remove("hidden");

  setTimeout(() => {
    loader.classList.add("hidden");

    const card = document.createElement("div");
    card.className = "card";

    let links = "";

    if (currentTab === "ip") {
      links = `
        <a href="https://www.virustotal.com/gui/ip-address/${input}" target="_blank" rel="noopener noreferrer">VirusTotal</a>
        <a href="https://www.abuseipdb.com/check/${input}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a>
      `;
    }

    if (currentTab === "domain") {
      links = `
        <a href="https://who.is/whois/${input}" target="_blank" rel="noopener noreferrer">Whois</a>
        <a href="https://securitytrails.com/domain/${input}/dns" target="_blank" rel="noopener noreferrer">SecurityTrails</a>
      `;
    }

    if (currentTab === "email") {
      links = `
        <a href="https://haveibeenpwned.com/account/${input}" target="_blank" rel="noopener noreferrer">HaveIBeenPwned</a>
      `;
    }

    if (currentTab === "username") {
      links = `
        <a href="https://whatsmyname.app/" target="_blank" rel="noopener noreferrer">WhatsMyName</a>
      `;
    }

    card.innerHTML = `
      <h3>${currentTab.toUpperCase()} OSINT for: ${input}</h3>
      <button onclick="copyText('${input}')">Copy Indicator</button>
      ${links}
    `;

    resultsDiv.appendChild(card);
  }, 600);
}

/* ---------------- DEFANG / REFANG ---------------- */

function defang() {
  const input = document.getElementById("defangInput").value.trim();
  if (!input) return;

  let output = input
    .replace(/http/gi, "hxxp")
    .replace(/\./g, "[.]");

  showDefangResult(output);
}

function refang() {
  const input = document.getElementById("defangInput").value.trim();
  if (!input) return;

  let output = input
    .replace(/hxxp/gi, "http")
    .replace(/\[\.\]/g, ".");

  showDefangResult(output);
}

function showDefangResult(result) {
  const container = document.getElementById("defangResult");
  container.innerHTML = `
    <div class="card">
      <strong>Result:</strong>
      <p>${result}</p>
      <button onclick="copyText('${result}')">Copy</button>
    </div>
  `;
}

/* ---------------- IOC EXTRACTOR ---------------- */

function extractIOCs() {
  const text = document.getElementById("logInput").value;
  const output = document.getElementById("extractedResults");
  output.innerHTML = "";

  if (!text) return;

  const patterns = {
    ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    domain: /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g,
    email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    md5: /\b[a-fA-F0-9]{32}\b/g,
    sha1: /\b[a-fA-F0-9]{40}\b/g,
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    url: /https?:\/\/[^\s]+/g
  };

  let found = [];

  for (let key in patterns) {
    const matches = text.match(patterns[key]);
    if (matches) {
      matches.forEach(m => {
        found.push({ type: key, value: m });
      });
    }
  }

  const unique = [...new Map(found.map(item => [item.value, item])).values()];

  if (unique.length === 0) {
    output.innerHTML = "<div class='card'>No IOCs Found</div>";
    return;
  }

  unique.forEach(item => {
    const div = document.createElement("div");
    div.className = "card";
    div.innerHTML = `
      <strong>${item.type.toUpperCase()}</strong><br>
      ${item.value}
      <br>
      <button onclick="copyText('${item.value}')">Copy</button>
      <button onclick="document.getElementById('iocInput').value='${item.value}'; generateLinks();">Investigate</button>
      <button onclick="document.getElementById('defangInput').value='${item.value}'; defang();">Defang</button>
    `;
    output.appendChild(div);
  });
}
