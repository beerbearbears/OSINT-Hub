let currentTab = "ip";

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

function copyText(text) {
  navigator.clipboard.writeText(text);
  alert("Copied: " + text);
}

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
