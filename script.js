function generateLinks() {
  const input = document.getElementById("iocInput").value.trim();
  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "";

  if (!input) return;

  const card = document.createElement("div");
  card.className = "card";

  card.innerHTML = `
    <h3>OSINT Links for: ${input}</h3>

    <strong>Network / IP</strong>
    <a href="https://www.virustotal.com/gui/search/${input}" target="_blank">VirusTotal</a>
    <a href="https://www.abuseipdb.com/check/${input}" target="_blank">AbuseIPDB</a>
    <a href="https://www.greynoise.io/viz/ip/${input}" target="_blank">GreyNoise</a>
    <a href="https://www.shodan.io/search?query=${input}" target="_blank">Shodan</a>

    <strong>Domain</strong>
    <a href="https://who.is/whois/${input}" target="_blank">Whois</a>
    <a href="https://securitytrails.com/domain/${input}/dns" target="_blank">SecurityTrails</a>

    <strong>Email</strong>
    <a href="https://haveibeenpwned.com/account/${input}" target="_blank">HaveIBeenPwned</a>

    <strong>Username</strong>
    <a href="https://whatsmyname.app/" target="_blank">WhatsMyName</a>
  `;

  resultsDiv.appendChild(card);
}

function extractIOCs() {
  const logText = document.getElementById("logInput").value;
  const output = document.getElementById("extracted");
  output.innerHTML = "";

  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;
  const hashRegex = /\b[A-Fa-f0-9]{32,64}\b/g;

  const ips = logText.match(ipRegex) || [];
  const domains = logText.match(domainRegex) || [];
  const hashes = logText.match(hashRegex) || [];

  const unique = [...new Set([...ips, ...domains, ...hashes])];

  if (unique.length === 0) {
    output.innerHTML = "<div class='card'>No IOCs Found</div>";
    return;
  }

  unique.forEach(ioc => {
    const link = document.createElement("a");
    link.href = "#";
    link.textContent = ioc;
    link.onclick = () => {
      document.getElementById("iocInput").value = ioc;
      generateLinks();
    };
    output.appendChild(link);
  });
}
