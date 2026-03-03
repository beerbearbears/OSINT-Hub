let input = document.getElementById("input");
let output = document.getElementById("output");

function detectType(val) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return "ip";          // IPv4
    if (/^[a-fA-F0-9]{32,64}$/.test(val)) return "hash";           // MD5/SHA
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(val)) return "email";    // Email
    if (/^[a-zA-Z0-9_-]{3,}$/i.test(val)) return "username";       // Username
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return "domain"; // Domain
    return null;
}

function showRelevantTools(type) {
    document.querySelectorAll(".tool-section").forEach(section => {
        if (section.dataset.type === type) section.style.display = "block";
        else section.style.display = "none";
    });
}

function search() {
    const val = input.value.trim();
    if (!val) return;

    const type = detectType(val);
    if (!type) { alert("Could not detect IOC type"); return; }

    showRelevantTools(type);
    updateAllLinks(val, type);

    output.value = `${type.toUpperCase()} Query: ${val}`;
}

// Update all links by type
function updateAllLinks(q, type) {
    if (type === "ip") {
        virustotal.href = `https://www.virustotal.com/gui/search/${q}`;
        abuseipdb.href = `https://www.abuseipdb.com/check/${q}`;
        spur.href = `https://spur.us/context/${q}`;
        ipinfo.href = `https://ipinfo.io/${q}`;
        threatminer.href = `https://www.threatminer.org/search.php?q=${q}`;
        urlscan.href = `https://urlscan.io/search/#${q}`;
        ibmxf.href = `https://exchange.xforce.ibmcloud.com/lookup/${q}`;
        talos.href = `https://talosintelligence.com/reputation_center/lookup?search=${q}`;
        alienotx.href = `https://otx.alienvault.com/indicator/?q=${q}`;
    }
    if (type === "domain") {
        passivedns.href = `https://www.circl.lu/services/passive-dns/?q=${q}`;
        securitytrails.href = `https://securitytrails.com/list/apex_domain/${q}`;
        censys.href = `https://search.censys.io/search?q=${q}`;
        shodan.href = `https://www.shodan.io/search?query=${q}`;
        netlas.href = `https://netlas.io/search?query=${q}`;
    }
    if (type === "email") {
        hunter.href = `https://hunter.io/search?q=${q}`;
        haveibeenpwned.href = `https://haveibeenpwned.com/unifiedsearch/${q}`;
    }
    if (type === "username") {
        namechk.href = `https://namechk.com/${q}`;
        whatsmyname.href = `https://whatsmyname.app/?q=${q}`;
    }
    if (type === "hash") {
        virustotalhash.href = `https://www.virustotal.com/gui/search/${q}`;
        threatminerhash.href = `https://www.threatminer.org/search.php?q=${q}`;
    }
}

// IOC utilities
function defang() { output.value = input.value.replace(/\./g, "[.]").replace(/http/g, "hxxp"); }
function refang() { output.value = output.value.replace(/\[\.\]/g, ".").replace(/hxxp/g, "http"); }
function extractIOCs() {
    const text = input.value;
    const ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
    const domains = text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [];
    const emails = text.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || [];
    output.value = `IPs:\n${ips.join("\n")}\n\nDomains:\n${domains.join("\n")}\n\nEmails:\n${emails.join("\n")}`;
}

// Copy / Clear / Dark mode
function copyOutput() { output.select(); document.execCommand("copy"); }
function clearAll() { input.value=""; output.value=""; document.querySelectorAll(".tool-section").forEach(s=>s.style.display="block"); }
function toggleDark() { document.body.classList.toggle("dark"); }
