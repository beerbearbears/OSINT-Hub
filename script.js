let currentType = "ip";

function setType(type) { currentType = type; }

function search() {
    let value = document.getElementById("input").value;
    if (!value) return;
    let loading = document.getElementById("loading");
    loading.style.display = "block";

    setTimeout(() => {
        loading.style.display = "none";
        document.getElementById("output").value = "Query: " + value;
        updateAllLinks(value);
    }, 800);
}

function updateAllLinks(q) {
    // PHISHING
    phishtank.href = "https://www.phishtank.com/search.php?query=" + q;
    phishtool.href = "https://www.phishtool.com/search/?query=" + q;
    dnstwister.href = "https://dnstwister.report/search?domain=" + q;
    scamsearch.href = "https://scamsearch.io/search?query=" + q;
    checkphish.href = "https://checkphish.bolster.ai/search?query=" + q;
    openphish.href = "https://openphish.com/search/?query=" + q;

    // THREAT & REPUTATION
    virustotal.href = "https://www.virustotal.com/gui/search/" + q;
    abuseipdb.href = "https://www.abuseipdb.com/check/" + q;
    spur.href = "https://spur.us/context/" + q;
    ipinfo.href = "https://ipinfo.io/" + q;
    threatminer.href = "https://www.threatminer.org/search.php?q=" + q;
    urlscan.href = "https://urlscan.io/search/#" + q;
    ibmxf.href = "https://exchange.xforce.ibmcloud.com/lookup/" + q;
    talos.href = "https://talosintelligence.com/reputation_center/lookup?search=" + q;
    alienotx.href = "https://otx.alienvault.com/indicator/?q=" + q;

    // DNS & INFRA
    passivedns.href = "https://www.circl.lu/services/passive-dns/?q=" + q;
    securitytrails.href = "https://securitytrails.com/list/apex_domain/" + q;
    censys.href = "https://search.censys.io/search?q=" + q;
    shodan.href = "https://www.shodan.io/search?query=" + q;
    netlas.href = "https://netlas.io/search?query=" + q;
    maclookup.href = "https://macvendors.com/query/" + q;
    uaParser.href = "https://useragentstring.com/?uas=" + q;
    blockchain.href = "https://www.blockchain.com/explorer?search=" + q;

    // EMAIL / USER
    hunter.href = "https://hunter.io/search?q=" + q;
    haveibeenpwned.href = "https://haveibeenpwned.com/unifiedsearch/" + q;
    namechk.href = "https://namechk.com/" + q;
    whatsmyname.href = "https://whatsmyname.app/?q=" + q;

    // ARCHIVE
    intelx.href = "https://intelx.io/search?query=" + q;
    leakix.href = "https://leakix.net/search?q=" + q;
    wayback.href = "https://web.archive.org/cite/" + q;

    // DECODE
    cyberchef.href = "https://gchq.github.io/CyberChef/#recipe=From_Base64('A','…')";
    cvelookup.href = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + q;
}

// IOC Utilities
function defang() {
    let val = input.value;
    output.value = val.replace(/\./g, "[.]").replace(/http/g, "hxxp");
}

function refang() {
    let val = output.value;
    output.value = val.replace(/\[\.\]/g, ".").replace(/hxxp/g, "http");
}

function extractIOCs() {
    let text = input.value;
    let ip = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
    let domain = text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [];
    let email = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || [];
    output.value = "IPs:\n" + ip.join("\n") + "\n\nDomains:\n" + domain.join("\n") + "\n\nEmails:\n" + email.join("\n");
}

// Copy & Clear
function copyOutput() { output.select(); document.execCommand("copy"); }
function clearAll() { input.value = ""; output.value = ""; }
function toggleDark() { document.body.classList.toggle("dark"); }
