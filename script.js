let currentType = "ip";

function setType(type) {
    currentType = type;
}

function search() {
    let value = document.getElementById("input").value;
    let loading = document.getElementById("loading");

    loading.style.display = "block";

    setTimeout(() => {
        loading.style.display = "none";
        document.getElementById("output").value = "Query: " + value;
        updatePhishingLinks(value);
    }, 800);
}

function updatePhishingLinks(query) {
    document.getElementById("phishtank").href =
        "https://www.phishtank.com/search.php?query=" + encodeURIComponent(query);

    document.getElementById("phishtool").href =
        "https://www.phishtool.com/search/?query=" + encodeURIComponent(query);

    document.getElementById("dnstwister").href =
        "https://dnstwister.report/search?domain=" + encodeURIComponent(query);

    document.getElementById("scamsearch").href =
        "https://scamsearch.io/search?query=" + encodeURIComponent(query);

    document.getElementById("checkphish").href =
        "https://checkphish.bolster.ai/search?query=" + encodeURIComponent(query);

    document.getElementById("openphish").href =
        "https://openphish.com/search/?query=" + encodeURIComponent(query);
}

function defang() {
    let val = document.getElementById("input").value;
    let defanged = val.replace(/\./g, "[.]").replace(/http/g, "hxxp");
    document.getElementById("output").value = defanged;
}

function refang() {
    let val = document.getElementById("output").value;
    let refanged = val.replace(/\[\.\]/g, ".").replace(/hxxp/g, "http");
    document.getElementById("output").value = refanged;
}

function extractIOCs() {
    let text = document.getElementById("input").value;

    let ipRegex = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
    let domainRegex = /\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    let emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

    let ips = text.match(ipRegex) || [];
    let domains = text.match(domainRegex) || [];
    let emails = text.match(emailRegex) || [];

    let result = "IPs:\n" + ips.join("\n") +
        "\n\nDomains:\n" + domains.join("\n") +
        "\n\nEmails:\n" + emails.join("\n");

    document.getElementById("output").value = result;
}

function copyOutput() {
    let output = document.getElementById("output");
    output.select();
    document.execCommand("copy");
    alert("Copied!");
}

function clearAll() {
    document.getElementById("input").value = "";
    document.getElementById("output").value = "";
}

function toggleDark() {
    document.body.classList.toggle("dark");
}
