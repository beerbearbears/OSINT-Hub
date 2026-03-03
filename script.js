document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("input");
    const output = document.getElementById("output");

    // Detect type of input
    function detectType(val) {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return "ip";
        if (/^[a-fA-F0-9]{32,64}$/.test(val)) return "hash";
        if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(val)) return "email";
        if (/^[a-zA-Z0-9_-]{3,}$/i.test(val)) return "username";
        if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return "domain";
        return null;
    }

    // Show relevant tool sections
    function showRelevantTools(type) {
        document.querySelectorAll(".tool-section").forEach(section => {
            section.style.display = (section.dataset.type === type || !section.dataset.type) ? "block" : "none";
        });
    }

    // All links for dynamic generation
    const links = {
        ip: {
            virustotal: (q) => `https://www.virustotal.com/gui/ip-address/${q}/detection`,
            abuseipdb: (q) => `https://www.abuseipdb.com/check/${q}`,
            spur: (q) => `https://vpn.spur.com/check/${q}`,
            ipinfo: (q) => `https://ipinfo.io/${q}`,
            threatminer: (q) => `https://www.threatminer.org/host.php?q=${q}`,
            ibmxf: (q) => `https://exchange.xforce.ibmcloud.com/ip/${q}`,
            talos: (q) => `https://talosintelligence.com/reputation_center/lookup?search=${q}`,
            alienotx: (q) => `https://otx.alienvault.com/indicator/ip/${q}`,
            scamalytics: (q) => `https://scamalytics.com/ip/${q}`
        },
        domain: {
            passivedns: (q) => `https://www.passivedns.io/?q=${q}`,
            securitytrails: (q) => `https://securitytrails.com/domain/${q}`,
            censys: (q) => `https://censys.io/domain/${q}`,
            shodan: (q) => `https://www.shodan.io/search?query=${q}`,
            netlas: (q) => `https://netlas.io/domain/${q}`,
            virustotal_domain: (q) => `https://www.virustotal.com/gui/domain/${q}/detection`,
            talos_domain: (q) => `https://talosintelligence.com/reputation_center/lookup?search=${q}`,
            ibmxf_domain: (q) => `https://exchange.xforce.ibmcloud.com/url/${q}`,
            alienotx_domain: (q) => `https://otx.alienvault.com/indicator/domain/${q}`,
            urlscan_domain: (q) => `https://urlscan.io/domain/${q}`,
            mxtoolbox: (q) => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist:${q}`,
            blacklistchecker: (q) => `https://www.blacklistchecker.com/?q=${q}`,
            cleantalk_bl: (q) => `https://cleantalk.org/blacklists/${q}`,
            cleantalk_malware: (q) => `https://cleantalk.org/malware/${q}`,
            sucuri: (q) => `https://sitecheck.sucuri.net/results/${q}`,
            urlvoid: (q) => `https://www.urlvoid.com/scan/${q}`,
            urlhaus: (q) => `https://urlhaus.abuse.ch/browse.php?search=${q}`,
            whois_domaintools: (q) => `https://whois.domaintools.com/${q}`,
            dnSlytics: (q) => `https://dnslytics.com/domain/${q}`,
            netcraft: (q) => `https://searchdns.netcraft.com/?host=${q}`,
            webcheck: (q) => `https://webcheck.spiderlabs.io/${q}`,
            hudsonrock_info: (q) => `https://intel.hudsonrock.com/info/${q}`,
            hudsonrock_urls: (q) => `https://intel.hudsonrock.com/urls/${q}`,
            socradar: (q) => `https://www.socradar.io/darkweb-search?q=${q}`,
            wayback: (q) => `https://web.archive.org/web/*/${q}`,
            wayback_save: (q) => `https://web.archive.org/save/${q}`,
            browserling: (q) => `https://www.browserling.com/browse/${q}`,
            anyrun_domain: (q) => `https://any.run/search/?q=${q}`,
            anyrun_safe: (q) => `https://any.run/safe?q=${q}`,
            phishing_checker: (q) => `https://phishingchecker.org/?q=${q}`,
            clickfix: (q) => `https://clickfix.com/hunter/${q}`,
            nitter: (q) => `https://nitter.net/search?q=${q}`
        },
        email: {
            hunter: (q) => `https://hunter.io/search/${q}`,
            haveibeenpwned: (q) => `https://haveibeenpwned.com/account/${q}`
        },
        username: {
            namechk: (q) => `https://namechk.com/${q}`,
            whatsmyname: (q) => `https://whatsmyname.app/${q}`
        },
        hash: {
            virustotalhash: (q) => `https://www.virustotal.com/gui/file/${q}/detection`,
            threatminerhash: (q) => `https://www.threatminer.org/file.php?q=${q}`,
            anyrun: (q) => `https://any.run/search/?q=${q}`,
            alienhash: (q) => `https://otx.alienvault.com/indicator/file/${q}`,
            taloshash: (q) => `https://talosintelligence.com/file-reputation?search=${q}`,
            ibmhash: (q) => `https://exchange.xforce.ibmcloud.com/malware/${q}`,
            triage: (q) => `https://www.tria.ge/search?q=${q}`,
            joesandbox: (q) => `https://www.joesandbox.com/search?query=${q}`,
            hybrid: (q) => `https://www.hybrid-analysis.com/search?query=${q}`
        }
    };

    // Update all links dynamically
    function updateAllLinks(q, type) {
        if (!links[type]) return;
        for (let id in links[type]) {
            const el = document.getElementById(id);
            if (el) {
                el.href = links[type][id](q);
                el.setAttribute("target", "_blank"); // open in new tab
            }
        }
    }

    // Search button functionality
    function search() {
        const val = input.value.trim();
        if (!val) return;
        const type = detectType(val);
        if (!type) { alert("Could not detect IOC type"); return; }
        showRelevantTools(type);
        updateAllLinks(val, type);
        output.value = `${type.toUpperCase()} Query: ${val}`;
    }

    // Tool button functions
    function defang() { output.value = input.value.replace(/\./g, "[.]").replace(/http/g, "hxxp"); }
    function refang() { output.value = output.value.replace(/\[\.\]/g, ".").replace(/hxxp/g, "http"); }

    function extractIOCs() {
        const text = input.value;
        const ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
        const domains = text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g) || [];
        const emails = text.match(/\b[^@\s]+@[^@\s]+\.[^@\s]+\b/g) || [];
        const hashes = text.match(/\b[A-Fa-f0-9]{32,64}\b/g) || [];
        output.value =
            `IPs:\n${ips.join("\n")}\n\nDomains:\n${domains.join("\n")}\n\nEmails:\n${emails.join("\n")}\n\nHashes:\n${hashes.join("\n")}`;
    }

    function copyOutput() { output.select(); document.execCommand("copy"); }
    function clearAll() {
        input.value = "";
        output.value = "";
        document.querySelectorAll(".tool-section").forEach(s => s.style.display = "block");
    }
    function toggleDark() { document.body.classList.toggle("dark"); }

    // Event listeners
    document.getElementById("search-btn").addEventListener("click", search);
    document.getElementById("defang-btn").addEventListener("click", defang);
    document.getElementById("refang-btn").addEventListener("click", refang);
    document.getElementById("extract-btn").addEventListener("click", extractIOCs);
    document.getElementById("copy-btn").addEventListener("click", copyOutput);
    document.getElementById("clear-all").addEventListener("click", clearAll);
    document.getElementById("toggle-dark").addEventListener("click", toggleDark);
    input.addEventListener("keypress", e => { if(e.key === "Enter") search(); });
});
