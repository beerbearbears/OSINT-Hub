document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("input");
    const output = document.getElementById("output");

    function detectType(val) {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return "ip";
        if (/^[a-fA-F0-9]{32,64}$/.test(val)) return "hash";
        if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(val)) return "email";
        if (/^[a-zA-Z0-9_-]{3,}$/i.test(val)) return "username";
        if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) return "domain";
        return null;
    }

    function showRelevantTools(type) {
        document.querySelectorAll(".tool-section").forEach(section => {
            if (section.dataset.type === type || !section.dataset.type) section.style.display = "block";
            else section.style.display = "none";
        });
    }

    const links = {
        // IP, domain, email, username, hash links here
        // (As I wrote earlier with all updated domain tools included)
    };

    function updateAllLinks(q, type) {
        if (!links[type]) return;
        for (let id in links[type]) {
            const el = document.getElementById(id);
            if (el) el.href = links[type][id];
        }
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
    function clearAll() { input.value=""; output.value=""; document.querySelectorAll(".tool-section").forEach(s=>s.style.display="block"); }
    function toggleDark() { document.body.classList.toggle("dark"); }

    document.getElementById("search-btn").addEventListener("click", search);
    document.getElementById("defang-btn").addEventListener("click", defang);
    document.getElementById("refang-btn").addEventListener("click", refang);
    document.getElementById("extract-btn").addEventListener("click", extractIOCs);
    document.getElementById("copy-btn").addEventListener("click", copyOutput);
    document.getElementById("clear-all").addEventListener("click", clearAll);
    document.getElementById("toggle-dark").addEventListener("click", toggleDark);
});
