(() => {
  "use strict";
  const form = document.getElementById("scan-form");
  const input = document.getElementById("url-input");
  const errorBox = document.getElementById("error");
  const result = document.getElementById("result");
  const historyList = document.getElementById("history-list");
  const STORAGE_KEY = "linklens-history-v1";
  const MAX_HISTORY = 8;

  function readHistory() {
    try {
      const data = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      return Array.isArray(data) ? data.filter(x => x && typeof x.url === "string" && typeof x.date === "string").slice(0, MAX_HISTORY) : [];
    } catch { return []; }
  }
  function writeHistory(items) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, MAX_HISTORY))); }
    catch { /* Local storage may be unavailable in private browsing. */ }
  }
  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
  }
  function clearError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
  }
  function isIpAddress(host) {
    if (host.startsWith("[") && host.endsWith("]")) return true;
    const parts = host.split(".");
    return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }
  function analyze(raw) {
    const value = raw.trim();
    if (!value) throw new Error("Please enter a URL.");
    if (/\s/.test(value)) throw new Error("The URL contains spaces. Check the address and try again.");
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value) && !value.startsWith("//")) {
      throw new Error("Include a protocol, for example https://example.com");
    }
    let parsed;
    try { parsed = new URL(value.startsWith("//") ? "https:" + value : value); }
    catch { throw new Error("That URL format looks invalid. Check it and try again."); }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Only http:// and https:// website URLs are supported.");
    }
    if (!parsed.hostname || !parsed.hostname.includes(".") && parsed.hostname !== "localhost" && !isIpAddress(parsed.hostname)) {
      throw new Error("This does not look like a complete website hostname.");
    }

    const host = parsed.hostname.toLowerCase();
    const findings = [];
    let score = 0;
    const add = (points, message) => { score += points; findings.push(message); };

    if (parsed.protocol !== "https:") add(2, "This URL uses HTTP, not HTTPS. The connection is not encrypted by TLS.");
    else findings.push("The URL uses HTTPS. This encrypts the connection but does not prove the site is legitimate.");
    if (parsed.username || parsed.password) add(3, "The URL contains text before the @ symbol that may disguise the actual destination.");
    if (isIpAddress(host)) add(2, "The hostname is an IP address rather than a typical domain name. This is a warning sign, not proof of harm.");
    if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--"))) add(2, "The hostname contains an internationalized/punycode label. Check for lookalike characters.");
    const labels = host.split(".");
    if (host.length > 70) add(1, "The hostname is unusually long.");
    if ((host.match(/-/g) || []).length >= 3) add(1, "The hostname contains several hyphens; inspect the spelling carefully.");
    if (/\b(login|verify|secure|account|update|wallet|password|signin|payment)\b/i.test(host)) add(1, "The hostname uses words often seen in account or payment lures. Legitimate sites can use these too.");
    if (parsed.href.length > 180) add(1, "The full URL is unusually long. Long URLs can hide confusing paths or parameters.");
    if (parsed.port && !((parsed.protocol === "https:" && parsed.port === "443") || (parsed.protocol === "http:" && parsed.port === "80"))) add(1, "The URL uses a non-default port. Make sure you expected this.");
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".invalid") || host.endsWith(".test") || host.endsWith(".example")) {
      findings.push("This appears to be a reserved/example hostname, usually used for testing rather than a public website.");
    }
    if (findings.length === 1) findings.push("No other checks in this small rule set were triggered. This does not mean the website is safe.");

    let level = "low", label = "Fewer indicators";
    if (score >= 4) { level = "high"; label = "Several warnings"; }
    else if (score >= 2) { level = "medium"; label = "Review carefully"; }
    return {url: parsed.href, host, protocol: parsed.protocol.replace(":", "").toUpperCase(), https: parsed.protocol === "https:", findings, score, level, label};
  }
  function renderResult(data) {
    document.getElementById("normalized-url").textContent = data.url;
    document.getElementById("protocol").textContent = data.protocol;
    document.getElementById("hostname").textContent = data.host;
    document.getElementById("https").textContent = data.https ? "Yes" : "No";
    const badge = document.getElementById("risk-badge");
    badge.textContent = data.label;
    badge.className = "status " + data.level;
    const list = document.getElementById("findings");
    list.replaceChildren();
    data.findings.forEach(message => {
      const li = document.createElement("li");
      li.textContent = message;
      list.appendChild(li);
    });
    const note = document.getElementById("verdict-note");
    note.className = "notice" + (data.level === "low" ? " good" : "");
    note.textContent = "Rule-based indicator score: " + data.score + ". This is not a probability of being malicious. Verify the domain independently before entering sensitive information.";
    result.classList.remove("hidden");
  }
  function renderHistory() {
    const items = readHistory();
    historyList.replaceChildren();
    if (!items.length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "No scans yet.";
      historyList.appendChild(p);
      return;
    }
    items.forEach((item, index) => {
      const row = document.createElement("div");
      row.className = "history-item";
      const info = document.createElement("div");
      info.className = "history-url";
      const urlText = document.createElement("div");
      urlText.textContent = item.url;
      const date = document.createElement("small");
      date.textContent = item.date + " · " + item.label;
      info.append(urlText, date);
      const actions = document.createElement("div");
      actions.className = "history-actions";
      const revisit = document.createElement("button");
      revisit.type = "button"; revisit.className = "secondary"; revisit.textContent = "View";
      revisit.addEventListener("click", () => { input.value = item.url; form.requestSubmit(); window.scrollTo({top:0,behavior:"smooth"}); });
      const remove = document.createElement("button");
      remove.type = "button"; remove.className = "secondary"; remove.textContent = "Delete";
      remove.setAttribute("aria-label", "Delete scan " + (index + 1));
      remove.addEventListener("click", () => { const next = readHistory(); next.splice(index, 1); writeHistory(next); renderHistory(); });
      actions.append(revisit, remove);
      row.append(info, actions);
      historyList.appendChild(row);
    });
  }
  form.addEventListener("submit", event => {
    event.preventDefault();
    clearError();
    try {
      const data = analyze(input.value);
      renderResult(data);
      const items = readHistory().filter(item => item.url !== data.url);
      items.unshift({url:data.url, date:new Date().toLocaleString(), label:data.label});
      writeHistory(items);
      renderHistory();
    } catch (error) {
      result.classList.add("hidden");
      showError(error instanceof Error ? error.message : "Something went wrong. Please try again.");
    }
  });
  document.querySelectorAll("[data-sample]").forEach(button => button.addEventListener("click", () => {
    input.value = button.dataset.sample;
    form.requestSubmit();
  }));
  document.getElementById("clear-history").addEventListener("click", () => {
    writeHistory([]);
    renderHistory();
  });
  renderHistory();
})();
