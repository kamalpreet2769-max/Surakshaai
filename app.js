/* SurakshaAI prototype: local rule-based analysis only.
   Do not add secret API keys to this public frontend. */
const $ = (id) => document.getElementById(id);
const STORAGE_KEY = "surakshaai.history.v1";
let currentTab = "message";
let lastResult = null;

const messagePatterns = [
  { re: /\b(otp|one[- ]time password|pin)\b/i, text: "Mentions an OTP, PIN, or one-time password. Never share these with anyone." },
  { re: /\b(password|bank login|cvv|card number)\b/i, text: "Requests or mentions sensitive account information. Do not share credentials." },
  { re: /\b(urgent|immediately|within \d+ hours|limited time|account will be blocked|suspended today)\b/i, text: "Uses urgency or threats to pressure you into acting quickly." },
  { re: /\b(won|winner|prize|free gift|lottery|claim your reward)\b/i, text: "Promises a prize or reward that may be designed to attract clicks or payments." },
  { re: /\b(pay (a |the )?(fee|charge)|processing fee|send money|deposit first|advance payment)\b/i, text: "Requests an upfront payment. Verify the organisation independently before paying." },
  { re: /\b(job offer|work from home|easy income|guaranteed income|daily earning)\b/i, text: "Makes a job or income claim that should be independently verified." },
  { re: /\b(click here|verify now|confirm your account|update kyc|kyc expired)\b/i, text: "Pushes you to click or verify account details. Open the official app or website yourself instead." },
  { re: /https?:\/\/|www\./i, text: "Contains a web address. Check the exact domain carefully before visiting it." },
  { re: /\b(gift card|crypto|investment guaranteed|double your money)\b/i, text: "Mentions a reward, investment, or payment pattern commonly abused in scams." }
];

function analyseMessage(raw) {
  const text = raw.trim();
  const findings = messagePatterns.filter(p => p.re.test(text)).map(p => p.text);
  if (text.length < 20) findings.push("There is limited context, so this message cannot be assessed confidently.");
  if (/\b(official|bank|government|police)\b/i.test(text)) {
    findings.push("A message claiming to be from an official organisation is not proof of authenticity.");
  }
  let level = findings.length >= 4 ? "high" : findings.length >= 2 ? "medium" : "low";
  if (!text) return null;
  const summary = level === "high" ? "Several warning signs were found. Treat this message as suspicious." :
    level === "medium" ? "Some warning signs were found. Verify the sender through an independent official channel." :
    "Few common warning signs were detected, but this does not prove the message is safe.";
  const advice = "Do not reply, pay, or share personal information until verified. Contact the organisation using a number or website you find independently.";
  if (!findings.length) findings.push("No matching common warning pattern was found by the basic checker. Sophisticated scams may not trigger these rules.");
  return { type:"Message", input:text, level, summary, findings, advice };
}

function analyseLink(raw) {
  const text = raw.trim();
  if (!text) return null;
  let findings = [];
  let parsed;
  try {
    // Require an explicit scheme so a pasted domain isn't silently treated as trusted.
    if (!/^https?:\/\//i.test(text)) throw new Error("Add http:// or https:// before the domain.");
    parsed = new URL(text);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only web URLs can be checked.");
    if (parsed.username || parsed.password) findings.push("The URL contains embedded username/password information. Do not use it.");
    if (parsed.protocol === "http:") findings.push("This link uses HTTP rather than HTTPS. Data may not be protected in transit.");
    if (parsed.hostname.startsWith("xn--") || parsed.hostname.includes(".xn--")) findings.push("The domain uses internationalised/punycode characters that can sometimes disguise lookalike names.");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) findings.push("The link uses a raw IP address instead of a recognisable domain.");
    if (parsed.hostname.split(".").length >= 5) findings.push("The domain has many subdomains. Check which registered domain it actually belongs to.");
    if (/(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|shorturl\.at|tiny\.cc)$/i.test(parsed.hostname)) findings.push("This appears to use a link-shortening service, which hides the final destination.");
    if (/@/.test(text)) findings.push("The URL includes an @ symbol, which can make the actual destination confusing.");
    if (/(login|verify|update|secure|account|kyc|wallet|payment|gift|prize)/i.test(parsed.hostname)) findings.push("The domain name contains terms often used in impersonation links. This alone does not prove fraud.");
    if (parsed.hostname.length > 60) findings.push("The hostname is unusually long; inspect it carefully for misspellings or misleading subdomains.");
  } catch (e) {
    return { type:"Link", input:text, level:"medium", summary:"The link could not be confidently parsed. Do not open it to test it.", findings:[e.message || "The URL format may be invalid.", "The app does not visit the link or check live threat databases."], advice:"Confirm the exact web address through the organisation's official app or a known, trusted source." };
  }
  const level = findings.length >= 3 ? "high" : findings.length >= 1 ? "medium" : "low";
  const summary = level === "high" ? "Multiple URL warning signs were found. Avoid opening it unless independently verified." :
    level === "medium" ? "Some URL warning signs were found. Verify the destination independently before taking action." :
    "No basic URL warning signs were detected. This is not a reputation check and does not prove the link is safe.";
  if (!findings.length) findings.push("No basic URL pattern was flagged. This prototype does not query live phishing databases or verify site ownership.");
  return { type:"Link", input:text, level, summary, findings, advice:"Do not enter passwords, OTPs, payment details, or personal information on a page reached from an unexpected message. Navigate to the official service yourself." };
}

function readHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(value) ? value : [];
  } catch { return []; }
}
function saveResult(result) {
  const history = readHistory();
  history.unshift({ ...result, id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()), date: new Date().toISOString() });
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, 50))); }
  catch { alert("Could not save history on this device. Your result is still shown."); }
  renderHistory();
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[ch]));
}
function showResult(result) {
  if (!result) return;
  lastResult = result;
  $("resultTitle").textContent = result.type + " analysis";
  $("riskBadge").textContent = result.level.toUpperCase() + " RISK";
  $("riskBadge").className = "risk " + result.level;
  $("resultSummary").textContent = result.summary;
  $("findings").innerHTML = result.findings.map(item => `<li>${escapeHtml(item)}</li>`).join("");
  $("resultAdvice").textContent = result.advice;
  $("resultPanel").classList.remove("hidden");
  $("resultPanel").scrollIntoView({ behavior:"smooth", block:"start" });
  saveResult(result);
}
function renderHistory() {
  const history = readHistory();
  $("historyCount").textContent = history.length;
  $("historyList").innerHTML = history.map(item => {
    const date = new Date(item.date);
    const dateText = Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
    const preview = item.input.length > 130 ? item.input.slice(0,130) + "…" : item.input;
    return `<article class="history-item"><span class="history-icon">${item.type === "Link" ? "🔗" : "✉️"}</span><main><strong>${escapeHtml(preview)}</strong><small>${escapeHtml(item.type)} · ${escapeHtml(item.level.toUpperCase())} · ${escapeHtml(dateText)}</small></main><button class="ghost small" data-delete="${escapeHtml(item.id)}" type="button" aria-label="Delete saved check">Delete</button></article>`;
  }).join("");
  $("emptyHistory").classList.toggle("hidden", history.length > 0);
}
function setTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  $("messagePanel").classList.toggle("hidden", tab !== "message");
  $("linkPanel").classList.toggle("hidden", tab !== "link");
  $("historyPanel").classList.toggle("hidden", tab !== "history");
  if (tab !== "history") $("resultPanel").classList.add("hidden");
  if (tab === "history") renderHistory();
}

document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => setTab(button.dataset.tab)));
$("messageInput").addEventListener("input", () => $("messageLength").textContent = $("messageInput").value.length + "/6000");
$("checkMessage").addEventListener("click", () => {
  const value = $("messageInput").value.trim();
  if (!value) return alert("Paste a message to check.");
  showResult(analyseMessage(value));
});
$("checkLink").addEventListener("click", () => {
  const value = $("linkInput").value.trim();
  if (!value) return alert("Paste a URL to check.");
  showResult(analyseLink(value));
});
$("checkAnother").addEventListener("click", () => {
  $("resultPanel").classList.add("hidden");
  if (lastResult && lastResult.type === "Link") { $("linkInput").focus(); } else { $("messageInput").focus(); }
});
function clearHistory() {
  if (!confirm("Delete all saved SurakshaAI checks from this device? This cannot be undone.")) return;
  localStorage.removeItem(STORAGE_KEY);
  renderHistory();
}
$("clearHistory").addEventListener("click", clearHistory);
$("clearHistory2").addEventListener("click", clearHistory);
$("historyList").addEventListener("click", event => {
  const id = event.target && event.target.dataset ? event.target.dataset.delete : null;
  if (!id) return;
  const history = readHistory().filter(item => item.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  renderHistory();
});
renderHistory();
