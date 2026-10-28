/**
 * ScamLens Frontend Application Logic
 * Interacts with FastAPI backend endpoints: /api/scan/message and /api/scan/url
 */

// Sample test cases for easy interactive demonstration
const SAMPLE_MESSAGES = {
  internship: "Congratulations! You have been selected for the Python Developer Internship at Global Tech Innovations. To confirm your joining and receive your company laptop kit, you are required to deposit a refundable registration fee of Rs. 2,500. This security deposit will be refunded with your first month stipend. Connect on WhatsApp to complete onboarding.",
  otp: "URGENT NOTICE: Your bank account will be suspended within 2 hours due to unverified KYC details. Urgent action required to prevent disconnection. Please verify your account immediately by replying with your 6-digit OTP and bank card PIN.",
  lottery: "CONGRATULATIONS! You have been selected as the lucky winner of the International Mega Draw. You have won $1,000,000 cash reward. To claim your jackpot prize, contact our claims officer on Telegram @MegaWinDesk within 24 hours.",
  legitimate: "Hello Alex, Thank you for taking the time to speak with our engineering team yesterday. We would like to schedule a 45-minute technical discussion next Tuesday at 2:00 PM. Please let us know if that time works or if you need an alternative slot. Best regards, Sarah Jenkins, HR Operations at CloudScale Inc.",
  promotion: "Weekend Flash Sale: Enjoy 35% discount on all outdoor gear this Saturday and Sunday only. Free standard shipping applies to orders over $50 at our official online catalog.",
};

const SAMPLE_URLS = {
  ip_host: "http://192.168.1.100:8080/secure/bank-login/verify",
  brand_spoof: "http://paypal-login-verify.example.com",
  shortener: "https://bit.ly/3xFreePrizeNow",
  punycode: "https://xn--pple-43d.com/support/login",
  legit_url: "https://internshala.com/internships",
};

// State
let lastScanResult = null;

// DOM Elements
const tabMessageBtn = document.getElementById("tab-message-btn");
const tabUrlBtn = document.getElementById("tab-url-btn");
const paneMessage = document.getElementById("pane-message");
const paneUrl = document.getElementById("pane-url");

const messageInput = document.getElementById("message-input");
const charCounter = document.getElementById("char-counter");
const clearMessageBtn = document.getElementById("clear-message-btn");
const scanMessageBtn = document.getElementById("scan-message-btn");

const urlInput = document.getElementById("url-input");
const clearUrlBtn = document.getElementById("clear-url-btn");
const scanUrlBtn = document.getElementById("scan-url-btn");

const errorAlert = document.getElementById("error-alert");
const errorMessage = document.getElementById("error-message");

const resultsContainer = document.getElementById("results-container");
const verdictBadge = document.getElementById("verdict-badge");
const verdictText = document.getElementById("verdict-text");
const scoreNumber = document.getElementById("score-number");
const scoreMeterFill = document.getElementById("score-meter-fill");
const summaryText = document.getElementById("summary-text");
const analyzedPreview = document.getElementById("analyzed-preview");
const indicatorCount = document.getElementById("indicator-count");
const indicatorsList = document.getElementById("indicators-list");
const noIndicatorsState = document.getElementById("no-indicators-state");
const recommendedActionsList = document.getElementById("recommended-actions-list");
const limitationsList = document.getElementById("limitations-list");
const copyReportBtn = document.getElementById("copy-report-btn");
const scanNewBtn = document.getElementById("scan-new-btn");

// Initialize Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupSampleButtons();
  setupInputs();
  setupScanActions();
  setupReportActions();
});

function setupTabs() {
  tabMessageBtn.addEventListener("click", () => switchTab("message"));
  tabUrlBtn.addEventListener("click", () => switchTab("url"));
}

function switchTab(target) {
  hideError();
  if (target === "message") {
    tabMessageBtn.classList.add("active");
    tabUrlBtn.classList.remove("active");
    paneMessage.classList.add("active");
    paneUrl.classList.remove("active");
  } else {
    tabUrlBtn.classList.add("active");
    tabMessageBtn.classList.remove("active");
    paneUrl.classList.add("active");
    paneMessage.classList.remove("active");
  }
}

function setupSampleButtons() {
  document.querySelectorAll(".sample-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const type = btn.getAttribute("data-type");
      const sampleKey = btn.getAttribute("data-sample");

      if (type === "message" && SAMPLE_MESSAGES[sampleKey]) {
        messageInput.value = SAMPLE_MESSAGES[sampleKey];
        updateCharCount();
        hideError();
      } else if (type === "url" && SAMPLE_URLS[sampleKey]) {
        urlInput.value = SAMPLE_URLS[sampleKey];
        hideError();
      }
    });
  });
}

function setupInputs() {
  messageInput.addEventListener("input", updateCharCount);

  messageInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      scanMessageBtn.click();
    }
  });

  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      scanUrlBtn.click();
    }
  });

  clearMessageBtn.addEventListener("click", () => {
    messageInput.value = "";
    updateCharCount();
    hideError();
  });

  clearUrlBtn.addEventListener("click", () => {
    urlInput.value = "";
    hideError();
  });
}

function updateCharCount() {
  const count = messageInput.value.length;
  charCounter.textContent = `${count.toLocaleString()} / 20,000 characters`;
}

function showError(msg) {
  errorMessage.textContent = msg;
  errorAlert.style.display = "flex";
  resultsContainer.style.display = "none";
}

function hideError() {
  errorAlert.style.display = "none";
}

function setButtonLoading(btn, isLoading) {
  const content = btn.querySelector(".btn-content");
  const spinner = btn.querySelector(".spinner");

  if (isLoading) {
    btn.disabled = true;
    content.style.opacity = "0.5";
    spinner.style.display = "inline-block";
  } else {
    btn.disabled = false;
    content.style.opacity = "1";
    spinner.style.display = "none";
  }
}

function setupScanActions() {
  scanMessageBtn.addEventListener("click", async () => {
    const text = messageInput.value.trim();
    if (text.length < 3) {
      showError("Please enter or paste at least 3 characters of text to scan.");
      return;
    }

    hideError();
    setButtonLoading(scanMessageBtn, true);

    try {
      const response = await fetch("/api/scan/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with status ${response.status}`);
      }

      const result = await response.json();
      displayResults(result);
    } catch (err) {
      showError(`Analysis failed: ${err.message}`);
    } finally {
      setButtonLoading(scanMessageBtn, false);
    }
  });

  scanUrlBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (url.length < 3) {
      showError("Please enter a link or domain with at least 3 characters.");
      return;
    }

    hideError();
    setButtonLoading(scanUrlBtn, true);

    try {
      const response = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with status ${response.status}`);
      }

      const result = await response.json();
      displayResults(result);
    } catch (err) {
      showError(`Analysis failed: ${err.message}`);
    } finally {
      setButtonLoading(scanUrlBtn, false);
    }
  });
}

function displayResults(data) {
  lastScanResult = data;

  // 1. Verdict badge & styling
  verdictBadge.className = "risk-badge";
  scoreMeterFill.className = "meter-fill";

  if (data.risk_level === "Suspicious") {
    verdictBadge.classList.add("risk-suspicious");
    scoreMeterFill.classList.add("fill-suspicious");
  } else if (data.risk_level === "Needs Verification") {
    verdictBadge.classList.add("risk-needs");
    scoreMeterFill.classList.add("fill-needs");
  } else {
    verdictBadge.classList.add("risk-low");
    scoreMeterFill.classList.add("fill-low");
  }

  verdictText.textContent = data.risk_level;
  scoreNumber.textContent = `${data.risk_score} / 100`;
  scoreMeterFill.style.width = `${Math.max(5, data.risk_score)}%`;

  // 2. Summary & preview
  summaryText.textContent = data.summary;
  analyzedPreview.textContent = data.analyzed_preview;

  // 3. Indicators
  indicatorCount.textContent = data.indicators.length;
  indicatorsList.innerHTML = "";

  if (data.indicators.length === 0) {
    noIndicatorsState.style.display = "flex";
  } else {
    noIndicatorsState.style.display = "none";
    data.indicators.forEach((ind) => {
      const card = document.createElement("div");
      card.className = "indicator-card";

      const severityClass = `sev-${ind.severity}`;

      let snippetHtml = "";
      if (ind.matched_text) {
        snippetHtml = `<div class="matched-snippet">Matched: "${escapeHtml(ind.matched_text)}"</div>`;
      }

      card.innerHTML = `
        <div class="indicator-header">
          <div class="indicator-category-row">
            <span class="indicator-category">${escapeHtml(ind.category)}</span>
            <span class="severity-pill ${severityClass}">${ind.severity}</span>
          </div>
        </div>
        <div class="indicator-title">${escapeHtml(ind.title)}</div>
        <div class="indicator-desc">${escapeHtml(ind.description)}</div>
        ${snippetHtml}
      `;
      indicatorsList.appendChild(card);
    });
  }

  // 4. Recommended Actions
  recommendedActionsList.innerHTML = "";
  data.recommended_actions.forEach((act) => {
    const li = document.createElement("li");
    li.textContent = act;
    recommendedActionsList.appendChild(li);
  });

  // 5. Limitations
  limitationsList.innerHTML = "";
  data.limitations.forEach((lim) => {
    const li = document.createElement("li");
    li.textContent = lim;
    limitationsList.appendChild(li);
  });

  // Show container and smoothly scroll to it
  resultsContainer.style.display = "flex";
  resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });
}

function setupReportActions() {
  copyReportBtn.addEventListener("click", () => {
    if (!lastScanResult) return;

    const report = formatReportMarkdown(lastScanResult);
    const setSuccessMessage = () => {
      const originalText = copyReportBtn.innerHTML;
      copyReportBtn.innerHTML = `✓ Copied to Clipboard`;
      setTimeout(() => {
        copyReportBtn.innerHTML = originalText;
      }, 2000);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(report).then(
        setSuccessMessage,
        () => fallbackCopy(report, setSuccessMessage)
      );
    } else {
      fallbackCopy(report, setSuccessMessage);
    }
  });

  scanNewBtn.addEventListener("click", () => {
    resultsContainer.style.display = "none";
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
}

function fallbackCopy(text, onSuccess) {
  try {
    const tempTextArea = document.createElement("textarea");
    tempTextArea.value = text;
    tempTextArea.style.position = "fixed";
    tempTextArea.style.opacity = "0";
    document.body.appendChild(tempTextArea);
    tempTextArea.focus();
    tempTextArea.select();
    const successful = document.execCommand("copy");
    document.body.removeChild(tempTextArea);
    if (successful && onSuccess) {
      onSuccess();
    } else {
      alert("Please copy the report text manually.");
    }
  } catch (err) {
    alert("Could not copy report to clipboard.");
  }
}

function formatReportMarkdown(result) {
  let md = `# ScamLens Safety Assessment Report\n\n`;
  md += `**Input Type:** ${result.input_type.toUpperCase()}\n`;
  md += `**Risk Level:** ${result.risk_level} (Score: ${result.risk_score}/100)\n`;
  md += `**Analyzed Preview:** ${result.analyzed_preview}\n`;
  md += `**Timestamp:** ${result.analyzed_at}\n\n`;
  md += `## Summary\n${result.summary}\n\n`;

  md += `## Warning Indicators (${result.indicators.length})\n`;
  if (result.indicators.length === 0) {
    md += `- No prominent scam indicators were detected.\n`;
  } else {
    result.indicators.forEach((i, idx) => {
      md += `${idx + 1}. **[${i.severity.toUpperCase()}] ${i.title}** (${i.category})\n`;
      md += `   - *Details:* ${i.description}\n`;
      if (i.matched_text) {
        md += `   - *Snippet:* "${i.matched_text}"\n`;
      }
    });
  }

  md += `\n## Recommended Actions\n`;
  result.recommended_actions.forEach((act) => {
    md += `- [ ] ${act}\n`;
  });

  md += `\n## Limitations & Notice\n`;
  result.limitations.forEach((lim) => {
    md += `* ${lim}\n`;
  });

  md += `\n*Generated by ScamLens - Transparent Rule-Based Detection Engine.*`;
  return md;
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
