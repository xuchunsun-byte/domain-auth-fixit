import {
  CHECKOUT_URL,
  PRICE_LABEL,
  buildCheckoutUrl,
  rememberCheck,
  recallCheck,
} from "./config.js";
import { normalizeDomain } from "./normalize.js";
import { runChecks, buildIssues, scoreFromFindings, pickTopIssues } from "./checker.js";
import { buildReport, reportToMarkdown } from "./markdown.js";

const form = document.getElementById("check-form");
const domainInput = document.getElementById("domain");
const selectorInput = document.getElementById("selector");
const errorEl = document.getElementById("form-error");
const submitBtn = document.getElementById("submit-btn");
const resultsEl = document.getElementById("results");
const cancelledBanner = document.getElementById("cancelled-banner");

// Keep last markdown in memory only (for a later checkout metadata path).
// Do not display or offer a download on the unpaid page.
let lastMarkdown = "";
let lastDomain = "";
let lastSelector = "";

function showCancelledIfNeeded() {
  if (!cancelledBanner) return;
  const params = new URLSearchParams(window.location.search);
  if (params.get("cancelled") === "1") {
    cancelledBanner.hidden = false;
    const recalled = recallCheck();
    const extra = cancelledBanner.querySelector("[data-cancelled-domain]");
    if (extra && recalled.domain) {
      extra.textContent = `You can run another free check for ${recalled.domain}, or try checkout again when you’re ready.`;
    }
    if (recalled.domain && domainInput && !domainInput.value) {
      domainInput.value = recalled.domain;
    }
    if (recalled.selector && selectorInput && !selectorInput.value) {
      selectorInput.value = recalled.selector;
    }
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityLabel(sev) {
  return escapeHtml(sev);
}

function renderResults({ domain, score, topIssues }) {
  const issuesHtml =
    topIssues.length === 0
      ? `<p class="muted">No outstanding issues in the free summary. A full Fix-it checklist is still available after the ${escapeHtml(PRICE_LABEL)} purchase (emailed after checkout).</p>`
      : `<ul class="issue-list">${topIssues
          .map(
            (issue) => `
        <li class="issue issue-${escapeHtml(issue.severity)}">
          <div class="issue-meta">
            <span class="sev sev-${escapeHtml(issue.severity)}">${severityLabel(issue.severity)}</span>
            <span class="issue-cat">${escapeHtml(issue.category)}</span>
          </div>
          <p class="issue-title">${escapeHtml(issue.title)}</p>
          <p class="issue-impact">${escapeHtml(issue.impact)}</p>
        </li>`
          )
          .join("")}</ul>`;

  const checkoutConfigured = Boolean(CHECKOUT_URL && CHECKOUT_URL.trim());

  const ctaHtml = checkoutConfigured
    ? `<button type="button" class="btn btn-primary" id="unlock-btn">Unlock full Fix-it — ${escapeHtml(PRICE_LABEL)}</button>
       <p class="micro">You will be sent to checkout ($12 one-time). Enter your sending domain there (required). The full report is emailed to the address used at checkout — it is not unlocked on this page. DNS health ≠ inbox guarantee.</p>`
    : `<button type="button" class="btn btn-primary" id="unlock-btn" aria-describedby="checkout-pending">Unlock full Fix-it — ${escapeHtml(PRICE_LABEL)}</button>
       <p id="checkout-pending" class="micro" role="status">Checkout is being connected. The ${escapeHtml(PRICE_LABEL)} Fix-it report is not available for purchase on this page yet. We will not invent a payment link.</p>
       <p class="micro">DNS health ≠ inbox guarantee.</p>`;

  resultsEl.innerHTML = `
    <section class="card results-card" aria-live="polite">
      <h2>Free summary for ${escapeHtml(domain)}</h2>
      <p class="score"><span class="score-num">${escapeHtml(String(score))}</span><span class="score-den">/ 100</span></p>
      <p class="muted">Health score from public DNS (MX, SPF, DKIM, DMARC, BIMI). DNS health ≠ inbox guarantee.</p>
      <h3>Top 3 issues</h3>
      ${issuesHtml}
      <div class="unlock">
        <h3>Full Fix-it report — ${escapeHtml(PRICE_LABEL)} one-time</h3>
        <p class="muted">Full checklist: problem → impact → suggested DNS record → where to paste, plus a Markdown file emailed after payment.</p>
        ${ctaHtml}
        <p id="unlock-msg" class="unlock-msg" hidden></p>
      </div>
    </section>
  `;
  resultsEl.hidden = false;

  const unlockBtn = document.getElementById("unlock-btn");
  const unlockMsg = document.getElementById("unlock-msg");
  if (unlockBtn) {
    unlockBtn.addEventListener("click", () => {
      if (!CHECKOUT_URL || !CHECKOUT_URL.trim()) {
        if (unlockMsg) {
          unlockMsg.hidden = false;
          unlockMsg.textContent =
            "Checkout is being connected. Please check back shortly — no payment link is available yet.";
        }
        return;
      }
      rememberCheck(lastDomain, lastSelector);
      const url = buildCheckoutUrl(CHECKOUT_URL.trim(), lastDomain, lastSelector || undefined);
      window.location.href = url;
    });
  }

  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function onSubmit(e) {
  e.preventDefault();
  errorEl.hidden = true;
  errorEl.textContent = "";

  const domain = normalizeDomain(domainInput.value);
  if (!domain) {
    errorEl.hidden = false;
    errorEl.textContent = "Enter a valid domain, such as yourdomain.com.";
    return;
  }

  const selectorRaw = (selectorInput.value || "").trim();
  const selector = selectorRaw || undefined;

  submitBtn.disabled = true;
  submitBtn.textContent = "Checking DNS…";
  resultsEl.hidden = true;
  resultsEl.innerHTML = "";
  lastMarkdown = "";

  try {
    const findings = await runChecks(domain, selector);
    const fullIssues = buildIssues(domain, findings);
    const score = scoreFromFindings(findings);
    const topIssues = pickTopIssues(fullIssues, 3);
    const report = buildReport({
      domain,
      selector,
      findings,
      score,
      topIssues,
      fullIssues,
      paid: false,
    });
    // Generated in memory only — not shown or offered for download until paid email fulfillment.
    lastMarkdown = reportToMarkdown(report);
    lastDomain = domain;
    lastSelector = selector || "";
    rememberCheck(domain, lastSelector);
    renderResults({ domain, score, topIssues });
  } catch (err) {
    console.error(err);
    errorEl.hidden = false;
    errorEl.textContent = "The DNS check failed. Public resolvers may be unreachable — please try again.";
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Check my domain";
  }
}

if (form) form.addEventListener("submit", onSubmit);
showCancelledIfNeeded();
