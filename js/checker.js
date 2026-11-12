/**
 * Domain auth checker — MX / SPF / DKIM / DMARC / BIMI via DoH.
 * Faithful port of web/src/lib/checker.ts
 *
 * Score weights (documented):
 * - MX present:            15
 * - SPF present:           20
 * - SPF lookup <= 10:      10  (partial if 8–10 warn; 0 if >10)
 * - SPF ends with ~all/-all: 5
 * - DKIM >=1 selector:     25
 * - DMARC present:         15
 * - DMARC p=quarantine/reject: 8  (p=none gets 2)
 * - BIMI present:           2  (nice-to-have)
 * Cap 100.
 *
 * SPF nested includes: follow `include:` one level deep for lookup-count
 * approximation only. Mechanisms that count toward the 10-lookup limit
 * (RFC 7208): include, a, mx, ptr, exists, redirect. We count top-level
 * + one nested level of include targets' mechanisms — not full recursion.
 */

import { dohQuery, isNxOrEmpty, mxHosts, txtStrings } from "./doh.js";

export const COMMON_DKIM_SELECTORS = [
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "default",
  "pm",
  "amazonses",
  "hs1",
  "hs2",
  "brevo",
];

const INCLUDE_RE = /\binclude:([^\s]+)/gi;

function findSpfRecord(txts) {
  return txts.find((t) => /^v=spf1\b/i.test(t.trim()));
}

function countLookupMechanisms(spf) {
  const includes = [];
  let m;
  const includeRe = new RegExp(INCLUDE_RE.source, "gi");
  while ((m = includeRe.exec(spf)) !== null) {
    includes.push(m[1].replace(/\.$/, ""));
  }
  // Count RFC-ish lookups at this level (include/a/mx/ptr/exists/redirect)
  const mechs = spf.match(/\b(include:[^\s]+|a(?::[^\s]+)?|mx(?::[^\s]+)?|ptr(?::[^\s]+)?|exists:[^\s]+|redirect=[^\s]+)/gi) || [];
  const bare = spf.match(/(?:^|\s)(a|mx)(?=\s|$)/gi) || [];
  // Prefer explicit mechanism matches; fall back to bare a/mx
  return { count: mechs.length || bare.length, includes };
}

function mechanismsSummary(spf) {
  const parts = [];
  if (/\s-all\s*$/i.test(spf) || /\s-all\b/i.test(spf)) parts.push("hardfail (-all)");
  else if (/\s~all\b/i.test(spf)) parts.push("softfail (~all)");
  else if (/\s\?all\b/i.test(spf)) parts.push("neutral (?all)");
  else if (/\s\+all\b/i.test(spf)) parts.push("pass-all (+all — dangerous)");
  else parts.push("no clear all mechanism");
  const inc = (spf.match(/include:/gi) || []).length;
  if (inc) parts.push(`${inc} include(s)`);
  return parts.join("; ");
}

async function checkMx(domain) {
  const resp = await dohQuery(domain, "MX");
  if (isNxOrEmpty(resp)) return { present: false, records: [] };
  return { present: true, records: mxHosts(resp) };
}

async function checkSpf(domain) {
  const resp = await dohQuery(domain, "TXT");
  const txts = txtStrings(resp);
  const record = findSpfRecord(txts);
  if (!record) {
    return {
      present: false,
      lookupCountApprox: 0,
      lookupLimit: 10,
      includes: [],
      nestedIncludes: [],
      hasAllSoftfail: false,
      hasAllHardfail: false,
      hasAllNeutralOrMissing: true,
    };
  }

  const top = countLookupMechanisms(record);
  const nestedIncludes = [];
  let nestedCount = 0;

  // Follow includes 1 level deep for count approximation
  await Promise.all(
    top.includes.slice(0, 10).map(async (inc) => {
      const r = await dohQuery(inc, "TXT");
      const nestedSpf = findSpfRecord(txtStrings(r));
      if (!nestedSpf) return;
      const nested = countLookupMechanisms(nestedSpf);
      nestedCount += nested.count;
      nestedIncludes.push(...nested.includes);
    })
  );

  const lookupCountApprox = top.count + nestedCount;
  const hasAllHardfail = /\s-all\b/i.test(record);
  const hasAllSoftfail = /\s~all\b/i.test(record);
  const hasAllNeutralOrMissing = !hasAllHardfail && !hasAllSoftfail;

  return {
    present: true,
    record,
    mechanismsSummary: mechanismsSummary(record),
    lookupCountApprox,
    lookupLimit: 10,
    includes: top.includes,
    nestedIncludes,
    hasAllSoftfail,
    hasAllHardfail,
    hasAllNeutralOrMissing,
  };
}

async function checkDkim(domain, selector) {
  const tried = [];
  const found = [];

  const list = selector
    ? [selector, ...COMMON_DKIM_SELECTORS.filter((s) => s !== selector)]
    : [...COMMON_DKIM_SELECTORS];

  // Probe provided first, then commons — parallel batches of 4 to stay polite
  for (let i = 0; i < list.length; i += 4) {
    const batch = list.slice(i, i + 4);
    await Promise.all(
      batch.map(async (sel) => {
        tried.push(sel);
        const name = `${sel}._domainkey.${domain}`;
        const resp = await dohQuery(name, "TXT");
        const txts = txtStrings(resp);
        const rec = txts.find((t) => /v=DKIM1/i.test(t) || /p=/i.test(t));
        if (rec) found.push({ selector: sel, record: rec });
      })
    );
    // Early exit if user selector found and we already have something — still finish commons lightly
    if (selector && found.some((f) => f.selector === selector) && found.length >= 1 && i >= 0) {
      // continue probing commons for completeness (MVP: stop after first batch+found if many)
    }
  }

  // Dedupe tried
  return {
    selectorsTried: [...new Set(tried)],
    selectorsFound: found,
  };
}

async function checkDmarc(domain) {
  const resp = await dohQuery(`_dmarc.${domain}`, "TXT");
  const txts = txtStrings(resp);
  const record = txts.find((t) => /v=DMARC1/i.test(t));
  if (!record) return { present: false };

  const policy = record.match(/\bp=([^;\s]+)/i)?.[1];
  const rua = record.match(/\brua=([^;\s]+)/i)?.[1];
  const pct = record.match(/\bpct=([^;\s]+)/i)?.[1];

  return { present: true, record, policy, rua, pct };
}

async function checkBimi(domain) {
  const resp = await dohQuery(`default._bimi.${domain}`, "TXT");
  const txts = txtStrings(resp);
  const record = txts.find((t) => /v=BIMI1/i.test(t) || /l=/i.test(t));
  if (!record) return { present: false };
  return { present: true, record };
}

export async function runChecks(domain, selector) {
  const [mx, spf, dkim, dmarc, bimi] = await Promise.all([
    checkMx(domain),
    checkSpf(domain),
    checkDkim(domain, selector),
    checkDmarc(domain),
    checkBimi(domain),
  ]);
  return { mx, spf, dkim, dmarc, bimi };
}

export function buildIssues(domain, f) {
  const issues = [];

  // MX
  if (!f.mx.present) {
    issues.push({
      id: "mx-missing",
      category: "MX",
      severity: "critical",
      title: "No MX records found",
      impact: "Receiving mail for this domain will fail; some receivers also treat missing MX as a weak sending signal.",
      suggestedRecord: `(ask your ESP/host for MX values)\n; Example only — replace with your provider's hosts\n10 mx1.example-esp.com.`,
      whereToPaste: "DNS zone for the apex domain (Cloudflare DNS → Records, or Namecheap Advanced DNS).",
      details: "NXDOMAIN or empty MX answer via DoH.",
    });
  } else {
    issues.push({
      id: "mx-ok",
      category: "MX",
      severity: "ok",
      title: "MX records present",
      impact: "Domain can receive mail at the DNS level.",
      details: f.mx.records.join(", "),
    });
  }

  // SPF
  if (!f.spf.present) {
    issues.push({
      id: "spf-missing",
      category: "SPF",
      severity: "critical",
      title: "SPF TXT record missing",
      impact: "Receivers cannot authorize your sending IPs/ESPs; higher chance of spam or reject on strict paths.",
      suggestedRecord: `v=spf1 include:_spf.example-esp.com ~all`,
      whereToPaste: `TXT record on ${domain} (apex). Replace include with your ESP's SPF include.`,
    });
  } else {
    if (f.spf.lookupCountApprox > 10) {
      issues.push({
        id: "spf-lookups-over",
        category: "SPF",
        severity: "critical",
        title: `SPF lookup count ≈ ${f.spf.lookupCountApprox} (over the limit of 10)`,
        impact: "RFC 7208 caps DNS lookups at 10. Over-limit SPF often fails evaluation → auth fail.",
        suggestedRecord: `Flatten or drop unused include: mechanisms. Keep a single ESP include + ~all.\nCurrent: ${f.spf.record}`,
        whereToPaste: `TXT on ${domain}. Prefer one ESP include; avoid chaining multiple ESPs.`,
        details: `Top includes: ${f.spf.includes.join(", ") || "(none)"}. Nested (1 level): ${f.spf.nestedIncludes.join(", ") || "(none)"}. Approximation only — not full recursive flatten.`,
      });
    } else if (f.spf.lookupCountApprox >= 8) {
      issues.push({
        id: "spf-lookups-high",
        category: "SPF",
        severity: "warning",
        title: `SPF lookup count ≈ ${f.spf.lookupCountApprox} (near limit of 10)`,
        impact: "Little headroom left; adding another ESP include may push you over 10.",
        suggestedRecord: f.spf.record,
        whereToPaste: `TXT on ${domain}. Consider flattening before adding vendors.`,
      });
    } else {
      issues.push({
        id: "spf-lookups-ok",
        category: "SPF",
        severity: "ok",
        title: `SPF lookups ≈ ${f.spf.lookupCountApprox} / 10`,
        impact: "Within the common 10-lookup budget (approx., 1-level nested).",
        details: f.spf.record,
      });
    }

    if (/\+all\b/i.test(f.spf.record || "")) {
      issues.push({
        id: "spf-plus-all",
        category: "SPF",
        severity: "critical",
        title: "SPF uses +all (allows anyone)",
        impact: "Effectively disables SPF protection; receivers may ignore or penalize.",
        suggestedRecord: (f.spf.record || "").replace(/\+all/i, "~all"),
        whereToPaste: `TXT on ${domain}.`,
      });
    } else if (f.spf.hasAllNeutralOrMissing) {
      issues.push({
        id: "spf-all-weak",
        category: "SPF",
        severity: "warning",
        title: "SPF lacks ~all or -all",
        impact: "Unauthorized senders may not be marked as fail/softfail.",
        suggestedRecord: `${f.spf.record} ~all`.replace(/\s+/g, " ").trim(),
        whereToPaste: `TXT on ${domain}. Start with ~all; move to -all after monitoring.`,
      });
    } else {
      issues.push({
        id: "spf-all-ok",
        category: "SPF",
        severity: "ok",
        title: f.spf.hasAllHardfail ? "SPF ends with -all" : "SPF ends with ~all",
        impact: "Unauthorized use is soft- or hard-failed per your policy.",
        details: f.spf.mechanismsSummary,
      });
    }
  }

  // DKIM
  if (f.dkim.selectorsFound.length === 0) {
    issues.push({
      id: "dkim-missing",
      category: "DKIM",
      severity: "critical",
      title: "No DKIM selectors found among common probes",
      impact: "Without DKIM, DMARC alignment is harder and many ESPs cannot authenticate.",
      suggestedRecord: `{selector}._domainkey.${domain} TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"`,
      whereToPaste: `Create a TXT at {selector}._domainkey under ${domain}. Copy selector + value from your ESP (Resend / Postmark / Google / Brevo / SES).`,
      details: `Tried: ${f.dkim.selectorsTried.join(", ")}`,
    });
  } else {
    issues.push({
      id: "dkim-found",
      category: "DKIM",
      severity: "ok",
      title: `DKIM found: ${f.dkim.selectorsFound.map((s) => s.selector).join(", ")}`,
      impact: "At least one DKIM public key is published.",
      details: f.dkim.selectorsFound.map((s) => `${s.selector}: ${s.record.slice(0, 120)}…`).join("\n"),
      whereToPaste: `Selectors live at {selector}._domainkey.${domain}.`,
    });
  }

  // DMARC
  if (!f.dmarc.present) {
    issues.push({
      id: "dmarc-missing",
      category: "DMARC",
      severity: "critical",
      title: "DMARC record missing",
      impact: "No policy for failed SPF/DKIM; Gmail/Yahoo sender requirements expect DMARC for many bulk senders.",
      suggestedRecord: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; pct=100`,
      whereToPaste: `TXT on _dmarc.${domain}. Start with p=none + rua, then tighten.`,
    });
  } else {
    const p = (f.dmarc.policy || "").toLowerCase();
    if (p === "none") {
      issues.push({
        id: "dmarc-p-none",
        category: "DMARC",
        severity: "warning",
        title: "DMARC policy is p=none",
        impact: "Useful for monitoring, but production bulk senders should plan quarantine/reject after reviewing rua reports.",
        suggestedRecord: (f.dmarc.record || "").replace(/p=none/i, "p=quarantine"),
        whereToPaste: `TXT on _dmarc.${domain}.`,
        details: `rua=${f.dmarc.rua || "(missing)"}; pct=${f.dmarc.pct || "100 (default)"}`,
      });
    } else {
      issues.push({
        id: "dmarc-policy-ok",
        category: "DMARC",
        severity: "ok",
        title: `DMARC policy p=${f.dmarc.policy}`,
        impact: "Receivers have an enforcement hint for failed auth.",
        details: f.dmarc.record,
      });
    }
    if (!f.dmarc.rua) {
      issues.push({
        id: "dmarc-rua-missing",
        category: "DMARC",
        severity: "info",
        title: "DMARC rua= not set",
        impact: "You will not receive aggregate failure reports to tune policy.",
        suggestedRecord: `${f.dmarc.record}; rua=mailto:dmarc@${domain}`,
        whereToPaste: `TXT on _dmarc.${domain}.`,
      });
    }
  }

  // BIMI
  if (!f.bimi.present) {
    issues.push({
      id: "bimi-missing",
      category: "BIMI",
      severity: "info",
      title: "BIMI not published (optional)",
      impact: "No brand logo via BIMI. Not required for basic auth; nice-to-have after DMARC enforcement.",
      suggestedRecord: `v=BIMI1; l=https://${domain}/bimi/logo.svg; a=`,
      whereToPaste: `TXT on default._bimi.${domain}. Requires stronger DMARC and often a verified mark certificate for major inboxes.`,
    });
  } else {
    issues.push({
      id: "bimi-ok",
      category: "BIMI",
      severity: "ok",
      title: "BIMI record present",
      impact: "Brand Indicators for Message Identification TXT found.",
      details: f.bimi.record,
    });
  }

  return issues;
}

export function scoreFromFindings(f) {
  let score = 0;
  if (f.mx.present) score += 15;
  if (f.spf.present) {
    score += 20;
    if (f.spf.lookupCountApprox <= 7) score += 10;
    else if (f.spf.lookupCountApprox <= 10) score += 5;
    // >10 → 0 for this bucket
    if (f.spf.hasAllHardfail || f.spf.hasAllSoftfail) score += 5;
  }
  if (f.dkim.selectorsFound.length > 0) score += 25;
  if (f.dmarc.present) {
    score += 15;
    const p = (f.dmarc.policy || "").toLowerCase();
    if (p === "reject" || p === "quarantine") score += 8;
    else if (p === "none") score += 2;
  }
  if (f.bimi.present) score += 2;
  return Math.max(0, Math.min(100, score));
}

export function pickTopIssues(issues, n = 3) {
  const rank = { critical: 0, warning: 1, info: 2, ok: 3 };
  return [...issues]
    .filter((i) => i.severity !== "ok")
    .sort((a, b) => rank[a.severity] - rank[b.severity])
    .slice(0, n);
}
