/**
 * Public site config for Domain Auth Fix-it (GitHub Pages).
 *
 * CHECKOUT_URL
 *   Leave empty until a real Creem (or other) checkout URL exists.
 *   Do not invent a payment link. The Unlock button will explain that
 *   checkout is being connected when this is empty.
 *
 * CHECKOUT_PARAM_STYLE
 *   "query" (default) or "hash".
 *
 * When CHECKOUT_URL is later filled, the $12 CTA navigates to that URL
 * and passes the checked domain (and optional DKIM selector) as follows.
 *
 * Query style (default):
 *   https://pay.example/checkout?domain=example.com&selector=google
 *   If CHECKOUT_URL already has a query string, params are appended with "&".
 *   An existing hash fragment on CHECKOUT_URL is preserved at the end.
 *
 * Hash style:
 *   https://pay.example/checkout#domain=example.com&selector=google
 *   If CHECKOUT_URL already has a hash, params are appended with "&".
 *
 * `selector` is omitted when the buyer left it blank.
 *
 * Suggested Creem return URLs (HTTPS):
 *   Success:  https://xuchunsun-byte.github.io/domain-auth-fixit/thanks/
 *   Cancel:   https://xuchunsun-byte.github.io/domain-auth-fixit/?cancelled=1
 *             (also https://xuchunsun-byte.github.io/domain-auth-fixit/cancelled/)
 */

export const BASE_PATH = "/domain-auth-fixit/";
export const CHECKOUT_URL = "";
export const CHECKOUT_PARAM_STYLE = "query"; // "query" | "hash"
export const PRICE_LABEL = "$12";

export const STORAGE_KEY_DOMAIN = "domain-auth-fixit:lastDomain";
export const STORAGE_KEY_SELECTOR = "domain-auth-fixit:lastSelector";

export function withBase(path) {
  const p = String(path || "").replace(/^\//, "");
  return BASE_PATH + p;
}

export function rememberCheck(domain, selector) {
  try {
    if (domain) localStorage.setItem(STORAGE_KEY_DOMAIN, domain);
    else localStorage.removeItem(STORAGE_KEY_DOMAIN);
    if (selector) localStorage.setItem(STORAGE_KEY_SELECTOR, selector);
    else localStorage.removeItem(STORAGE_KEY_SELECTOR);
  } catch {
    /* private mode / blocked storage */
  }
}

export function recallCheck() {
  try {
    return {
      domain: localStorage.getItem(STORAGE_KEY_DOMAIN) || "",
      selector: localStorage.getItem(STORAGE_KEY_SELECTOR) || "",
    };
  } catch {
    return { domain: "", selector: "" };
  }
}

export function buildCheckoutUrl(checkoutUrl, domain, selector) {
  if (!checkoutUrl) return "";
  const params = new URLSearchParams();
  if (domain) params.set("domain", domain);
  if (selector) params.set("selector", selector);
  const qs = params.toString();
  if (!qs) return checkoutUrl;

  if (CHECKOUT_PARAM_STYLE === "hash") {
    const hashIndex = checkoutUrl.indexOf("#");
    if (hashIndex === -1) return `${checkoutUrl}#${qs}`;
    const base = checkoutUrl.slice(0, hashIndex);
    const existing = checkoutUrl.slice(hashIndex + 1);
    if (!existing) return `${base}#${qs}`;
    return `${base}#${existing}&${qs}`;
  }

  const hashIndex = checkoutUrl.indexOf("#");
  const urlNoHash = hashIndex === -1 ? checkoutUrl : checkoutUrl.slice(0, hashIndex);
  const hash = hashIndex === -1 ? "" : checkoutUrl.slice(hashIndex);
  const joiner = urlNoHash.includes("?") ? "&" : "?";
  return `${urlNoHash}${joiner}${qs}${hash}`;
}
