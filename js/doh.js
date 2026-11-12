/**
 * DNS-over-HTTPS helpers (Cloudflare primary, Google fallback).
 * Faithful port of web/src/lib/doh.ts (without Next.js fetch extensions).
 */

const CF = "https://cloudflare-dns.com/dns-query";
const GOOGLE = "https://dns.google/resolve";
const DOH_TIMEOUT_MS = 8_000;

async function fetchDoh(url) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      cache: "no-store",
      signal: ac.signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function dohQuery(name, type) {
  const q = encodeURIComponent(name);
  const cf = await fetchDoh(`${CF}?name=${q}&type=${type}`);
  if (cf) return cf;
  const g = await fetchDoh(`${GOOGLE}?name=${q}&type=${type}`);
  if (g) return g;
  return { Status: 2 }; // SERVFAIL-ish empty
}

export function txtStrings(resp) {
  if (!resp?.Answer) return [];
  return resp.Answer.filter((a) => a.type === 16 || a.data)
    .map((a) => a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, ""))
    .map((s) => s.replace(/\\"/g, '"'));
}

export function mxHosts(resp) {
  if (!resp?.Answer) return [];
  // data like "10 mail.example.com."
  return resp.Answer.map((a) => {
    const parts = a.data.trim().split(/\s+/);
    const host = (parts[parts.length - 1] || "").replace(/\.$/, "");
    return host;
  }).filter(Boolean);
}

export function isNxOrEmpty(resp) {
  if (!resp) return true;
  if (resp.Status === 3) return true;
  return !resp.Answer || resp.Answer.length === 0;
}
