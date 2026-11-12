/** Strip protocol, path, port; lowercase host. Faithful port of web/src/lib/normalize.ts */
export function normalizeDomain(input) {
  let s = (input || "").trim().toLowerCase();
  if (!s) return "";
  s = s.replace(/^https?:\/\//, "");
  s = s.replace(/^\/\//, "");
  s = s.split("/")[0] || "";
  s = s.split("?")[0] || "";
  s = s.split("#")[0] || "";
  s = s.split(":")[0] || ""; // drop port
  s = s.replace(/\.$/, "");
  // basic hostname chars
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s) && !/^[a-z0-9-]+\.[a-z]{2,}$/.test(s)) {
    // allow single-label + TLD loosely; reject empties / spaces
    if (!/^[a-z0-9.-]+$/.test(s) || !s.includes(".")) {
      return "";
    }
  }
  return s;
}
