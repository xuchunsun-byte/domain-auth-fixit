# Domain Auth Fix-it

Public static site for **Domain Auth Fix-it**: a plain-English SPF, DKIM, and DMARC health check for sending domains.

Live site: https://xuchunsun-byte.github.io/domain-auth-fixit/

**DNS health ≠ inbox guarantee.** This tool only reads public DNS (MX, SPF, DKIM, DMARC, BIMI). A passing score does not promise inbox placement, open rates, or deliverability outcomes.

## What this repo is

GitHub Pages (project site, source `/` on the default branch). No server, no paid hosting, no custom domain in this repo.

- Free summary: score (0–100) and Top 3 issues, shown in the browser after a check.
- Paid Fix-it report ($12 one-time): emailed to the address used at checkout after payment. This static host cannot verify payment or unlock the full report on the page.

## Checkout URL (fill after Creem lists the product)

Edit `js/config.js`:

- `CHECKOUT_URL` — official Creem product/checkout link for Domain Auth Fix-it Report ($12 one-time, `prod_1ohwE1GXukY8zV2uSxQ4xe`). Creem also collects a required “Sending domain” field (and optional DKIM selector) at checkout for email fulfillment.
- `CHECKOUT_PARAM_STYLE` — `"query"` (default) or `"hash"`.

When `CHECKOUT_URL` is set, the Unlock button sends the buyer there and appends:

| Param | When |
| --- | --- |
| `domain` | Always, the normalized domain just checked |
| `selector` | Only if the buyer entered a DKIM selector |

**Query style (default)**

```
https://pay.example/checkout?domain=example.com&selector=google
```

If `CHECKOUT_URL` already has a `?…` query, these params are appended with `&`. An existing `#fragment` on the URL is preserved at the end.

**Hash style** (`CHECKOUT_PARAM_STYLE = "hash"`)

```
https://pay.example/checkout#domain=example.com&selector=google
```

If `CHECKOUT_URL` already has a hash, params are appended with `&`.

The checked domain (and selector, if any) is also stored in `localStorage` under `domain-auth-fixit:lastDomain` and `domain-auth-fixit:lastSelector` so the thanks and cancel pages can mention it.

### Suggested return URLs for the payment provider

- Success: https://xuchunsun-byte.github.io/domain-auth-fixit/thanks/
- Cancel: https://xuchunsun-byte.github.io/domain-auth-fixit/?cancelled=1
  - Alternate: https://xuchunsun-byte.github.io/domain-auth-fixit/cancelled/

## Pages

- `/` — landing + checker; `?cancelled=1` shows a cancelled checkout note
- `/thanks/` — success / email-fulfillment message
- `/cancelled/` — cancelled checkout
- `/privacy/` and `/terms/` — stubs (not counsel-reviewed)

## Local preview

Serve this directory over HTTP (module scripts will not load from `file://`):

```bash
python3 -m http.server 8080
# open http://127.0.0.1:8080/
```

Asset paths on the live site are relative and work under the `/domain-auth-fixit/` project Pages base path.
