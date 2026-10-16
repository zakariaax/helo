# Bulk TLD checker

A local page that takes a list of names and checks a set of TLDs for each one. It uses public registry data. There is no account, no API key, and no paid WHOIS service.

## Best free method

Use **RDAP** first. Fall back to **DNS** only when a TLD has no RDAP server. Do not use **WHOIS** for a bulk yes/no.

| Method | What it tells you | Confidence |
| --- | --- | --- |
| RDAP | The registry’s own HTTPS directory. HTTP 200 means the domain is registered. HTTP 404 means the registry has no record of it. | High |
| DNS | Whether the public DNS has the name. Records usually mean it is taken. NXDOMAIN usually means it is free. | Medium for “taken”, low for “available” |
| WHOIS | Free on port 43, but every registry writes a different paragraph, bulk queries get cut off, and privacy redaction hides contact data you do not need. | Too messy to parse |

RDAP “not found” is a stronger availability signal than DNS. It is still not a promise you can register the name: it can be premium, reserved, or blocked when you try to buy it. Owner contacts are often redacted. That does not change the found / not-found answer.

DNS is only a hint. A registered domain with no nameservers can look free (NXDOMAIN). A wildcard TLD can make every name look taken. If both the registry and DNS fail, or DNS has no clear answer, this app marks it **unknown**. It never turns a failure into “available”.

## How a check runs

1. The page normalizes your paste: blank lines, comments, uppercase, spaces, full domains (`brand.com`, `https://www.brand.co.uk/path`), email-shaped text, and international names (shown in Unicode, looked up in punycode).
2. The server downloads the [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) and matches each TLD to a registry server.
3. For a TLD that has RDAP, it requests `https://<registry>/domain/<name>.<tld>` with a short timeout. Many names are checked at once, and each name’s extensions are rotated so the run does not finish one name before the next one starts. There is a cap per registry so one slow server does not stall the rest.
4. For a TLD with no RDAP server, it asks Cloudflare DNS-over-HTTPS, then Google DNS-over-HTTPS, for an NXDOMAIN versus existing records. The local resolver is used only if those are unreachable.
5. If the registry does not answer (timeout, browser block, or rate limit), the same DNS hint is used and the chip says DNS. RDAP 200 and RDAP 404 stay authoritative. If DNS also fails, the result stays unknown.
6. The progress line shows a rough time-left estimate as soon as you click Check, then replaces it with a measured estimate after the first results arrive.
7. Finished answers are remembered in this browser tab, so a repeat check does not ask again. Unknowns are remembered too; use **Recheck unknowns** to try those again. **Clear tab cache** forgets everything stored in the tab. Click a registered, available, or unknown count to list those extensions.

The TLD box starts with every extension in the IANA root (largest zones first). Four sets sit above it:

- **All TLDs** — the full root list.
- **Famous 400** — the 400 largest zones, ranked by how many domains they hold.
- **Launch** — the short list worth buying for a new product.
- **Countries** — the 80 largest country-code extensions.

You can still edit or paste your own list. Up to 150 names per run.

## Setup

The public site is [https://zakariaax.github.io/helo/](https://zakariaax.github.io/helo/). It runs in the browser, with no install.

To run the same page on this computer:

```bash
python3 server.py
```

Open http://127.0.0.1:8765. The local server listens on this machine only.

## Tests

```bash
python3 -m unittest tests.test_checker
```
