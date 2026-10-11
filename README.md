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

DNS is only a hint. A registered domain with no nameservers can look free (NXDOMAIN). A wildcard TLD can make every name look taken. If a lookup times out, is rate-limited, or returns an error, this app marks it **unknown**. It never turns a failure into “available”.

## How a check runs

1. The page normalizes your paste: blank lines, comments, uppercase, spaces, full domains (`brand.com`, `https://www.brand.co.uk/path`), email-shaped text, and international names (shown in Unicode, looked up in punycode).
2. The server downloads the [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) and matches each TLD to a registry server.
3. For a TLD that has RDAP, it requests `https://<registry>/domain/<name>.<tld>` with a timeout and one retry. Several lookups run at once, with a cap per registry so one slow server does not get flooded.
4. For a TLD with no RDAP server (for example `.io`, `.co`, `.de` in the default list), it asks Cloudflare DNS-over-HTTPS, then Google DNS-over-HTTPS, for an NXDOMAIN versus existing records. The local resolver is used only if those are unreachable.
5. If RDAP exists but the request fails, the result stays unknown. DNS is not used to paper over a registry outage.
6. Finished answers are remembered in this browser tab, so a repeat check does not ask again. Unknowns are remembered too; use **Recheck unknowns** to try those again. **Clear tab cache** forgets everything stored in the tab.

The default TLD list is a mix of common gTLDs and ccTLDs. Edit it or paste your own, up to 40 TLDs and 150 names per run.

## Setup

Python 3.9 or newer. No packages to install.

```bash
python3 server.py
```

Open http://127.0.0.1:8765

The server listens on your machine only. Lookups go from your computer to IANA, the registry RDAP servers, and public DNS resolvers.

## Tests

```bash
python3 -m unittest tests.test_checker
```
