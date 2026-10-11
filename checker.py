"""Free bulk TLD checks: public RDAP, then DNS only when RDAP is unpublished.

RDAP bases come from the IANA bootstrap file. A domain query that returns
HTTP 404 is a not-found answer from the registry. DNS (DNS-over-HTTPS, then
the local resolver) is used only when IANA lists no RDAP server for that
suffix. A failed lookup stays "unknown" and is never reported as available.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "BulkTLDChecker/1.0 (local; public RDAP and DNS only)"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

RDAP_TIMEOUT = 6.0
RDAP_RETRIES = 1
DNS_TIMEOUT = 5.0
DNS_RETRIES = 1

# Global cap, then a per-host cap. Acquire the global slot first so a thread
# never holds a host slot while waiting for the global one.
_GLOBAL = threading.Semaphore(24)
_HOSTS: dict[str, threading.Semaphore] = {}
_HOSTS_LOCK = threading.Lock()
_HOST_LIMIT = 4

MAX_NAMES = 150
MAX_TLDS = 40

DEFAULT_TLDS = [
    "com",
    "net",
    "org",
    "info",
    "biz",
    "io",
    "co",
    "ai",
    "app",
    "dev",
    "me",
    "tv",
    "cc",
    "xyz",
    "online",
    "site",
    "tech",
    "store",
    "shop",
    "cloud",
    "us",
    "uk",
    "ca",
    "de",
    "au",
    "fr",
    "nl",
    "eu",
]

# Multi-label suffixes we strip when someone pastes a full domain.
# Longest match wins. This is a practical subset, not the full Public Suffix List.
_MULTI_SUFFIXES = (
    "co.uk",
    "org.uk",
    "me.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "co.nz",
    "org.nz",
    "net.nz",
    "com.br",
    "com.mx",
    "com.ar",
    "com.co",
    "co.jp",
    "or.jp",
    "ne.jp",
    "co.za",
    "org.za",
    "com.tr",
    "co.in",
    "com.cn",
    "com.tw",
    "com.hk",
    "com.sg",
    "co.kr",
    "co.id",
    "com.my",
    "com.ph",
    "com.vn",
    "co.th",
    "com.pl",
    "co.il",
    "com.pt",
    "co.id",
    "com.es",
)

_LABEL_RE_SOURCE = r"(?:xn--[a-z0-9-]{1,59}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"

POSITIVE_DNS_TYPES = {1, 2, 5, 15, 16, 28, 33, 43, 65}

_CACHE: dict[tuple, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()
_BOOT: Bootstrap | None = None
_BOOT_LOADING = False
_BOOT_CV = threading.Condition()


@dataclass
class Bootstrap:
    suffixes: dict[str, list[str]]
    publication: str | None
    error: str | None
    fetched_at: float


@dataclass
class ParsedName:
    ascii: str
    display: str


@dataclass
class ParseOutcome:
    names: list[ParsedName] = field(default_factory=list)
    tlds: list[ParsedName] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    duplicate_count: int = 0
    error: str | None = None


def default_tld_text() -> str:
    return "\n".join(DEFAULT_TLDS)


class _HostSlot:
    def __init__(self, host: str) -> None:
        self.host = host or "unknown"
        self._host_sem: threading.Semaphore | None = None

    def __enter__(self) -> _HostSlot:
        _GLOBAL.acquire()
        try:
            with _HOSTS_LOCK:
                sem = _HOSTS.get(self.host)
                if sem is None:
                    sem = threading.Semaphore(_HOST_LIMIT)
                    _HOSTS[self.host] = sem
            sem.acquire()
            self._host_sem = sem
        except BaseException:
            _GLOBAL.release()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._host_sem is not None:
            self._host_sem.release()
        _GLOBAL.release()


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    header = exc.headers.get("Retry-After") if exc.headers else None
    if not header:
        return None
    try:
        seconds = float(header)
    except ValueError:
        return None
    if 0 < seconds <= 3:
        return seconds
    return None


def http_get(
    url: str,
    accept: str,
    timeout: float,
    retries: int,
    max_bytes: int = 262144,
) -> tuple[int | None, bytes, str | None]:
    """GET a URL. Returns (status, body, error). Status is None when no HTTP response arrived."""
    host = urllib.parse.urlparse(url).hostname or "unknown"
    delay = 0.35
    last_error = "request failed"
    with _HostSlot(host):
        for attempt in range(retries + 1):
            request = urllib.request.Request(
                url,
                headers={"Accept": accept, "User-Agent": USER_AGENT},
            )
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    return response.status, response.read(max_bytes), None
            except urllib.error.HTTPError as exc:
                body = exc.read(8192) if exc.fp else b""
                if exc.code == 429:
                    wait = _retry_after(exc)
                    if wait is not None and attempt < retries:
                        time.sleep(wait)
                        continue
                    return exc.code, body, None
                if exc.code in (500, 502, 503, 504) and attempt < retries:
                    time.sleep(delay)
                    delay *= 2
                    last_error = f"HTTP {exc.code}"
                    continue
                return exc.code, body, None
            except Exception as exc:
                last_error = exc.__class__.__name__
                if attempt < retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                return None, b"", last_error
    return None, b"", last_error


def _normalize_service_urls(urls: list) -> list[str]:
    https = []
    http = []
    for url in urls:
        if not isinstance(url, str):
            continue
        cleaned = url.strip()
        lower = cleaned.lower()
        if lower.startswith("https://"):
            https.append(cleaned)
        elif lower.startswith("http://"):
            http.append(cleaned)
    return https or http


def fetch_bootstrap() -> Bootstrap:
    # The bootstrap file is larger than a single domain reply, so give it a higher cap.
    status, body, err = http_get(
        BOOTSTRAP_URL,
        "application/json",
        timeout=20,
        retries=2,
        max_bytes=1_048_576,
    )
    fetched_at = time.time()
    if status != 200 or not body:
        reason = err or f"HTTP {status}"
        return Bootstrap({}, None, f"Could not download the IANA RDAP directory ({reason}).", fetched_at)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return Bootstrap(
            {},
            None,
            f"IANA RDAP directory was not valid JSON ({exc.__class__.__name__}, {len(body)} bytes).",
            fetched_at,
        )
    suffixes: dict[str, list[str]] = {}
    for entry in data.get("services") or []:
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        tlds, urls = entry
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        normalized = _normalize_service_urls(urls)
        if not normalized:
            continue
        for tld in tlds:
            if isinstance(tld, str) and tld.strip():
                suffixes[tld.strip().lower()] = normalized
    if not suffixes:
        return Bootstrap({}, data.get("publication"), "IANA RDAP directory contained no servers.", fetched_at)
    return Bootstrap(suffixes, data.get("publication"), None, fetched_at)


def get_bootstrap(force: bool = False) -> Bootstrap:
    global _BOOT, _BOOT_LOADING
    with _BOOT_CV:
        while _BOOT_LOADING:
            _BOOT_CV.wait()
        fresh = False
        if _BOOT is not None and not force:
            ttl = 60 if _BOOT.error else 12 * 3600
            fresh = (time.time() - _BOOT.fetched_at) < ttl
        if fresh and _BOOT is not None:
            return _BOOT
        _BOOT_LOADING = True
    try:
        boot = fetch_bootstrap()
    except Exception as exc:
        boot = Bootstrap({}, None, f"Could not download the IANA RDAP directory ({exc.__class__.__name__}).", time.time())
    with _BOOT_CV:
        _BOOT = boot
        _BOOT_LOADING = False
        _BOOT_CV.notify_all()
    return boot


def urls_for_domain(fqdn: str, boot: Bootstrap) -> list[str]:
    """Longest suffix match against the IANA RDAP bootstrap."""
    labels = [part for part in fqdn.lower().split(".") if part]
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        found = boot.suffixes.get(suffix)
        if found:
            return found
    return []


def rdap_domain_url(base: str, fqdn: str) -> str:
    return base.rstrip("/") + "/domain/" + urllib.parse.quote(fqdn.lower(), safe=".-")


def _loads_json(raw: bytes) -> dict | None:
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def classify_rdap(status: int | None, raw: bytes) -> dict | None:
    """Return a result fragment for a definitive RDAP answer, or None if the call failed."""
    data = _loads_json(raw)
    error_code = data.get("errorCode") if data else None
    if error_code is not None:
        try:
            error_code = int(error_code)
        except (TypeError, ValueError):
            error_code = None
    if status == 404 or (status == 200 and error_code == 404):
        return {
            "status": "available",
            "method": "rdap",
            "confidence": "high",
            "detail": (
                "The registry's RDAP server has no record of this domain. "
                "That is a strong availability signal. The name can still be premium, reserved, or blocked when you try to register it."
            ),
        }
    if status == 200 and data is not None:
        if error_code:
            return None
        if data.get("objectClassName") == "domain" or data.get("ldhName"):
            statuses = [str(item) for item in (data.get("status") or []) if item][:4]
            extra = f" Registry status: {', '.join(statuses)}." if statuses else ""
            return {
                "status": "registered",
                "method": "rdap",
                "confidence": "high",
                "detail": "Registered. The registry's RDAP server returned this domain." + extra,
            }
        return None
    if status == 200 and raw and b"objectClassName" in raw and b"domain" in raw:
        return {
            "status": "registered",
            "method": "rdap",
            "confidence": "high",
            "detail": "Registered. The registry's RDAP server returned this domain.",
        }
    return None


def _rdap_failure_detail(status: int | None, err: str | None) -> str:
    if status == 429:
        return "The RDAP server rate-limited this lookup. Marked unknown, not available."
    if status in (401, 403):
        return f"The RDAP server refused the query (HTTP {status}). Marked unknown, not available."
    if status is not None and status >= 400:
        return f"The RDAP server returned HTTP {status}. Marked unknown, not available."
    if err:
        return f"The RDAP server did not respond ({err}). Marked unknown, not available."
    return "The RDAP lookup failed. Marked unknown, not available."


def check_rdap(fqdn: str, bases: list[str]) -> dict:
    last = {
        "status": "unknown",
        "method": "rdap",
        "confidence": "none",
        "detail": "The RDAP lookup failed. Marked unknown, not available.",
    }
    for base in bases[:3]:
        status, body, err = http_get(
            rdap_domain_url(base, fqdn),
            "application/rdap+json, application/json",
            RDAP_TIMEOUT,
            RDAP_RETRIES,
        )
        classified = classify_rdap(status, body)
        if classified:
            return classified
        last = {
            "status": "unknown",
            "method": "rdap",
            "confidence": "none",
            "detail": _rdap_failure_detail(status, err),
        }
        # A definitive HTTP answer that we could not classify should not be retried
        # against another base if the server clearly responded with a client error
        # other than 404 (already classified) — except 429/5xx, where another base may work.
        if status is not None and status not in (429, 500, 502, 503, 504) and err is None:
            break
    return last


def _status_code(payload: dict | None) -> int | None:
    if not payload or "Status" not in payload:
        return None
    try:
        return int(payload["Status"])
    except (TypeError, ValueError):
        return None


def _has_positive_answers(payload: dict | None) -> bool:
    if not payload:
        return False
    for answer in payload.get("Answer") or []:
        if isinstance(answer, dict) and answer.get("type") in POSITIVE_DNS_TYPES:
            return True
    return False


def query_doh(fqdn: str, record_type: str) -> dict | None:
    quoted = urllib.parse.quote(fqdn)
    endpoints = (
        f"https://cloudflare-dns.com/dns-query?name={quoted}&type={record_type}",
        f"https://dns.google/resolve?name={quoted}&type={record_type}",
    )
    for url in endpoints:
        status, body, _err = http_get(url, "application/dns-json", DNS_TIMEOUT, DNS_RETRIES)
        if status == 200 and body:
            data = _loads_json(body)
            if data is not None and "Status" in data:
                return data
    return None


def _system_dns(fqdn: str) -> dict:
    try:
        socket.getaddrinfo(fqdn, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        noname = getattr(socket, "EAI_NONAME", -2)
        nodata = getattr(socket, "EAI_NODATA", None)
        if exc.errno == noname or (nodata is not None and exc.errno == nodata):
            return {
                "status": "available",
                "method": "dns",
                "confidence": "low",
                "detail": (
                    "Public DNS-over-HTTPS did not answer. The local resolver reported no such host. "
                    "This is a weak hint, not proof the name is unregistered."
                ),
            }
        return {
            "status": "unknown",
            "method": "dns",
            "confidence": "none",
            "detail": "DNS lookup failed. Marked unknown, not available.",
        }
    except Exception:
        return {
            "status": "unknown",
            "method": "dns",
            "confidence": "none",
            "detail": "DNS lookup failed. Marked unknown, not available.",
        }
    return {
        "status": "registered",
        "method": "dns",
        "confidence": "low",
        "detail": (
            "Public DNS-over-HTTPS did not answer. The local resolver returned an address, so the name is probably in use. "
            "DNS cannot tell a normal registration apart from a wildcard or a parked name."
        ),
    }


def classify_dns(ns_payload: dict | None, address_payloads: list[dict | None]) -> dict:
    if ns_payload is None and not any(address_payloads):
        return _system_dns_placeholder()
    ns_status = _status_code(ns_payload)
    if ns_status == 3:
        return {
            "status": "available",
            "method": "dns",
            "confidence": "low",
            "detail": (
                "DNS returned NXDOMAIN: the public DNS has no such name. "
                "This is only a hint. A registered domain with no nameservers can look the same."
            ),
        }
    if _has_positive_answers(ns_payload) or any(_has_positive_answers(item) for item in address_payloads):
        return {
            "status": "registered",
            "method": "dns",
            "confidence": "medium",
            "detail": (
                "DNS has records for this name, so it is probably registered. "
                "A name can show up in DNS without being a normal registration, for example on a wildcard TLD."
            ),
        }
    statuses = []
    if ns_status is not None:
        statuses.append(ns_status)
    for item in address_payloads:
        code = _status_code(item)
        if code is not None:
            statuses.append(code)
    if any(code == 3 for code in statuses) and any(code == 0 for code in statuses):
        return {
            "status": "unknown",
            "method": "dns",
            "confidence": "none",
            "detail": "DNS answers disagreed, so this one is unknown rather than available.",
        }
    if statuses and all(code == 0 for code in statuses):
        return {
            "status": "unknown",
            "method": "dns",
            "confidence": "none",
            "detail": (
                "DNS returned no error and no records. The name might be registered without nameservers, "
                "so it is not marked available."
            ),
        }
    if any(code == 2 for code in statuses):
        return {
            "status": "unknown",
            "method": "dns",
            "confidence": "none",
            "detail": "DNS reported a server failure. Marked unknown, not available.",
        }
    return {
        "status": "unknown",
        "method": "dns",
        "confidence": "none",
        "detail": "DNS was inconclusive. Marked unknown, not available.",
    }


def _system_dns_placeholder() -> dict:
    """Sentinel handled by check_dns when every DNS-over-HTTPS query failed."""
    return {"status": "doh-failed"}


def check_dns(fqdn: str) -> dict:
    ns_payload = query_doh(fqdn, "NS")
    address_payloads: list[dict | None] = []
    if ns_payload is None or (
        _status_code(ns_payload) == 0 and not _has_positive_answers(ns_payload)
    ):
        address_payloads = [query_doh(fqdn, "A"), query_doh(fqdn, "AAAA")]
    classified = classify_dns(ns_payload, address_payloads)
    if classified.get("status") == "doh-failed":
        return _system_dns(fqdn)
    if ns_payload is None and classified["status"] == "unknown":
        system = _system_dns(fqdn)
        if system["status"] != "unknown":
            return system
    return classified


def check_fqdn(fqdn: str, boot: Bootstrap) -> dict:
    if boot.error or not boot.suffixes:
        result = check_dns(fqdn)
        result["detail"] = "No RDAP directory was available, so this used DNS only. " + result["detail"]
        return result
    bases = urls_for_domain(fqdn, boot)
    if not bases:
        result = check_dns(fqdn)
        suffix = fqdn.split(".", 1)[-1]
        result["detail"] = f"No public RDAP server is listed for .{suffix}. " + result["detail"]
        return result
    # RDAP exists. A failed RDAP call stays unknown — DNS must not turn a registry
    # outage into a false "available".
    return check_rdap(fqdn, bases)


def _cache_get(key: tuple) -> dict | None:
    now = time.time()
    with _CACHE_LOCK:
        item = _CACHE.get(key)
        if not item:
            return None
        expires, value = item
        if expires < now:
            _CACHE.pop(key, None)
            return None
        return dict(value)


def _cache_set(key: tuple, value: dict) -> None:
    ttl = 30 if value.get("status") == "unknown" else 30 * 60
    with _CACHE_LOCK:
        _CACHE[key] = (time.time() + ttl, dict(value))


def clear_memory_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def peek_bootstrap() -> Bootstrap | None:
    with _BOOT_CV:
        return _BOOT


def check_pair(ascii_name: str, display: str, tld: ParsedName, boot: Bootstrap, fresh: bool = False) -> dict:
    fqdn = f"{ascii_name}.{tld.ascii}"
    key = (ascii_name, tld.ascii)
    if not fresh:
        cached = _cache_get(key)
        if cached is not None:
            cached["display"] = display
            cached["tldDisplay"] = tld.display
            cached["cached"] = True
            return cached
    try:
        outcome = check_fqdn(fqdn, boot)
    except Exception:
        outcome = {
            "status": "unknown",
            "method": "rdap" if urls_for_domain(fqdn, boot) else "dns",
            "confidence": "none",
            "detail": "The lookup failed. Marked unknown, not available.",
        }
    result = {
        "type": "result",
        "name": ascii_name,
        "display": display,
        "tld": tld.ascii,
        "tldDisplay": tld.display,
        "fqdn": fqdn,
        "status": outcome["status"],
        "method": outcome["method"],
        "confidence": outcome["confidence"],
        "detail": outcome["detail"],
        "cached": False,
    }
    _cache_set(key, result)
    return result


def _strip_wrappers(token: str) -> str:
    text = token.strip().lower()
    text = (
        text.replace("\u3002", ".")
        .replace("\uff0e", ".")
        .replace("\uff61", ".")
        .replace("\u200b", "")
        .replace("\ufeff", "")
    )
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        text = text.split("@")[-1]
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            text = host
    return text.strip().strip(".")


def _encode_label(label: str) -> str:
    if label.startswith("xn--"):
        label.encode("ascii")
        return label
    encoded = label.encode("idna").decode("ascii")
    if not encoded:
        raise ValueError("invalid label")
    return encoded


def _decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            return label
    return label


def _valid_ascii_label(label: str) -> bool:
    if not label or len(label) > 63:
        return False
    if label.startswith("xn--"):
        rest = label[4:]
        if not rest or len(rest) > 59:
            return False
        return all(char.isalnum() or char == "-" for char in rest) and rest[0] != "-" and rest[-1] != "-"
    if label[0] == "-" or label[-1] == "-":
        return False
    return all(char.isalnum() or char == "-" for char in label)


def _suffix_length(ascii_labels: list[str]) -> int:
    tail_pairs = []
    for suffix in _MULTI_SUFFIXES:
        parts = suffix.split(".")
        tail_pairs.append(parts)
    tail_pairs.sort(key=len, reverse=True)
    for parts in tail_pairs:
        if len(ascii_labels) > len(parts) and ascii_labels[-len(parts) :] == parts:
            return len(parts)
    return 1


def extract_name(token: str) -> ParsedName:
    text = _strip_wrappers(token)
    if not text:
        raise ValueError("empty")
    if any(char.isspace() for char in text):
        raise ValueError("invalid characters")
    raw_labels = text.split(".")
    if any(not part for part in raw_labels):
        raise ValueError("invalid label")
    try:
        ascii_labels = [_encode_label(part) for part in raw_labels]
    except Exception as exc:
        raise ValueError("invalid characters") from exc
    if not all(_valid_ascii_label(part) for part in ascii_labels):
        raise ValueError("invalid label")
    if ".".join(ascii_labels) in _MULTI_SUFFIXES:
        raise ValueError("this is a suffix, not a name")
    if len(ascii_labels) == 1:
        ascii_name = ascii_labels[0]
        display = _decode_label(ascii_name) if raw_labels[0].startswith("xn--") else raw_labels[0]
        return ParsedName(ascii_name, display)
    suffix_len = _suffix_length(ascii_labels)
    if len(ascii_labels) <= suffix_len:
        raise ValueError("this is a suffix, not a name")
    index = len(ascii_labels) - suffix_len - 1
    ascii_name = ascii_labels[index]
    original = raw_labels[index]
    display = _decode_label(ascii_name) if original.startswith("xn--") else original
    return ParsedName(ascii_name, display)


def parse_tld_token(token: str) -> ParsedName:
    text = _strip_wrappers(token).lstrip(".")
    if not text:
        raise ValueError("empty")
    raw_labels = text.split(".")
    if not 1 <= len(raw_labels) <= 3 or any(not part for part in raw_labels):
        raise ValueError("invalid TLD")
    try:
        ascii_labels = [_encode_label(part) for part in raw_labels]
    except Exception as exc:
        raise ValueError("invalid TLD") from exc
    if not all(_valid_ascii_label(part) for part in ascii_labels):
        raise ValueError("invalid TLD")
    ascii_tld = ".".join(ascii_labels)
    if any(part.startswith("xn--") for part in raw_labels):
        display = ".".join(_decode_label(part) for part in ascii_labels)
    else:
        display = ".".join(raw_labels)
    return ParsedName(ascii_tld, display)


def parse_input(names_text: str, tlds_text: str) -> ParseOutcome:
    outcome = ParseOutcome()
    seen_names: set[str] = set()
    pieces = []
    for line in str(names_text or "").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for bit in _split_tokens(stripped):
            if bit.startswith("#"):
                break
            pieces.append(bit)
    for bit in pieces:
        try:
            name = extract_name(bit)
        except ValueError as exc:
            outcome.skipped.append({"value": bit[:80], "reason": str(exc)})
            continue
        if name.ascii in seen_names:
            outcome.duplicate_count += 1
            continue
        seen_names.add(name.ascii)
        outcome.names.append(name)
    seen_tlds: set[str] = set()
    for bit in _split_tokens(str(tlds_text or "")):
        if bit.startswith("#"):
            continue
        try:
            tld = parse_tld_token(bit)
        except ValueError as exc:
            outcome.skipped.append({"value": bit[:80], "reason": str(exc)})
            continue
        if tld.ascii in seen_tlds:
            continue
        seen_tlds.add(tld.ascii)
        outcome.tlds.append(tld)
    if not outcome.names:
        outcome.error = "Enter at least one name."
    elif len(outcome.names) > MAX_NAMES:
        outcome.error = f"{MAX_NAMES} names maximum per run. This list has {len(outcome.names)}. Split it and check again."
    elif not outcome.tlds:
        outcome.error = "Enter at least one TLD."
    elif len(outcome.tlds) > MAX_TLDS:
        outcome.error = f"{MAX_TLDS} TLDs maximum per run. This list has {len(outcome.tlds)}."
    return outcome


def _split_tokens(text: str) -> list[str]:
    chunks = []
    current = []
    for char in text.replace(",", " ").replace(";", " "):
        if char.isspace():
            if current:
                chunks.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        chunks.append("".join(current))
    return [chunk for chunk in chunks if chunk]


def coverage_for(tlds: list[str], boot: Bootstrap) -> dict:
    rdap = []
    dns = []
    usable = boot.suffixes and not boot.error
    for tld in tlds:
        if usable and urls_for_domain(f"example.{tld}", boot):
            rdap.append(tld)
        else:
            dns.append(tld)
    return {"rdap": rdap, "dns": dns}

