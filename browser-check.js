/* Browser engine for the public site. Registries are queried directly from the page. */
(function () {
  const MAX_NAMES = 150;
  const MAX_TLDS = 5000;
  const MULTI_SUFFIXES = [
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "org.nz", "net.nz",
    "com.br", "com.mx", "com.ar", "com.co",
    "co.jp", "or.jp", "ne.jp",
    "co.za", "org.za", "com.tr", "co.in",
    "com.cn", "com.tw", "com.hk", "com.sg",
    "co.kr", "co.id", "com.my", "com.ph", "com.vn",
    "co.th", "com.pl", "co.il", "com.pt", "com.es",
  ].sort(function (a, b) { return b.split(".").length - a.split(".").length; });
  const POSITIVE = { 1: 1, 2: 1, 5: 1, 15: 1, 16: 1, 28: 1, 33: 1, 43: 1, 65: 1 };
  const GLOBAL_LIMIT = 28;
  const globalLimit = makeLimiter(GLOBAL_LIMIT);
  const hostLimits = {};
  const DOH_HOST_LIMIT = { "cloudflare-dns.com": 10, "dns.google": 10 };
  let suffixes = null;
  let publication = null;
  let bootstrapError = null;

  function makeLimiter(max) {
    let active = 0;
    const waiting = [];
    return {
      async acquire() {
        if (active >= max) await new Promise(function (resolve) { waiting.push(resolve); });
        active += 1;
      },
      release() {
        active -= 1;
        const next = waiting.shift();
        if (next) next();
      },
    };
  }

  function hostLimiter(host) {
    const max = DOH_HOST_LIMIT[host] || 4;
    if (!hostLimits[host]) hostLimits[host] = makeLimiter(max);
    return hostLimits[host];
  }

  function interleave(groups) {
    const lanes = groups.map(function (pairs, index) {
      if (!pairs || pairs.length < 2) return (pairs || []).slice();
      const shift = index % pairs.length;
      return pairs.slice(shift).concat(pairs.slice(0, shift));
    });
    const cursors = lanes.map(function () { return 0; });
    const out = [];
    let pending = true;
    while (pending) {
      pending = false;
      for (let lane = 0; lane < lanes.length; lane += 1) {
        if (cursors[lane] >= lanes[lane].length) continue;
        out.push(lanes[lane][cursors[lane]]);
        cursors[lane] += 1;
        pending = true;
      }
    }
    return out;
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  function punyDecode(input) {
    const base = 36;
    const tMin = 1;
    const tMax = 26;
    let n = 128;
    let i = 0;
    let bias = 72;
    const output = [];
    const delim = input.lastIndexOf("-");
    let basic = delim > 0 ? delim : 0;
    for (let index = 0; index < basic; index += 1) output.push(input.charCodeAt(index));
    let index = basic ? basic + 1 : 0;
    while (index < input.length) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (index >= input.length) return input;
        const digit = input.charCodeAt(index);
        index += 1;
        let value = digit - 48;
        if (digit >= 97) value = digit - 97;
        else if (digit >= 65) value = digit - 65;
        if (value < 0 || value > 35) return input;
        i += value * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (value < t) break;
        w *= base - t;
      }
      const outLen = output.length + 1;
      bias = adapt(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      output.splice(i, 0, n);
      i += 1;
    }
    try {
      return String.fromCodePoint.apply(null, output);
    } catch (error) {
      return input;
    }
  }

  function adapt(delta, numPoints, first) {
    delta = first ? Math.floor(delta / 700) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > 455) {
      delta = Math.floor(delta / 35);
      k += 36;
    }
    return k + Math.floor((36 + 1) * delta / (delta + 38));
  }

  function toAsciiLabel(label) {
    if (label.startsWith("xn--")) return label;
    const host = new URL("http://" + label + ".com").hostname;
    return host.slice(0, -4);
  }

  function decodeLabel(label) {
    if (!label.startsWith("xn--")) return label;
    const decoded = punyDecode(label.slice(4));
    return decoded || label;
  }

  function validAsciiLabel(label) {
    if (!label || label.length > 63) return false;
    if (label.startsWith("xn--")) {
      const rest = label.slice(4);
      if (!rest || rest.length > 59 || rest[0] === "-" || rest[rest.length - 1] === "-") return false;
      return /^[a-z0-9-]+$/.test(rest);
    }
    if (label[0] === "-" || label[label.length - 1] === "-") return false;
    return /^[a-z0-9-]+$/.test(label);
  }

  function stripWrappers(token) {
    let text = String(token || "").trim().toLowerCase();
    text = text.replace(/\u3002/g, ".").replace(/\uff0e/g, ".").replace(/\uff61/g, ".").replace(/\u200b/g, "").replace(/\ufeff/g, "");
    if (text.indexOf("://") >= 0) text = text.split("://").slice(1).join("://");
    text = text.split("/")[0].split("?")[0].split("#")[0];
    if (text.indexOf("@") >= 0) text = text.split("@").pop();
    if ((text.match(/:/g) || []).length === 1) {
      const parts = text.split(":");
      if (/^\d+$/.test(parts[1])) text = parts[0];
    }
    return text.replace(/^\.+|\.+$/g, "");
  }

  function suffixLength(labels) {
    const joined = labels.join(".");
    for (let index = 0; index < MULTI_SUFFIXES.length; index += 1) {
      const suffix = MULTI_SUFFIXES[index];
      const parts = suffix.split(".");
      if (labels.length > parts.length && joined.endsWith("." + suffix)) return parts.length;
    }
    return 1;
  }

  function extractName(token) {
    const text = stripWrappers(token);
    if (!text) throw new Error("empty");
    if (/\s/.test(text)) throw new Error("invalid characters");
    const raw = text.split(".");
    if (raw.some(function (part) { return !part; })) throw new Error("invalid label");
    let ascii;
    try {
      ascii = raw.map(toAsciiLabel);
    } catch (error) {
      throw new Error("invalid characters");
    }
    if (!ascii.every(validAsciiLabel)) throw new Error("invalid label");
    if (MULTI_SUFFIXES.indexOf(ascii.join(".")) >= 0) throw new Error("this is a suffix, not a name");
    if (ascii.length === 1) {
      return { ascii: ascii[0], display: raw[0].startsWith("xn--") ? decodeLabel(ascii[0]) : raw[0] };
    }
    const suffix = suffixLength(ascii);
    if (ascii.length <= suffix) throw new Error("this is a suffix, not a name");
    const at = ascii.length - suffix - 1;
    return { ascii: ascii[at], display: raw[at].startsWith("xn--") ? decodeLabel(ascii[at]) : raw[at] };
  }

  function parseTld(token) {
    const text = stripWrappers(token).replace(/^\.+/, "");
    if (!text) throw new Error("empty");
    const raw = text.split(".");
    if (raw.length < 1 || raw.length > 3 || raw.some(function (part) { return !part; })) throw new Error("invalid TLD");
    let ascii;
    try {
      ascii = raw.map(toAsciiLabel);
    } catch (error) {
      throw new Error("invalid TLD");
    }
    if (!ascii.every(validAsciiLabel)) throw new Error("invalid TLD");
    const display = raw.some(function (part) { return part.startsWith("xn--"); })
      ? ascii.map(decodeLabel).join(".")
      : raw.join(".");
    return { ascii: ascii.join("."), display: display };
  }

  function splitTokens(text) {
    return String(text || "").replace(/[,;]/g, " ").split(/\s+/).filter(Boolean);
  }

  function parse(namesText, tldsText) {
    const names = [];
    const tlds = [];
    const skipped = [];
    let duplicateCount = 0;
    const seenNames = {};
    const seenTlds = {};
    String(namesText || "").replace(/\r/g, "\n").split("\n").forEach(function (line) {
      const stripped = line.trim();
      if (!stripped || stripped.charAt(0) === "#") return;
      const bits = splitTokens(stripped);
      for (let index = 0; index < bits.length; index += 1) {
        if (bits[index].charAt(0) === "#") break;
        try {
          const name = extractName(bits[index]);
          if (seenNames[name.ascii]) duplicateCount += 1;
          else {
            seenNames[name.ascii] = 1;
            names.push(name);
          }
        } catch (error) {
          skipped.push({ value: bits[index].slice(0, 80), reason: error.message });
        }
      }
    });
    splitTokens(tldsText).forEach(function (bit) {
      if (bit.charAt(0) === "#") return;
      try {
        const tld = parseTld(bit);
        if (seenTlds[tld.ascii]) return;
        seenTlds[tld.ascii] = 1;
        tlds.push(tld);
      } catch (error) {
        skipped.push({ value: bit.slice(0, 80), reason: error.message });
      }
    });
    let error = null;
    if (!names.length) error = "Enter at least one name.";
    else if (names.length > MAX_NAMES) error = MAX_NAMES + " names maximum per run. This list has " + names.length + ". Split it and check again.";
    else if (!tlds.length) error = "Enter at least one TLD.";
    else if (tlds.length > MAX_TLDS) error = MAX_TLDS + " TLDs maximum per run. This list has " + tlds.length + ".";
    return {
      names: names,
      tlds: tlds,
      skipped: skipped.slice(0, 40),
      skippedCount: skipped.length,
      duplicateCount: duplicateCount,
      error: error,
    };
  }

  async function httpGet(url, accept, timeout, retries) {
    const host = new URL(url).hostname || "unknown";
    const limiter = hostLimiter(host);
    await globalLimit.acquire();
    await limiter.acquire();
    try {
      let delay = 350;
      let lastError = "request failed";
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        const controller = new AbortController();
        const timer = setTimeout(function () { controller.abort(); }, timeout);
        try {
          const response = await fetch(url, {
            headers: { Accept: accept },
            referrerPolicy: "no-referrer",
            signal: controller.signal,
          });
          const body = await response.text();
          if ((response.status === 429 || response.status >= 500) && attempt < retries) {
            await sleep(delay);
            delay *= 2;
            continue;
          }
          return { status: response.status, body: body, error: null };
        } catch (error) {
          lastError = error && error.name ? error.name : "error";
          if (attempt < retries) {
            await sleep(delay);
            delay *= 2;
            continue;
          }
          return { status: null, body: "", error: lastError };
        } finally {
          clearTimeout(timer);
        }
      }
      return { status: null, body: "", error: lastError };
    } finally {
      limiter.release();
      globalLimit.release();
    }
  }

  function classifyRdap(status, body) {
    let data = null;
    try { data = body ? JSON.parse(body) : null; } catch (error) { data = null; }
    let errorCode = data && data.errorCode != null ? Number(data.errorCode) : null;
    if (status === 404 || (status === 200 && errorCode === 404)) {
      return {
        status: "available",
        method: "rdap",
        confidence: "high",
        detail: "The registry's RDAP server has no record of this domain. That is a strong availability signal. The name can still be premium, reserved, or blocked when you try to register it.",
      };
    }
    if (status === 200 && data && !errorCode && (data.objectClassName === "domain" || data.ldhName)) {
      const statuses = (data.status || []).slice(0, 4).join(", ");
      return {
        status: "registered",
        method: "rdap",
        confidence: "high",
        detail: "Registered. The registry's RDAP server returned this domain." + (statuses ? " Registry status: " + statuses + "." : ""),
      };
    }
    return null;
  }

  function urlsFor(fqdn) {
    const labels = fqdn.toLowerCase().split(".").filter(Boolean);
    for (let index = 0; index < labels.length; index += 1) {
      const suffix = labels.slice(index).join(".");
      if (suffixes && suffixes[suffix]) return suffixes[suffix];
    }
    return [];
  }

  async function checkRdap(fqdn, bases) {
    let last = {
      status: "unknown",
      method: "rdap",
      confidence: "none",
      detail: "The RDAP lookup failed. Marked unknown, not available.",
    };
    const path = "/domain/" + encodeURIComponent(fqdn).replace(/%2E/gi, ".");
    for (let index = 0; index < Math.min(bases.length, 2); index += 1) {
      const base = bases[index].replace(/\/$/, "");
      let hit = await httpGet(base + path, "application/rdap+json, application/json", 4000, 0);
      if (hit.status === 429) {
        await sleep(250);
        hit = await httpGet(base + path, "application/rdap+json, application/json", 4000, 0);
      }
      const classified = classifyRdap(hit.status, hit.body);
      if (classified) return classified;
      if (hit.status === 429) last.detail = "The RDAP server rate-limited this lookup. Marked unknown, not available.";
      else if (hit.status) last.detail = "The RDAP server returned HTTP " + hit.status + ". Marked unknown, not available.";
      else last.detail = "The RDAP server did not respond (" + (hit.error || "error") + "). Marked unknown, not available.";
      if (hit.status && [429, 500, 502, 503, 504].indexOf(hit.status) < 0) break;
    }
    return last;
  }

  function hasAnswers(payload) {
    return payload && (payload.Answer || []).some(function (answer) { return POSITIVE[answer.type]; });
  }

  async function queryDoh(fqdn, type) {
    const name = encodeURIComponent(fqdn);
    const urls = [
      "https://cloudflare-dns.com/dns-query?name=" + name + "&type=" + type,
      "https://dns.google/resolve?name=" + name + "&type=" + type,
    ];
    for (let index = 0; index < urls.length; index += 1) {
      const hit = await httpGet(urls[index], "application/dns-json", 3500, 0);
      if (hit.status === 200 && hit.body) {
        try {
          const data = JSON.parse(hit.body);
          if (data && data.Status != null) return data;
        } catch (error) { /* try the next resolver */ }
      }
    }
    return null;
  }

  function classifyDns(nsPayload, addresses) {
    if (!nsPayload && !addresses.some(Boolean)) {
      return { status: "unknown", method: "dns", confidence: "none", detail: "DNS lookup failed. Marked unknown, not available." };
    }
    if (nsPayload && Number(nsPayload.Status) === 3) {
      return {
        status: "available",
        method: "dns",
        confidence: "low",
        detail: "DNS returned NXDOMAIN: the public DNS has no such name. This is only a hint. A registered domain with no nameservers can look the same.",
      };
    }
    if (hasAnswers(nsPayload) || addresses.some(hasAnswers)) {
      return {
        status: "registered",
        method: "dns",
        confidence: "medium",
        detail: "DNS has records for this name, so it is probably registered. A name can show up in DNS without being a normal registration, for example on a wildcard TLD.",
      };
    }
    return {
      status: "unknown",
      method: "dns",
      confidence: "none",
      detail: "DNS was inconclusive. Marked unknown, not available.",
    };
  }

  async function checkDns(fqdn) {
    const nsPayload = await queryDoh(fqdn, "NS");
    let addresses = [];
    if (!nsPayload || (Number(nsPayload.Status) === 0 && !hasAnswers(nsPayload))) {
      addresses = [await queryDoh(fqdn, "A"), await queryDoh(fqdn, "AAAA")];
    }
    return classifyDns(nsPayload, addresses);
  }

  async function checkOne(item) {
    const fqdn = item.name + "." + item.tld;
    let outcome;
    if (bootstrapError || !suffixes) {
      outcome = await checkDns(fqdn);
      outcome.detail = "No RDAP directory was available, so this used DNS only. " + outcome.detail;
    } else {
      const bases = urlsFor(fqdn);
      if (!bases.length) {
        outcome = await checkDns(fqdn);
        outcome.detail = "No public RDAP server is listed for ." + item.tld + ". " + outcome.detail;
      } else {
        outcome = await checkRdap(fqdn, bases);
        if (outcome.status === "unknown") {
          const dns = await checkDns(fqdn);
          if (dns.status === "unknown") {
            dns.detail = "The registry did not answer, and DNS failed too. Marked unknown, not available.";
          } else {
            dns.detail = "The registry did not answer, so this is a DNS hint. " + dns.detail;
          }
          outcome = dns;
        }
      }
    }
    return {
      type: "result",
      name: item.name,
      display: item.display || item.name,
      tld: item.tld,
      tldDisplay: item.tldDisplay || item.tld,
      fqdn: fqdn,
      status: outcome.status,
      method: outcome.method,
      confidence: outcome.confidence,
      detail: outcome.detail,
      cached: false,
    };
  }

  async function loadDefaults() {
    const response = await fetch("tld_presets.json", { referrerPolicy: "no-referrer" });
    if (!response.ok) throw new Error("preset list");
    const presets = await response.json();
    return { presets: presets, defaultPreset: "all", text: (presets.all || []).join("\n") };
  }

  async function loadBootstrap() {
    const hit = await httpGet("https://data.iana.org/rdap/dns.json", "application/json", 20000, 1);
    suffixes = {};
    if (hit.status !== 200 || !hit.body) {
      bootstrapError = "Could not download the IANA RDAP directory.";
      return { suffixes: [], publication: null, error: bootstrapError, count: 0 };
    }
    try {
      const data = JSON.parse(hit.body);
      (data.services || []).forEach(function (entry) {
        if (!entry || entry.length !== 2) return;
        const https = (entry[1] || []).filter(function (url) { return String(url).indexOf("https://") === 0; });
        const http = (entry[1] || []).filter(function (url) { return String(url).indexOf("http://") === 0; });
        const urls = https.length ? https : http;
        if (!urls.length) return;
        (entry[0] || []).forEach(function (tld) { suffixes[String(tld).toLowerCase()] = urls; });
      });
      publication = data.publication || null;
      bootstrapError = null;
    } catch (error) {
      suffixes = {};
      bootstrapError = "IANA RDAP directory was not valid JSON.";
    }
    return {
      suffixes: Object.keys(suffixes),
      publication: publication,
      error: bootstrapError,
      count: Object.keys(suffixes).length,
    };
  }

  async function checkAll(checks, options) {
    const signal = options.signal;
    if (options.onMeta) {
      options.onMeta({
        type: "meta",
        total: checks.length,
        publication: publication,
        bootstrapError: bootstrapError,
      });
    }
    let cursor = 0;
    const workers = Math.min(GLOBAL_LIMIT, Math.max(1, checks.length));
    async function worker() {
      while (cursor < checks.length) {
        if (signal && signal.aborted) return;
        const item = checks[cursor];
        cursor += 1;
        try {
          const result = await checkOne(item);
          if (options.onResult) options.onResult(result);
        } catch (error) {
          if (options.onResult) {
            options.onResult({
              type: "result",
              name: item.name,
              display: item.display || item.name,
              tld: item.tld,
              tldDisplay: item.tldDisplay || item.tld,
              fqdn: item.name + "." + item.tld,
              status: "unknown",
              method: "rdap",
              confidence: "none",
              detail: "The lookup failed. Marked unknown, not available.",
              cached: false,
            });
          }
        }
      }
    }
    await Promise.all(Array.from({ length: workers }, worker));
  }

  const api = {
    parse: parse,
    loadDefaults: loadDefaults,
    loadBootstrap: loadBootstrap,
    checkAll: checkAll,
    interleave: interleave,
    punyDecode: punyDecode,
    extractName: extractName,
  };
  const root = typeof globalThis !== "undefined" ? globalThis : window;
  root.TldBrowser = api;
})();
