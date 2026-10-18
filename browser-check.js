/* Browser engine for the public site. Registries are queried directly from the page. */
(function () {
  const MAX_NAMES = 20000;
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
  const GLOBAL_LIMIT = 96;
  const RDAP_TIMEOUT = 1000;
  const globalLimit = makeLimiter(GLOBAL_LIMIT);
  const hostLimits = {};
  const DOH_HOST_LIMIT = { "cloudflare-dns.com": 32, "dns.google": 32, "doh.dns.sb": 32 };
  const DOH_BASES = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://doh.dns.sb/dns-query",
  ];
  let dohCursor = 0;
  const rdapFailures = {};
  let rdapSkip = {};
  try {
    const savedSkip = JSON.parse(sessionStorage.getItem("tld-checker-rdap-skip-v1") || "{}");
    if (savedSkip && typeof savedSkip === "object") rdapSkip = savedSkip;
  } catch (error) {
    rdapSkip = {};
  }
  let suffixes = null;
  let publication = null;
  let bootstrapError = null;

  function makeLimiter(max) {
    let active = 0;
    const waiting = [];
    return {
      async acquire(signal) {
        if (signal && signal.aborted) return false;
        if (active >= max) {
          const granted = await new Promise(function (resolve) {
            let settled = false;
            const entry = {
              resolve: function (value) {
                if (settled) return;
                settled = true;
                resolve(value);
              },
            };
            waiting.push(entry);
            if (signal) {
              signal.addEventListener("abort", function () {
                const index = waiting.indexOf(entry);
                if (index >= 0) waiting.splice(index, 1);
                entry.resolve(false);
              }, { once: true });
            }
          });
          if (!granted) return false;
        }
        active += 1;
        return true;
      },
      release() {
        active -= 1;
        const next = waiting.shift();
        if (next) next.resolve(true);
      },
    };
  }

  function hostLimiter(host) {
    const max = DOH_HOST_LIMIT[host] || 8;
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

  function sleep(ms, signal) {
    return new Promise(function (resolve) {
      const timer = setTimeout(done, ms);
      function done() {
        if (signal) signal.removeEventListener("abort", done);
        clearTimeout(timer);
        resolve();
      }
      if (signal) {
        if (signal.aborted) {
          done();
          return;
        }
        signal.addEventListener("abort", done, { once: true });
      }
    });
  }

  function stopped(signal) {
    return !!(signal && signal.aborted);
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

  function splitDomain(token) {
    const text = stripWrappers(token);
    if (!text) throw new Error("empty");
    if (/\s/.test(text)) throw new Error("invalid characters");
    const raw = text.split(".");
    if (raw.length < 2) throw new Error("write the extension, like si.si");
    if (raw.some(function (part) { return !part; })) throw new Error("invalid label");
    let ascii;
    try {
      ascii = raw.map(toAsciiLabel);
    } catch (error) {
      throw new Error("invalid characters");
    }
    if (!ascii.every(validAsciiLabel)) throw new Error("invalid label");
    const suffix = suffixLength(ascii);
    if (ascii.length <= suffix) throw new Error("this is a suffix, not a domain");
    const at = ascii.length - suffix - 1;
    const labelAscii = ascii[at];
    const labelRaw = raw[at];
    const labelDisplay = labelRaw.startsWith("xn--") ? decodeLabel(labelAscii) : labelRaw;
    const tldAscii = ascii.slice(at + 1).join(".");
    const tldRaw = raw.slice(at + 1);
    const tldDisplay = tldRaw.some(function (part) { return part.startsWith("xn--"); })
      ? ascii.slice(at + 1).map(decodeLabel).join(".")
      : tldRaw.join(".");
    return {
      ascii: labelAscii + "." + tldAscii,
      display: labelDisplay + "." + tldDisplay,
      checkName: labelAscii,
      tlds: [{ ascii: tldAscii, display: tldDisplay }],
    };
  }

  function parseDomains(text) {
    const names = [];
    const tlds = [];
    const skipped = [];
    let duplicateCount = 0;
    const seen = {};
    const seenTlds = {};
    String(text || "").replace(/\r/g, "\n").split("\n").forEach(function (line) {
      const stripped = line.trim();
      if (!stripped || stripped.charAt(0) === "#") return;
      const bits = splitTokens(stripped);
      for (let index = 0; index < bits.length; index += 1) {
        if (bits[index].charAt(0) === "#") break;
        try {
          const domain = splitDomain(bits[index]);
          if (seen[domain.ascii]) duplicateCount += 1;
          else {
            seen[domain.ascii] = 1;
            names.push(domain);
            domain.tlds.forEach(function (tld) {
              if (seenTlds[tld.ascii]) return;
              seenTlds[tld.ascii] = 1;
              tlds.push(tld);
            });
          }
        } catch (error) {
          skipped.push({ value: bits[index].slice(0, 80), reason: error.message });
        }
      }
    });
    let error = null;
    if (!names.length) error = "Enter at least one domain, like si.si or alpha.dev.";
    else if (names.length > MAX_NAMES) error = MAX_NAMES + " domains maximum per run. This list has " + names.length + ". Split it and check again.";
    return {
      names: names,
      tlds: tlds,
      skipped: skipped.slice(0, 40),
      skippedCount: skipped.length,
      duplicateCount: duplicateCount,
      error: error,
      manual: true,
    };
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

  async function httpGet(url, accept, timeout, retries, signal) {
    if (stopped(signal)) return { status: null, body: "", error: "AbortError" };
    const host = new URL(url).hostname || "unknown";
    const limiter = hostLimiter(host);
    const globalOk = await globalLimit.acquire(signal);
    if (!globalOk) return { status: null, body: "", error: "AbortError" };
    let hostHeld = false;
    try {
      const hostOk = await limiter.acquire(signal);
      if (!hostOk) return { status: null, body: "", error: "AbortError" };
      hostHeld = true;
      let delay = 350;
      let lastError = "request failed";
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        if (stopped(signal)) return { status: null, body: "", error: "AbortError" };
        const controller = new AbortController();
        let userStop = false;
        const onAbort = function () {
          userStop = true;
          controller.abort();
        };
        if (signal) signal.addEventListener("abort", onAbort);
        const timer = setTimeout(function () { controller.abort(); }, timeout);
        try {
          const response = await fetch(url, {
            headers: { Accept: accept },
            referrerPolicy: "no-referrer",
            signal: controller.signal,
          });
          const body = await response.text();
          if ((response.status === 429 || response.status >= 500) && attempt < retries) {
            await sleep(delay, signal);
            delay *= 2;
            continue;
          }
          return { status: response.status, body: body, error: null };
        } catch (error) {
          if (userStop || stopped(signal)) return { status: null, body: "", error: "AbortError" };
          const name = error && error.name ? error.name : "error";
          lastError = name === "AbortError" ? "TimeoutError" : name;
          if (attempt < retries) {
            await sleep(delay, signal);
            delay *= 2;
            continue;
          }
          return { status: null, body: "", error: lastError };
        } finally {
          clearTimeout(timer);
          if (signal) signal.removeEventListener("abort", onAbort);
        }
      }
      return { status: null, body: "", error: lastError };
    } finally {
      if (hostHeld) limiter.release();
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

  function rdapHost(base) {
    try { return new URL(base).host; } catch (error) { return ""; }
  }

  function saveRdapSkip() {
    try { sessionStorage.setItem("tld-checker-rdap-skip-v1", JSON.stringify(rdapSkip)); } catch (error) { /* the skip list is also kept in memory */ }
  }

  function markRdapDown(base) {
    const host = rdapHost(base);
    if (!host || rdapSkip[host]) return;
    rdapFailures[host] = (rdapFailures[host] || 0) + 1;
    if (rdapFailures[host] >= 2) {
      rdapSkip[host] = 1;
      saveRdapSkip();
    }
  }

  function markRdapUp(base) {
    const host = rdapHost(base);
    if (!host) return;
    rdapFailures[host] = 0;
    if (rdapSkip[host]) {
      delete rdapSkip[host];
      saveRdapSkip();
    }
  }

  function urlsFor(fqdn) {
    const labels = fqdn.toLowerCase().split(".").filter(Boolean);
    for (let index = 0; index < labels.length; index += 1) {
      const suffix = labels.slice(index).join(".");
      if (suffixes && suffixes[suffix]) return suffixes[suffix];
    }
    return [];
  }

  async function checkRdap(fqdn, bases, signal, timeout) {
    let last = {
      status: "unknown",
      method: "rdap",
      confidence: "none",
      detail: "The RDAP lookup failed. Marked unknown, not available.",
    };
    const path = "/domain/" + encodeURIComponent(fqdn).replace(/%2E/gi, ".");
    for (let index = 0; index < Math.min(bases.length, 1); index += 1) {
      if (stopped(signal)) return null;
      const base = bases[index].replace(/\/$/, "");
      const hit = await httpGet(base + path, "application/rdap+json, application/json", timeout || RDAP_TIMEOUT, 0, signal);
      if (hit.error === "AbortError" || stopped(signal)) return null;
      const classified = classifyRdap(hit.status, hit.body);
      if (classified) {
        markRdapUp(base);
        return classified;
      }
      if (!hit.status || hit.status === 429) markRdapDown(base);
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

  async function queryDoh(fqdn, type, signal) {
    const name = encodeURIComponent(fqdn);
    const start = dohCursor;
    dohCursor = (dohCursor + 1) % DOH_BASES.length;
    for (let step = 0; step < 2; step += 1) {
      if (stopped(signal)) return null;
      const base = DOH_BASES[(start + step) % DOH_BASES.length];
      const hit = await httpGet(base + "?name=" + name + "&type=" + type, "application/dns-json", 1400, 0, signal);
      if (hit.error === "AbortError" || stopped(signal)) return null;
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

  async function checkDns(fqdn, signal) {
    const nsPayload = await queryDoh(fqdn, "NS", signal);
    if (stopped(signal)) return null;
    let addresses = [];
    if (!nsPayload || (Number(nsPayload.Status) === 0 && !hasAnswers(nsPayload))) {
      const address = await queryDoh(fqdn, "A", signal);
      if (stopped(signal)) return null;
      addresses = address ? [address] : [];
    }
    return classifyDns(nsPayload, addresses);
  }

  async function checkOne(item, signal) {
    if (stopped(signal)) return null;
    const fqdn = item.name + "." + item.tld;
    let outcome;
    if (bootstrapError || !suffixes) {
      outcome = await checkDns(fqdn, signal);
      if (!outcome || stopped(signal)) return null;
      outcome.detail = "No RDAP directory was available, so this used DNS only. " + outcome.detail;
    } else {
      const listed = urlsFor(fqdn);
      const bases = listed.filter(function (base) { return !rdapSkip[rdapHost(base)]; }).slice(0, 1);
      if (!listed.length) {
        outcome = await checkDns(fqdn, signal);
        if (!outcome || stopped(signal)) return null;
        outcome.detail = "No public RDAP server is listed for ." + item.tld + ". " + outcome.detail;
      } else if (!bases.length) {
        outcome = await checkDns(fqdn, signal);
        if (!outcome || stopped(signal)) return null;
        outcome.detail = "This registry stopped answering, so this is a DNS hint. " + outcome.detail;
      } else {
        outcome = await checkRdap(fqdn, bases, signal, RDAP_TIMEOUT);
        if (!outcome || stopped(signal)) return null;
        if (outcome.status === "unknown") {
          const dns = await checkDns(fqdn, signal);
          if (!dns || stopped(signal)) return null;
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
      row: item.row || item.name,
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
          const result = await checkOne(item, signal);
          if (stopped(signal)) return;
          if (!result) continue;
          if (options.onResult) options.onResult(result);
        } catch (error) {
          if (stopped(signal)) return;
          if (options.onResult) {
            options.onResult({
              type: "result",
              name: item.name,
              display: item.display || item.name,
              tld: item.tld,
              tldDisplay: item.tldDisplay || item.tld,
              row: item.row || item.name,
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
    parseDomains: parseDomains,
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
