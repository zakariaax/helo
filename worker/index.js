const COOKIE = "helo_session";
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 8000;
const USER_COLUMNS = "id, username, contact_email AS email, name, role, daily_limit, password_hash, password_salt";
const DEFAULT_THEME = {
  accent: "#00a76f",
  bg: "#ffffff",
  ink: "#1c252e",
  card: "#ffffff",
  muted: "#637381",
  line: "#dfe3e8",
  muted: "#637381",
  line: "#dfe3e8",
  fontSize: 15,
  font: "Public Sans",
  heading: "Public Sans",
  radius: 16,
  glow: false,
  density: "comfortable",
};
const FONT_NAMES = ["Public Sans", "Inter", "DM Sans", "Nunito Sans"];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/")) return await handleApi(request, env, url);
      if (url.pathname === "/check") return await serveCheck(request, env);
      if (url.pathname === "/" || url.pathname === "/index.html") return serveHtml(request, env);
      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(error);
      return json({ error: "Something went wrong." }, 500);
    }
  },
};

async function handleApi(request, env, url) {
  const path = url.pathname;
  if (request.method === "POST" && path === "/api/signup") return signup(request, env);
  if (request.method === "POST" && path === "/api/login") return login(request, env);
  if (request.method === "POST" && path === "/api/logout") return logout(request, env);
  if (request.method === "GET" && path === "/api/me") return me(request, env);
  if (request.method === "POST" && path === "/api/password") return changePassword(request, env);

  const user = await currentUser(request, env);
  if (!user) return json({ error: "Sign in first." }, 401);

  if (request.method === "POST" && path === "/api/profile") return updateProfile(request, env, user);
  if (request.method === "POST" && path === "/api/usage") return reserveUsage(request, env, user);
  if (request.method === "POST" && path === "/api/site") return siteStatus(request, env, user);
  if (request.method === "GET" && path === "/api/stats") return stats(env, user);
  if (request.method === "GET" && path === "/api/lists") return listLists(env, user);
  if (request.method === "POST" && path === "/api/lists") return createList(request, env, user);
  const listMatch = path.match(/^\/api\/lists\/([0-9a-f-]{36})$/);
  if (listMatch && request.method === "GET") return getList(env, user, listMatch[1]);
  if (listMatch && request.method === "DELETE") return deleteList(env, user, listMatch[1]);

  if (path === "/api/admin/settings" && request.method === "POST") return adminSettings(request, env, user);
  if (path === "/api/admin/users" && request.method === "GET") return adminUsers(env, user);
  if (path === "/api/admin/users" && request.method === "POST") return adminCreateUser(request, env, user);
  const userMatch = path.match(/^\/api\/admin\/users\/([0-9a-f-]{36})$/);
  if (userMatch && request.method === "POST") return adminUpdateUser(request, env, user, userMatch[1]);

  return json({ error: "Not found." }, 404);
}

async function signup(request, env) {
  const body = await readBody(request);
  const username = cleanUsername(body.username || body.email);
  const email = cleanEmail(body.contactEmail || "");
  const name = cleanName(body.name, username);
  const password = String(body.password || "");
  const usernameError = validateUsername(username);
  if (usernameError) return json({ error: usernameError }, 400);
  if (email) {
    const emailError = validateEmail(email);
    if (emailError) return json({ error: emailError }, 400);
  }
  if (!name) return json({ error: "Write your name." }, 400);
  const passwordError = validatePassword(password);
  if (passwordError) return json({ error: passwordError }, 400);

  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
  const role = Number(count?.n || 0) === 0 ? "admin" : "user";
  const created = await insertUser(env, { username, email, name, password, role, dailyLimit: null });
  if (created.error) return json({ error: created.error }, created.status);
  return sessionResponse(request, env, created.user, { user: publicUser(created.user) }, 201);
}

async function login(request, env) {
  const body = await readBody(request);
  const key = cleanUsername(body.username || body.email);
  const password = String(body.password || "");
  const row = await env.DB.prepare(
    `SELECT ${USER_COLUMNS} FROM users WHERE username = ? OR contact_email = ?`
  ).bind(key, key).first();
  if (!row || !(await verifyPassword(password, row.password_salt, row.password_hash))) {
    return json({ error: "Username or password is wrong." }, 401);
  }
  return sessionResponse(request, env, row, { user: publicUser(row) });
}

async function logout(request, env) {
  const token = readCookie(request, COOKIE);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
  }
  return json({ ok: true }, 200, clearCookie(request));
}

async function me(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ user: null }, 200);
  const lists = await env.DB.prepare("SELECT COUNT(*) AS n FROM lists WHERE user_id = ?").bind(user.id).first();
  const settings = await getSettings(env);
  const quota = await quotaFor(env, user, settings.dailyLimit);
  return json({
    user: publicUser(user),
    listCount: Number(lists?.n || 0),
    quota,
    workspaceLimit: settings.dailyLimit,
    theme: settings.theme,
  });
}

async function updateProfile(request, env, user) {
  const body = await readBody(request);
  const name = cleanName(body.name, user.username);
  const email = cleanEmail(body.email);
  if (!name) return json({ error: "Write your name." }, 400);
  if (email) {
    const emailError = validateEmail(email);
    if (emailError) return json({ error: emailError }, 400);
    const taken = await env.DB.prepare("SELECT id FROM users WHERE contact_email = ? AND id != ?").bind(email, user.id).first();
    if (taken) return json({ error: "That email is already used." }, 409);
  }
  await env.DB.prepare("UPDATE users SET name = ?, contact_email = ? WHERE id = ?").bind(name, email || null, user.id).run();
  const row = await env.DB.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).bind(user.id).first();
  return json({ user: publicUser(row) });
}

async function changePassword(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: "Sign in first." }, 401);
  const body = await readBody(request);
  const current = String(body.current || "");
  const next = String(body.next || "");
  const row = await env.DB.prepare("SELECT password_hash, password_salt FROM users WHERE id = ?").bind(user.id).first();
  if (!row || !(await verifyPassword(current, row.password_salt, row.password_hash))) {
    return json({ error: "The current password is wrong." }, 401);
  }
  const passwordError = validatePassword(next);
  if (passwordError) return json({ error: passwordError }, 400);
  const salt = randomSalt();
  const passwordHash = await hashPassword(next, salt);
  await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?").bind(passwordHash, salt, user.id).run();
  return json({ ok: true });
}

async function reserveUsage(request, env, user) {
  const body = await readBody(request);
  const count = Math.floor(Number(body.count));
  if (!Number.isFinite(count) || count < 1 || count > 20000) return json({ error: "That check size is not valid." }, 400);
  const charged = await chargeUsage(env, user, count);
  if (!charged.ok) return json(charged.body, charged.status);
  return json(charged.quota);
}

async function chargeUsage(env, user, count) {
  const settings = await getSettings(env);
  const quota = await quotaFor(env, user, settings.dailyLimit);
  if (quota.unlimited) return { ok: true, quota: { ...quota, reserved: count } };
  if (quota.used + count > quota.limit) {
    return {
      ok: false,
      status: 429,
      body: {
        error: "Daily limit reached. " + quota.used + " of " + quota.limit + " name checks used today.",
        ...quota,
      },
    };
  }
  await env.DB.prepare(
    `INSERT INTO usage_days (user_id, day, checks) VALUES (?, ?, ?)
     ON CONFLICT(user_id, day) DO UPDATE SET checks = checks + excluded.checks`
  ).bind(user.id, utcDay(), count).run();
  const next = await quotaFor(env, user, settings.dailyLimit);
  return { ok: true, quota: { ...next, reserved: count } };
}

const PARK_NS = [
  "sedoparking.com", "sedo.com", "dan.com", "afternic.com", "afternicdns.com", "bodis.com",
  "parkingcrew.net", "above.com", "cashparking.com", "hugedomains.com", "undeveloped.com",
  "namebright.com", "smartname.com", "dsredirection.com", "fastpark.net", "parklogic.com",
  "skenzo.com", "internettraffic.com", "rookdns.com", "namedrive.com", "domainnamesales.com",
  "uniregistrymarket.link", "dnsparking.com", "parkingpage.com", "sav.com", "buydomains.com",
];
const SALE_HOSTS = [
  "dan.com", "sedo.com", "afternic.com", "hugedomains.com", "undeveloped.com", "atom.com",
  "bodis.com", "above.com", "buydomains.com", "domainmarket.com", "namebright.com", "sav.com",
];
const SALE_PHRASES = [
  "domain for sale", "this domain is for sale", "domain name for sale", "buy this domain",
  "domain may be for sale", "this domain may be for sale", "purchase this domain",
  "inquire about this domain", "this webpage is parked", "domain is parked",
  "parked free, courtesy of godaddy", "is available for purchase",
];
const SITE_UA = "Mozilla/5.0 (compatible; HeloSiteCheck/1.0)";
let rdapDirectory = null;
let rdapDirectoryAt = 0;

async function siteStatus(request, env, user) {
  const body = await readBody(request);
  const domain = cleanDomain(body.domain);
  if (!domain) return json({ error: "Write a domain like example.com." }, 400);
  const charged = await chargeUsage(env, user, 1);
  if (!charged.ok) return json(charged.body, charged.status);
  try {
    const result = await inspectDomain(domain);
    return json({ ...result, quota: charged.quota });
  } catch (error) {
    return json({
      domain,
      tld: extensionOf(domain),
      registered: null,
      kind: "unknown",
      detail: "The check did not finish.",
      sale: "",
      quota: charged.quota,
    });
  }
}

async function inspectDomain(domain) {
  const tld = extensionOf(domain);
  const registered = await registrationStatus(domain);
  const dns = await websiteDns(domain);
  const page = registered === false ? null : await openHome(domain);
  const judged = classifySite({ registered, dns, page });
  return { domain, tld, registered, kind: judged.kind, detail: judged.detail, sale: judged.sale || "" };
}

function classifySite({ registered, dns, page }) {
  if (registered === false) return { kind: "available", detail: "The registry has no record of this domain." };
  const salePage = page && page.sale;
  if (salePage || (dns.parked && !(page && page.live))) {
    const where = salePage || dns.parkedName || "a for-sale host";
    return { kind: "for-sale", sale: where, detail: "Registered, and the page is for sale (" + where + ")." };
  }
  if (page && page.live) {
    return {
      kind: "live",
      detail: registered === true ? "Registered, and a website answered." : "A website answered. The registry did not confirm the name.",
    };
  }
  if (registered === true) {
    return {
      kind: "offline",
      detail: dns.hasAddress ? "Registered, but the site did not open." : "Registered, with no website address.",
    };
  }
  return { kind: "unknown", detail: "The registry and the site did not give a clear answer." };
}

async function registrationStatus(domain) {
  const directory = await rdapBootstrap();
  const base = directory ? rdapBaseFor(directory, domain) : "";
  if (!base) return null;
  try {
    const response = await fetch(base.replace(/\/$/, "") + "/domain/" + domain, {
      headers: { accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(5000),
      redirect: "follow",
    });
    if (response.status === 404) return false;
    if (response.status === 200) return true;
  } catch (error) {
    return null;
  }
  return null;
}

async function rdapBootstrap() {
  if (rdapDirectory && Date.now() - rdapDirectoryAt < 6 * 60 * 60 * 1000) return rdapDirectory;
  try {
    const response = await fetch("https://data.iana.org/rdap/dns.json", {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return rdapDirectory;
    rdapDirectory = await response.json();
    rdapDirectoryAt = Date.now();
  } catch (error) {
    return rdapDirectory;
  }
  return rdapDirectory;
}

function rdapBaseFor(directory, domain) {
  let best = "";
  let bestLen = -1;
  for (const service of directory.services || []) {
    const names = service[0] || [];
    const urls = service[1] || [];
    for (const name of names) {
      const suffix = String(name || "").toLowerCase();
      if ((domain === suffix || domain.endsWith("." + suffix)) && suffix.length > bestLen && urls[0]) {
        best = urls[0];
        bestLen = suffix.length;
      }
    }
  }
  return best;
}

async function websiteDns(domain) {
  const [address, quadA, cname, names] = await Promise.all([
    dnsAnswers(domain, "A"),
    dnsAnswers(domain, "AAAA"),
    dnsAnswers(domain, "CNAME"),
    dnsAnswers(domain, "NS"),
  ]);
  const parkedName = names.map((row) => String(row.data || "").replace(/\.$/, "").toLowerCase()).find((host) => hostMatches(host, PARK_NS)) || "";
  return {
    hasAddress: address.length + quadA.length + cname.length > 0,
    parked: Boolean(parkedName),
    parkedName,
  };
}

async function dnsAnswers(name, type) {
  try {
    const response = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(4000),
    });
    if (!response.ok) return [];
    const data = await response.json();
    if (data.Status !== 0) return [];
    if (data.Answer && data.Answer.length) return data.Answer;
    return type === "NS" ? (data.Authority || []).filter((row) => row.type === 2) : [];
  } catch (error) {
    return [];
  }
}

async function openHome(domain) {
  const hosts = domain.startsWith("www.") ? [domain] : [domain, "www." + domain];
  for (const host of hosts) {
    for (const scheme of ["https", "http"]) {
      try {
        const response = await fetch(scheme + "://" + host + "/", {
          redirect: "follow",
          signal: AbortSignal.timeout(5000),
          headers: { "user-agent": SITE_UA, accept: "text/html,application/xhtml+xml" },
        });
        const text = await readLimited(response, 24000);
        const finalHost = new URL(response.url).hostname.toLowerCase();
        const sale = saleSignal(finalHost, text);
        const live = response.status > 0 && response.status < 400 && text.length > 80 && !sale;
        if (sale || live) return { live, sale, status: response.status };
      } catch (error) {
        continue;
      }
    }
  }
  return null;
}

function saleSignal(host, text) {
  if (hostMatches(host, SALE_HOSTS)) return host;
  const sample = String(text || "").toLowerCase();
  const phrase = SALE_PHRASES.find((item) => sample.includes(item));
  return phrase || "";
}

async function readLimited(response, max) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < max) {
    const step = await reader.read();
    if (step.done) break;
    chunks.push(step.value);
    size += step.value.length;
  }
  try { await reader.cancel(); } catch (error) { /* already finished */ }
  const bytes = new Uint8Array(Math.min(size, max));
  let offset = 0;
  for (const chunk of chunks) {
    const take = Math.min(chunk.length, bytes.length - offset);
    bytes.set(chunk.subarray(0, take), offset);
    offset += take;
    if (offset >= bytes.length) break;
  }
  return new TextDecoder().decode(bytes);
}

function hostMatches(host, list) {
  const name = String(host || "").toLowerCase().replace(/\.$/, "");
  return list.some((item) => name === item || name.endsWith("." + item));
}

function extensionOf(domain) {
  const parts = domain.split(".");
  if (parts.length >= 3 && ["co", "com", "org", "net", "ac"].includes(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {
    return parts.slice(-2).join(".");
  }
  return parts[parts.length - 1] || "";
}

function cleanDomain(value) {
  let text = String(value || "").trim().toLowerCase();
  text = text.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (text.startsWith("www.")) text = text.slice(4);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(text)) return "";
  return text;
}

function lastDays(count) {
  const out = [];
  const now = Date.now();
  for (let i = count - 1; i >= 0; i -= 1) out.push(new Date(now - i * 86400000).toISOString().slice(0, 10));
  return out;
}

function sumDays(rows, days) {
  const wanted = new Set(days);
  return rows.reduce((total, row) => total + (wanted.has(row.day) ? Number(row.checks || 0) : 0), 0);
}

async function stats(env, user) {
  const days = lastDays(14);
  const prev = lastDays(28);
  const last7 = days.slice(7);
  const prev7 = prev.slice(14, 21);
  const settings = await getSettings(env);
  const quota = await quotaFor(env, user, settings.dailyLimit);
  const mine = (await env.DB.prepare("SELECT day, checks FROM usage_days WHERE user_id = ? AND day >= ?").bind(user.id, prev[0]).all()).results || [];
  const total = await env.DB.prepare("SELECT COALESCE(SUM(checks), 0) AS n, COUNT(*) AS d FROM usage_days WHERE user_id = ? AND checks > 0").bind(user.id).first();
  const lists = (await env.DB.prepare(
    `SELECT id, title, mode, target, updated_at,
            CASE WHEN trim(names) = '' THEN 0 ELSE length(trim(names)) - length(replace(trim(names), char(10), '')) + 1 END AS name_count
     FROM lists WHERE user_id = ? ORDER BY updated_at DESC`
  ).bind(user.id).all()).results || [];
  const byDay = Object.fromEntries(mine.map((row) => [row.day, Number(row.checks || 0)]));
  const payload = {
    today: utcDay(),
    quota,
    series: days.map((day) => ({ day, checks: byDay[day] || 0 })),
    totals: {
      allTime: Number(total?.n || 0),
      activeDays: Number(total?.d || 0),
      last7: sumDays(mine, last7),
      prev7: sumDays(mine, prev7),
      last14: sumDays(mine, days),
    },
    lists: {
      count: lists.length,
      names: lists.reduce((n, row) => n + Number(row.name_count || 0), 0),
      bulk: lists.filter((row) => row.mode !== "manual").length,
      manual: lists.filter((row) => row.mode === "manual").length,
      recent: lists.slice(0, 5).map((row) => ({ id: row.id, title: row.title, mode: row.mode, target: row.target, updatedAt: row.updated_at, names: Number(row.name_count || 0) })),
    },
  };
  if (user.role === "admin") {
    const people = await env.DB.prepare(
      "SELECT COUNT(*) AS n, SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) AS admins, SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS fresh FROM users"
    ).bind(Date.now() - 7 * 86400000).first();
    const everyone = (await env.DB.prepare("SELECT day, SUM(checks) AS checks, COUNT(DISTINCT user_id) AS people FROM usage_days WHERE day >= ? AND checks > 0 GROUP BY day").bind(days[0]).all()).results || [];
    const top = (await env.DB.prepare(
      `SELECT users.id, users.username, users.name, SUM(usage_days.checks) AS checks
       FROM usage_days JOIN users ON users.id = usage_days.user_id
       WHERE usage_days.day >= ? GROUP BY users.id ORDER BY checks DESC LIMIT 5`
    ).bind(last7[0]).all()).results || [];
    const savedLists = await env.DB.prepare("SELECT COUNT(*) AS n FROM lists").first();
    const all = Object.fromEntries(everyone.map((row) => [row.day, row]));
    payload.workspace = {
      users: Number(people?.n || 0),
      admins: Number(people?.admins || 0),
      newUsers7d: Number(people?.fresh || 0),
      activeToday: Number(all[utcDay()]?.people || 0),
      checksToday: Number(all[utcDay()]?.checks || 0),
      lists: Number(savedLists?.n || 0),
      dailyLimit: settings.dailyLimit,
      series: days.map((day) => ({ day, checks: Number(all[day]?.checks || 0), people: Number(all[day]?.people || 0) })),
      top: top.map((row) => ({ name: row.name || row.username, username: row.username, checks: Number(row.checks || 0) })),
    };
  }
  return json(payload);
}

async function listLists(env, user) {
  const result = await env.DB.prepare(
    "SELECT id, title, mode, target, updated_at, length(names) AS names_length FROM lists WHERE user_id = ? ORDER BY updated_at DESC"
  ).bind(user.id).all();
  return json({ lists: result.results || [] });
}

async function createList(request, env, user) {
  const body = await readBody(request);
  const parsed = parseList(body);
  if (parsed.error) return json({ error: parsed.error }, 400);
  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO lists (id, user_id, title, names, tlds, mode, target, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, user.id, parsed.title, parsed.names, parsed.tlds, parsed.mode, parsed.target, now).run();
  return json({ list: { id, title: parsed.title, mode: parsed.mode, target: parsed.target, updated_at: now } }, 201);
}

async function getList(env, user, id) {
  const row = await env.DB.prepare(
    "SELECT id, title, names, tlds, mode, target, updated_at FROM lists WHERE id = ? AND user_id = ?"
  ).bind(id, user.id).first();
  if (!row) return json({ error: "That list was not found." }, 404);
  return json({ list: row });
}

async function deleteList(env, user, id) {
  const result = await env.DB.prepare("DELETE FROM lists WHERE id = ? AND user_id = ?").bind(id, user.id).run();
  if (!result.meta?.changes) return json({ error: "That list was not found." }, 404);
  return json({ ok: true });
}

async function adminSettings(request, env, actor) {
  if (actor.role !== "admin") return json({ error: "Only an admin can change workspace settings." }, 403);
  const body = await readBody(request);
  const current = await getSettings(env);
  const dailyLimit = body.dailyLimit == null ? current.dailyLimit : parseLimit(body.dailyLimit);
  if (dailyLimit == null) return json({ error: "Daily limit must be a whole number from 0 to 100000." }, 400);
  const theme = cleanTheme(body.theme || current.theme);
  await env.DB.prepare("INSERT INTO app_settings (key, value) VALUES ('daily_limit', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(String(dailyLimit)).run();
  await env.DB.prepare("INSERT INTO app_settings (key, value) VALUES ('theme', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(JSON.stringify(theme)).run();
  return json({ workspaceLimit: dailyLimit, theme });
}

async function adminUsers(env, user) {
  if (user.role !== "admin") return json({ error: "Only an admin can see users." }, 403);
  const day = utcDay();
  const result = await env.DB.prepare(
    `SELECT users.id, users.username, users.contact_email AS email, users.name, users.role, users.daily_limit, users.created_at,
            COALESCE(usage_days.checks, 0) AS used_today
     FROM users
     LEFT JOIN usage_days ON usage_days.user_id = users.id AND usage_days.day = ?
     ORDER BY users.created_at ASC`
  ).bind(day).all();
  const settings = await getSettings(env);
  return json({
    users: (result.results || []).map(publicUser),
    workspaceLimit: settings.dailyLimit,
    theme: settings.theme,
  });
}

async function adminCreateUser(request, env, actor) {
  if (actor.role !== "admin") return json({ error: "Only an admin can add users." }, 403);
  const body = await readBody(request);
  const username = cleanUsername(body.username);
  const email = cleanEmail(body.email);
  const name = cleanName(body.name, username);
  const role = body.role === "admin" ? "admin" : "user";
  const password = String(body.password || "");
  const usernameError = validateUsername(username);
  if (usernameError) return json({ error: usernameError }, 400);
  if (!name) return json({ error: "Write a name." }, 400);
  if (email) {
    const emailError = validateEmail(email);
    if (emailError) return json({ error: emailError }, 400);
  }
  const passwordError = validatePassword(password);
  if (passwordError) return json({ error: passwordError }, 400);
  const dailyLimit = body.dailyLimit == null || body.dailyLimit === "" ? null : parseLimit(body.dailyLimit);
  if (body.dailyLimit != null && body.dailyLimit !== "" && dailyLimit == null) {
    return json({ error: "Daily limit must be a whole number from 0 to 100000." }, 400);
  }
  const created = await insertUser(env, { username, email, name, password, role, dailyLimit });
  if (created.error) return json({ error: created.error }, created.status);
  return json({ user: publicUser(created.user) }, 201);
}

async function adminUpdateUser(request, env, actor, id) {
  if (actor.role !== "admin") return json({ error: "Only an admin can change users." }, 403);
  const body = await readBody(request);
  const target = await env.DB.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).bind(id).first();
  if (!target) return json({ error: "That user was not found." }, 404);
  const username = body.username == null ? target.username : cleanUsername(body.username);
  const email = body.email == null ? (target.email || "") : cleanEmail(body.email);
  const name = body.name == null ? target.name : cleanName(body.name, username);
  const role = body.role == null ? target.role : body.role === "admin" ? "admin" : body.role === "user" ? "user" : "";
  const usernameError = validateUsername(username);
  if (usernameError) return json({ error: usernameError }, 400);
  if (!name) return json({ error: "Write a name." }, 400);
  if (!role) return json({ error: "Role must be admin or user." }, 400);
  if (email) {
    const emailError = validateEmail(email);
    if (emailError) return json({ error: emailError }, 400);
  }
  let dailyLimit = target.daily_limit == null ? null : Number(target.daily_limit);
  if (body.dailyLimit != null) {
    dailyLimit = body.dailyLimit === "" ? null : parseLimit(body.dailyLimit);
    if (body.dailyLimit !== "" && dailyLimit == null) return json({ error: "Daily limit must be a whole number from 0 to 100000." }, 400);
  }
  if (target.role === "admin" && role === "user") {
    const admins = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").first();
    if (Number(admins?.n || 0) <= 1) return json({ error: "The last admin has to stay an admin." }, 400);
  }
  const usernameTaken = await env.DB.prepare("SELECT id FROM users WHERE username = ? AND id != ?").bind(username, id).first();
  if (usernameTaken) return json({ error: "That username is taken." }, 409);
  if (email) {
    const emailTaken = await env.DB.prepare("SELECT id FROM users WHERE contact_email = ? AND id != ?").bind(email, id).first();
    if (emailTaken) return json({ error: "That email is already used." }, 409);
  }
  await env.DB.prepare(
    "UPDATE users SET username = ?, email = ?, contact_email = ?, name = ?, role = ?, daily_limit = ? WHERE id = ?"
  ).bind(username, username, email || null, name, role, dailyLimit, id).run();
  const row = await env.DB.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).bind(id).first();
  return json({ user: publicUser(row) });
}

async function insertUser(env, fields) {
  const usernameTaken = await env.DB.prepare("SELECT id FROM users WHERE username = ? OR email = ?").bind(fields.username, fields.username).first();
  if (usernameTaken) return { error: "That username is taken.", status: 409 };
  if (fields.email) {
    const emailTaken = await env.DB.prepare("SELECT id FROM users WHERE contact_email = ?").bind(fields.email).first();
    if (emailTaken) return { error: "That email is already used.", status: 409 };
  }
  const id = crypto.randomUUID();
  const salt = randomSalt();
  const passwordHash = await hashPassword(fields.password, salt);
  await env.DB.prepare(
    `INSERT INTO users (id, email, username, contact_email, name, password_hash, password_salt, role, daily_limit, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, fields.username, fields.username, fields.email || null, fields.name, passwordHash, salt, fields.role, fields.dailyLimit, Date.now()).run();
  const user = await env.DB.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).bind(id).first();
  return { user };
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email || "",
    name: user.name,
    role: user.role,
    dailyLimit: user.daily_limit == null || user.daily_limit === "" ? null : Number(user.daily_limit),
    usedToday: user.used_today == null ? undefined : Number(user.used_today),
    created_at: user.created_at,
  };
}

async function quotaFor(env, user, workspaceLimit) {
  const day = utcDay();
  const row = await env.DB.prepare("SELECT checks FROM usage_days WHERE user_id = ? AND day = ?").bind(user.id, day).first();
  const used = Number(row?.checks || 0);
  if (user.role === "admin") return { used, limit: null, unlimited: true, remaining: null };
  const limit = user.daily_limit == null ? workspaceLimit : Number(user.daily_limit);
  return { used, limit, unlimited: false, remaining: Math.max(0, limit - used) };
}

async function getSettings(env) {
  const rows = await env.DB.prepare("SELECT key, value FROM app_settings WHERE key IN ('daily_limit', 'theme')").all();
  const found = Object.fromEntries((rows.results || []).map((row) => [row.key, row.value]));
  const parsedLimit = parseLimit(found.daily_limit == null ? 100 : found.daily_limit);
  let theme = DEFAULT_THEME;
  try {
    theme = cleanTheme(found.theme ? JSON.parse(found.theme) : DEFAULT_THEME);
  } catch (error) {
    theme = DEFAULT_THEME;
  }
  return { dailyLimit: parsedLimit == null ? 100 : parsedLimit, theme };
}

function parseLimit(value) {
  if (typeof value === "string" && value.trim() === "") return null;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > 100000) return null;
  return number;
}

function cleanTheme(input) {
  const theme = { ...DEFAULT_THEME };
  const source = input && typeof input === "object" ? input : {};
  for (const key of ["accent", "bg", "ink", "card", "muted", "line"]) {
    if (typeof source[key] === "string" && /^#[0-9a-fA-F]{6}$/.test(source[key])) theme[key] = source[key].toLowerCase();
  }
  const size = Number(source.fontSize);
  if (Number.isInteger(size) && size >= 13 && size <= 22) theme.fontSize = size;
  const radius = Number(source.radius);
  if (Number.isInteger(radius) && radius >= 8 && radius <= 28) theme.radius = radius;
  if (FONT_NAMES.includes(source.font)) theme.font = source.font;
  if (FONT_NAMES.includes(source.heading)) theme.heading = source.heading;
  if (source.glow === false) theme.glow = false;
  if (source.glow === true) theme.glow = true;
  theme.density = source.density === "compact" ? "compact" : "comfortable";
  return theme;
}

function utcDay() {
  return new Date().toISOString().slice(0, 10);
}

function parseList(body) {
  const title = String(body.title || "").trim().slice(0, 80);
  const names = String(body.names || "");
  const tlds = String(body.tlds || "");
  const mode = body.mode === "manual" ? "manual" : "bulk";
  const target = String(body.target || "si").trim().toLowerCase().replace(/^\.+/, "").replace(/[^a-z0-9.-]/g, "").slice(0, 32) || "si";
  if (!title) return { error: "Give the list a name." };
  if (names.length > 500000) return { error: "That name list is too long." };
  if (tlds.length > 20000) return { error: "That TLD list is too long." };
  return { title, names, tlds, mode, target };
}

async function sessionResponse(request, env, user, payload, status = 200) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const expires = Date.now() + SESSION_MS;
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").bind(tokenHash, user.id, expires).run();
  return json(payload, status, cookieHeader(request, token, expires));
}

async function currentUser(request, env) {
  const token = readCookie(request, COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT users.id, users.username, users.contact_email AS email, users.name, users.role, users.daily_limit, sessions.expires_at
     FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ?`
  ).bind(await sha256(token)).first();
  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return null;
  }
  return row;
}

async function serveCheck(request, env) {
  const url = new URL(request.url);
  const user = await currentUser(request, env);
  if (!user) return Response.redirect(new URL("/", request.url), 302);
  if (url.searchParams.get("embed") !== "1") {
    const dest = new URL("/", request.url);
    dest.searchParams.set("page", "check");
    const list = url.searchParams.get("list");
    if (list) dest.searchParams.set("list", list);
    return Response.redirect(dest, 302);
  }
  const asset = await env.ASSETS.fetch(new Request(new URL("/check.html", request.url)));
  if (!asset.ok) return asset;
  const html = await asset.text();
  const chrome = checkChrome(user, true);
  const body = html.includes("<body>") ? html.replace("<body>", "<body>" + chrome) : chrome + html;
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function checkChrome(user, embed) {
  const who = escapeHtml(user.name || user.username);
  const role = user.role === "admin" ? "Admin" : "User";
  const usersLink = user.role === "admin" ? '<a href="/?page=users">Users</a>' : "";
  const sidebar = embed ? "" : `<aside class="helo-side" id="helo-side">
  <div class="helo-brand"><div class="helo-mark">H</div><strong>Helo</strong></div>
  <div class="helo-kicker">OVERVIEW</div>
  <nav>
    <a href="/">Dashboard</a>
    <a href="/?page=lists">Saved lists</a>
    <a class="is-on" href="/check">Check names</a>
    ${usersLink}
    <a href="/?page=settings">Settings</a>
  </nav>
  <div class="helo-quota" id="helo-quota"></div>
  <div class="helo-user">
    <div class="helo-avatar">${escapeHtml((user.name || user.username || "H").slice(0, 1).toUpperCase())}</div>
    <div><strong>${who}</strong><small>${role}</small></div>
    <button type="button" id="helo-signout">Sign out</button>
  </div>
</aside>`;
  return `${sidebar}
<div id="saas-bar"><input id="saas-title" maxlength="80" placeholder="List name" aria-label="List name"><button type="button" id="saas-save">Save list</button><span id="saas-note"></span></div>
<style>
  ${embed ? ".mode-toggle-standalone { display: none !important; }" : "body { padding-left: 280px; }"}
  .helo-side { position: fixed; top: 0; left: 0; bottom: 0; width: 280px; z-index: 40; background: var(--bg); border-right: 1px dashed var(--divider); display: flex; flex-direction: column; padding: 20px 16px; }
  .helo-brand, .helo-user { display: flex; align-items: center; gap: 10px; }
  .helo-mark, .helo-avatar { width: 40px; height: 40px; border-radius: 12px; display: grid; place-items: center; font-weight: 800; flex: none; color: var(--primary-ink); background: linear-gradient(135deg, var(--primary-light), var(--primary-dark)); }
  .helo-avatar { border-radius: 50%; }
  .helo-kicker { margin: 20px 12px 8px; color: var(--text-3); font-size: 11px; font-weight: 700; letter-spacing: 0.08em; }
  .helo-side nav { display: flex; flex-direction: column; gap: 4px; }
  .helo-side nav a { text-decoration: none; color: var(--text-2); border-radius: 8px; padding: 10px 12px; font-size: 14px; font-weight: 500; }
  .helo-side nav a:hover { background: var(--hover); }
  .helo-side nav a.is-on { background: var(--primary-8); color: var(--nav-on); font-weight: 600; }
  .helo-quota { margin: 12px 8px; color: var(--text-2); font-size: 13px; }
  .helo-user { margin-top: auto; padding-top: 12px; }
  .helo-user strong, .helo-user small { display: block; }
  .helo-user small { color: var(--text-3); }
  .helo-user button { margin-left: auto; border: 0; background: none; color: var(--nav-on); font-weight: 700; cursor: pointer; }
  #saas-bar { position: sticky; top: 0; z-index: 20; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; padding: 12px 40px; background: var(--header); backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); border-bottom: 1px dashed var(--divider); }
  #saas-bar button { font: inherit; font-size: 14px; border-radius: 8px; min-height: 36px; padding: 6px 14px; border: 0; background: var(--inherit-bg); color: var(--inherit-ink); cursor: pointer; font-weight: 700; }
  #saas-bar button:hover { opacity: .9; }
  #saas-bar input { font: inherit; font-size: 14px; border: 1px solid var(--input-line); border-radius: 8px; padding: 8px 12px; min-width: 220px; background: transparent; color: inherit; outline: none; }
  #saas-bar input:focus { border-color: var(--text); box-shadow: inset 0 0 0 1px var(--text); }
  #saas-note { color: var(--text-2); font-size: 13px; }
  @media (max-width: 600px) { #saas-bar { padding: 10px 16px; } }
</style>
<script>
(function () {
  const FONT = {
    "Public Sans": '"Public Sans", system-ui, -apple-system, "Segoe UI", sans-serif',
    Inter: 'Inter, system-ui, -apple-system, "Segoe UI", sans-serif',
    "DM Sans": '"DM Sans", system-ui, -apple-system, "Segoe UI", sans-serif',
    "Nunito Sans": '"Nunito Sans", system-ui, -apple-system, "Segoe UI", sans-serif'
  };
  function inkFor(hex) {
    const n = parseInt(String(hex || "").slice(1), 16);
    if (!Number.isFinite(n)) return "#ffffff";
    const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255 > 0.62 ? "#1c252e" : "#ffffff";
  }
  function applyTheme(theme) {
    if (!theme) return;
    const root = document.documentElement;
    root.style.setProperty("--primary", theme.accent);
    root.style.setProperty("--primary-ink", inkFor(theme.accent));
    root.style.setProperty("--radius", theme.radius + "px");
    root.style.setProperty("--font-size", theme.fontSize + "px");
    root.style.setProperty("--font", FONT[theme.font] || FONT["Public Sans"]);
  }
  function publishQuota(quota) {
    if (!quota) return;
    const text = quota.unlimited ? "Checks today: unlimited" : ("Checks today: " + quota.used + " / " + quota.limit);
    const node = document.getElementById("helo-quota");
    if (node) node.textContent = text;
    if (window.parent && window.parent !== window) window.parent.postMessage({ type: "helo-quota", quota: quota }, location.origin);
  }
  fetch("/api/me").then(function (response) { return response.json(); }).then(function (data) {
    applyTheme(data.theme);
    publishQuota(data.quota);
  }).catch(function () {});
  const signout = document.getElementById("helo-signout");
  if (signout) signout.addEventListener("click", function () {
    fetch("/api/logout", { method: "POST" }).then(function () { location.href = "/"; });
  });
  const params = new URLSearchParams(location.search);
  const existing = params.get("list");
  function fill(list) {
    const names = document.getElementById("names");
    const tlds = document.getElementById("tlds");
    const target = document.getElementById("target");
    const title = document.getElementById("saas-title");
    if (title && list.title) title.value = list.title;
    if (names) names.value = list.names || "";
    if (tlds && list.tlds) tlds.value = list.tlds;
    if (target && list.target) target.value = list.target;
    if (names) names.dispatchEvent(new Event("input"));
    if (tlds) tlds.dispatchEvent(new Event("input"));
    if (target) target.dispatchEvent(new Event("input"));
    const modeButton = document.getElementById(list.mode === "manual" ? "mode-manual" : "mode-bulk");
    if (modeButton) modeButton.click();
  }
  if (existing) {
    fetch("/api/lists/" + existing).then(function (response) { return response.json(); }).then(function (data) {
      if (data.list) fill(data.list);
    }).catch(function () {});
  }
  const button = document.getElementById("saas-save");
  const note = document.getElementById("saas-note");
  if (button) {
    button.addEventListener("click", function () {
      const title = document.getElementById("saas-title").value.trim();
      note.textContent = "Saving…";
      fetch("/api/lists", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          title: title,
          names: document.getElementById("names").value,
          tlds: document.getElementById("tlds").value,
          mode: document.getElementById("mode-manual").classList.contains("is-on") ? "manual" : "bulk",
          target: document.getElementById("target").value || "si"
        })
      }).then(function (response) { return response.json().then(function (data) { return { ok: response.ok, data: data }; }); })
        .then(function (result) {
          note.textContent = result.ok ? "Saved." : (result.data.error || "Could not save.");
        }).catch(function () { note.textContent = "Could not save."; });
    });
  }
  const check = document.getElementById("check");
  if (!check) return;
  let armed = false;
  check.addEventListener("click", function (event) {
    if (armed) { armed = false; return; }
    const names = (document.getElementById("names").value || "").split(/\\n/).map(function (line) { return line.trim(); }).filter(Boolean);
    if (!names.length) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (note) note.textContent = "Checking the daily limit…";
    fetch("/api/usage", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ count: names.length })
    }).then(function (response) { return response.json().then(function (data) { return { ok: response.ok, data: data }; }); })
      .then(function (result) {
        if (!result.ok) {
          if (note) note.textContent = result.data.error || "Daily limit reached.";
          return;
        }
        publishQuota(result.data);
        if (note) note.textContent = result.data.unlimited ? "No daily limit on this account." : (result.data.remaining + " checks left today.");
        armed = true;
        check.click();
      }).catch(function () { if (note) note.textContent = "Could not check the daily limit."; });
  }, true);
})();
</script>`;
}

async function serveHtml(request, env) {
  const asset = await env.ASSETS.fetch(request);
  const headers = new Headers(asset.headers);
  headers.set("cache-control", "no-store");
  return new Response(asset.body, { status: asset.status, headers });
}

function cookieHeader(request, token, expiresMs) {
  const maxAge = Math.floor((expiresMs - Date.now()) / 1000);
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return "set-cookie:" + COOKIE + "=" + token + "; HttpOnly; Path=/; SameSite=Lax; Max-Age=" + maxAge + secure;
}

function clearCookie(request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return "set-cookie:" + COOKIE + "=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0" + secure;
}

function json(payload, status = 200, extra) {
  const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
  if (extra && extra.startsWith("set-cookie:")) headers["set-cookie"] = extra.slice("set-cookie:".length);
  return new Response(JSON.stringify(payload), { status, headers });
}

async function readBody(request) {
  try {
    const data = await request.json();
    return data && typeof data === "object" ? data : {};
  } catch (error) {
    return {};
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanName(value, fallback) {
  const name = String(value || "").trim().slice(0, 80);
  if (name) return name;
  return String(fallback || "").split("@")[0].slice(0, 80);
}

function validateUsername(username) {
  if (!/^[a-z0-9][a-z0-9._-]{1,31}$/.test(username)) return "Use 2–32 letters or numbers for the username.";
  return "";
}

function validateEmail(email) {
  if (!email || email.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "Write a valid email.";
  return "";
}

function validatePassword(password) {
  if (password.length < 8) return "Use at least 8 characters.";
  if (password.length > 200) return "That password is too long.";
  return "";
}

function randomSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: hexToBytes(saltHex),
    iterations: PBKDF2_ITERATIONS,
    hash: "SHA-256",
  }, key, 256);
  return [...new Uint8Array(bits)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password, saltHex, expected) {
  const actual = await hashPassword(password, saltHex);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i += 1) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function readCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  const parts = header.split(/;\s*/);
  for (const part of parts) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index) === name) return decodeURIComponent(part.slice(index + 1));
  }
  return "";
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}
