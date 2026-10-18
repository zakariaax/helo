const COOKIE = "helo_session";
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 8000;

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

  if (request.method === "GET" && path === "/api/lists") return listLists(env, user);
  if (request.method === "POST" && path === "/api/lists") return createList(request, env, user);
  const listMatch = path.match(/^\/api\/lists\/([0-9a-f-]{36})$/);
  if (listMatch && request.method === "GET") return getList(env, user, listMatch[1]);
  if (listMatch && request.method === "DELETE") return deleteList(env, user, listMatch[1]);

  if (path === "/api/admin/users" && request.method === "GET") return adminUsers(env, user);
  const roleMatch = path.match(/^\/api\/admin\/users\/([0-9a-f-]{36})$/);
  if (roleMatch && request.method === "POST") return adminSetRole(request, env, user, roleMatch[1]);

  return json({ error: "Not found." }, 404);
}

async function signup(request, env) {
  const body = await readBody(request);
  const email = cleanEmail(body.email);
  const name = cleanName(body.name, email);
  const password = String(body.password || "");
  const emailError = validateEmail(email);
  if (emailError) return json({ error: emailError }, 400);
  if (!name) return json({ error: "Write your name." }, 400);
  const passwordError = validatePassword(password);
  if (passwordError) return json({ error: passwordError }, 400);

  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
  const role = Number(count?.n || 0) === 0 ? "admin" : "user";
  const id = crypto.randomUUID();
  const salt = randomSalt();
  const passwordHash = await hashPassword(password, salt);
  try {
    await env.DB.prepare(
      "INSERT INTO users (id, email, name, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(id, email, name, passwordHash, salt, role, Date.now()).run();
  } catch (error) {
    if (String(error).includes("UNIQUE")) return json({ error: "An account with that email already exists." }, 409);
    throw error;
  }
  const user = { id, email, name, role };
  return sessionResponse(request, env, user, { user: publicUser(user) }, 201);
}

async function login(request, env) {
  const body = await readBody(request);
  const email = cleanEmail(body.email);
  const password = String(body.password || "");
  const row = await env.DB.prepare(
    "SELECT id, email, name, role, password_hash, password_salt FROM users WHERE email = ?"
  ).bind(email).first();
  if (!row || !(await verifyPassword(password, row.password_salt, row.password_hash))) {
    return json({ error: "Email or password is wrong." }, 401);
  }
  const user = { id: row.id, email: row.email, name: row.name, role: row.role };
  return sessionResponse(request, env, user, { user: publicUser(user) });
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
  return json({ user: publicUser(user), listCount: Number(lists?.n || 0) });
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

async function adminUsers(env, user) {
  if (user.role !== "admin") return json({ error: "Only an admin can see users." }, 403);
  const result = await env.DB.prepare(
    "SELECT id, email, name, role, created_at FROM users ORDER BY created_at ASC"
  ).all();
  return json({ users: result.results || [] });
}

async function adminSetRole(request, env, actor, id) {
  if (actor.role !== "admin") return json({ error: "Only an admin can change roles." }, 403);
  const body = await readBody(request);
  const role = body.role === "admin" ? "admin" : body.role === "user" ? "user" : "";
  if (!role) return json({ error: "Role must be admin or user." }, 400);
  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(id).first();
  if (!target) return json({ error: "That user was not found." }, 404);
  if (target.role === "admin" && role === "user") {
    const admins = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").first();
    if (Number(admins?.n || 0) <= 1) return json({ error: "The last admin has to stay an admin." }, 400);
  }
  await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, id).run();
  return json({ ok: true, role });
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
    `SELECT users.id, users.email, users.name, users.role, sessions.expires_at
     FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ?`
  ).bind(await sha256(token)).first();
  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return null;
  }
  return { id: row.id, email: row.email, name: row.name, role: row.role };
}

function publicUser(user) {
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}

async function serveCheck(request, env) {
  const user = await currentUser(request, env);
  if (!user) return Response.redirect(new URL("/", request.url), 302);
  const asset = await env.ASSETS.fetch(new Request(new URL("/check.html", request.url)));
  if (!asset.ok) return asset;
  const html = await asset.text();
  const bar = checkBar(user);
  const body = html.includes("<body>") ? html.replace("<body>", "<body>" + bar) : bar + html;
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function checkBar(user) {
  return `<div id="saas-bar"><a href="/">Dashboard</a><input id="saas-title" maxlength="80" placeholder="List name" aria-label="List name"><button type="button" id="saas-save">Save list</button><span id="saas-note"></span><span id="saas-who">${escapeHtml(user.email)}</span></div>
<style>
  #saas-bar { position: sticky; top: 0; z-index: 20; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; padding: 10px 16px; background: #fffdf8; border-bottom: 1px solid #e4d9cb; }
  #saas-bar a, #saas-bar button { font: inherit; border-radius: 999px; padding: 7px 12px; border: 1px solid #e4d9cb; background: #fff; color: #1e1a16; text-decoration: none; font-weight: 700; }
  #saas-bar button { background: #1b4f3a; color: #f4faf6; border-color: transparent; cursor: pointer; }
  #saas-bar input { font: inherit; border: 1px solid #e4d9cb; border-radius: 999px; padding: 7px 12px; min-width: 180px; }
  #saas-note { color: #5f574e; font-size: 13px; }
  #saas-who { margin-left: auto; color: #5f574e; font-size: 13px; }
</style>
<script>
(function () {
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
  if (!button) return;
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

function cleanName(value, email) {
  const name = String(value || "").trim().slice(0, 80);
  if (name) return name;
  return email.split("@")[0].slice(0, 80);
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
