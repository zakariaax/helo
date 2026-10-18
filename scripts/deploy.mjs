import { execSync } from "node:child_process";
import fs from "node:fs";

if (!process.env.CLOUDFLARE_API_TOKEN) {
  console.error("CLOUDFLARE_API_TOKEN is not set. Add it as a Cursor secret, then run this from a new agent.");
  process.exit(1);
}

const placeholder = "00000000-0000-0000-0000-000000000001";
let toml = fs.readFileSync("wrangler.toml", "utf8");

if (toml.includes(placeholder)) {
  const id = findDatabaseId();
  toml = toml.replace(placeholder, id);
  fs.writeFileSync("wrangler.toml", toml);
  console.log("Wrote the D1 database id into wrangler.toml");
}

execSync("npx wrangler d1 migrations apply helo --remote", { stdio: "inherit" });
execSync("npx wrangler deploy", { stdio: "inherit" });

function findDatabaseId() {
  let created = "";
  try {
    created = execSync("npx wrangler d1 create helo", { encoding: "utf8" });
  } catch (error) {
    created = String(error.stdout || "") + String(error.stderr || "");
  }
  const fromCreate = created.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
  if (fromCreate && created.toLowerCase().includes("helo")) return fromCreate[0];
  const listed = execSync("npx wrangler d1 list --json", { encoding: "utf8" });
  const rows = JSON.parse(listed);
  const found = rows.find((row) => row.name === "helo");
  const id = found && (found.uuid || found.database_id);
  if (!id) {
    console.error(created);
    throw new Error("Could not create or find the helo D1 database.");
  }
  return id;
}
