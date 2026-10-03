/**
 * OSINT-X · 09 REPORT
 * Save any output-contract result as JSON / TXT / HTML under ./reports/.
 * Zero dependencies. Escapes HTML. Returns the written file path.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { makeResult } from "./common.mjs";

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function toTxt(result) {
  const lines = [
    "OSINT-X REPORT",
    `target:       ${result.target}`,
    `status:       ${result.status}`,
    `retrieved_at: ${result.retrieved_at}`,
    `sources:      ${(result.sources ?? []).join(", ") || "(none)"}`,
    `errors:       ${(result.errors ?? []).join(" | ") || "(none)"}`,
    "",
    "DATA",
    JSON.stringify(result.data ?? {}, null, 2),
  ];
  return lines.join("\n") + "\n";
}

function toHtml(result) {
  const rows = Object.entries(result.data ?? {})
    .map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td><pre>${escapeHtml(JSON.stringify(v, null, 2))}</pre></td></tr>`)
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT-X report — ${escapeHtml(result.target)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.5rem;vertical-align:top;text-align:left}
th{width:180px;background:#f5f5f5}pre{white-space:pre-wrap;margin:0}.meta{color:#555}
</style></head>
<body>
<h1>OSINT-X report</h1>
<p class="meta">target: <strong>${escapeHtml(result.target)}</strong> · status: <strong>${escapeHtml(result.status)}</strong><br>
retrieved_at: ${escapeHtml(result.retrieved_at)}<br>
sources: ${escapeHtml((result.sources ?? []).join(", ") || "(none)")}<br>
errors: ${escapeHtml((result.errors ?? []).join(" | ") || "(none)")}</p>
<table>${rows || "<tr><td>(no data)</td></tr>"}</table>
<p class="meta">Passive OSINT only — observed data above; inferences are labeled inside each module.</p>
</body>
</html>
`;
}

function safeBase(target) {
  return String(target ?? "report").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "report";
}

/**
 * @param {object} result output-contract result
 * @param {{format?: "json"|"txt"|"html", outDir?: string, basename?: string}} opts
 */
export async function saveReport(result, { format = "json", outDir = "./reports", basename = null } = {}) {
  const fmt = String(format).toLowerCase();
  if (!["json", "txt", "html"].includes(fmt)) {
    return makeResult(result?.target ?? "", { errors: [`unsupported format ${JSON.stringify(format)} (json/txt/html)`] });
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const name = `${basename ?? safeBase(result?.target)}-${stamp}.${fmt}`;
  const dir = path.resolve(outDir);
  try {
    await fs.mkdir(dir, { recursive: true });
    const body = fmt === "json" ? JSON.stringify(result, null, 2) + "\n" : fmt === "txt" ? toTxt(result) : toHtml(result);
    const file = path.join(dir, name);
    await fs.writeFile(file, body, "utf8");
    return { ...makeResult(result?.target ?? "", { data: { file, format: fmt }, sources: ["report:local-file"] }), file };
  } catch (err) {
    return makeResult(result?.target ?? "", { errors: [`report write failed: ${err?.message ?? err}`] });
  }
}
