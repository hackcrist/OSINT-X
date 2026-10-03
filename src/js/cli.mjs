#!/usr/bin/env node
/**
 * OSINT-X · console menu (Node 18+, zero dependencies).
 * 01–09 modules + 00 EXIT. Public information / authorized targets only.
 */
import readline from "node:readline";
import { printResult } from "./lib/common.mjs";
import { investigateDomain } from "./lib/domain.mjs";
import { scanPorts } from "./lib/portscan.mjs";
import { enumerateSubdomains } from "./lib/subdomain.mjs";
import { analyzePhone } from "./lib/phone.mjs";
import { checkUsername } from "./lib/username.mjs";
import { investigateIp } from "./lib/ipinfo.mjs";
import { investigateEmail } from "./lib/email.mjs";
import { investigateUrl } from "./lib/url.mjs";
import { saveReport } from "./lib/report.mjs";

const MENU = `
OSINT-X — passive intelligence console (public info only)
  01 DOMAIN     DNS + RDAP
  02 PORTSCAN   TCP connect (authorized targets only)
  03 SUBDOMAIN  crt.sh passive enumeration
  04 PHONE      offline E.164 parse
  05 USERNAME   public-presence check
  06 IPINFO     ip-api + reverse DNS
  07 EMAIL      MX/SPF/DMARC via DNS
  08 URL        headers + redirects + TLS cert
  09 REPORT     save last result (json/txt/html)
  00 EXIT
`;

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((resolve) => rl.question(q, (a) => resolve(a.trim())));

let lastResult = null;

async function maybeSave() {
  if (!lastResult) return;
  const want = (await ask("Save report? [json/txt/html/no] (no): ")).toLowerCase() || "no";
  if (["json", "txt", "html"].includes(want)) {
    const saved = await saveReport(lastResult, { format: want });
    printResult(saved);
  }
}

async function handle(choice) {
  switch (choice) {
    case "01": case "1": {
      const d = await ask("Domain: ");
      lastResult = await investigateDomain(d);
      printResult(lastResult);
      break;
    }
    case "02": case "2": {
      const h = await ask("Host (IP/hostname, authorized only): ");
      const p = await ask("Ports [default: common] (e.g. 80,443 or 1-1024): ");
      lastResult = await scanPorts(h, p || null);
      printResult(lastResult);
      break;
    }
    case "03": case "3": {
      const d = await ask("Domain: ");
      lastResult = await enumerateSubdomains(d);
      printResult(lastResult);
      break;
    }
    case "04": case "4": {
      const p = await ask("Phone (+E.164, e.g. +34123456789): ");
      lastResult = analyzePhone(p);
      printResult(lastResult);
      break;
    }
    case "05": case "5": {
      const u = await ask("Username: ");
      lastResult = await checkUsername(u);
      printResult(lastResult);
      break;
    }
    case "06": case "6": {
      const ip = await ask("IP address: ");
      lastResult = await investigateIp(ip);
      printResult(lastResult);
      break;
    }
    case "07": case "7": {
      const e = await ask("Email: ");
      lastResult = await investigateEmail(e);
      printResult(lastResult);
      break;
    }
    case "08": case "8": {
      const u = await ask("URL (http/https): ");
      lastResult = await investigateUrl(u);
      printResult(lastResult);
      break;
    }
    case "09": case "9": {
      if (!lastResult) {
        console.log("No result yet — run a module 01–08 first.");
        break;
      }
      const f = (await ask("Format [json/txt/html] (json): ")).toLowerCase() || "json";
      const saved = await saveReport(lastResult, { format: f });
      printResult(saved);
      break;
    }
    default:
      console.log("Unknown option. Use 01–09 or 00.");
      return;
  }
  await maybeSave();
}

async function main() {
  console.log("Reminder: query public info and scan only systems you own / are authorized to test.");
  for (;;) {
    console.log(MENU);
    const choice = await ask("osint-x> ");
    if (choice === "00" || choice === "0" || /^exit$/i.test(choice)) {
      console.log("Bye.");
      rl.close();
      process.exit(0);
    }
    try {
      await handle(choice);
    } catch (err) {
      console.error(`error: ${err?.message ?? err}`);
    }
  }
}

main();
