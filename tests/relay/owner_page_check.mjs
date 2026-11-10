// Runs the owner page's own checks (src/uam/relay/owners/static/owner.js)
// on cases the Python tests build, and prints what the page decided.
// usage: node owner_page_check.mjs <owner.js> <cases.json>
import { readFileSync } from "node:fs";

const [script, casesPath] = process.argv.slice(2);
const source = readFileSync(script, "utf8");
const page = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const cases = JSON.parse(readFileSync(casesPath, "utf8"));

const out = { approvals: [], labels: {}, dates: {} };
for (const c of cases.approvals) {
  try {
    out.approvals.push({ name: c.name, ok: true, screen: await page.checkApproval(c.answer, c.previous) });
  } catch (e) {
    out.approvals.push({ name: c.name, ok: false, error: String(e.message) });
  }
}
for (const label of cases.labels) out.labels[label] = page.validLabel(label);
for (const iso of cases.dates) out.dates[iso] = page.addedOn(iso);
process.stdout.write(JSON.stringify(out));
