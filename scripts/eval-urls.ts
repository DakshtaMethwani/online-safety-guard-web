/**
 * URL inspector evaluation harness.
 *
 * Reads tests/data/urls.csv (label: bad | safe | hard) and reports precision,
 * recall and false-positive rate for the URL inspector, plus the risk-score
 * distribution per class. Use it to tune the thresholds in url-scoring.ts.
 *
 * Default mode is deterministic/offline (no network) so numbers are
 * reproducible and safe to run anywhere. `--online` uses the real network.
 *
 *   npm run eval            # offline, deterministic
 *   npm run eval -- --online
 */
import fs from "node:fs";
import path from "node:path";
import { inspectUrl, createDefaultInspectDeps, type InspectDeps } from "../server";

type Label = "bad" | "safe" | "hard";
interface Row {
  url: string;
  label: Label;
  note: string;
}

function readCsv(file: string): Row[] {
  const text = fs.readFileSync(file, "utf8");
  const rows: Row[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("url,")) continue;
    const [url, label, ...rest] = trimmed.split(",");
    if (!url || (label !== "bad" && label !== "safe" && label !== "hard")) continue;
    rows.push({ url, label, note: rest.join(",") });
  }
  return rows;
}

const WELL_KNOWN = [
  "google.com", "youtube.com", "wikipedia.org", "github.com", "amazon.com",
  "linkedin.com", "microsoft.com", "apple.com",
];

function trancoLookup(host: string): number | null {
  let h = host.toLowerCase();
  while (h.includes(".")) {
    if (WELL_KNOWN.includes(h)) return 1;
    h = h.slice(h.indexOf(".") + 1);
  }
  return null;
}

function offlineDeps(): InspectDeps {
  return {
    providers: [
      {
        id: "eval-clean",
        label: "Eval clean provider",
        isConfigured: () => true,
        lookup: async () => ({ status: "clean" as const, note: "offline eval: reputation not consulted" }),
      },
    ],
    followRedirects: async (url: string) => ({
      status: "none" as const,
      hops: [{ url, status: 200 }],
      finalUrl: url,
      method: "GET" as const,
      note: "offline eval: connectivity not consulted",
    }),
    gemini: async () => null,
    intel: {
      dns: async () => ({ exists: true }),
      tls: async () => ({ valid: true, daysToExpiry: 300 }),
      // Well-known domains are old; unknown domains in a threat dataset are
      // typically recently registered (a realistic, reproducible assumption).
      domainAgeDays: async (domain: string) => ({ ageDays: trancoLookup(domain) ? 3000 : 45 }),
      trancoRank: async (host: string) => ({ rank: trancoLookup(host) }),
    },
  };
}

function onlineDeps(): InspectDeps {
  // Uses the server's real defaults (URLhaus / Safe Browsing / OpenPhish if a
  // local feed exists, DNS, TLS, RDAP, Tranco file).
  return createDefaultInspectDeps();
}

function pct(n: number, d: number): string {
  return d === 0 ? "n/a" : `${((n / d) * 100).toFixed(1)}%`;
}

function dist(scores: number[]): string {
  if (!scores.length) return "(none)";
  const sorted = [...scores].sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const median = sorted[Math.floor(sorted.length / 2)];
  const mean = Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length);
  return `min=${min} median=${median} mean=${mean} max=${max}`;
}

async function main(): Promise<void> {
  const online = process.argv.includes("--online");
  const file = path.join(process.cwd(), "tests", "data", "urls.csv");
  const rows = readCsv(file);
  const deps = online ? onlineDeps() : offlineDeps();

  console.log(`URL inspector evaluation (${online ? "ONLINE" : "offline/deterministic"})`);
  console.log(`Dataset: ${file} (${rows.length} rows)\n`);

  const results: Array<{ row: Row; verdict: string; riskScore: number; confidence: number }> = [];
  for (const row of rows) {
    const r = await inspectUrl(row.url, deps);
    results.push({ row, verdict: r.verdict, riskScore: r.riskScore, confidence: r.confidence });
  }

  const flagged = (v: string) => v === "MALICIOUS" || v === "SUSPICIOUS";
  const isSafe = (v: string) => v === "LOW_RISK";

  const bad = results.filter((r) => r.row.label === "bad");
  const safe = results.filter((r) => r.row.label === "safe");
  const hard = results.filter((r) => r.row.label === "hard");

  const tp = bad.filter((r) => flagged(r.verdict)).length;
  const fn = bad.filter((r) => isSafe(r.verdict)).length;
  const fp = safe.filter((r) => flagged(r.verdict)).length;
  const tn = safe.filter((r) => isSafe(r.verdict)).length;

  console.log("Labeled metrics (bad = positive, safe = negative; UNVERIFIED abstains):");
  console.log(`  Precision : ${pct(tp, tp + fp)}  (${tp}/${tp + fp})`);
  console.log(`  Recall    : ${pct(tp, tp + fn)}  (${tp}/${tp + fn})`);
  console.log(`  FPR       : ${pct(fp, fp + tn)}  (${fp}/${fp + tn})`);
  console.log(`  Abstained : ${bad.filter((r) => r.verdict === "UNVERIFIED").length + safe.filter((r) => r.verdict === "UNVERIFIED").length}`);
  console.log("");
  console.log(`Score distribution by class:`);
  console.log(`  bad  : ${dist(bad.map((r) => r.riskScore))}`);
  console.log(`  safe : ${dist(safe.map((r) => r.riskScore))}`);
  console.log(`  hard : ${dist(hard.map((r) => r.riskScore))}`);
  console.log("");

  console.log("Per-URL results:");
  for (const r of results) {
    const mark = r.row.label === "bad" ? (flagged(r.verdict) ? "[ok]  " : "[MISS]") : r.row.label === "safe" ? (flagged(r.verdict) ? "[FP]  " : "[ok]  ") : "      ";
    console.log(
      `  ${mark} ${r.verdict.padEnd(11)} risk=${String(r.riskScore).padStart(3)} conf=${String(r.confidence).padStart(3)}  ${r.row.label.padEnd(4)}  ${r.row.url}`
    );
  }
}

main().catch((err) => {
  console.error("eval failed:", err);
  process.exit(1);
});
