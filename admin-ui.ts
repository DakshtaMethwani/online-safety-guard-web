/**
 * Admin-only UI for Online Safety Guard.
 *
 * IMPORTANT: this file is used ONLY by the admin pages. It deliberately does
 * not reuse the shared public `pageShell`/CSS from gateway.ts, and every style
 * it emits is scoped under `.sg-admin` so nothing can leak into the public
 * pages (homepage, /go/ link pages, etc.).
 *
 * Security notes:
 *  - The admin CSP (see gateway.ts setAdminSecurityHeaders) is unchanged:
 *    `script-src 'self'` (no inline scripts) and `style-src 'self'
 *    'unsafe-inline'`. This UI uses an external script and a <style> block;
 *    it never emits inline <script>, inline event handlers or inline style="".
 *  - No external font/script/stylesheet is referenced; a system font stack is used.
 *  - All attacker-controlled values (sender, subject) are HTML-escaped, and the
 *    client script only ever writes them via textContent.
 */
import type { GatewayDb, MailStats } from "./gateway-db";

/* ------------------------------------------------------------------ helpers */

function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Short, non-identifying label for a hashed mailbox. */
export function mailboxLabel(prefix: string): string {
  return `Mailbox ${prefix}`;
}

/** Defang a URL for display: never render it as something clickable. */
function defang(url: string): string {
  return url
    .replace(/^https?:\/\//i, (m) => m.replace(/:\/\//, "[:]//"))
    .replace(/\./g, "[.]");
}

/* ------------------------------------------------------------------- charts */

const DAY_LABELS_DAYS = 86400000;

/**
 * Stacked bar chart: one bar per day, segments coloured by verdict.
 * Values are SVG geometry attributes (no inline styles). Each bar group is
 * focusable (tabindex=0) and carries a <title> so hover AND keyboard focus
 * surface the exact numbers.
 */
function stackedBarsSvg(perDay: MailStats["perDay"]): string {
  const w = 760;
  const h = 240;
  const padL = 40;
  const padR = 10;
  const padT = 12;
  const padB = 40;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const max = Math.max(1, ...perDay.map((d) => d.safe + d.unverified + d.blocked + d.error));
  const slot = innerW / Math.max(perDay.length, 1);
  const barW = Math.max(3, Math.min(26, slot - 4));
  const labelEvery = Math.max(1, Math.ceil(perDay.length / 10));

  const grid: string[] = [];
  for (let i = 0; i <= 4; i++) {
    const y = padT + (innerH * i) / 4;
    const val = Math.round((max * (4 - i)) / 4);
    grid.push(`<line class="sg-grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${w - padR}" y2="${y.toFixed(1)}" />`);
    grid.push(`<text class="sg-axis" x="${padL - 6}" y="${(y + 3).toFixed(1)}" text-anchor="end">${val}</text>`);
  }

  const bars = perDay
    .map((d, i) => {
      const total = d.safe + d.unverified + d.blocked + d.error;
      const x = padL + slot * i + (slot - barW) / 2;
      let y = padT + innerH;
      const seg = (cls: string, value: number) => {
        if (!value) return "";
        const segH = (value / max) * innerH;
        y -= segH;
        return `<rect class="seg ${cls}" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${segH.toFixed(1)}" />`;
      };
      const title = `${d.date}: ${d.safe} safe, ${d.unverified} needs review, ${d.blocked} blocked`;
      const label =
        i % labelEvery === 0
          ? `<text class="sg-axis" x="${(x + barW / 2).toFixed(1)}" y="${h - 22}" text-anchor="middle">${esc(d.date.slice(5))}</text>`
          : "";
      return `<g class="sg-bar" tabindex="0" role="img" aria-label="${esc(title)}"><title>${esc(title)}</title>${label}${seg(
        "seg-safe",
        d.safe
      )}${seg("seg-unverified", d.unverified)}${seg("seg-blocked", d.blocked)}${seg("seg-error", d.error)}</g>`;
    })
    .join("");

  return `<svg class="sg-chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Messages per day by verdict">${grid.join(
    ""
  )}<line class="sg-axis-line" x1="${padL}" y1="${padT + innerH}" x2="${w - padR}" y2="${padT + innerH}" />${bars}</svg>`;
}

/**
 * Donut of the verdict split. Segment length/offset use SVG stroke attributes.
 */
function donutSvg(totals: { safe: number; unverified: number; blocked: number; error: number }): string {
  const size = 190;
  const r = 66;
  const stroke = 24;
  const c = 2 * Math.PI * r;
  const total = totals.safe + totals.unverified + totals.blocked + totals.error;
  const parts = [
    { cls: "seg-safe", value: totals.safe },
    { cls: "seg-unverified", value: totals.unverified },
    { cls: "seg-blocked", value: totals.blocked },
    { cls: "seg-error", value: totals.error },
  ].filter((p) => p.value > 0);

  let offset = 0;
  const segs = parts
    .map((p) => {
      const len = total > 0 ? (p.value / total) * c : 0;
      const el = `<circle class="seg ${p.cls}" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke-width="${stroke}" stroke-dasharray="${len.toFixed(
        2
      )} ${(c - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 ${size / 2} ${size / 2})" />`;
      offset += len;
      return el;
    })
    .join("");

  return `<svg class="sg-donut" viewBox="0 0 ${size} ${size}" role="img" aria-label="Verdict split">
    <circle class="sg-donut-track" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke-width="${stroke}" />
    ${segs}
    <text class="sg-donut-total" x="${size / 2}" y="${size / 2 - 2}" text-anchor="middle">${total}</text>
    <text class="sg-donut-cap" x="${size / 2}" y="${size / 2 + 18}" text-anchor="middle">messages</text>
  </svg>`;
}

/** Horizontal bars for "what the guard did". */
function actionBarsSvg(actions: Array<{ action: string; count: number }>, labelOf: (a: string) => string): string {
  const rows = actions.length ? actions : [{ action: "none", count: 0 }];
  const max = Math.max(1, ...rows.map((r) => r.count));
  const w = 520;
  const rowH = 34;
  const labelW = 150;
  const h = rows.length * rowH + 8;
  const body = rows
    .map((r, i) => {
      const y = i * rowH + 6;
      const barW = ((w - labelW - 60) * r.count) / max;
      return `<g class="sg-action-row"><text class="sg-axis" x="0" y="${y + 18}">${esc(labelOf(r.action))}</text>
        <rect class="sg-bar-bg" x="${labelW}" y="${y + 6}" width="${w - labelW - 60}" height="16" rx="6" />
        <rect class="seg seg-accent" x="${labelW}" y="${y + 6}" width="${Math.max(2, barW).toFixed(1)}" height="16" rx="6" />
        <text class="sg-axis" x="${w - 8}" y="${y + 18}" text-anchor="end">${r.count}</text></g>`;
    })
    .join("");
  return `<svg class="sg-chart sg-chart-actions" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMinYMin meet" role="img" aria-label="Actions taken by the guard">${body}</svg>`;
}

/* -------------------------------------------------------------------- CSS */

const SG_ADMIN_CSS = `<style>
  html, body { margin: 0; min-height: 100%; background: #101416; }
  .sg-admin {
    color-scheme: dark;
    --sg-bg: #101416;
    --sg-bg-2: #151b18;
    --sg-panel: #1b251e;
    --sg-panel-2: #202c23;
    --sg-border: #3a4b3d;
    --sg-text: #eef2ec;
    --sg-muted: #a7b1a8;
    --sg-accent: #d9f36b;
    --sg-safe: #9fcd51;
    --sg-amber: #fbbf24;
    --sg-rose: #fb7185;
    --sg-slate: #64748b;
    --sg-shadow: 0 12px 30px rgb(8 13 9 / 0.18);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: radial-gradient(1100px 520px at 50% -12%, #202a21 0%, var(--sg-bg) 58%);
    color: var(--sg-text);
    min-height: 100vh;
    padding: 18px 20px 32px;
    line-height: 1.5;
  }
  .sg-admin[data-theme="light"] {
    color-scheme: light;
    --sg-bg: #f2f7f6;
    --sg-bg-2: #ffffff;
    --sg-panel: #ffffff;
    --sg-panel-2: #f4faf8;
    --sg-border: #cfe3de;
    --sg-text: #08231e;
    --sg-muted: #4d6b64;
    --sg-shadow: 0 12px 30px rgb(2 32 27 / 0.12);
    background: radial-gradient(1000px 500px at 50% -12%, #dff3ee 0%, var(--sg-bg) 60%);
  }
  .sg-admin * { box-sizing: border-box; }
  .sg-wrap { max-width: 1180px; margin: 0 auto; }
  .sg-console { display: grid; grid-template-columns: 208px minmax(0, 1fr); gap: 18px; align-items: start; }
  .sg-sidebar { position: sticky; top: 18px; background: var(--sg-panel); border: 1px solid var(--sg-border); border-radius: 16px; padding: 12px; box-shadow: var(--sg-shadow); }
  .sg-sidebar-brand { display: flex; align-items: center; gap: 9px; color: var(--sg-text); font-size: 13px; font-weight: 800; padding: 8px 9px 18px; }
  .sg-sidebar-mark { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 9px; background: var(--sg-accent); color: #182014; font-size: 15px; }
  .sg-sidebar-label { color: var(--sg-muted); font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; padding: 7px 9px; }
  .sg-sidebar-nav { display: grid; gap: 3px; }
  .sg-sidebar-nav a { display: flex; align-items: center; gap: 8px; text-decoration: none; color: var(--sg-muted); font-size: 12.5px; font-weight: 600; border-radius: 9px; padding: 9px; }
  .sg-sidebar-nav a:hover { background: var(--sg-panel-2); color: var(--sg-text); }
  .sg-sidebar-nav a.is-active { background: color-mix(in srgb, var(--sg-accent) 13%, var(--sg-panel-2)); color: var(--sg-text); box-shadow: inset 3px 0 var(--sg-accent); }
  .sg-sidebar-icon { width: 17px; text-align: center; color: var(--sg-accent); }
  .sg-console-main { min-width: 0; }
  .sg-admin a { color: var(--sg-accent); }
  .sg-admin :focus-visible { outline: 2px solid var(--sg-accent); outline-offset: 2px; border-radius: 6px; }

  .sg-header { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .sg-header-stashed { display: none; }
  .sg-title { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .sg-title h1 { font-size: 20px; margin: 0; letter-spacing: -0.01em; }
  .sg-role { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; padding: 3px 9px; border-radius: 999px; border: 1px solid var(--sg-border); color: var(--sg-muted); background: var(--sg-panel-2); }
  .sg-role.is-admin { color: var(--sg-accent); border-color: rgb(45 212 191 / 0.5); }
  .sg-header-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }

  .sg-tabs { display: flex; gap: 6px; flex-wrap: wrap; border-bottom: 1px solid var(--sg-border); padding-bottom: 8px; margin-bottom: 12px; }
  .sg-tab { text-decoration: none; color: var(--sg-muted); font-weight: 600; font-size: 13.5px; padding: 7px 13px; border-radius: 999px; }
  .sg-tab:hover { color: var(--sg-text); background: var(--sg-panel-2); }
  .sg-tab.is-active { color: var(--sg-text); background: var(--sg-panel-2); border: 1px solid var(--sg-border); }
  .sg-count { display: inline-block; min-width: 18px; text-align: center; margin-left: 5px; padding: 0 5px; border-radius: 999px; background: var(--sg-rose); color: #20040a; font-size: 11px; font-weight: 800; }

  .sg-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0; margin: 6px 0 14px; border: 1px solid var(--sg-border); border-radius: 14px; background: var(--sg-panel); }
  .sg-card { background: transparent; border: 0; border-right: 1px solid var(--sg-border); border-radius: 0; padding: 13px 15px; }
  .sg-card:last-child { border-right: 0; }
  .sg-card .n { font-size: 25px; font-weight: 800; letter-spacing: -0.02em; }
  .sg-card .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--sg-muted); margin-top: 2px; }
  .sg-card.v-safe .n { color: var(--sg-safe); }
  .sg-card.v-review .n { color: var(--sg-amber); }
  .sg-card.v-blocked .n { color: var(--sg-rose); }
  .sg-delta { font-size: 11.5px; font-weight: 700; display: inline-block; margin-top: 6px; color: var(--sg-muted); }
  .sg-delta.up { color: var(--sg-rose); }
  .sg-delta.down { color: var(--sg-safe); }
  .sg-delta.flat { color: var(--sg-muted); }

  .sg-grid-2 { display: grid; grid-template-columns: 1.6fr 1fr; gap: 12px; align-items: start; }
  .sg-grid-2 > .sg-panel { align-self: start; }
  .sg-stack { display: grid; gap: 14px; align-content: start; }
  .sg-console-main > .sg-panel + .sg-grid-2,
  .sg-console-main > .sg-grid-2 + .sg-grid-2,
  .sg-console-main > .sg-grid-2 + .sg-panel { margin-top: 14px; }
  .sg-console-main > .sg-presets { margin-bottom: 12px; }
  .sg-console-main > form.sg-panel.sg-filters { margin-bottom: 14px; }
  .sg-console-main > div.sg-filters { margin-top: 10px; margin-bottom: 14px; }
  @media (max-width: 860px) { .sg-grid-2 { grid-template-columns: 1fr; } }
  .sg-panel { background: var(--sg-panel); border: 1px solid var(--sg-border); border-radius: 16px; padding: 15px; box-shadow: var(--sg-shadow); }
  .sg-panel h2 { font-size: 14px; margin: 0 0 12px; letter-spacing: 0.02em; }
  .sg-panel h2 .sg-sub { color: var(--sg-muted); font-weight: 500; letter-spacing: 0; }

  .sg-legend { display: flex; gap: 8px; flex-wrap: wrap; margin: 0 0 10px; padding: 0; list-style: none; }
  .sg-legend button { cursor: pointer; display: inline-flex; gap: 7px; align-items: center; font: inherit; font-size: 12.5px; font-weight: 600; color: var(--sg-text); background: var(--sg-panel-2); border: 1px solid var(--sg-border); border-radius: 999px; padding: 5px 11px; }
  .sg-legend button[aria-pressed="false"] { opacity: 0.45; }
  .sg-swatch { width: 11px; height: 11px; border-radius: 3px; display: inline-block; }
  .sg-swatch.seg-safe { background: var(--sg-safe); }
  .sg-swatch.seg-unverified { background: var(--sg-amber); }
  .sg-swatch.seg-blocked { background: var(--sg-rose); }
  .sg-swatch.seg-error { background: var(--sg-slate); }

  .sg-chart { width: 100%; height: auto; overflow: visible; }
  .sg-grid { stroke: var(--sg-border); stroke-width: 1; opacity: 0.55; }
  .sg-axis-line { stroke: var(--sg-border); stroke-width: 1; }
  .sg-axis { fill: var(--sg-muted); font-size: 10.5px; font-family: inherit; }
  .sg-bar { cursor: default; }
  .sg-admin.hide-safe .seg-safe, .sg-admin.hide-unverified .seg-unverified, .sg-admin.hide-blocked .seg-blocked { display: none; }
  rect.seg-safe { fill: var(--sg-safe); }
  rect.seg-unverified { fill: var(--sg-amber); }
  rect.seg-blocked { fill: var(--sg-rose); }
  rect.seg-error { fill: var(--sg-slate); }
  circle.seg-safe { stroke: var(--sg-safe); }
  circle.seg-unverified { stroke: var(--sg-amber); }
  circle.seg-blocked { stroke: var(--sg-rose); }
  circle.seg-error { stroke: var(--sg-slate); }
  rect.seg-accent { fill: var(--sg-accent); }
  .sg-bar:hover .seg, .sg-bar:focus-visible .seg { filter: brightness(1.18); }
  .sg-donut { width: 100%; max-width: 220px; height: auto; display: block; margin: 0 auto; }
  .sg-donut-track { stroke: var(--sg-panel-2); }
  .sg-donut-total { fill: var(--sg-text); font-size: 30px; font-weight: 800; font-family: inherit; }
  .sg-donut-cap { fill: var(--sg-muted); font-size: 11px; font-family: inherit; }
  .sg-bar-bg { fill: var(--sg-panel-2); }

  .sg-table-wrap { overflow-x: auto; border: 1px solid var(--sg-border); border-radius: 14px; }
  .sg-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .sg-table th { text-align: left; padding: 10px 12px; color: var(--sg-muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-size: 10.5px; border-bottom: 1px solid var(--sg-border); background: var(--sg-panel-2); white-space: nowrap; }
  .sg-table td { padding: 10px 12px; border-bottom: 1px solid var(--sg-border); vertical-align: middle; }
  .sg-table tr:last-child td { border-bottom: none; }
  .sg-row.is-unread td { background: rgb(45 212 191 / 0.07); }
  .sg-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }
  .sg-muted { color: var(--sg-muted); }
  .sg-sub-line { display: block; color: var(--sg-muted); font-size: 11px; }
  .sg-subject { max-width: 320px; }
  .sg-dot { display: inline-block; width: 8px; height: 8px; border-radius: 999px; background: var(--sg-accent); margin-right: 6px; vertical-align: middle; }

  .sg-badge { display: inline-block; font-size: 10.5px; font-weight: 800; letter-spacing: 0.05em; text-transform: uppercase; padding: 3px 8px; border-radius: 999px; border: 1px solid var(--sg-border); }
  .sg-badge.v-safe { color: var(--sg-safe); border-color: rgb(52 211 153 / 0.5); background: rgb(52 211 153 / 0.12); }
  .sg-badge.v-unverified { color: var(--sg-amber); border-color: rgb(251 191 36 / 0.5); background: rgb(251 191 36 / 0.12); }
  .sg-badge.v-blocked { color: var(--sg-rose); border-color: rgb(251 113 133 / 0.5); background: rgb(251 113 133 / 0.12); }
  .sg-badge.v-error, .sg-badge.v-neutral { color: var(--sg-muted); background: var(--sg-panel-2); }

  .sg-btn { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; font: inherit; font-size: 12.5px; font-weight: 700; color: #04211c; background: var(--sg-accent); border: 1px solid transparent; border-radius: 10px; padding: 8px 13px; text-decoration: none; }
  .sg-btn.sg-sm { padding: 6px 11px; font-size: 12px; }
  .sg-btn.sg-ghost { background: transparent; color: var(--sg-muted); border-color: var(--sg-border); }
  .sg-btn.sg-danger { background: var(--sg-rose); color: #2a0510; }
  .sg-admin[data-theme="light"] .sg-btn { color: #ffffff; }
  .sg-btn:hover { filter: brightness(1.06); }

  .sg-filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 0 0 14px; }
  .sg-filters label { font-size: 11.5px; color: var(--sg-muted); display: inline-flex; gap: 6px; align-items: center; }
  .sg-input, .sg-select { background: var(--sg-bg-2); color: var(--sg-text); border: 1px solid var(--sg-border); border-radius: 10px; padding: 7px 10px; font: inherit; font-size: 12.5px; }
  .sg-presets { display: flex; gap: 6px; flex-wrap: wrap; }
  .sg-presets a { font-size: 12px; text-decoration: none; color: var(--sg-muted); border: 1px solid var(--sg-border); border-radius: 999px; padding: 5px 11px; }
  .sg-presets a:hover { color: var(--sg-text); background: var(--sg-panel-2); }

  .sg-empty { text-align: center; padding: 34px 16px; color: var(--sg-muted); }
  .sg-empty h3 { color: var(--sg-text); margin: 0 0 6px; font-size: 15px; }

  .sg-checklist { list-style: none; margin: 0; padding: 0; }
  .sg-checklist li { display: flex; justify-content: space-between; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--sg-border); font-size: 13px; }
  .sg-checklist li:last-child { border-bottom: none; }

  .sg-alert-row { display: flex; flex-direction: column; gap: 4px; padding: 10px 0; border-bottom: 1px solid var(--sg-border); }
  .sg-alert-row:last-child { border-bottom: none; }
  .sg-alert-head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }

  .sg-settings { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; margin-top: 8px; }
  .sg-settings label { display: inline-flex; gap: 7px; align-items: center; font-size: 13px; color: var(--sg-muted); }
  .sg-settings input[type="checkbox"] { width: 15px; height: 15px; accent-color: var(--sg-accent); }

  /* side panel */
  .sg-panel-overlay { position: fixed; inset: 0; background: rgb(0 0 0 / 0.5); display: flex; justify-content: flex-end; z-index: 60; }
  .sg-panel-overlay[hidden] { display: none; }
  .sg-side { width: min(520px, 100%); height: 100%; overflow-y: auto; background: var(--sg-bg-2); border-left: 1px solid var(--sg-border); padding: 18px; }
  .sg-side h2 { margin: 0 0 4px; font-size: 16px; }
  .sg-side dl { display: grid; grid-template-columns: 110px 1fr; gap: 6px 12px; margin: 14px 0; font-size: 13px; }
  .sg-side dt { color: var(--sg-muted); }
  .sg-side dd { margin: 0; word-break: break-word; }
  .sg-side-head { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }

  /* toasts + alert dialog */
  .sg-toasts { position: fixed; right: 16px; bottom: 16px; z-index: 70; display: flex; flex-direction: column; gap: 10px; width: min(360px, calc(100vw - 32px)); }
  .sg-toast { background: var(--sg-panel); border: 1px solid var(--sg-border); border-radius: 14px; padding: 12px 14px; box-shadow: var(--sg-shadow); }
  .sg-toast.v-unverified { border-color: rgb(251 191 36 / 0.55); }
  .sg-toast .sg-toast-head { display: flex; justify-content: space-between; gap: 8px; align-items: center; font-size: 11.5px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em; color: var(--sg-amber); }
  .sg-toast .sg-toast-body { font-size: 13px; margin-top: 6px; word-break: break-word; }
  .sg-toast .sg-toast-actions { display: flex; gap: 8px; margin-top: 10px; }
  .sg-x { background: transparent; border: none; color: var(--sg-muted); font-size: 17px; line-height: 1; cursor: pointer; padding: 0 4px; }

  .sg-dialog-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.6); display: flex; align-items: center; justify-content: center; z-index: 80; padding: 16px; }
  .sg-dialog-backdrop[hidden] { display: none; }
  .sg-dialog { width: min(520px, 100%); background: var(--sg-panel); border: 1px solid rgb(251 113 133 / 0.55); border-radius: 18px; padding: 20px; box-shadow: var(--sg-shadow); }
  .sg-dialog h2 { margin: 0 0 4px; font-size: 17px; color: var(--sg-rose); display: flex; align-items: center; gap: 8px; }
  .sg-dialog .sg-dialog-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
  .sg-kv { display: grid; grid-template-columns: 92px 1fr; gap: 6px 12px; margin: 12px 0 0; font-size: 13.5px; }
  .sg-kv dt { color: var(--sg-muted); }
  .sg-kv dd { margin: 0; word-break: break-word; }

  @media (max-width: 560px) {
    .sg-admin { padding: 12px 10px 40px; }
    .sg-title h1 { font-size: 17px; }
    .sg-subject { max-width: 160px; }
  }
  @media (max-width: 780px) {
    .sg-console { grid-template-columns: 1fr; gap: 12px; }
    .sg-sidebar { position: static; padding: 8px; }
    .sg-sidebar-brand { padding-bottom: 9px; }
    .sg-sidebar-nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
</style>`;

/* ---------------------------------------------------------------- app HTML */

export type AdminRole = "admin" | "viewer";
export type AdminTab = "overview" | "activity" | "links" | "settings";

export interface AdminFilters {
  provider: string;
  verdict: string;
  from: string;
  to: string;
  q: string;
  account: string;
  offset: number;
}

export interface AdminAppOptions {
  db: GatewayDb;
  now: Date;
  role: AdminRole;
  previewViewer: boolean;
  tab: AdminTab;
  days: number;
  filters: AdminFilters;
}

const ACTIVITY_LIMIT = 50;

function verdictBadge(v: string): string {
  const cls =
    v === "SAFE" ? "v-safe" : v === "UNVERIFIED" ? "v-unverified" : v === "BLOCKED" ? "v-blocked" : "v-neutral";
  return `<span class="sg-badge ${cls}">${esc(v)}</span>`;
}

const ACTION_LABEL: Record<string, string> = {
  none: "No action",
  labeled: "Labeled",
  moved_to_spam: "Moved to spam",
  protected_copy: "Protected copy",
  restored: "Restored",
};

function deltaHtml(current: number, previous: number, label: string): string {
  const diff = current - previous;
  const cls = diff > 0 ? "up" : diff < 0 ? "down" : "flat";
  const sign = diff > 0 ? "+" : "";
  return `<span class="sg-delta ${cls}">${sign}${diff} vs previous ${esc(label)}</span>`;
}

export function renderAdminApp(opts: AdminAppOptions): string {
  const { db, now, role, previewViewer, tab, days, filters } = opts;
  const isAdmin = role === "admin" && !previewViewer;
  const providerFilter =
    filters.provider === "gmail" || filters.provider === "outlook"
      ? (filters.provider as "gmail" | "outlook")
      : undefined;
  const stats = db.mailStats(days, now, providerFilter);
  const alerts = db.mailLatestAlerts(5);
  const latestId = db.listMailEvents({ limit: 1 })[0]?.id ?? 0;
  const unread = db.unreadMailCount();
  const storeSubjects = db.getSetting("store_subjects", process.env.STORE_SUBJECTS === "0" ? "0" : "1") === "1";
  const popupVerdicts = db.getSetting("popup_verdicts", "BLOCKED,UNVERIFIED");
  const retentionDays = Math.max(1, Number(process.env.EVENT_RETENTION_DAYS) || 30);

  const since24 = new Date(now.getTime() - DAY_LABELS_DAYS).toISOString();
  const since48 = new Date(now.getTime() - 2 * DAY_LABELS_DAYS).toISOString();
  const last24 = db.countMailEvents({ from: since24, provider: providerFilter });
  const prev24 = db.countMailEvents({ from: since48, provider: providerFilter }) - last24;

  const qs = (extra: Record<string, string | number | undefined>): string => {
    const params = new URLSearchParams();
    if (days) params.set("days", String(days));
    for (const [k, v] of Object.entries(extra)) {
      if (v !== undefined && v !== "" && v !== null) params.set(k, String(v));
    }
    const s = params.toString();
    return s ? `?${s}` : "";
  };
  const tabHref = (t: AdminTab) => `/admin/mail${qs({ tab: t })}`;
  const activityFilters: Record<string, string | number | undefined> = {
    tab: "activity",
    provider: filters.provider,
    verdict: filters.verdict,
    from: filters.from,
    to: filters.to,
    q: filters.q,
    account: isAdmin ? filters.account : undefined,
  };

  // ---- summary cards
  const cards = [
    { label: "Scanned", value: stats.totals.scanned, cls: "", delta: deltaHtml(stats.totals.scanned, stats.previous.scanned, `${days} days`) },
    { label: "Safe", value: stats.totals.safe, cls: "v-safe", delta: deltaHtml(stats.totals.safe, stats.previous.safe, `${days} days`) },
    { label: "Needs review", value: stats.totals.unverified, cls: "v-review", delta: deltaHtml(stats.totals.unverified, stats.previous.unverified, `${days} days`) },
    { label: "Blocked", value: stats.totals.blocked, cls: "v-blocked", delta: deltaHtml(stats.totals.blocked, stats.previous.blocked, `${days} days`) },
    { label: "Last 24h", value: last24, cls: "", delta: deltaHtml(last24, prev24, "24h") },
  ]
    .map(
      (c) =>
        `<div class="sg-card ${c.cls}"><div class="n">${c.value}</div><div class="l">${esc(c.label)}</div>${c.delta}</div>`
    )
    .join("");

  const legend = `
    <ul class="sg-legend" role="list">
      <li><button type="button" data-legend="safe" aria-pressed="true"><span class="sg-swatch seg-safe"></span>Safe</button></li>
      <li><button type="button" data-legend="unverified" aria-pressed="true"><span class="sg-swatch seg-unverified"></span>Needs review</button></li>
      <li><button type="button" data-legend="blocked" aria-pressed="true"><span class="sg-swatch seg-blocked"></span>Blocked</button></li>
    </ul>`;

  // Provider filter for the Overview (Gmail / Outlook / all).
  const overviewProviderSwitch = `
    <div class="sg-presets">
      <a href="/admin/mail${qs({ tab: "overview", days })}"${!providerFilter ? ' aria-current="page"' : ""}>All providers</a>
      <a href="/admin/mail${qs({ tab: "overview", days, provider: "gmail" })}"${providerFilter === "gmail" ? ' aria-current="page"' : ""}>Gmail</a>
      <a href="/admin/mail${qs({ tab: "overview", days, provider: "outlook" })}"${providerFilter === "outlook" ? ' aria-current="page"' : ""}>Outlook</a>
    </div>`;

  const overview = `
    ${overviewProviderSwitch}
    <section class="sg-cards">${cards}</section>
    <div class="sg-panel">
      <h2>Messages per day <span class="sg-sub">last ${days} days</span></h2>
      ${legend}
      ${stackedBarsSvg(stats.perDay)}
    </div>
    <div class="sg-grid-2">
      <div class="sg-panel">
        <h2>Verdict split</h2>
        ${donutSvg(stats.totals)}
        <ul class="sg-checklist">
          <li><span>Safe</span><strong>${stats.totals.safe}</strong></li>
          <li><span>Needs review</span><strong>${stats.totals.unverified}</strong></li>
          <li><span>Blocked</span><strong>${stats.totals.blocked}</strong></li>
          <li><span>Errors</span><strong>${stats.totals.error}</strong></li>
        </ul>
      </div>
      <div class="sg-stack">
        <div class="sg-panel">
          <h2>What the guard did</h2>
          ${actionBarsSvg(stats.actions, (a) => ACTION_LABEL[a] || a)}
        </div>
        <div class="sg-panel">
          <h2>Latest alerts <span class="sg-sub">last 5 non-safe</span></h2>
          ${
            alerts.length
              ? alerts
                  .map(
                    (e) => `
            <div class="sg-alert-row">
              <div class="sg-alert-head">
                ${verdictBadge(e.verdict)}
                <span class="sg-mono">${esc(e.senderDisplay || e.senderDomain || "unknown sender")}</span>
                ${e.linkCount ? `<span class="sg-muted">${e.linkCount} link(s)</span>` : ""}
              </div>
              <div class="sg-subject">${esc(e.subject || "(no subject stored)")}</div>
              <div><button type="button" class="sg-btn sg-ghost sg-sm" data-view-links="${e.id}" data-sender="${esc(
                      e.senderDisplay || e.senderDomain || ""
                    )}" data-subject="${esc(e.subject || "")}" data-verdict="${esc(e.verdict)}" data-action="${esc(
                      e.action
                    )}" data-message-ref="${esc(e.messageRef)}" data-link-count="${e.linkCount}">View links</button></div>
            </div>`
                  )
                  .join("")
              : `<p class="sg-muted">No alerts yet.</p>`
          }
        </div>
      </div>
    </div>
    <div class="sg-panel">
        <h2>Senders that need attention <span class="sg-sub">top 6, needs review + blocked</span></h2>
        ${
          stats.topSenders.length
            ? `<div class="sg-table-wrap"><table class="sg-table"><thead><tr><th>Sender domain</th><th>Needs review</th><th>Blocked</th><th>Total</th></tr></thead><tbody>${stats.topSenders
                .map(
                  (s) =>
                    `<tr><td class="sg-mono">${esc(s.domain)}</td><td>${s.needsReview}</td><td>${s.blocked}</td><td>${s.needsReview + s.blocked}</td></tr>`
                )
                .join("")}</tbody></table></div>`
            : `<p class="sg-muted">Nothing flagged in this range.</p>`
        }
    </div>
    <p class="sg-muted">
      Events older than ${retentionDays} days are deleted automatically. Aggregates are computed in SQL — the page never downloads every row.
    </p>`;

  // ---- activity tab
  const list = db.listMailEvents({
    provider: (filters.provider || undefined) as any,
    verdict: (filters.verdict || undefined) as any,
    from: filters.from || undefined,
    to: filters.to || undefined,
    q: filters.q || undefined,
    accountPrefix: isAdmin && filters.account ? filters.account : undefined,
    limit: ACTIVITY_LIMIT,
    offset: filters.offset,
  });
  const total = db.countMailEvents({
    provider: (filters.provider || undefined) as any,
    verdict: (filters.verdict || undefined) as any,
    from: filters.from || undefined,
    to: filters.to || undefined,
    q: filters.q || undefined,
    accountPrefix: isAdmin && filters.account ? filters.account : undefined,
  });

  const providerOptions = [
    { v: "", l: "All providers" },
    { v: "gmail", l: "Gmail" },
    { v: "outlook", l: "Outlook" },
  ]
    .map((o) => `<option value="${esc(o.v)}"${filters.provider === o.v ? " selected" : ""}>${esc(o.l)}</option>`)
    .join("");
  const verdictOptions = [{ v: "", l: "All verdicts" }, { v: "SAFE", l: "Safe" }, { v: "UNVERIFIED", l: "Needs review" }, { v: "BLOCKED", l: "Blocked" }, { v: "ERROR", l: "Error" }]
    .map((o) => `<option value="${esc(o.v)}"${filters.verdict === o.v ? " selected" : ""}>${esc(o.l)}</option>`)
    .join("");
  const accountOptions = [
    `<option value="">All mailboxes</option>`,
    ...stats.accounts.map(
      (a) => `<option value="${esc(a.prefix)}"${filters.account === a.prefix ? " selected" : ""}>${esc(mailboxLabel(a.prefix))} (${a.count})</option>`
    ),
  ].join("");

  const preset = (label: string, fromDays: number | null) => {
    if (fromDays === null) {
      return `<a href="/admin/mail${qs({ tab: "activity" })}">All time</a>`;
    }
    const from = new Date(now.getTime() - fromDays * DAY_LABELS_DAYS).toISOString().slice(0, 10);
    const to = now.toISOString().slice(0, 10);
    return `<a href="/admin/mail${qs({ tab: "activity", from, to })}">Last ${fromDays} days</a>`;
  };

  const rows = list
    .map(
      (e) => `
    <tr class="sg-row${e.isRead ? "" : " is-unread"}" id="sg-row-${e.id}" data-id="${e.id}" data-verdict="${esc(e.verdict)}" data-provider="${esc(
        e.provider
      )}">
      <td class="sg-muted">${e.isRead ? "" : `<span class="sg-dot" aria-label="Unread"></span>`}${esc(new Date(e.createdAt).toLocaleString())}</td>
      <td><span class="sg-badge v-neutral">${e.provider === "gmail" ? "Gmail" : "Outlook"}</span></td>
      <td class="sg-mono sg-muted">${esc(mailboxLabel(e.accountHash.slice(0, 6)))}</td>
      <td>${esc(e.senderDisplay || e.senderDomain || "(unknown sender)")}${
        e.senderDisplay && e.senderDomain ? `<span class="sg-sub-line sg-mono">${esc(e.senderDomain)}</span>` : ""
      }</td>
      <td class="sg-subject">${esc(e.subject || (storeSubjects ? "(no subject)" : "(subjects not stored)"))}</td>
      <td>${verdictBadge(e.verdict)}</td>
      <td class="sg-muted">${esc(ACTION_LABEL[e.action] || e.action)}</td>
      <td class="sg-muted">${e.linkCount}</td>
      <td><button type="button" class="sg-btn sg-ghost sg-sm" data-view-links="${e.id}" data-sender="${esc(
        e.senderDisplay || e.senderDomain || ""
      )}" data-subject="${esc(e.subject || "")}" data-verdict="${esc(e.verdict)}" data-action="${esc(e.action)}" data-message-ref="${esc(
        e.messageRef
      )}" data-link-count="${e.linkCount}">View links</button></td>
    </tr>`
    )
    .join("");

  const activeFilterChips: string[] = [];
  if (filters.provider) activeFilterChips.push(`provider: ${esc(filters.provider)}`);
  if (filters.verdict) activeFilterChips.push(`verdict: ${esc(filters.verdict)}`);
  if (filters.from || filters.to) activeFilterChips.push(`dates: ${esc(filters.from || "…")} → ${esc(filters.to || "…")}`);
  if (filters.q) activeFilterChips.push(`search: ${esc(filters.q)}`);
  if (isAdmin && filters.account) activeFilterChips.push(esc(mailboxLabel(filters.account)));

  const showMore =
    filters.offset + ACTIVITY_LIMIT < total
      ? `<p><a class="sg-btn sg-ghost sg-sm" href="/admin/mail${qs({ ...activityFilters, offset: filters.offset + ACTIVITY_LIMIT })}">Show more</a> <span class="sg-muted">showing ${list.length} of ${total}</span></p>`
      : `<p class="sg-muted">Showing ${list.length} of ${total}</p>`;

  const activity = `
    <form class="sg-panel" method="get" action="/admin/mail">
      <input type="hidden" name="tab" value="activity" />
      <input type="hidden" name="days" value="${days}" />
      <div class="sg-filters">
        <label>Provider <select class="sg-select" name="provider">${providerOptions}</select></label>
        <label>Verdict <select class="sg-select" name="verdict">${verdictOptions}</select></label>
        <label>From <input class="sg-input" type="date" name="from" value="${esc(filters.from)}" /></label>
        <label>To <input class="sg-input" type="date" name="to" value="${esc(filters.to)}" /></label>
        <label>Search <input class="sg-input" type="search" name="q" value="${esc(filters.q)}" placeholder="sender or subject" /></label>
        ${isAdmin ? `<label>Mailbox <select class="sg-select" name="account">${accountOptions}</select></label>` : ""}
        <button type="submit" class="sg-btn sg-sm">Apply</button>
        <a class="sg-btn sg-ghost sg-sm" href="/admin/mail${qs({ tab: "activity" })}">Reset</a>
      </div>
      <div class="sg-presets">${preset("Last 7 days", 7)} ${preset("Last 14 days", 14)} ${preset("Last 30 days", 30)} ${preset("All time", null)}</div>
    </form>
    <div class="sg-filters">
      ${isAdmin ? `<button type="button" class="sg-btn sg-sm" data-mark-read>Mark all read</button><button type="button" class="sg-btn sg-ghost sg-sm" id="sg-export">Export CSV</button>` : ""}
      <button type="button" class="sg-btn sg-ghost sg-sm" id="sg-notify">Enable desktop notifications</button>
    </div>
    <div class="sg-panel">
      <h2>History <span class="sg-sub">${activeFilterChips.length ? esc(activeFilterChips.join(" · ")) : "no filters"}</span></h2>
      ${
        list.length
          ? `<div class="sg-table-wrap"><table class="sg-table"><thead><tr><th>Time</th><th>Provider</th><th>Mailbox</th><th>Sender</th><th>Subject</th><th>Verdict</th><th>Action</th><th>Links</th><th></th></tr></thead><tbody id="sg-tbody">${rows}</tbody></table></div>`
          : `<div class="sg-empty"><h3>No mail events match these filters</h3><p>Try a wider date range, or reset the filters.</p><a class="sg-btn sg-sm" href="/admin/mail${qs({ tab: "activity" })}">Reset filters</a></div>`
      }
      ${showMore}
    </div>`;

  // ---- links tab (admin only)
  const linkRows = db
    .recentLinks(50)
    .map((l) => {
      let display = l.url;
      try {
        display = new URL(l.url).hostname + new URL(l.url).pathname;
      } catch {
        /* keep raw */
      }
      const truncated = display.length > 56 ? display.slice(0, 56) + "…" : display;
      const badge =
        l.status === "SAFE" ? "v-safe" : l.status === "BLOCKED" ? "v-blocked" : l.status === "UNVERIFIED" ? "v-unverified" : "v-neutral";
      return `<tr>
        <td class="sg-mono" title="${esc(l.url)}">${esc(truncated)}</td>
        <td><span class="sg-badge ${badge}">${esc(l.status)}</span></td>
        <td class="sg-muted sg-mono">${esc(l.messageRef)}</td>
        <td class="sg-muted">${esc(new Date(l.createdAt).toLocaleString())}</td>
        <td>
          <form method="post" action="/admin/links/${encodeURIComponent(l.id)}/override" class="sg-filters">
            <select name="status" class="sg-select">
              <option value="SAFE"${l.status === "SAFE" ? " selected" : ""}>SAFE</option>
              <option value="BLOCKED"${l.status === "BLOCKED" ? " selected" : ""}>BLOCKED</option>
              <option value="UNVERIFIED"${l.status === "UNVERIFIED" ? " selected" : ""}>UNVERIFIED</option>
            </select>
            <input type="hidden" name="next" value="/admin/mail?tab=links" />
            <button type="submit" class="sg-btn sg-sm">Override</button>
          </form>
        </td>
      </tr>`;
    })
    .join("");

  const linksTab = isAdmin
    ? `
    <div class="sg-panel">
      <h2>Recent links <span class="sg-sub">joined to mail by message reference</span></h2>
      ${
        linkRows
          ? `<div class="sg-table-wrap"><table class="sg-table"><thead><tr><th>Destination</th><th>Status</th><th>Message</th><th>Created</th><th>Override</th></tr></thead><tbody>${linkRows}</tbody></table></div>`
          : `<div class="sg-empty"><h3>No links yet</h3><p>Links appear here once a scanned message references them.</p></div>`
      }
    </div>`
    : "";

  const settingsTab = isAdmin
    ? `
    <div class="sg-panel" id="mail-settings">
      <h2>Mail settings</h2>
      <form method="post" action="/admin/mail/settings" class="sg-settings">
        <label><input type="checkbox" name="store_subjects" ${storeSubjects ? "checked" : ""} /> Store subjects</label>
        <label><input type="checkbox" name="popup_blocked" ${popupVerdicts.includes("BLOCKED") ? "checked" : ""} /> Pop-up for BLOCKED</label>
        <label><input type="checkbox" name="popup_unverified" ${popupVerdicts.includes("UNVERIFIED") ? "checked" : ""} /> Pop-up for UNVERIFIED</label>
        <button type="submit" class="sg-btn sg-sm">Save settings</button>
      </form>
      <p class="sg-muted">When "Store subjects" is off, only the sender domain is kept. Blocklist and allowlist remain on the <a href="/admin">Links admin page</a>.</p>
    </div>`
    : "";

  const body =
    tab === "overview" ? overview : tab === "activity" ? activity : tab === "settings" ? (isAdmin ? settingsTab : overview) : isAdmin ? linksTab : overview;

  const rangeSwitch = `
    <div class="sg-presets">
      <a href="/admin/mail${qs({ tab, days: 7 })}"${days === 7 ? ' aria-current="page"' : ""}>7 days</a>
      <a href="/admin/mail${qs({ tab, days: 14 })}"${days === 14 ? ' aria-current="page"' : ""}>14 days</a>
      <a href="/admin/mail${qs({ tab, days: 30 })}"${days === 30 ? ' aria-current="page"' : ""}>30 days</a>
    </div>`;

  const viewerToggle =
    role === "admin"
      ? `<a class="sg-btn sg-ghost sg-sm" href="/admin/mail${qs({ tab, viewer: previewViewer ? "0" : "1" })}">${
          previewViewer ? "Exit viewer preview" : "View as viewer"
        }</a>`
      : "";

  const activityCount = unread > 0 ? `<span class="sg-count" id="sg-unread">${unread}</span>` : `<span class="sg-count" id="sg-unread" hidden>0</span>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Mail Activity · Online Safety Guard Admin</title>
<meta name="robots" content="noindex, nofollow" />
${SG_ADMIN_CSS}
</head>
<body>
<div class="sg-admin" id="sg-admin" data-theme="dark"
     data-role="${esc(previewViewer ? "viewer" : role)}"
     data-server-role="${esc(role)}"
     data-preview="${previewViewer ? "1" : "0"}"
     data-since="${latestId}"
     data-popup="${esc(popupVerdicts)}"
     data-tab="${esc(tab)}"
     data-filters-active="${Object.keys(activityFilters).some((k) => k !== "tab" && activityFilters[k]) ? "1" : "0"}"
     data-store-subjects="${storeSubjects ? "1" : "0"}">
  <div class="sg-wrap">
    <header class="sg-header sg-header-stashed">
      <div class="sg-title">
        <h1>Safety Guard Admin</h1>
        <span class="sg-role${role === "admin" ? " is-admin" : ""}">${esc(role === "admin" ? (previewViewer ? "admin · viewer preview" : "admin") : "viewer")}</span>
      </div>
      <div class="sg-header-actions">
        ${rangeSwitch}
        ${viewerToggle}
        <button type="button" class="sg-btn sg-ghost sg-sm" id="sg-theme-stashed" aria-pressed="false">Light theme</button>
      </div>
    </header>

    <div class="sg-console">
      <aside class="sg-sidebar" aria-label="Admin navigation">
        <div class="sg-sidebar-brand"><span class="sg-sidebar-mark">◉</span>Safety Guard</div>
        <div class="sg-sidebar-label">Admin console</div>
        <nav class="sg-sidebar-nav">
          <a class="${tab === "overview" ? "is-active" : ""}" href="${tabHref("overview")}"><span class="sg-sidebar-icon">▦</span>Overview</a>
          <a class="${tab === "activity" ? "is-active" : ""}" href="${tabHref("activity")}"><span class="sg-sidebar-icon">✉</span>Mail activity ${activityCount}</a>
          ${isAdmin ? `<a href="/admin"><span class="sg-sidebar-icon">⊞</span>Allow &amp; block lists</a>
          <a class="${tab === "settings" ? "is-active" : ""}" href="${tabHref("settings")}"><span class="sg-sidebar-icon">⚙</span>Settings</a>` : ""}
        </nav>
      </aside>
      <main class="sg-console-main">
        <header class="sg-header">
          <div class="sg-title"><h1>${tab === "overview" ? "Overview" : tab === "activity" ? "Mail Activity" : tab === "settings" ? "Settings" : "Link Review"}</h1><span class="sg-role${role === "admin" ? " is-admin" : ""}">${esc(role)}</span></div>
          <div class="sg-header-actions">${tab === "overview" || tab === "activity" ? rangeSwitch : ""}${viewerToggle}<button type="button" class="sg-btn sg-ghost sg-sm" id="sg-theme" aria-pressed="false">Light theme</button></div>
        </header>
        ${body}
      </main>
    </div>
  </div>

  <div class="sg-panel-overlay" id="sg-panel" hidden>
    <aside class="sg-side" role="dialog" aria-modal="true" aria-labelledby="sg-panel-title">
      <div class="sg-side-head">
        <h2 id="sg-panel-title">Message details</h2>
        <button type="button" class="sg-x" id="sg-panel-close" aria-label="Close details">×</button>
      </div>
      <dl id="sg-panel-fields"></dl>
      <h3>Links</h3>
      <div id="sg-panel-links" class="sg-muted">Loading…</div>
    </aside>
  </div>

  <div class="sg-toasts" id="sg-toasts" aria-live="polite" aria-relevant="additions"></div>

  <div class="sg-dialog-backdrop" id="sg-dialog" hidden>
    <div class="sg-dialog" role="alertdialog" aria-modal="true" aria-labelledby="sg-dialog-title" aria-describedby="sg-dialog-desc">
      <h2 id="sg-dialog-title">Blocked email</h2>
      <dl class="sg-kv" id="sg-dialog-fields"></dl>
      <div class="sg-dialog-actions">
        <button type="button" class="sg-btn sg-danger" id="sg-dialog-view">View links</button>
        <button type="button" class="sg-btn sg-ghost" id="sg-dialog-mute">Mute for 1 hour</button>
        <button type="button" class="sg-btn sg-ghost" id="sg-dialog-dismiss">Dismiss</button>
      </div>
      <p id="sg-dialog-desc" class="sg-muted">Esc closes this alert.</p>
    </div>
  </div>

  <script src="/admin/admin.js" defer></script>
</div>
</body>
</html>`;
}

/* ---------------------------------------------------------------- client JS */

/**
 * External admin script (CSP blocks inline scripts). It only ever writes
 * attacker-controlled strings through textContent, never innerHTML.
 */
export const ADMIN_APP_JS = `(function () {
  "use strict";
  var root = document.getElementById("sg-admin");
  if (!root) return;

  var serverRole = root.getAttribute("data-server-role") || "viewer";
  var isAdmin = (root.getAttribute("data-role") || "viewer") === "admin";
  var since = parseInt(root.getAttribute("data-since") || "0", 10) || 0;
  var popupVerdicts = (root.getAttribute("data-popup") || "").split(",").filter(Boolean);
  var filtersActive = root.getAttribute("data-filters-active") === "1";
  var POLL_MS = 10000;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function badge(v) {
    var cls = v === "SAFE" ? "v-safe" : v === "UNVERIFIED" ? "v-unverified" : v === "BLOCKED" ? "v-blocked" : "v-neutral";
    return el("span", "sg-badge " + cls, v);
  }

  /* ---- theme ---- */
  var themeBtn = document.getElementById("sg-theme");
  function applyTheme(t) {
    root.setAttribute("data-theme", t);
    if (themeBtn) { themeBtn.textContent = t === "light" ? "Dark theme" : "Light theme"; themeBtn.setAttribute("aria-pressed", t === "light" ? "true" : "false"); }
  }
  try { applyTheme(localStorage.getItem("sg_theme") || "dark"); } catch (e) { applyTheme("dark"); }
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    try { localStorage.setItem("sg_theme", next); } catch (e) {}
    applyTheme(next);
  });

  /* ---- legend toggles ---- */
  var legendState = { safe: true, unverified: true, blocked: true };
  Array.prototype.forEach.call(document.querySelectorAll("[data-legend]"), function (btn) {
    btn.addEventListener("click", function () {
      var key = btn.getAttribute("data-legend");
      legendState[key] = !legendState[key];
      btn.setAttribute("aria-pressed", legendState[key] ? "true" : "false");
      root.classList.toggle("hide-" + key, !legendState[key]);
    });
  });

  /* ---- unread badge ---- */
  function setUnread(n) {
    var b = document.getElementById("sg-unread");
    if (!b) return;
    if (n > 0) { b.hidden = false; b.textContent = String(n); } else { b.hidden = true; b.textContent = "0"; }
  }

  function markRead(ids) {
    if (serverRole !== "admin") return; // readers cannot change data
    fetch("/api/events/read", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(ids && ids.length ? { ids: ids } : {})
    }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && typeof d.unread === "number") setUnread(d.unread); })
      .catch(function () {});
  }

  /* ---- details side panel ---- */
  var panel = document.getElementById("sg-panel");
  var panelFields = document.getElementById("sg-panel-fields");
  var panelLinks = document.getElementById("sg-panel-links");
  var lastFocus = null;

  function defang(u) {
    return String(u).replace(/^https?:\\/\\//i, function (m) { return m.replace("://", "[:]//"); }).replace(/\\./g, "[.]");
  }

  function openPanel(btn) {
    lastFocus = btn;
    var sender = btn.getAttribute("data-sender") || "";
    var subject = btn.getAttribute("data-subject") || "";
    var verdict = btn.getAttribute("data-verdict") || "";
    var action = btn.getAttribute("data-action") || "";
    var links = btn.getAttribute("data-link-count") || "0";
    var ref = btn.getAttribute("data-message-ref") || "";
    clear(panelFields);
    [["Sender", sender], ["Subject", subject || "(no subject stored)"], ["Verdict", verdict], ["Action", action], ["Links", links + " link(s)"]].forEach(function (pair) {
      panelFields.appendChild(el("dt", null, pair[0]));
      var dd = el("dd");
      if (pair[0] === "Verdict") dd.appendChild(badge(pair[1])); else dd.textContent = pair[1];
      panelFields.appendChild(dd);
    });
    clear(panelLinks);
    panelLinks.appendChild(el("p", "sg-muted", "Loading…"));
    panel.hidden = false;
    if (panel.querySelector("#sg-panel-close")) panel.querySelector("#sg-panel-close").focus();

    fetch("/api/message/" + encodeURIComponent(ref) + "/verdict", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        clear(panelLinks);
        var ul = el("ul", "sg-checklist");
        var list = (data && data.links) || [];
        if (!list.length) { panelLinks.appendChild(el("p", "sg-muted", "No links recorded for this message.")); return; }
        list.forEach(function (l) {
          var li = el("li");
          li.appendChild(el("span", "sg-mono", defang(l.url)));
          li.appendChild(badge(l.status));
          ul.appendChild(li);
        });
        panelLinks.appendChild(ul);
        if (isAdmin) {
          var form = document.createElement("form");
          form.method = "post"; form.action = "/admin/links/" + encodeURIComponent(list[0].id) + "/override"; form.className = "sg-filters";
          var sel = document.createElement("select"); sel.name = "status"; sel.className = "sg-select";
          ["SAFE", "BLOCKED", "UNVERIFIED"].forEach(function (v) { var o = document.createElement("option"); o.value = v; if (v === list[0].status) o.selected = true; o.textContent = v; sel.appendChild(o); });
          var next = document.createElement("input"); next.type = "hidden"; next.name = "next"; next.value = "/admin/mail?tab=activity";
          var submit = document.createElement("button"); submit.type = "submit"; submit.className = "sg-btn sg-sm"; submit.textContent = "Override first link";
          form.appendChild(sel); form.appendChild(next); form.appendChild(submit);
          panelLinks.appendChild(form);
        }
      })
      .catch(function () { clear(panelLinks); panelLinks.appendChild(el("p", "sg-muted", "Could not load links.")); });
  }

  function closePanel() {
    panel.hidden = true;
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  var panelClose = document.getElementById("sg-panel-close");
  if (panelClose) panelClose.addEventListener("click", closePanel);
  if (panel) panel.addEventListener("click", function (ev) { if (ev.target === panel) closePanel(); });

  /* ---- notifications (opt-in, no sound) ---- */
  function notify(title, body) {
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    try { if (localStorage.getItem("sg_notify") === "1") new Notification(title, { body: body }); } catch (e) {}
  }

  /* ---- blocked alert dialog ---- */
  var dialog = document.getElementById("sg-dialog");
  var dialogFields = document.getElementById("sg-dialog-fields");
  var dialogQueue = [];
  var currentAlert = null;

  function dialogOpen() { return dialog && !dialog.hidden; }

  function showDialog(ev) {
    currentAlert = ev;
    clear(dialogFields);
    [["Sender", ev.senderDisplay || ev.senderDomain || "unknown"], ["Subject", ev.subject || "(no subject stored)"], ["Links", (ev.linkCount || 0) + " link(s)"]].forEach(function (pair) {
      dialogFields.appendChild(el("dt", null, pair[0]));
      dialogFields.appendChild(el("dd", null, pair[1]));
    });
    dialog.hidden = false;
    var view = document.getElementById("sg-dialog-view");
    if (view) view.focus();
    notify("Blocked email", (ev.senderDisplay || ev.senderDomain || "unknown") + " — " + (ev.subject || "(no subject)"));
  }

  function closeDialog() {
    if (dialog) dialog.hidden = true;
    currentAlert = null;
    if (dialogQueue.length) showDialog(dialogQueue.shift());
  }
  var dialogView = document.getElementById("sg-dialog-view");
  var dialogMute = document.getElementById("sg-dialog-mute");
  var dialogDismiss = document.getElementById("sg-dialog-dismiss");
  if (dialogDismiss) dialogDismiss.addEventListener("click", closeDialog);
  if (dialogView) dialogView.addEventListener("click", function () {
    var ev = currentAlert;
    var ref = ev && ev.messageRef ? ev.messageRef : "";
    closeDialog();
    if (ref) fetch("/api/message/" + encodeURIComponent(ref) + "/verdict", { headers: { "Accept": "application/json" } }).then(function (r) { return r.json(); }).then(function (data) {
      var list = (data && data.links) || [];
      if (!list.length) return;
      var row = document.getElementById("sg-row-" + ev.id);
      if (row) { row.scrollIntoView({ behavior: "smooth", block: "center" }); }
    }).catch(function () {});
  });
  if (dialogMute) dialogMute.addEventListener("click", function () {
    try { localStorage.setItem("sg_mute_blocked_until", String(Date.now() + 3600000)); } catch (e) {}
    closeDialog();
  });
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") { if (dialogOpen()) closeDialog(); else if (panel && !panel.hidden) closePanel(); }
  });

  /* ---- unverified toasts (auto-close ~10s, pause on hover) ---- */
  var toastBox = document.getElementById("sg-toasts");
  function toast(ev) {
    var box = el("div", "sg-toast v-unverified");
    var head = el("div", "sg-toast-head");
    head.appendChild(el("span", null, "Needs review"));
    var x = el("button", "sg-x", "\\u00d7"); x.setAttribute("aria-label", "Dismiss"); x.type = "button";
    head.appendChild(x);
    box.appendChild(head);
    box.appendChild(el("div", "sg-toast-body", (ev.senderDisplay || ev.senderDomain || "unknown") + " — " + (ev.subject || "(no subject stored)")));
    var actions = el("div", "sg-toast-actions");
    var view = el("button", "sg-btn sg-sm", "View links"); view.type = "button";
    view.addEventListener("click", function () { var r = document.getElementById("sg-row-" + ev.id); if (r) r.scrollIntoView({ behavior: "smooth", block: "center" }); box.remove(); });
    actions.appendChild(view); box.appendChild(actions);
    var timer = window.setTimeout(function () { box.remove(); }, 10000);
    box.addEventListener("mouseenter", function () { window.clearTimeout(timer); });
    box.addEventListener("mouseleave", function () { timer = window.setTimeout(function () { box.remove(); }, 10000); });
    x.addEventListener("click", function () { box.remove(); });
    toastBox.appendChild(box);
    notify("Needs review", (ev.senderDisplay || ev.senderDomain || "unknown") + " — " + (ev.subject || "(no subject stored)"));
  }

  function handleNew(events) {
    var qualifying = events.filter(function (e) { return popupVerdicts.indexOf(e.verdict) !== -1; });
    if (!qualifying.length) return;
    var mutedUntil = 0;
    try { mutedUntil = parseInt(localStorage.getItem("sg_mute_blocked_until") || "0", 10) || 0; } catch (e) {}
    qualifying.forEach(function (e) {
      if (e.verdict === "BLOCKED") {
        if (Date.now() < mutedUntil) return;
        if (dialogOpen()) dialogQueue.push(e); else showDialog(e);
      } else {
        toast(e);
      }
    });
  }

  /* ---- polling ---- */
  function poll() {
    fetch("/api/events?since=" + since, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
      .then(function (data) {
        var events = (data && data.events) || [];
        if (data && typeof data.unread === "number") setUnread(data.unread);
        if (!events.length) return;
        since = events.reduce(function (m, e) { return Math.max(m, e.id); }, since);
        handleNew(events);
      })
      .catch(function () {});
  }
  window.setInterval(poll, POLL_MS);

  /* ---- row actions (delegated) ---- */
  document.addEventListener("click", function (ev) {
    var t = ev.target;
    if (!t || !t.closest) return;
    var viewBtn = t.closest("[data-view-links]");
    if (viewBtn) { openPanel(viewBtn); return; }
    var markBtn = t.closest("[data-mark-read]");
    if (markBtn) {
      markRead(null);
      Array.prototype.forEach.call(document.querySelectorAll(".sg-row.is-unread"), function (r) { r.classList.remove("is-unread"); });
      var dots = document.querySelectorAll(".sg-row .sg-dot"); Array.prototype.forEach.call(dots, function (d) { d.remove(); });
    }
  });

  /* ---- CSV export (admin only) ---- */
  var exportBtn = document.getElementById("sg-export");
  if (exportBtn && isAdmin) exportBtn.addEventListener("click", function () {
    fetch("/api/events?limit=200", { headers: { "Accept": "application/json" } }).then(function (r) { return r.json(); }).then(function (data) {
      var events = (data && data.events) || [];
      var head = ["id", "created_at", "provider", "sender_domain", "sender_display", "subject", "verdict", "action", "link_count"];
      function cell(v) { var s = v == null ? "" : String(v); return '"' + s.replace(/"/g, '""') + '"'; }
      var lines = [head.join(",")];
      events.forEach(function (e) {
        lines.push([e.id, e.createdAt, e.provider, e.senderDomain, e.senderDisplay, e.subject, e.verdict, e.action, e.linkCount].map(cell).join(","));
      });
      var blob = new Blob([lines.join("\\n")], { type: "text/csv" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = "mail-activity.csv";
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    }).catch(function () {});
  });

  /* ---- desktop notifications opt-in ---- */
  var notifyBtn = document.getElementById("sg-notify");
  if (notifyBtn) notifyBtn.addEventListener("click", function () {
    if (typeof Notification === "undefined") return;
    Notification.requestPermission().then(function (p) {
      try { if (p === "granted") localStorage.setItem("sg_notify", "1"); else localStorage.removeItem("sg_notify"); } catch (e) {}
    });
  });
})();`;
