/* Online Safety Guard - Outlook task pane.
 * Reads the open message's links, checks them against the site's /api/inspect
 * endpoint, shows the verdict, and reports the event to /api/events.
 * No inline scripts; every attacker-controlled value is written with textContent.
 */
(function () {
  "use strict";

  var KEY_SETTING = "SG_ADDIN_KEY";
  var WARN_KEY = "sgWarningBar";
  var POLL_MS = 3000;
  var POLL_MAX = 10; // ~30 seconds
  var MAX_LINKS = 20;
  var OWN_HOST = (typeof location !== "undefined" ? location.hostname : "").toLowerCase();

  var els = {};
  var state = { key: "", ref: null, gatewayUrl: null, running: false, lastVerdict: null };

  function $(id) { return document.getElementById(id); }

  function show(el, on) { if (el) el.hidden = !on; }
  function setText(el, text) { if (el) el.textContent = text == null ? "" : String(text); }

  /* ----------------------------------------------------------- SHA-256 (hex) */

  function sha256Hex(text) {
    // Compact synchronous SHA-256. Kept local so it works in every add-in webview.
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var bytes = [];
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c < 128) bytes.push(c);
      else if (c < 2048) { bytes.push(192 | (c >> 6), 128 | (c & 63)); }
      else { bytes.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63)); }
    }
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (var s = 7; s >= 0; s--) bytes.push((bitLen / Math.pow(2, s * 8)) & 0xff);

    var w = new Array(64);
    for (var off = 0; off < bytes.length; off += 64) {
      for (var t = 0; t < 16; t++) {
        w[t] = (bytes[off + t * 4] << 24) | (bytes[off + t * 4 + 1] << 16) | (bytes[off + t * 4 + 2] << 8) | bytes[off + t * 4 + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c2 = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c2) ^ (b & c2);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c2; c2 = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c2) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    return h.map(function (x) { return ("00000000" + (x >>> 0).toString(16)).slice(-8); }).join("");
  }

  /* ------------------------------------------------------------ link helpers */

  function defang(url) {
    return String(url)
      .replace(/^https:\/\//i, "hxxps://")
      .replace(/^http:\/\//i, "hxxp://")
      .replace(/\./g, "[.]");
  }

  function normalizeLink(raw) {
    if (typeof raw !== "string") return null;
    var value = raw.trim().replace(/[.,;:!?)\]]+$/, "");
    if (!/^https?:\/\//i.test(value)) return null;
    try {
      var u = new URL(value);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      if (u.hostname.toLowerCase() === OWN_HOST) return null; // skip our own domain
      return u.href;
    } catch (e) {
      return null;
    }
  }

  function extractLinks(html) {
    var out = [];
    var seen = {};
    function push(raw) {
      var link = normalizeLink(raw);
      if (!link || seen[link] || out.length >= MAX_LINKS) return;
      seen[link] = true;
      out.push(link);
    }
    try {
      var doc = new DOMParser().parseFromString(html || "", "text/html");
      var anchors = doc.querySelectorAll("a[href]");
      for (var i = 0; i < anchors.length; i++) push(anchors[i].getAttribute("href"));
      var text = doc.body ? doc.body.textContent || "" : "";
      var re = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
      var m;
      while ((m = re.exec(text)) !== null && out.length < MAX_LINKS) push(m[0]);
    } catch (e) {
      /* ignore parse errors */
    }
    return out;
  }

  /* -------------------------------------------------------------- rendering */

  var VERDICT = {
    SAFE: { cls: "sgp-safe", label: "Safe", text: "No threats detected. The links in this email look safe." },
    UNVERIFIED: { cls: "sgp-amber", label: "Needs review", text: "Do not click links unless you are sure." },
    BLOCKED: { cls: "sgp-rose", label: "Blocked", text: "Dangerous - do not click anything." },
    PENDING: { cls: "", label: "Checking\u2026", text: "Inspecting the links in this email\u2026" },
    ERROR: { cls: "sgp-amber", label: "Check failed", text: "Check failed - treat links with care." }
  };

  function linkPill(status) {
    var map = { SAFE: "sgp-safe", BLOCKED: "sgp-rose", UNVERIFIED: "sgp-amber" };
    var span = document.createElement("span");
    span.className = "sgp-pill " + (map[status] || "sgp-neutral");
    span.textContent = status || "PENDING";
    return span;
  }

  function renderLinks(links) {
    var list = els.linkList;
    while (list.firstChild) list.removeChild(list.firstChild);
    if (!links || !links.length) {
      show(els.noLinks, true);
      setText(els.linkCount, "");
      return;
    }
    show(els.noLinks, false);
    setText(els.linkCount, "(" + links.length + ")");
    links.forEach(function (l) {
      var li = document.createElement("li");
      var code = document.createElement("span");
      code.className = "sgp-url";
      code.textContent = defang(l.url); // defanged, never a clickable raw link
      li.appendChild(code);
      li.appendChild(linkPill(l.status));
      list.appendChild(li);
    });
  }

  function renderVerdict(verdict, reason, links, meta) {
    var v = VERDICT[verdict] || VERDICT.ERROR;
    els.verdictBadge.className = "sgp-badge " + v.cls;
    setText(els.verdictBadge, v.label);
    setText(els.verdictText, v.text);
    setText(els.reasonText, reason || "");
    renderLinks(links);
    var total = (links || []).length;
    setText(els.metaText, meta ? meta + " \u00b7 " + total + " link(s) checked" : "");
    show(els.resultPanel, true);
    show(els.failPanel, false);
    state.lastVerdict = verdict;
  }

  /* ------------------------------------------------------------- API calls */

  function apiFetch(path, options) {
    options = options || {};
    options.headers = options.headers || {};
    options.headers["Authorization"] = "Bearer " + state.key;
    options.headers["Accept"] = "application/json";
    if (options.body) options.headers["Content-Type"] = "application/json";
    return fetch(path, options).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (!res.ok) {
          var msg = (data && data.error) || ("HTTP " + res.status);
          throw new Error(msg);
        }
        return data;
      });
    });
  }

  function postEvent(verdict, senderDomain, senderDisplay, subject, linkCount) {
    var mailbox = "";
    try { mailbox = Office.context.mailbox.userProfile.emailAddress || ""; } catch (e) { mailbox = ""; }
    return apiFetch("/api/events", {
      method: "POST",
      body: JSON.stringify({
        provider: "outlook",
        mailbox: mailbox,
        message_ref: state.ref,
        sender_domain: senderDomain,
        sender_display: senderDisplay,
        subject: subject,
        verdict: verdict,
        action: "none",
        link_count: linkCount
      })
    }).catch(function () { /* reporting must never block the user */ });
  }

  function notifyBar(item, verdict) {
    try {
      var messages = item.notificationMessages;
      if (!messages) return;
      messages.removeAsync(WARN_KEY, function () {
        if (verdict === "BLOCKED" || verdict === "UNVERIFIED") {
          messages.addAsync(WARN_KEY, {
            type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
            message: verdict === "BLOCKED"
              ? "Online Safety Guard: DANGEROUS - do not click any links in this email."
              : "Online Safety Guard: check the links before you click - do not click unless you are sure.",
            persistent: true
          });
        }
      });
    } catch (e) { /* notification bar is best-effort */ }
  }

  /* ------------------------------------------------------------ main flow */

  function getItem() {
    try { return Office.context.mailbox.item || null; } catch (e) { return null; }
  }

  function readBodyHtml(item) {
    return new Promise(function (resolve) {
      try {
        item.body.getAsync(Office.CoercionType.Html, function (result) {
          resolve(result && result.status === Office.AsyncResultStatus.Succeeded ? result.value : "");
        });
      } catch (e) {
        resolve("");
      }
    });
  }

  function readBodyText(item) {
    return new Promise(function (resolve) {
      try {
        item.body.getAsync(Office.CoercionType.Text, function (result) {
          resolve(result && result.status === Office.AsyncResultStatus.Succeeded ? result.value : "");
        });
      } catch (e) {
        resolve("");
      }
    });
  }

  var RISK_META = {
    SAFE: { cls: "sgp-safe", label: "Low risk" },
    SUSPICIOUS: { cls: "sgp-amber", label: "Medium risk" },
    DANGEROUS_SCAM: { cls: "sgp-rose", label: "High risk" }
  };

  function analyzeMessage(text, senderDisplay) {
    return apiFetch("/api/analyze-message", {
      method: "POST",
      body: JSON.stringify({ message: text || "", sender: senderDisplay || "", platform: "Outlook / Email" })
    }).catch(function () { return null; });
  }

  function renderMessageRisk(result) {
    if (!result) { show(els.msgRiskPanel, false); return; }
    var meta = RISK_META[result.safetyStatus] || RISK_META.SUSPICIOUS;
    els.msgRiskBadge.className = "sgp-badge " + meta.cls;
    setText(els.msgRiskBadge, meta.label);
    setText(els.msgRiskScore, "Risk score: " + (typeof result.riskScore === "number" ? result.riskScore : "?") + "/100");
    setText(els.msgScamType, result.scamType || "");
    setText(els.msgSummary, result.verdictSummary || "");

    var list = els.msgFlags;
    while (list.firstChild) list.removeChild(list.firstChild);
    var flags = Array.isArray(result.redFlags) ? result.redFlags.slice(0, 6) : [];
    flags.forEach(function (f) {
      var li = document.createElement("li");
      li.className = f.severity === "high" ? "sgp-flag-high" : f.severity === "medium" ? "sgp-flag-medium" : "";
      var b = document.createElement("b");
      b.textContent = (f.flag || "") + ": ";
      li.appendChild(b);
      li.appendChild(document.createTextNode(f.evidence || ""));
      list.appendChild(li);
    });
    show(els.msgRiskPanel, true);
  }

  function pollVerdict() {
    var attempts = 0;
    return new Promise(function (resolve, reject) {
      function tick() {
        attempts++;
        apiFetch("/api/message/" + encodeURIComponent(state.ref) + "/verdict")
          .then(function (data) {
            if (data && data.verdict && data.verdict !== "PENDING") return resolve(data);
            if (attempts >= POLL_MAX) return resolve(data || { verdict: "UNVERIFIED", links: [] });
            setTimeout(tick, POLL_MS);
          })
          .catch(reject);
      }
      tick();
    });
  }

  function runAnalysis() {
    var item = getItem();
    if (!item || !state.key) return;
    if (state.running) return;

    var subject = "";
    var senderEmail = "";
    var senderDisplay = "";
    try {
      subject = item.subject || "";
      var from = item.from || item.sender || {};
      senderEmail = from.emailAddress || "";
      senderDisplay = from.displayName || senderEmail || "";
    } catch (e) { /* keep defaults */ }

    var itemId = "";
    try { itemId = Office.context.mailbox.itemId || item.itemId || ""; } catch (e) { itemId = ""; }
    if (!itemId) {
      showFail("This message could not be identified.");
      return;
    }

    state.running = true;
    state.ref = sha256Hex(String(itemId));
    state.gatewayUrl = null;
    show(els.failPanel, false);
    show(els.resultPanel, true);
    renderVerdict("PENDING", "Checking the links in this email\u2026", [], "");
    setText(els.subStatus, "Checking\u2026");

    show(els.msgRiskPanel, false);

    Promise.all([readBodyHtml(item), readBodyText(item)])
      .then(function (parts) {
        var html = parts[0];
        var text = parts[1];
        var urls = extractLinks(html);
        var msgPromise = analyzeMessage(text, senderDisplay);

        var linkPromise = !urls.length
          ? Promise.resolve({ verdict: "SAFE", links: [], reason: "No links found in this email." })
          : apiFetch("/api/inspect", {
              method: "POST",
              body: JSON.stringify({ message_ref: state.ref, urls: urls })
            }).then(function (created) {
              if (created && created.links && created.links.length) {
                state.gatewayUrl = created.links[0].gateway_url || null;
              }
              return pollVerdict();
            });

        return Promise.all([linkPromise, msgPromise]);
      })
      .then(function (results) {
        var result = results[0];
        var msgResult = results[1];
        var verdict = mapVerdict(result.verdict);
        var links = (result.links || []).map(function (l) {
          return { url: l.url, status: mapVerdict(l.status) };
        });
        renderVerdict(verdict, result.reason || result.verdictReason || "", links, "");
        renderMessageRisk(msgResult);
        setText(els.subStatus, "Done");
        notifyBar(item, verdict);
        postEvent(verdict, domainOf(senderEmail), senderDisplay, subject, links.length);
        state.running = false;
      })
      .catch(function (err) {
        state.running = false;
        showFail(err && err.message ? err.message : "The safety server could not be reached.");
      });
  }

  function mapVerdict(serverVerdict) {
    // gateway verdicts: SAFE | BLOCKED | UNVERIFIED | PENDING
    if (serverVerdict === "SAFE") return "SAFE";
    if (serverVerdict === "BLOCKED") return "BLOCKED";
    if (serverVerdict === "PENDING") return "PENDING";
    return "UNVERIFIED";
  }

  function domainOf(email) {
    var at = String(email || "").lastIndexOf("@");
    return at >= 0 ? String(email).slice(at + 1).toLowerCase() : null;
  }

  function showFail(detail) {
    show(els.resultPanel, false);
    show(els.msgRiskPanel, false);
    show(els.failPanel, true);
    setText(els.failDetail, detail || "Could not reach the safety server.");
    setText(els.subStatus, "Check failed");
    // Report the failure so the dashboard can show it (verdict ERROR).
    postEvent("ERROR", null, null, "", 0);
  }

  /* -------------------------------------------------------------- key flow */

  function loadKey() {
    try { return Office.context.roamingSettings.get(KEY_SETTING) || ""; } catch (e) { return ""; }
  }

  function saveKey(value) {
    try { Office.context.roamingSettings.set(KEY_SETTING, value); Office.context.roamingSettings.saveAsync(); } catch (e) { /* ignore */ }
  }

  function forgetKey() {
    try { Office.context.roamingSettings.remove(KEY_SETTING); Office.context.roamingSettings.saveAsync(); } catch (e) { /* ignore */ }
    state.key = "";
    show(els.keyPanel, true);
    show(els.resultPanel, false);
    show(els.failPanel, false);
    show(els.forgetKeyFoot, false);
    setText(els.keyStatus, "Key removed.");
  }

  function applyKey(key) {
    state.key = key || "";
    var has = Boolean(state.key);
    show(els.keyPanel, !has);
    show(els.forgetKeyFoot, has);
    setText(els.subStatus, has ? "Ready" : "Add-in key required");
    if (has) runAnalysis();
  }

  function wire() {
    els = {
      keyPanel: $("keyPanel"),
      keyInput: $("keyInput"),
      saveKey: $("saveKey"),
      forgetKey: $("forgetKey"),
      forgetKeyFoot: $("forgetKeyFoot"),
      keyStatus: $("keyStatus"),
      resultPanel: $("resultPanel"),
      verdictBadge: $("verdictBadge"),
      verdictText: $("verdictText"),
      reasonText: $("reasonText"),
      linkList: $("linkList"),
      linkCount: $("linkCount"),
      noLinks: $("noLinks"),
      openCheck: $("openCheck"),
      retry: $("retry"),
      retryFail: $("retryFail"),
      failPanel: $("failPanel"),
      failDetail: $("failDetail"),
      metaText: $("metaText"),
      subStatus: $("subStatus"),
      msgRiskPanel: $("msgRiskPanel"),
      msgRiskBadge: $("msgRiskBadge"),
      msgRiskScore: $("msgRiskScore"),
      msgScamType: $("msgScamType"),
      msgSummary: $("msgSummary"),
      msgFlags: $("msgFlags")
    };

    if (els.saveKey) {
      els.saveKey.addEventListener("click", function () {
        var value = (els.keyInput && els.keyInput.value || "").trim();
        if (!value) { setText(els.keyStatus, "Enter the add-in key."); return; }
        saveKey(value);
        setText(els.keyStatus, "Key saved.");
        if (els.keyInput) els.keyInput.value = "";
        applyKey(value);
      });
    }
    [els.forgetKey, els.forgetKeyFoot].forEach(function (btn) {
      if (btn) btn.addEventListener("click", forgetKey);
    });
    if (els.retry) els.retry.addEventListener("click", runAnalysis);
    if (els.retryFail) els.retryFail.addEventListener("click", runAnalysis);
    if (els.openCheck) {
      els.openCheck.addEventListener("click", function () {
        window.open("https://online-safety-guard-web.onrender.com/", "_blank", "noopener,noreferrer");
      });
    }
  }

  function onOfficeReady() {
    wire();
    applyKey(loadKey());
    try {
      Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, function () {
        state.running = false;
        if (state.key) runAnalysis();
      });
    } catch (e) { /* ItemChanged needs pinning + Mailbox 1.5 */ }
  }

  if (typeof Office !== "undefined" && Office.onReady) {
    Office.onReady(function () { onOfficeReady(); });
  } else {
    // Office.js failed to load: still show a usable pane.
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { wire(); setText($("subStatus"), "Office is unavailable in this window."); });
    else { wire(); setText($("subStatus"), "Office is unavailable in this window."); }
  }
})();
