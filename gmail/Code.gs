/**
 * Online Safety Guard — Gmail add-on.
 *
 * Reads the open message's links, checks them against the site's /api/inspect
 * endpoint, shows the verdict as a card, and reports the event to /api/events.
 * Mirrors outlook/taskpane.js, but runs on Google's servers (Apps Script),
 * not in the user's browser — every network call here is server-to-server via
 * UrlFetchApp, so BASE_URL must be a publicly reachable HTTPS URL. It cannot
 * be http://localhost.
 *
 * Setup: see gmail/README.md.
 */

// EDIT THIS after you deploy the server (e.g. to Render).
var BASE_URL = 'https://safety-guard-web-ncra.onrender.com';

var KEY_PROPERTY = 'SG_ADDIN_KEY';
var POLL_INTERVAL_MS = 2000;
var POLL_MAX_ATTEMPTS = 6; // ~12s, kept short so the card renders promptly
var MAX_LINKS = 20;

/* --------------------------------------------------------------- key store */

function getAddinKey_() {
  return PropertiesService.getUserProperties().getProperty(KEY_PROPERTY) || '';
}

function saveAddinKey_(key) {
  PropertiesService.getUserProperties().setProperty(KEY_PROPERTY, key);
}

function forgetAddinKey_() {
  PropertiesService.getUserProperties().deleteProperty(KEY_PROPERTY);
}

/* -------------------------------------------------------------- API calls */

function apiFetch_(path, options) {
  options = options || {};
  var headers = options.headers || {};
  headers['Authorization'] = 'Bearer ' + getAddinKey_();
  headers['Accept'] = 'application/json';
  var params = {
    method: options.method || 'get',
    headers: headers,
    muteHttpExceptions: true,
  };
  if (options.payload) {
    params.contentType = 'application/json';
    params.payload = options.payload;
  }
  var response = UrlFetchApp.fetch(BASE_URL + path, params);
  var code = response.getResponseCode();
  var text = response.getContentText();
  var data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
  if (code < 200 || code >= 300) {
    var msg = (data && data.error) || ('HTTP ' + code);
    throw new Error(msg);
  }
  return data;
}

function postEvent_(payload) {
  try {
    apiFetch_('/api/events', { method: 'post', payload: JSON.stringify(payload) });
  } catch (e) {
    // Reporting must never block the user from seeing their verdict.
  }
}

function pollVerdict_(ref) {
  for (var attempt = 0; attempt < POLL_MAX_ATTEMPTS; attempt++) {
    var data = apiFetch_('/api/message/' + encodeURIComponent(ref) + '/verdict');
    if (data && data.verdict && data.verdict !== 'PENDING') return data;
    if (attempt < POLL_MAX_ATTEMPTS - 1) Utilities.sleep(POLL_INTERVAL_MS);
    else return data;
  }
}

/* ------------------------------------------------------------ link helpers */

function defang_(url) {
  return String(url)
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}

function ownHost_() {
  try { return BASE_URL.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase(); }
  catch (e) { return ''; }
}

function normalizeLink_(raw) {
  if (typeof raw !== 'string') return null;
  var value = raw.trim().replace(/[.,;:!?)\]]+$/, '');
  if (!/^https?:\/\//i.test(value)) return null;
  var hostMatch = /^https?:\/\/([^\/?#]+)/i.exec(value);
  var host = hostMatch ? hostMatch[1].toLowerCase() : '';
  if (!host || host === ownHost_()) return null;
  return value;
}

/** Regex-based extraction (Apps Script has no DOM parser server-side). */
function extractLinks_(html) {
  var out = [];
  var seen = {};
  function push(raw) {
    var link = normalizeLink_(raw);
    if (!link || seen[link] || out.length >= MAX_LINKS) return;
    seen[link] = true;
    out.push(link);
  }
  var hrefRe = /href\s*=\s*["']([^"']+)["']/gi;
  var m;
  while ((m = hrefRe.exec(html || '')) !== null && out.length < MAX_LINKS) push(m[1]);
  var text = String(html || '').replace(/<[^>]*>/g, ' ');
  var urlRe = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
  while ((m = urlRe.exec(text)) !== null && out.length < MAX_LINKS) push(m[0]);
  return out;
}

function sha256Hex_(text) {
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, text, Utilities.Charset.UTF_8);
  return bytes.map(function (b) {
    var v = (b + 256) % 256;
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

function domainOf_(email) {
  var at = String(email || '').lastIndexOf('@');
  return at >= 0 ? String(email).slice(at + 1).toLowerCase() : null;
}

function mapVerdict_(serverVerdict) {
  if (serverVerdict === 'SAFE') return 'SAFE';
  if (serverVerdict === 'BLOCKED') return 'BLOCKED';
  if (serverVerdict === 'PENDING') return 'PENDING';
  return 'UNVERIFIED';
}

/* ------------------------------------------------------------ card builders */

var VERDICT_META = {
  SAFE: { label: 'Safe', color: '#1e8e3e', text: 'No threats detected. The links in this email look safe.' },
  UNVERIFIED: { label: 'Needs review', color: '#b06000', text: 'Do not click links unless you are sure.' },
  BLOCKED: { label: 'Blocked', color: '#c5221f', text: 'Dangerous — do not click anything.' },
  PENDING: { label: 'Still checking…', color: '#5f6368', text: 'Inspection is taking longer than usual. Tap Refresh to check again.' },
  ERROR: { label: 'Check failed', color: '#b06000', text: 'Check failed — treat links with care.' },
};

var RISK_META = {
  SAFE: { label: 'Low risk', color: '#1e8e3e' },
  SUSPICIOUS: { label: 'Medium risk', color: '#b06000' },
  DANGEROUS_SCAM: { label: 'High risk', color: '#c5221f' },
};

/** Message-content analysis (separate from the link check). Never blocks the card on failure. */
function analyzeMessage_(text, senderDisplay) {
  try {
    return apiFetch_('/api/analyze-message', {
      method: 'post',
      payload: JSON.stringify({ message: text || '', sender: senderDisplay || '', platform: 'Gmail' }),
    });
  } catch (e) {
    return null;
  }
}

function keyEntryCard_(status) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextInput()
      .setFieldName('keyInput')
      .setTitle('Add-in key')
      .setHint('Ask whoever runs the server for the Gmail add-on key'))
    .addWidget(CardService.newTextButton()
      .setText('Save key')
      .setOnClickAction(CardService.newAction().setFunctionName('saveKeyAction')));
  if (status) section.addWidget(CardService.newTextParagraph().setText(status));
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Online Safety Guard'))
    .addSection(section)
    .build();
}

function errorCard_(message) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText('<b>Check failed</b><br>' + message))
    .addWidget(CardService.newTextButton()
      .setText('Retry')
      .setOnClickAction(CardService.newAction().setFunctionName('reCheckAction')));
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Online Safety Guard'))
    .addSection(section)
    .build();
}

function resultCard_(verdict, reason, links, gatewayUrl, msgResult) {
  var meta = VERDICT_META[verdict] || VERDICT_META.ERROR;
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph()
      .setText('<font color="' + meta.color + '"><b>' + meta.label + '</b></font><br>' + meta.text));
  if (reason) section.addWidget(CardService.newTextParagraph().setText(reason));

  if (links && links.length) {
    links.forEach(function (l) {
      var m = VERDICT_META[l.status] || VERDICT_META.UNVERIFIED;
      section.addWidget(CardService.newTextParagraph()
        .setText('<font color="' + m.color + '">●</font> ' + defang_(l.url) + ' — ' + m.label));
    });
  } else {
    section.addWidget(CardService.newTextParagraph().setText('No links found in this email.'));
  }

  var buttons = CardService.newButtonSet();
  if (gatewayUrl) {
    buttons.addButton(CardService.newTextButton()
      .setText('Open safety check page')
      .setOpenLink(CardService.newOpenLink().setUrl(gatewayUrl)));
  }
  buttons.addButton(CardService.newTextButton()
    .setText('Re-check')
    .setOnClickAction(CardService.newAction().setFunctionName('reCheckAction')));
  section.addWidget(buttons);

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Online Safety Guard'))
    .addSection(section);

  if (msgResult) {
    var rMeta = RISK_META[msgResult.safetyStatus] || RISK_META.SUSPICIOUS;
    var riskSection = CardService.newCardSection().setHeader('Message content risk');
    riskSection.addWidget(CardService.newTextParagraph().setText(
      '<font color="' + rMeta.color + '"><b>' + rMeta.label + '</b></font> — ' +
      'Risk score ' + (typeof msgResult.riskScore === 'number' ? msgResult.riskScore : '?') + '/100'));
    if (msgResult.scamType) {
      riskSection.addWidget(CardService.newTextParagraph().setText('<b>' + msgResult.scamType + '</b>'));
    }
    if (msgResult.verdictSummary) {
      riskSection.addWidget(CardService.newTextParagraph().setText(msgResult.verdictSummary));
    }
    var flags = Array.isArray(msgResult.redFlags) ? msgResult.redFlags.slice(0, 6) : [];
    flags.forEach(function (f) {
      riskSection.addWidget(CardService.newTextParagraph()
        .setText('• <b>' + (f.flag || '') + ':</b> ' + (f.evidence || '')));
    });
    card.addSection(riskSection);
  }

  return card.build();
}

/* -------------------------------------------------------------- main flow */

function runAnalysis_(e) {
  var key = getAddinKey_();
  if (!key) return keyEntryCard_();

  var messageId = e && e.gmail && e.gmail.messageId;
  if (!messageId) return errorCard_('This message could not be identified.');

  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(messageId);

    var subject = message.getSubject() || '';
    var senderRaw = message.getFrom() || '';
    var senderMatch = /<([^>]+)>/.exec(senderRaw);
    var senderEmail = senderMatch ? senderMatch[1] : senderRaw;
    var senderDisplay = senderRaw;
    var html = message.getBody() || '';

    var ref = sha256Hex_(String(messageId));
    var mailbox = '';
    try { mailbox = Session.getActiveUser().getEmail() || ''; } catch (err) { mailbox = ''; }

    var urls = extractLinks_(html);
    var plainText = message.getPlainBody() || '';
    var msgResult = analyzeMessage_(plainText, senderDisplay);

    if (!urls.length) {
      postEvent_({
        provider: 'gmail', mailbox: mailbox, message_ref: ref,
        sender_domain: domainOf_(senderEmail), sender_display: senderDisplay,
        subject: subject, verdict: 'SAFE', action: 'none', link_count: 0,
      });
      return resultCard_('SAFE', 'No links found in this email.', [], null, msgResult);
    }

    var created = apiFetch_('/api/inspect', {
      method: 'post',
      payload: JSON.stringify({ message_ref: ref, urls: urls }),
    });
    var gatewayUrl = (created && created.links && created.links[0] && created.links[0].gateway_url) || null;

    var result = pollVerdict_(ref);
    var verdict = mapVerdict_(result && result.verdict);
    var links = ((result && result.links) || []).map(function (l) {
      return { url: l.url, status: mapVerdict_(l.status) };
    });

    postEvent_({
      provider: 'gmail', mailbox: mailbox, message_ref: ref,
      sender_domain: domainOf_(senderEmail), sender_display: senderDisplay,
      subject: subject, verdict: verdict, action: 'none', link_count: links.length,
    });

    return resultCard_(verdict, (result && (result.reason || result.verdictReason)) || '', links, gatewayUrl, msgResult);
  } catch (err) {
    return errorCard_(err && err.message ? err.message : 'The safety server could not be reached.');
  }
}

function onGmailMessageOpen(e) {
  return runAnalysis_(e);
}

function reCheckAction(e) {
  var card = runAnalysis_(e);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

function saveKeyAction(e) {
  var value = ((e.formInput && e.formInput.keyInput) || '').trim();
  if (!value) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(keyEntryCard_('Enter the add-in key.')))
      .build();
  }
  saveAddinKey_(value);
  var card = runAnalysis_(e);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

/* --------------------------------------------------------------- homepage */

function onHomepage(e) {
  var hasKey = Boolean(getAddinKey_());
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      hasKey
        ? 'Open an email to check its links.'
        : 'Set your add-in key below, then open an email to check its links.'));
  if (!hasKey) {
    section.addWidget(CardService.newTextInput()
      .setFieldName('keyInput')
      .setTitle('Add-in key'));
    section.addWidget(CardService.newTextButton()
      .setText('Save key')
      .setOnClickAction(CardService.newAction().setFunctionName('saveKeyHomepageAction')));
  } else {
    section.addWidget(CardService.newTextButton()
      .setText('Forget key')
      .setOnClickAction(CardService.newAction().setFunctionName('forgetKeyAction')));
  }
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Online Safety Guard'))
    .addSection(section)
    .build();
}

function saveKeyHomepageAction(e) {
  var value = ((e.formInput && e.formInput.keyInput) || '').trim();
  if (value) saveAddinKey_(value);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(onHomepage(e)))
    .build();
}

/* ------------------------------------------------------------- settings */

function onSettingsUniversalAction(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(onHomepage(e)))
    .build();
}

function forgetKeyAction(e) {
  forgetAddinKey_();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(onHomepage(e)))
    .build();
}
