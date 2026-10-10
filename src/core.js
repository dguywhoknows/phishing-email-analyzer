/* Email parsing, link and domain analysis, punycode, header hops and risk scoring (pure, unit-tested). */

var BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'linkedin', 'dropbox', 'docusign', 'chase', 'wellsfargo', 'bankofamerica', 'rbc', 'td', 'scotiabank', 'fedex', 'ups', 'dhl', 'usps', 'canadapost', 'irs', 'cra', 'steam', 'coinbase', 'binance', 'adobe', 'office365', 'outlook', 'icloud', 'northwindbank'];
var BAD_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'cam', 'icu', 'buzz', 'loan'];
var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 't.ly'];
var PHRASES = {
  urgency: /\b(urgent(ly)?|immediately|within (24|48) hours|right away|as soon as possible|final (notice|warning)|act now|expires? (today|soon)|last chance|time.sensitive)\b/gi,
  credentials: /\b(verify your (account|identity|information)|confirm your (password|account|details|identity)|log ?in to (verify|confirm|restore)|update your (payment|billing|account) (info|information|details)|enter your (password|pin|ssn|social security))\b/gi,
  money: /\b(gift ?cards?|wire transfer|bitcoin|crypto(currency)? wallet|refund of \$?[\d,.]+|unclaimed (funds|prize)|you (have )?won|lottery|invoice attached|payment (failed|declined|overdue))\b/gi,
  threat: /\b(account (will be |has been )?(suspended|locked|closed|terminated|disabled|restricted)|legal action|unauthori[sz]ed (access|activity|login)|security alert|unusual (sign.in|activity))\b/gi,
  generic: /\b(dear (customer|user|client|member|account holder|sir\/madam|valued customer))\b/gi,
};

/* ---------- parsing ---------- */
function splitHeaders(raw) {
  var lines = String(raw).replace(/\r/g, '').split('\n');
  if (!/^[\w-]+:\s/.test(lines[0] || '')) return { headers: {}, body: raw, list: [] };
  var headers = {}, list = [], i = 0, key = null;
  for (; i < lines.length; i++) {
    var l = lines[i];
    if (!l.trim()) { i++; break; }
    var m = l.match(/^([\w-]+):\s*(.*)$/);
    if (m) { key = m[1].toLowerCase(); headers[key] = headers[key] ? headers[key] + '\n' + m[2] : m[2]; list.push({ name: m[1], value: m[2] }); }
    else if (key && /^\s/.test(l)) { headers[key] += ' ' + l.trim(); list[list.length - 1].value += ' ' + l.trim(); }
    else return { headers: {}, body: raw, list: [] };
  }
  return { headers: headers, body: lines.slice(i).join('\n'), list: list };
}
function addrOf(s) { var m = String(s || '').match(/<([^>]+)>/) || String(s || '').match(/([\w.+-]+@[\w.-]+)/); return m ? m[1].toLowerCase() : ''; }
function displayName(s) { return String(s || '').replace(/<[^>]+>/, '').replace(/"/g, '').trim(); }
function domainOf(addr) { return addr.split('@')[1] || ''; }
function regDomain(host) {
  var parts = String(host).toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  var sld = parts[parts.length - 2];
  return (['co', 'com', 'org', 'net', 'ac', 'gov', 'edu'].indexOf(sld) >= 0 && parts[parts.length - 1].length === 2 ? parts.slice(-3) : parts.slice(-2)).join('.');
}
function extractLinks(body) {
  var links = [], seen = {};
  var add = function (href, text) {
    href = href.replace(/&amp;/g, '&').replace(/[)\].,;'"]+$/, '');
    var key = href + '|' + (text || '');
    if (seen[key]) return;
    seen[key] = 1;
    var url;
    try { url = new URL(/^https?:\/\//i.test(href) ? href : 'http://' + href); } catch (e) { return; }
    links.push({ href: href, text: (text || '').trim(), url: url });
  };
  body.replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, function (_, href, text) { add(href, text.replace(/<[^>]+>/g, '')); return ''; });
  body.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, function (_, text, href) { add(href, text); return ''; });
  var plain = body.replace(/<a\b[\s\S]*?<\/a>/gi, ' ').replace(/\[[^\]]+\]\([^)]+\)/g, ' ');
  (plain.match(/\bhttps?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/gi) || []).forEach(function (u) { add(u, ''); });
  return links;
}

/* ---------- punycode (RFC 3492 decode) and confusables ---------- */
function punyDecode(label) {
  if (!/^xn--/i.test(label)) return label;
  var input = label.slice(4).toLowerCase(), base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  var b = input.lastIndexOf('-'), out = b > 0 ? input.slice(0, b).split('') : [], i = 0, n = 128, bias = 72;
  var adapt = function (delta, num, first) { delta = first ? Math.floor(delta / damp) : delta >> 1; delta += Math.floor(delta / num); var k = 0; while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; } return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew)); };
  var digit = function (c) { var x = c.charCodeAt(0); return x - 48 < 10 ? x - 22 : x - 97 < 26 ? x - 97 : base; };
  for (var p = b > 0 ? b + 1 : 0; p < input.length;) {
    var oldi = i, w = 1;
    for (var k = base; ; k += base) {
      if (p >= input.length) return label;
      var d = digit(input[p++]);
      i += d * w;
      var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, String.fromCodePoint(n));
  }
  return out.join('');
}
function unicodeHost(host) { return String(host).split('.').map(punyDecode).join('.'); }
var CONFUSABLE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ӏ': 'l', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ο': 'o', 'α': 'a', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ρ': 'p', 'ι': 'i' };
function skeleton(s) { return String(s).toLowerCase().split('').map(function (c) { return CONFUSABLE[c] || c; }).join(''); }
function mixedScript(label) { return /[a-z]/i.test(label) && /[Ͱ-ϿЀ-ӿ]/.test(label); }

/* ---------- lookalikes ---------- */
function lev(a, b) {
  var d = [];
  for (var i = 0; i <= a.length; i++) { d.push([i]); for (var j = 1; j <= b.length; j++) d[i].push(i ? 0 : j); }
  for (i = 1; i <= a.length; i++) for (j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}
function deglyph(s) { return s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[0]/g, 'o').replace(/[1l|]/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/[4@]/g, 'a').replace(/7/g, 't').replace(/-/g, ''); }
function lookalike(host) {
  var label = skeleton(unicodeHost(regDomain(host)).split('.')[0]);
  var raw = regDomain(host).split('.')[0];
  for (var x = 0; x < BRANDS.length; x++) {
    var b = BRANDS[x];
    if (raw === b) return null;
    var dg = deglyph(label), bg = deglyph(b);
    if (label === b || dg === bg || (b.length >= 5 && lev(label, b) <= (b.length > 8 ? 2 : 1)) || (b.length >= 5 && dg.indexOf(bg) >= 0)) return b;
  }
  return null;
}

/* ---------- URL inspection ---------- */
function redirectTargets(url) {
  var out = [];
  url.searchParams.forEach(function (v, k) {
    var dec = v;
    for (var n = 0; n < 3 && /%[0-9a-f]{2}/i.test(dec); n++) { try { dec = decodeURIComponent(dec); } catch (e) { break; } }
    if (/^(https?:)?\/\/[^\s]+\.[a-z]{2,}/i.test(dec) || /^https?:\/\//i.test(dec)) out.push({ param: k, target: dec });
  });
  return out;
}
function linkFlags(href, text) {
  var url;
  try { url = new URL(/^https?:\/\//i.test(href) ? href : 'http://' + href); } catch (e) { return [{ w: 10, t: 'URL could not be parsed' }]; }
  var host = url.hostname.toLowerCase(), rd = regDomain(host), f = [], add = function (w, t) { f.push({ w: w, t: t }); };
  var textHost = (String(text || '').match(/(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i) || [])[1];
  if (textHost && regDomain(textHost.toLowerCase()) !== rd) add(25, 'displays "' + textHost + '" but goes to ' + rd);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(20, 'raw IP address');
  if (host.indexOf('xn--') >= 0) { var u = unicodeHost(host); add(mixedScript(u.split('.').slice(-2)[0]) ? 30 : 15, 'punycode host renders as "' + u + '"'); }
  var tld = host.split('.').pop();
  if (BAD_TLDS.indexOf(tld) >= 0) add(10, 'high-abuse TLD .' + tld);
  if (SHORTENERS.indexOf(host) >= 0) add(8, 'URL shortener hides the destination');
  if (url.username || /^[^/]*\/\/[^/]*@/.test(href)) add(15, '"@" trick: everything before @ is ignored by the browser');
  if (url.protocol === 'http:' && /^http:/i.test(href)) add(5, 'no HTTPS');
  if (host.split('.').length >= 5) add(8, 'deeply nested subdomains');
  var redirs = redirectTargets(url);
  if (redirs.length) add(12, 'redirects through a "' + redirs[0].param + '" parameter to ' + (function () { try { return new URL(redirs[0].target.replace(/^\/\//, 'http://')).hostname; } catch (e) { return redirs[0].target; } })());
  var la = lookalike(host);
  if (la) add(30, 'domain imitates "' + la + '"');
  else {
    var inSub = BRANDS.find(function (b) { return b.length > 3 && (host.replace(rd, '') + url.pathname).toLowerCase().indexOf(b) >= 0 && rd.indexOf(b) !== 0; });
    if (inSub) add(20, '"' + inSub + '" appears in the subdomain/path but the real domain is ' + rd);
  }
  return f;
}
function inspectUrl(href) {
  var url = new URL(/^[a-z]+:\/\//i.test(href) ? href : 'http://' + href);
  var host = url.hostname.toLowerCase(), rd = regDomain(host);
  var params = [];
  url.searchParams.forEach(function (v, k) { params.push({ k: k, v: v }); });
  return {
    scheme: url.protocol.replace(':', ''), user: url.username, host: host, unicode: unicodeHost(host), registrable: rd,
    subdomains: host === rd ? [] : host.slice(0, -rd.length - 1).split('.'),
    port: url.port, path: decodeURIComponent(url.pathname), params: params, fragment: url.hash.slice(1),
    redirects: redirectTargets(url), flags: linkFlags(href, ''),
  };
}

/* ---------- header hops ---------- */
function parseReceived(headers) {
  var raw = headers.received ? headers.received.split('\n') : [];
  return raw.map(function (r) {
    var from = (r.match(/\bfrom\s+([^\s;()]+)/i) || [])[1] || '';
    var ip = (r.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/) || r.match(/\((?:[^)]*?)(\d{1,3}(?:\.\d{1,3}){3})/) || [])[1] || '';
    var by = (r.match(/\bby\s+([^\s;()]+)/i) || [])[1] || '';
    var when = r.indexOf(';') >= 0 ? r.slice(r.lastIndexOf(';') + 1).trim() : '';
    var t = when ? Date.parse(when) : NaN;
    return { from: from, ip: ip, by: by, when: when, t: isNaN(t) ? null : t };
  }).reverse().map(function (hop, i, all) { hop.delay = i && hop.t != null && all[i - 1].t != null ? Math.round((hop.t - all[i - 1].t) / 1000) : null; return hop; });
}

/* ---------- scoring ---------- */
function verdictOf(score) { return score >= 60 ? ['bad', 'Likely phishing'] : score >= 30 ? ['warn', 'Suspicious'] : ['good', 'Probably safe']; }
function scanEmail(raw, opts) {
  opts = opts || {};
  var trusted = (opts.trusted || []).map(function (d) { return d.toLowerCase(); }), blocked = (opts.blocked || []).map(function (d) { return d.toLowerCase(); });
  var sp = splitHeaders(raw), headers = sp.headers, body = sp.body, sig = [];
  var add = function (w, text, kind) { sig.push({ w: w, text: text, kind: kind || 'other' }); };
  var from = headers.from || (body.match(/^from:\s*(.+)$/im) || [])[1] || '';
  var fromAddr = addrOf(from), fromDom = domainOf(fromAddr), fromName = displayName(from);

  var auth = (headers['authentication-results'] || '') + ' ' + (headers['received-spf'] ? 'spf=' + headers['received-spf'].split(/\s/)[0].toLowerCase() : '');
  var res = function (k) { var m = auth.match(new RegExp(k + '=(\\w+)', 'i')); return m ? m[1].toLowerCase() : undefined; };
  var spf = res('spf'), dkim = res('dkim'), dmarc = res('dmarc');
  if (spf && spf !== 'pass') add(spf === 'fail' ? 25 : 12, 'SPF ' + spf + ': the sending server is not authorized for ' + (fromDom || 'this domain'), 'auth');
  if (dkim && dkim !== 'pass') add(dkim === 'fail' ? 20 : 10, 'DKIM ' + dkim + ': the signature is missing or invalid', 'auth');
  if (dmarc && dmarc !== 'pass') add(25, 'DMARC ' + dmarc + ': the domain owner’s policy says reject or quarantine', 'auth');
  if (spf === 'pass' && dkim === 'pass' && dmarc === 'pass') add(-15, 'SPF, DKIM and DMARC all pass', 'auth');
  if (!Object.keys(headers).length) add(0, 'No raw headers pasted, so authentication can’t be checked', 'auth');

  var reply = addrOf(headers['reply-to']), ret = addrOf(headers['return-path']);
  if (reply && fromDom && regDomain(domainOf(reply)) !== regDomain(fromDom)) add(15, 'Reply-To (' + reply + ') differs from the sender domain (' + fromDom + ')', 'sender');
  if (ret && fromDom && regDomain(domainOf(ret)) !== regDomain(fromDom)) add(8, 'Return-Path domain (' + domainOf(ret) + ') differs from From (' + fromDom + ')', 'sender');
  var mid = (headers['message-id'] || '').match(/@([^>\s]+)/);
  if (mid && fromDom && regDomain(mid[1]) !== regDomain(fromDom) && !/google|outlook|amazonses|sendgrid|mailchimp|mcsv/.test(mid[1])) add(5, 'Message-ID was generated by ' + mid[1] + ', not the sender’s domain', 'sender');
  var nameBrand = BRANDS.find(function (b) { return b.length > 3 && fromName.toLowerCase().replace(/\s/g, '').indexOf(b) >= 0; });
  if (nameBrand && fromDom && regDomain(fromDom).indexOf(nameBrand) !== 0) add(20, 'Display name claims "' + fromName + '" but mail comes from ' + fromDom, 'sender');
  if (fromDom) { var la = lookalike(fromDom); if (la) add(30, 'Sender domain ' + fromDom + ' imitates "' + la + '"', 'sender'); }
  var freeMail = /@(gmail|outlook|hotmail|yahoo|proton|icloud|aol)\./i.test(fromAddr);
  if (freeMail && nameBrand) add(15, 'A "company" email sent from a free webmail account', 'sender');
  if (freeMail && /\b(ceo|cfo|coo|president|director|vp|chief|founder|manager)\b/i.test(fromName)) add(25, 'An executive ("' + fromName + '") writing from a personal webmail address, a classic CEO-fraud pattern', 'sender');
  if (fromDom && trusted.indexOf(regDomain(fromDom)) >= 0 && spf !== 'fail' && dmarc !== 'fail') add(-20, fromDom + ' is on your trusted list', 'list');
  if (fromDom && blocked.indexOf(regDomain(fromDom)) >= 0) add(40, fromDom + ' is on your blocked list', 'list');

  var links = extractLinks(body);
  links.forEach(function (l) {
    l.flags = linkFlags(l.href, l.text).map(function (f) { add(f.w, 'Link ' + l.url.hostname.toLowerCase() + ': ' + f.t, 'link'); return f.t; });
    if (blocked.indexOf(regDomain(l.url.hostname)) >= 0) { l.flags.push('blocked domain'); add(40, 'Link to blocked domain ' + regDomain(l.url.hostname), 'list'); }
  });

  var text = body.replace(/<[^>]+>/g, ' ');
  var hits = {};
  Object.keys(PHRASES).forEach(function (k) { var seen = {}; hits[k] = (text.match(PHRASES[k]) || []).map(function (s) { return s.toLowerCase(); }).filter(function (s) { return seen[s] ? false : (seen[s] = 1); }); });
  if (hits.urgency.length) add(Math.min(16, 4 * hits.urgency.length), 'Pressure language: “' + hits.urgency.slice(0, 3).join('”, “') + '”', 'language');
  if (hits.credentials.length) add(15, 'Asks you to verify credentials: “' + hits.credentials[0] + '”', 'language');
  if (hits.money.length) add(15, 'Money bait: “' + hits.money.slice(0, 2).join('”, “') + '”', 'language');
  if (hits.threat.length) add(10, 'Threatens account consequences: “' + hits.threat[0] + '”', 'language');
  if (hits.generic.length) add(5, 'Generic greeting: “' + hits.generic[0] + '”', 'language');
  if (/\b(keep (this|it) (confidential|between us|quiet)|don.t tell anyone|do not discuss)\b/i.test(text)) add(12, 'Asks for secrecy, which isolates you from people who could spot the scam', 'language');
  if (/\b(are you (at your desk|available|around)|quick favou?r|i need you to (buy|purchase|send|pay))\b/i.test(text)) add(10, 'An unusual, informal request for an urgent favor', 'language');
  if (/\b(scratch|codes?)\b/i.test(text) && hits.money.some(function (m) { return m.indexOf('gift') >= 0; })) add(15, 'Asks for gift-card codes, which are untraceable and a hallmark of fraud', 'language');
  var att = text.match(/\b[\w-]+\.(exe|scr|js|vbs|bat|cmd|iso|img|html?|docm|xlsm|zip|rar)\b/gi);
  if (att) add(20, 'Risky attachment or file reference: ' + att.filter(function (a, i) { return att.indexOf(a) === i; }).slice(0, 3).join(', '), 'attachment');
  if (links.length && !sig.some(function (s) { return s.w > 0 && s.kind === 'link'; })) add(-5, 'Links point to consistent, ordinary domains', 'link');

  var score = Math.max(0, Math.min(100, sig.reduce(function (a, s) { return a + s.w; }, 0)));
  return { headers: headers, headerList: sp.list, body: body, from: from, fromDom: fromDom, subject: headers.subject || '', links: links, sig: sig.sort(function (a, b) { return b.w - a.w; }), score: score, verdict: verdictOf(score), hits: hits, auth: { spf: spf, dkim: dkim, dmarc: dmarc }, hops: parseReceived(headers) };
}
/* Points per category, for the breakdown chart. */
function scoreByKind(sig) { var out = {}; sig.forEach(function (s) { if (s.w > 0) out[s.kind] = (out[s.kind] || 0) + s.w; }); return out; }

/* ---------- .eml decoding ---------- */
function decodeQP(s) {
  var bytes = String(s).replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, function (_, x) { return String.fromCharCode(parseInt(x, 16)); });
  try { return decodeURIComponent(escape(bytes)); } catch (e) { return bytes; }
}
function decodeB64(s) {
  var bin = atob(String(s).replace(/\s+/g, ''));
  try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; }
}
function decodePart(headers, body) {
  var enc = (headers['content-transfer-encoding'] || '').toLowerCase();
  return enc === 'quoted-printable' ? decodeQP(body) : enc === 'base64' ? decodeB64(body) : body;
}
/* Flatten a MIME message into its top-level header block plus the most useful text body (HTML preferred, for links). */
function flattenMime(raw) {
  var top = splitHeaders(raw);
  if (!top.list.length) return raw;
  var ct = top.headers['content-type'] || '', parts = [];
  var walk = function (headers, body) {
    var t = headers['content-type'] || 'text/plain', b = (t.match(/boundary="?([^";]+)"?/i) || [])[1];
    if (/^multipart\//i.test(t) && b) {
      body.split('--' + b).slice(1).forEach(function (chunk) {
        if (/^--/.test(chunk)) return;
        var p = splitHeaders(chunk.replace(/^\r?\n/, ''));
        walk(p.headers, p.body);
      });
    } else if (/^text\/(plain|html)/i.test(t) && !/attachment/i.test(headers['content-disposition'] || '')) parts.push({ type: /html/i.test(t) ? 'html' : 'plain', text: decodePart(headers, body) });
    else if (headers['content-disposition'] || /name=/i.test(t)) { var nm = ((headers['content-disposition'] || '') + ' ' + t).match(/name="?([^";]+)"?/i); parts.push({ type: 'attachment', text: nm ? nm[1] : 'attachment' }); }
  };
  walk(top.headers, top.body);
  if (!parts.length) return raw;
  var html = parts.filter(function (p) { return p.type === 'html'; })[0], plain = parts.filter(function (p) { return p.type === 'plain'; })[0];
  var atts = parts.filter(function (p) { return p.type === 'attachment'; }).map(function (p) { return 'Attachment: ' + p.text; });
  var head = top.list.filter(function (x) { return !/^content-/i.test(x.name) && !/^mime-version$/i.test(x.name); }).map(function (x) { return x.name + ': ' + x.value; }).join('\n');
  return head + '\n\n' + ((html || plain || { text: '' }).text + (atts.length ? '\n\n' + atts.join('\n') : '')).trim();
}
