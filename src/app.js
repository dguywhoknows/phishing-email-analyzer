const { $, $$, h, esc, busy, toast, md, store, download } = Kit;
let last = null;
let history = store.get('history', []);
const lists = Object.assign({ trusted: [], blocked: [] }, store.get('lists', {}));
const saveLists = () => store.set('lists', lists);
const KIND_LABEL = { auth: 'Authentication', sender: 'Sender', link: 'Links', language: 'Language', attachment: 'Attachments', list: 'Your lists', other: 'Other' };

/* ================= scan page ================= */
function runScan(raw, record = true) {
  last = scanEmail(raw, lists);
  renderScan(last);
  renderHeaders(last);
  if (record) {
    history.unshift({ id: Date.now(), t: Date.now(), subject: last.subject || '(no subject)', from: last.from, fromDom: last.fromDom, score: last.score, verdict: last.verdict[1], links: last.links.length, raw: raw.slice(0, 20000) });
    history = history.slice(0, 200);
    store.set('history', history);
  }
}
function renderScan(r) {
  const [cls, label] = r.verdict, col = `var(--${cls})`, C = 2 * Math.PI * 34;
  $('#verdict').innerHTML = `<svg width="90" height="90" viewBox="0 0 90 90" role="img" aria-label="Risk ${r.score}"><circle cx="45" cy="45" r="34" fill="none" stroke="var(--line)" stroke-width="10"/><circle cx="45" cy="45" r="34" fill="none" stroke="${col}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(C * r.score) / 100} ${C}" transform="rotate(-90 45 45)"/><text x="45" y="51" text-anchor="middle" font-size="20" font-weight="800" fill="var(--text)">${r.score}</text></svg>
    <div><div class="big" style="color:${col}">${label}</div><div class="small muted">Risk score from ${r.sig.filter((s) => s.w).length} signals${r.fromDom ? ` · sender ${esc(r.fromDom)}` : ''}</div>
    <div class="row small" style="margin-top:6px">${['spf', 'dkim', 'dmarc'].map((k) => `<span class="tag ${r.auth[k] === 'pass' ? 'good' : r.auth[k] ? 'bad' : ''}">${k.toUpperCase()} ${r.auth[k] || 'n/a'}</span>`).join('')}</div></div>`;
  const by = scoreByKind(r.sig), max = Math.max(1, ...Object.values(by));
  $('#breakdown').innerHTML = Object.keys(by).length ? Object.entries(by).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="bd-row"><span>${KIND_LABEL[k] || k}</span><div class="bar"><span style="width:${(100 * v) / max}%;background:var(--${v >= 25 ? 'bad' : 'warn'})"></span></div><span class="mono">+${v}</span></div>`).join('') : 'No risk points.';
  $('#signals').innerHTML = r.sig.map((s) => `<div class="sig"><span class="w ${s.w > 14 ? 'bad' : s.w > 0 ? 'warn' : 'good'}">${s.w > 0 ? '+' : ''}${s.w}</span><span>${esc(s.text)}</span></div>`).join('') || 'No signals.';
  $('#links').innerHTML = r.links.length ? `<table><tr><th>Shown as</th><th>Actually goes to</th><th>Flags</th><th></th></tr>${r.links.map((l, i) => `<tr><td>${esc(l.text || '(raw URL)')}</td><td class="mono">${esc(unicodeHost(l.url.hostname))}<div class="muted">${esc(l.href.slice(0, 80))}</div></td><td>${l.flags.length ? l.flags.map((f) => `<span class="tag bad">${esc(f)}</span>`).join(' ') : '<span class="tag good">ok</span>'}</td><td><button class="btn ghost sm" data-inspect="${i}">Inspect</button></td></tr>`).join('')}</table>` : 'No links found.';
  $$('[data-inspect]').forEach((b) => (b.onclick = () => { $('#urlIn').value = r.links[+b.dataset.inspect].href; Router.go('url'); inspect(); }));
  let b = esc(r.body.replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n\n').replace(/<(?!\/?a\b)[^>]+>/g, '').replace(/<a\b[^>]*>([\s\S]*?)<\/a>/gi, '[$1]'));
  Object.values(PHRASES).forEach((re) => { b = b.replace(new RegExp(re.source, 'gi'), (m) => `<mark>${m}</mark>`); });
  b = b.replace(/\bhttps?:\/\/[^\s<]+/gi, (m) => `<mark class="u">${m}</mark>`);
  $('#body').innerHTML = b.trim() || '—';
  $('#ai').disabled = false;
  $('#report').disabled = false;
  $('#aiCard').classList.add('hidden');
}
function reportText(r) {
  return [`Phishing check: ${r.verdict[1]} (risk ${r.score}/100)`, `From: ${r.from || 'unknown'}`, `Subject: ${r.subject || '(none)'}`, `SPF ${r.auth.spf || 'n/a'} · DKIM ${r.auth.dkim || 'n/a'} · DMARC ${r.auth.dmarc || 'n/a'}`, '', 'Signals:', ...r.sig.filter((s) => s.w).map((s) => `  ${s.w > 0 ? '+' : ''}${s.w}  ${s.text}`), '', 'Links:', ...(r.links.length ? r.links.map((l) => `  ${l.text || '(raw)'} -> ${l.href}${l.flags.length ? '  [' + l.flags.join('; ') + ']' : ''}`) : ['  none'])].join('\n');
}

async function second() {
  const r = last;
  const out = await AI.chat([
    { role: 'system', content: 'You are an email security analyst helping a non-technical person. Judge whether the email is phishing, using the deterministic signals provided plus your own reading of tone, context and plausibility (do not blindly trust the score). Return JSON {"verdict":"phishing|suspicious|likely legitimate","confidence":0-100,"summary":"2 sentences in plain language","reasons":["..."],"do":["safe next step"],"dont":["thing to avoid"]}.' },
    { role: 'user', content: `Headers: ${JSON.stringify({ from: r.from, 'reply-to': r.headers['reply-to'], 'return-path': r.headers['return-path'], subject: r.headers.subject, auth: r.auth })}\nLocal score: ${r.score}/100\nSignals:\n${r.sig.map((s) => `${s.w}: ${s.text}`).join('\n')}\nLinks: ${r.links.map((l) => `${l.text || '(raw)'} -> ${l.href}`).join('; ')}\n\nBody:\n${r.body.replace(/<[^>]+>/g, ' ').slice(0, 5000)}` },
  ], { json: true, temperature: 0.2, demo: () => ({ verdict: r.score >= 60 ? 'phishing' : r.score >= 30 ? 'suspicious' : 'likely legitimate', confidence: Math.min(95, 50 + Math.abs(r.score - 45)), summary: `Based on ${r.sig.filter((s) => s.w > 0).length} warning signs, this message ${r.score >= 60 ? 'shows the classic pattern of a credential-phishing attempt' : r.score >= 30 ? 'has some warning signs that deserve caution' : 'looks like ordinary mail'}.`, reasons: r.sig.filter((s) => s.w > 0).slice(0, 4).map((s) => s.text), do: ['Open the company’s website by typing its address yourself', 'Report the message as phishing in your mail app'], dont: ['Don’t click links or open attachments in this email', 'Never enter passwords from an email link'] }) });
  const v = String(out.verdict || '').toLowerCase();
  const cls = v.includes('phish') ? 'bad' : v.includes('susp') ? 'warn' : 'good';
  const list = (t, xs) => (xs?.length ? `<h3 style="margin-top:10px">${t}</h3><ul>${xs.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '');
  $('#aiOut').innerHTML = `<div class="row"><span class="tag ${cls}" style="font-size:14px">${esc(out.verdict)}</span><span class="small muted">confidence ${out.confidence}%</span></div><p style="margin-top:8px">${esc(out.summary)}</p><div class="prose">${list('Why', out.reasons)}${list('Do', out.do)}${list('Don’t', out.dont)}</div>`;
  $('#aiCard').classList.remove('hidden');
}

Object.keys(SAMPLES).forEach((k) => $('#samples').append(h('button', { class: 'btn sm ghost', onclick: () => { $('#email').value = SAMPLES[k]; $('#scan').click(); } }, k)));
$('#scan').onclick = () => { const raw = $('#email').value; if (!raw.trim()) return toast('Paste an email first', 'err'); runScan(raw); };
$('#ai').onclick = (e) => busy(e.currentTarget, second);
$('#report').onclick = () => navigator.clipboard.writeText(reportText(last)).then(() => toast('Report copied'));
$('#eml').onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $('#email').value = flattenMime(await f.text());
  e.target.value = '';
  runScan($('#email').value);
  toast('Loaded ' + f.name);
};

/* ================= headers page ================= */
function renderHeaders(r) {
  const hops = r.hops;
  $('#hopSummary').textContent = hops.length ? `${hops.length} hop${hops.length === 1 ? '' : 's'}${hops.some((x) => x.delay != null) ? ` · ${hops.reduce((a, x) => a + (x.delay || 0), 0)} s total` : ''}` : '';
  $('#hops').innerHTML = '';
  if (!hops.length) $('#hops').append(h('div', { class: 'empty' }, 'No Received headers. Paste the full original message ("Show original" in Gmail, "View source" in Outlook) to see the delivery path.'));
  hops.forEach((x, i) => $('#hops').append(h('div', { class: 'hop' },
    h('span', { class: 'n' }, i + 1),
    h('div', {}, h('div', {}, h('b', { class: 'mono' }, x.from || '?'), ' → ', h('span', { class: 'mono' }, x.by || '?')), h('div', { class: 'small muted' }, [x.ip && `IP ${x.ip}`, x.when].filter(Boolean).join(' · '))),
    h('span', { class: 'small delay' + (x.delay > 300 ? ' slow' : '') }, x.delay == null ? '' : x.delay < 0 ? `${x.delay}s (clock skew)` : `+${x.delay}s`))));
  const A = r.auth, row = (k, v, note) => `<dt>${k}</dt><dd><span class="tag ${v === 'pass' ? 'good' : v ? 'bad' : ''}">${v || 'not present'}</span> <span class="small muted">${note}</span></dd>`;
  $('#authTable').innerHTML = `<dl class="kv">${row('SPF', A.spf, 'Was the sending server allowed to send for this domain?')}${row('DKIM', A.dkim, 'Was the message cryptographically signed and unchanged?')}${row('DMARC', A.dmarc, 'Do SPF/DKIM line up with the visible From domain?')}</dl>`;
  const H = r.headers, cell = (k, v) => `<dt>${k}</dt><dd>${v ? esc(v) : '<span class="muted">—</span>'}</dd>`;
  $('#identity').innerHTML = `<dl class="kv">${cell('From', H.from)}${cell('Reply-To', H['reply-to'])}${cell('Return-Path', H['return-path'])}${cell('Message-ID', H['message-id'])}${cell('Date', H.date)}${cell('X-Mailer', H['x-mailer'])}</dl>`;
  $('#allHeaders').innerHTML = r.headerList.length ? `<table><tr><th>Header</th><th>Value</th></tr>${r.headerList.map((x) => `<tr><td class="mono">${esc(x.name)}</td><td class="mono small" style="word-break:break-all">${esc(x.value)}</td></tr>`).join('')}</table>` : '<div class="empty">No headers in the pasted text.</div>';
}

/* ================= URL inspector ================= */
const URL_SAMPLES = ['https://login.paypal.com.account-check.xyz/signin?next=https%3A%2F%2Fpaypal.com', 'https://www.contoso.com@203.0.113.9/invoice', 'https://news.example.com/r?url=https%3A%2F%2Fevil.top%2Fdrop', 'http://xn--pple-43d.com/id'];
URL_SAMPLES.forEach((u) => $('#urlSamples').append(h('button', { class: 'btn ghost sm mono', onclick: () => { $('#urlIn').value = u; inspect(); } }, u.length > 40 ? u.slice(0, 38) + '…' : u)));
function inspect() {
  const v = $('#urlIn').value.trim(), out = $('#urlOut');
  out.innerHTML = '';
  if (!v) return;
  let u;
  try { u = inspectUrl(v); } catch { out.append(h('div', { class: 'card empty' }, 'That does not parse as a URL.')); return; }
  const risk = Math.min(100, u.flags.reduce((a, f) => a + f.w, 0)), [cls, label] = verdictOf(risk);
  const parts = h('div', { class: 'url-parts' },
    h('span', { class: 'p-scheme' }, u.scheme + '://'),
    u.user ? h('span', { class: 'p-user', title: 'Ignored by the browser' }, u.user + '@') : null,
    u.subdomains.length ? h('span', { class: 'p-sub', title: 'Subdomains: chosen freely by the domain owner' }, u.subdomains.join('.') + '.') : null,
    h('span', { class: 'p-rd', title: 'The part that decides who owns the site' }, u.registrable),
    u.port ? h('span', {}, ':' + u.port) : null,
    h('span', { class: 'p-path' }, u.path + (u.params.length ? '?' + u.params.map((p) => p.k + '=…').join('&') : '')));
  out.append(
    h('div', { class: 'card stack' }, h('div', { class: 'row between' }, h('h2', { style: 'margin:0' }, 'Anatomy'), h('span', { class: 'tag ' + cls }, `${label} · ${risk}`)), parts,
      h('p', { class: 'small muted', style: 'margin:0' }, 'The highlighted ', h('b', {}, u.registrable), ' is who actually owns this site. Everything to its left can be anything the owner wants.')),
    h('div', { class: 'grid cols-2' },
      h('div', { class: 'card' }, h('h2', {}, 'Details'), h('dl', { class: 'kv' },
        h('dt', {}, 'Host'), h('dd', { class: 'mono' }, u.host), h('dt', {}, 'Displays as'), h('dd', { class: 'mono' }, u.unicode),
        h('dt', {}, 'Owner domain'), h('dd', { class: 'mono' }, u.registrable), h('dt', {}, 'Scheme'), h('dd', {}, u.scheme === 'https' ? 'https (encrypted, says nothing about trust)' : u.scheme),
        h('dt', {}, 'Path'), h('dd', { class: 'mono' }, u.path), ...(u.fragment ? [h('dt', {}, 'Fragment'), h('dd', { class: 'mono' }, u.fragment)] : []))),
      h('div', { class: 'card' }, h('h2', {}, 'Flags'), u.flags.length ? u.flags.map((f) => h('div', { class: 'sig' }, h('span', { class: 'w ' + (f.w > 14 ? 'bad' : 'warn') }, '+' + f.w), h('span', {}, f.t))) : h('div', { class: 'empty' }, 'No red flags in the URL itself.'))),
    u.params.length ? h('div', { class: 'card' }, h('h2', {}, 'Query parameters'), h('div', { class: 'table-wrap' }, h('table', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Value')), u.params.map((p) => h('tr', {}, h('td', { class: 'mono' }, p.k), h('td', { class: 'mono', style: 'word-break:break-all' }, p.v)))))) : '',
    u.redirects.length ? h('div', { class: 'card' }, h('h2', {}, 'Hidden redirect'), u.redirects.map((x) => h('div', { class: 'row' }, h('span', { class: 'tag warn' }, x.param), h('span', { class: 'mono', style: 'word-break:break-all' }, x.target), h('button', { class: 'btn sm', onclick: () => { $('#urlIn').value = x.target; inspect(); } }, 'Inspect target')))) : '');
}
$('#urlGo').onclick = inspect;
$('#urlIn').addEventListener('keydown', (e) => e.key === 'Enter' && inspect());

/* ================= training ================= */
let deck = [], pos = 0, answers = store.get('training', []);
function shuffle(a) { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }
function startTraining() { deck = shuffle(TRAINING); pos = 0; renderTraining(); }
function renderTrainStats() {
  const right = answers.filter((a) => a.ok).length;
  $('#trainStats').innerHTML = [['Answered', answers.length], ['Correct', answers.length ? Math.round((100 * right) / answers.length) + '%' : '—'], ['Missed phish', answers.filter((a) => !a.ok && a.answer === 'phish').length]]
    .map(([k, v]) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');
  $('#trainLog').innerHTML = answers.slice(0, 12).map((a) => `<div class="row between" style="padding:4px 0;border-bottom:1px solid var(--line)"><span>${esc(a.subject)}</span><span class="tag ${a.ok ? 'good' : 'bad'}">${a.ok ? 'right' : 'wrong'}</span></div>`).join('') || '<span class="muted">No answers yet.</span>';
}
function renderTraining() {
  renderTrainStats();
  const box = $('#trainCard');
  box.innerHTML = '';
  if (pos >= deck.length) {
    box.append(h('div', { class: 'card stack' }, h('h2', { style: 'margin:0' }, 'Round complete'), h('p', {}, `You answered ${deck.length} messages. Restart for a new order, or generate a fresh message.`), h('button', { class: 'btn primary', onclick: startTraining }, 'Play again')));
    return;
  }
  const item = deck[pos], p = splitHeaders(item.raw);
  const view = h('div', { class: 'mail-view' }, item.raw);
  const result = h('div', {});
  const decide = (guess) => {
    const ok = guess === item.answer, r = scanEmail(item.raw, lists);
    answers.unshift({ t: Date.now(), subject: p.headers.subject || '(no subject)', answer: item.answer, ok });
    store.set('training', answers.slice(0, 300));
    actions.remove();
    result.append(h('div', { class: 'card stack', style: `border-color:var(--${ok ? 'good' : 'bad'})` },
      h('div', { class: 'row between' }, h('b', { style: `color:var(--${ok ? 'good' : 'bad'})` }, ok ? 'Correct' : 'Not quite'), h('span', { class: 'tag ' + (item.answer === 'phish' ? 'bad' : 'good') }, item.answer === 'phish' ? 'Phishing' : 'Legitimate')),
      h('p', { style: 'margin:0' }, item.tell),
      h('div', { class: 'small muted' }, `Scanner: ${r.verdict[1]} (${r.score}). Top signals: ${r.sig.filter((s) => s.w > 0).slice(0, 3).map((s) => s.text).join('; ') || 'none'}`),
      h('button', { class: 'btn primary', onclick: () => { pos++; renderTraining(); } }, pos + 1 < deck.length ? 'Next message' : 'Finish')));
    renderTrainStats();
  };
  const actions = h('div', { class: 'train-actions' }, h('button', { class: 'btn', style: 'border-color:var(--good)', onclick: () => decide('legit') }, 'Looks legitimate'), h('button', { class: 'btn', style: 'border-color:var(--bad)', onclick: () => decide('phish') }, 'Phishing'));
  box.append(h('div', { class: 'card stack' }, h('div', { class: 'row between' }, h('span', { class: 'small muted' }, `Message ${pos + 1} of ${deck.length}`), h('span', { class: 'small muted' }, item.generated ? 'Generated' : 'Built-in')), view, actions), result);
}
$('#trainRestart').onclick = startTraining;
$('#trainGen').onclick = (e) => busy(e.currentTarget, async () => {
  const phish = Math.random() < 0.6;
  const out = await AI.chat([
    { role: 'system', content: 'Write one realistic training email for a phishing-awareness exercise. Use only fictional companies (Contoso, Fabrikam, Northwind, Tailspin, Woodgrove, Litware) and reserved example domains or obviously fake ones. Include From and Subject header lines, a blank line, then the body. Return JSON {"raw":"full message","answer":"phish|legit","tell":"one sentence on the giveaway or why it is safe"}.' },
    { role: 'user', content: phish ? 'Make it a subtle phishing email.' : 'Make it a legitimate email that might look suspicious at first glance.' },
  ], { json: true, temperature: 0.9, demo: () => Object.assign({}, TRAINING[Math.floor(Math.random() * TRAINING.length)]) });
  if (!out.raw) return toast('No message came back', 'err');
  deck.splice(pos, 0, { raw: out.raw, answer: out.answer === 'legit' ? 'legit' : 'phish', tell: out.tell || '', generated: true });
  renderTraining();
});

/* ================= history + lists ================= */
function renderHistory() {
  const n = history.length, bad = history.filter((x) => x.score >= 60).length;
  $('#histSummary').textContent = n ? `${n} scan${n === 1 ? '' : 's'} · ${bad} likely phishing · ${history.filter((x) => x.score >= 30 && x.score < 60).length} suspicious` : 'Scans you run are kept here, in this browser only.';
  $('#histTable').innerHTML = '';
  if (!n) { $('#histTable').append(h('div', { class: 'empty' }, 'No scans yet.')); }
  else $('#histTable').append(h('table', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Subject'), h('th', {}, 'Sender'), h('th', {}, 'Risk'), h('th', {})),
    history.map((x) => h('tr', {},
      h('td', { class: 'small' }, new Date(x.t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })),
      h('td', {}, x.subject), h('td', { class: 'mono small' }, x.fromDom || '—'),
      h('td', {}, h('span', { class: 'tag ' + verdictOf(x.score)[0] }, `${x.score} · ${x.verdict}`)),
      h('td', { style: 'white-space:nowrap' },
        h('button', { class: 'btn ghost sm', onclick: () => { $('#email').value = x.raw; runScan(x.raw, false); Router.go('scan'); } }, 'Open'),
        x.fromDom ? h('button', { class: 'btn ghost sm', onclick: () => addTo(x.score >= 60 ? 'blocked' : 'trusted', regDomain(x.fromDom)) }, x.score >= 60 ? 'Block' : 'Trust') : null,
        h('button', { class: 'btn ghost sm', 'aria-label': 'Delete', onclick: () => { history = history.filter((y) => y !== x); store.set('history', history); renderHistory(); } }, '×'))))));
  [['trusted', '#trustList'], ['blocked', '#blockList']].forEach(([k, sel]) => {
    $(sel).innerHTML = '';
    if (!lists[k].length) $(sel).append(h('span', { class: 'small muted' }, 'None yet.'));
    lists[k].forEach((d) => $(sel).append(h('span', { class: 'chip' }, d, h('button', { 'aria-label': 'Remove ' + d, onclick: () => { lists[k] = lists[k].filter((x) => x !== d); saveLists(); renderHistory(); } }, '×'))));
  });
}
function addTo(k, domain) {
  domain = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return toast('Enter a domain like example.com', 'err');
  const other = k === 'trusted' ? 'blocked' : 'trusted';
  lists[other] = lists[other].filter((x) => x !== domain);
  if (!lists[k].includes(domain)) lists[k].push(domain);
  saveLists(); renderHistory();
  toast(`${domain} added to ${k}`);
}
$('#trustForm').onsubmit = (e) => { e.preventDefault(); addTo('trusted', regDomain($('#trustIn').value.trim() || 'x')); $('#trustIn').value = ''; };
$('#blockForm').onsubmit = (e) => { e.preventDefault(); addTo('blocked', regDomain($('#blockIn').value.trim() || 'x')); $('#blockIn').value = ''; };
$('#histClear').onclick = () => { if (history.length && confirm('Delete all scan history?')) { history = []; store.set('history', history); renderHistory(); } };
$('#histCsv').onclick = () => {
  const q = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
  download('scan-history.csv', ['date,subject,sender_domain,score,verdict,links', ...history.map((x) => [new Date(x.t).toISOString(), q(x.subject), x.fromDom, x.score, q(x.verdict), x.links].join(','))].join('\n'), 'text/csv');
};

/* ================= boot ================= */
Router.on('history', renderHistory);
Router.on('training', () => deck.length || startTraining());
$('#email').value = SAMPLES['Bank phish'];
runScan($('#email').value, false);
renderHistory();
