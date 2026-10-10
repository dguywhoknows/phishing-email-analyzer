const BANK = `From: "Northwind Bank Security" <alerts@northwlnd-bank.com>
Reply-To: support-desk@mail-verify-center.top
Subject: URGENT: Your account has been suspended
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=mail-verify-center.top; dkim=none; dmarc=fail
Received: from mx.example.net by inbox.example.net; Tue, 6 Oct 2026 10:00:09 +0000
Received: from relay.verify-center.top ([203.0.113.7]) by mx.example.net; Tue, 6 Oct 2026 10:00:01 +0000

Dear Customer,
Your account has been suspended. Verify your identity within 24 hours.
<a href="http://northwindbank.secure-login.verify-id.top/login">https://www.northwindbank.com/secure</a>`;
const NEWS = `From: "Contoso Weekly" <news@contoso.com>
Reply-To: news@contoso.com
Authentication-Results: mx; spf=pass smtp.mailfrom=contoso.com; dkim=pass; dmarc=pass

Read the full article: https://www.contoso.com/blog/sleep-tips`;
const GIFT = `From: "Dana Whitfield (CEO)" <dana.whitfield.ceo@gmail.com>
Subject: Quick favor

Hi, I need a quick favor handled immediately. I need you to purchase 5 Apple gift cards. It's time-sensitive.
Scratch off the codes and send them as soon as possible. Please keep this confidential.`;

test('splitHeaders unfolds continuation lines and keeps repeats', () => {
  const s = splitHeaders('Subject: Hello\n  world\nReceived: a\nReceived: b\n\nBody');
  assert.eq(s.headers.subject, 'Hello world');
  assert.eq(s.headers.received, 'a\nb');
  assert.eq(s.body, 'Body');
  assert.eq(s.list.length, 3);
  assert.deepEq(splitHeaders('Just a body').headers, {});
});

test('address helpers and registrable domains', () => {
  assert.eq(addrOf('"Bob" <Bob@Example.com>'), 'bob@example.com');
  assert.eq(displayName('"Bob Smith" <bob@example.com>'), 'Bob Smith');
  assert.eq(regDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.eq(regDomain('mail.google.com'), 'google.com');
});

test('extractLinks reads anchors, markdown links and bare URLs', () => {
  const l = extractLinks('<a href="https://a.com/x">Click</a> [docs](https://b.org/y) and www.c.net/z.');
  assert.deepEq(l.map((x) => x.url.hostname), ['a.com', 'b.org', 'www.c.net']);
  assert.eq(l[0].text, 'Click');
});

test('punyDecode follows RFC 3492', () => {
  assert.eq(punyDecode('xn--mnchen-3ya'), 'münchen');
  assert.eq(punyDecode('xn--bcher-kva'), 'bücher');
  assert.eq(unicodeHost('www.xn--bcher-kva.ch'), 'www.bücher.ch');
  assert.eq(punyDecode('plain'), 'plain');
});

test('homographs are caught through the confusable skeleton', () => {
  const host = new URL('http://аpple.com').hostname;
  assert.ok(host.startsWith('xn--'));
  assert.eq(unicodeHost(host), 'аpple.com');
  assert.eq(skeleton('аpple'), 'apple');
  assert.ok(mixedScript('аpple')); assert.ok(!mixedScript('bücher'));
  assert.eq(lookalike(host), 'apple');
});

test('lookalike flags typos and glyph swaps but not the real brand', () => {
  assert.eq(lookalike('paypa1.com'), 'paypal');
  assert.eq(lookalike('northwlnd-bank.com'), 'northwindbank');
  assert.eq(lookalike('rnicrosoft.com'), 'microsoft');
  assert.eq(lookalike('paypal.com'), null);
  assert.eq(lookalike('contoso.com'), null);
});

test('linkFlags spots IPs, @ tricks, brand-in-subdomain and redirects', () => {
  const t = (href, text) => linkFlags(href, text).map((f) => f.t).join(' | ');
  assert.ok(/raw IP/.test(t('http://192.168.1.1/login')));
  assert.ok(/"@" trick/.test(t('https://paypal.com@evil.com/')));
  const sub = t('https://www.google.com.evil.top/x');
  assert.ok(/high-abuse TLD \.top/.test(sub)); assert.ok(/"google" appears in the subdomain/.test(sub));
  assert.ok(/redirects through a "url" parameter to evil\.top/.test(t('https://ok.com/r?url=https%3A%2F%2Fevil.top%2Fx')));
  assert.ok(/displays "www.bank.com" but goes to other.com/.test(t('https://other.com', 'www.bank.com')));
  assert.eq(linkFlags('https://www.contoso.com/blog', '').length, 0);
});

test('inspectUrl decomposes a URL', () => {
  const u = inspectUrl('https://login.paypal.com.secure.xyz/a%20b?u=1&next=https://evil.top#frag');
  assert.eq(u.registrable, 'secure.xyz');
  assert.deepEq(u.subdomains, ['login', 'paypal', 'com']);
  assert.eq(u.path, '/a b'); assert.eq(u.params.length, 2); assert.eq(u.fragment, 'frag');
  assert.eq(u.redirects[0].target, 'https://evil.top');
});

test('parseReceived orders hops oldest first with delays', () => {
  const hops = parseReceived(splitHeaders(BANK).headers);
  assert.eq(hops.length, 2);
  assert.eq(hops[0].from, 'relay.verify-center.top'); assert.eq(hops[0].ip, '203.0.113.7');
  assert.eq(hops[1].by, 'inbox.example.net'); assert.eq(hops[1].delay, 8);
});

test('scanEmail separates phishing, CEO fraud and a real newsletter', () => {
  const bank = scanEmail(BANK), news = scanEmail(NEWS), gift = scanEmail(GIFT);
  assert.ok(bank.score >= 60, 'bank ' + bank.score); assert.eq(bank.verdict[1], 'Likely phishing');
  assert.ok(bank.sig.some((s) => /imitates "northwindbank"/.test(s.text)));
  assert.ok(news.score < 30, 'news ' + news.score);
  assert.ok(gift.score >= 60, 'gift ' + gift.score);
  assert.ok(gift.sig.some((s) => /CEO-fraud/.test(s.text)));
  const k = scoreByKind(bank.sig);
  assert.ok(k.auth >= 45 && k.link > 0 && k.language > 0);
});

test('trusted and blocked lists adjust the score', () => {
  const plain = scanEmail('From: a@shop.example\n\nYour order shipped.');
  assert.eq(scanEmail('From: a@shop.example\n\nYour order shipped.', { blocked: ['shop.example'] }).score, Math.min(100, plain.score + 40));
  assert.eq(scanEmail(NEWS, { trusted: ['contoso.com'] }).score, 0);
});

test('flattenMime decodes multipart quoted-printable and base64 bodies', () => {
  const eml = [
    'From: a@shop.example', 'Subject: Hi', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="XX"', '',
    '--XX', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'Caf=C3=A9 opens at 9 =', 'today', '',
    '--XX', 'Content-Type: application/octet-stream; name="invoice.html"', 'Content-Disposition: attachment; filename="invoice.html"', 'Content-Transfer-Encoding: base64', '', 'PGgxPkhpPC9oMT4=', '',
    '--XX--', '',
  ].join('\n');
  const flat = flattenMime(eml);
  assert.ok(flat.startsWith('From: a@shop.example\nSubject: Hi\n\n'));
  assert.ok(flat.includes('Café opens at 9 today'));
  assert.ok(flat.includes('Attachment: invoice.html'));
  assert.ok(!/Content-Type/.test(flat));
  assert.eq(decodeB64('SGVsbG8='), 'Hello');
  assert.eq(flattenMime('no headers here'), 'no headers here');
});
