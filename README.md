# phishing-email-analyzer

[![tests](https://github.com/dguywhoknows/phishing-email-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/dguywhoknows/phishing-email-analyzer/actions/workflows/tests.yml)

Paste a suspicious email and get local forensics (headers, links, lookalike domains, pressure language) plus an AI second opinion.

Live: https://dguywhoknows.github.io/phishing-email-analyzer/

## Overview

Phish Scope runs a set of explainable checks entirely in your browser. It parses raw headers to read SPF/DKIM/DMARC results, Reply-To and Return-Path mismatches, and display-name spoofing. It pulls every link out of HTML, Markdown and plain text, then flags text/destination mismatches, raw IPs, punycode, high-abuse TLDs, shorteners and the '@' trick. It catches lookalike domains with Levenshtein distance plus homoglyph folding (rn→m, 0→o, 1→l), scores urgency, credential, money and threat language, and highlights it in the body. Each signal adds a visible weight to a 0-100 risk score. An optional AI analyst then gives a plain-language verdict with do's and don'ts.

## Pages

- **Scan**
- **Headers**
- **URL inspector**
- **Training**
- **History**
- **Settings**

## Features

- Raw header parsing with folded-line support; SPF / DKIM / DMARC badge readout
- Sender checks: Reply-To / Return-Path mismatch, display-name brand spoofing, free-webmail 'executives'
- Link extraction from HTML anchors, Markdown and bare URLs, with per-link flags
- Lookalike detection: Levenshtein + homoglyph normalization against a brand list; brand-in-subdomain trick
- Social-engineering lexicon (urgency, credentials, money, threats, generic greetings) with in-body highlighting
- Transparent weighted scoring, so every point is explained
- AI second opinion: verdict, confidence, reasons, safe next steps
- Headers page: Received-chain delivery path with per-hop delays, an SPF/DKIM/DMARC explainer, identity fields (Reply-To, Return-Path, Message-ID) and the full header table
- URL inspector page: colour-coded URL anatomy showing the domain that actually owns the site, punycode/IDN decoding, query parameters, hidden redirect targets and URL-level red flags
- Homograph detection: an RFC 3492 punycode decoder plus a Cyrillic/Greek confusables skeleton catches domains like аpple.com
- Open .eml files directly: multipart MIME with quoted-printable and base64 bodies is decoded in the browser, and attachments are listed
- Training page: spot-the-phish game over built-in fictional emails, with the giveaway and the scanner's view after each answer, plus AI-generated practice messages
- History page: past scans with risk, re-open, CSV export, and trusted/blocked domain lists that adjust future scores
- Risk breakdown by category and a copyable plain-text report

## How it works

LLM calls are used for:

- Analyst review that weighs the deterministic signals against tone and plausibility (JSON)

Everything else (header parsing, link extraction, domain analysis, lexicon matching, scoring, highlighting) runs locally in the browser.

## Getting started

No build step and no dependencies. Serve the folder with any static server:

```bash
git clone https://github.com/dguywhoknows/phishing-email-analyzer.git
cd phishing-email-analyzer
python -m http.server 8000
```

Then open http://localhost:8000.

### Configuration

Without an API key the app runs in demo mode with sample model output. To use a live model, open
**Settings → Configure provider** and paste a key for [Groq](https://console.groq.com/keys) or
[OpenRouter](https://openrouter.ai/keys). The key is stored in this browser's `localStorage` (namespaced to
this app) and is sent only to the selected provider.

## Testing

`src/core.js` holds the app's logic as pure functions and is covered by 12 unit tests.

```bash
node tests/run-node.js        # CI runs this on every push
```

Or open `tests/index.html` in a browser ([live](https://dguywhoknows.github.io/phishing-email-analyzer/tests/)).

## Project structure

```
index.html           markup for every page
src/app.js           UI, page wiring and event handlers
src/core.js          pure logic with no DOM access (unit-tested)
src/demo.js          sample responses used when no API key is configured
src/lib/ai.js        LLM client: Groq / OpenRouter, streaming, JSON mode, retries
src/lib/dom.js       DOM helpers, namespaced storage, markdown renderer
src/lib/router.js    hash router and the Settings page
styles/base.css      design tokens and shared components
styles/app.css       app-specific styles
tests/               unit tests (browser runner + Node runner for CI)
```

## Tech

- Registrable-domain heuristics (eTLD+1 approximation)
- Levenshtein edit distance + homoglyph folding
- Regex-based NLP lexicons
- Parsing, punycode, link analysis, MIME decoding and scoring in src/core.js covered by unit tests run in the browser and in CI
- Vanilla JavaScript, no framework or bundler
- Deployed with GitHub Pages

## License

MIT
