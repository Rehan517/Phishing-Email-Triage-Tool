# PhishTriage

PhishTriage is an offline, defensive triage tool for SOC analysts. It takes a raw phishing email (.eml) and produces a clean, structured report with a verdict and risk score in seconds, so an analyst can decide whether to escalate.

## What it does

- Checks headers to make sure that the domains are legitimate
- Checks authentication results (SPF/DKIM/DMARC) to see if they have passed
- Hashes attachments to see if they contain malware
- Produces a verdict report with a risk score and recommended action

## Why it matters (the SOC context)

Phishing triage is one of the highest-volume tasks an L1 SOC analyst handles. The same header, authentication, and IOC checks repeated on email after email. PhishTriage automates that repetitive first pass so the analyst spends their time on the decision, not the data-gathering. It deliberately stays offline and defensive: it analyses emails, it never sends or generates anything.

## The checks explained

- Header analysis (From/Reply-To/Return-Path): Here we check the From and Return-Path to check if the domains are the same and if they are not we should be suspicious
- SPF/DKIM/DMARC: Next we check the authentication results to see if it has passed. Note: passing means the email is authentic, not necessarily safe.
- IOC extraction: We check the content of the email to see if there are any malicious links
- Defanging: We make sure the links are altered so that they are not clickable so anyone looking at our report does not click on the links
- Attachment Hashing: a hash of the attachments is also generated which can be checked on external tools like VirusTotal
- Scoring/Verdict: A risk score and verdict are generated depending on the amount of errors found

## Installation

```bash
  git clone https://github.com/Rehan517/Phishing-Email-Triage-Tool.git
  cd phishtriage
  python3 -m venv venv
  source venv/bin/activate
  python3 phishtriage.py samples/test_attachment.eml
```

## Usage

Edit the filename in **main**, then run `python3 phishtriage.py`

## Example output

```
==================================================
PHISHTRIAGE REPORT
==================================================
VERDICT: SUSPICIOUS — REVIEW (risk score: 1)

Notes:

- 1 attachment(s) present

HEADERS:
From: "[BB] - Seu saldo foi liberado - Código: 11084339647130851921" <prestonconstance587@gmail.com>
Reply-To: None
Return-Path: prestonconstance587@gmail.com
Hops: 6

AUTHENTICATION RESULTS:
spf: pass
dkim: pass
dmarc: pass

IOCs:
Domains: []
URLs: 0 found
Attachments: [{'filename': 'csWuYjyqO2IR.pdf', 'md5': 'f1b1ac7839d2b2a1e458b5d87c7b2ca2', 'sha256': 'cfc5fbc759dcc599c8329dd94f9364394c7b1e875d6ff515c7337e00fb1f30cf', 'size_bytes': 97566}]
```

## Sample source & safety note

Phishing sample emails were downloaded from https://github.com/rf-peixoto/phishing_pot/tree/main

## Limitations & future work

- Offline only: no live reputation lookups yet (planned: VirusTotal / AbuseIPDB / URLhaus enrichment using the attachment hashes and domains the tool already extracts).
- Heuristic scoring: a simple, explainable points model, not ML.
- Planned: a web UI for uploading emails.
