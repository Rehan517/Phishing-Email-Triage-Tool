# PhishTriage Output:

```
==================================================
           PHISHTRIAGE REPORT
==================================================
VERDICT: LIKELY MALICIOUS — ESCALATE  (risk score: 3)

Notes:
  - From domain 'access-accsecurity.com' and Return-Path domain 'thcultarfdes.co.uk' do not match (suspicious)
  - DMARC result missing (could not fully assess)
  - SPF result missing (could not fully assess)
  - DKIM result missing (could not fully assess)
  - No authentication method could be verified (SPF/DKIM/DMARC all inconclusive)

HEADERS:
  From: "Microsoft account team", _ <no-reply@access-accsecurity.com>
  Reply-To: sotrecognizd@gmail.com
  Return-Path: bounce@thcultarfdes.co.uk
  Hops: 4

AUTHENTICATION RESULTS:
  spf: none
  dkim: none
  dmarc: permerror

IOCs:
  Domains: ['thebandalisty[.]com']
  URLs: 1 found
  Attachments: []
```

# Investigation: Email impersonating Microsoft account security

**Sample:** sample-10.eml (source: Phishing Pot)
**Date analysed:** 25/06/2026
**Verdict:** LIKELY MALICIOUS — ESCALATE

## Summary

This is a credential-harvesting phishing email impersonating a Microsoft account security alert. It uses the pretext of a suspicious sign-in to pressure the recipient into clicking through and entering the Microsoft credentials on an attacker-controlled page. Multiple header and authentication red flags confirm it is not from Microsoft. Verdict: LIKELY MALICIOUS- ESCALATE

## What the email claims to be

The email is style as an official 'Microsoft account team' security notification, displaying the sender name Microsoft account team to appear legitimate. the underlying sender address, however, is 'no-reply@access-accesecurity.com'. this is a lookalike domain designed to resemble a Microsoft security address without belonging to Microsoft. The lure relies on urgency around accout security to prompt the victim to act quickly.

## Findings (the evidence)

- Sender/header analysis:
  The From address no-reply@access-accsecurity.com is a lookalike domain impersonating Microsoft's security team - it resembles an official address but is not a Microsoft domain. The Reply-To is sotrecognizd@gmail.com, a personal Gmail account, and the Return-Path is bounce@thcultarfdes.co.uk, a third unrelated domain. Three different, unrelated domains across the sender fields is a strong spoofing indicator; legitimate senders are consistent.
- Authentication:
  No authentication method could be verified — SPF and DKIM returned 'none' and DMARC a 'permerror', meaning the email carries no valid proof it came from the domain it claims. Legitimate Microsoft mail authenticates cleanly; the complete absence of verifiable authentication is itself a red flag.
- IOCs:
  There is one domain in the email 'thebandalisty[.]com' which is directing the viewer to a random address which most is likely malicious. it has no relationship to Microsoft, and is the likely destination where credentials would be harvested.

## Assessment & verdict

Every independant check failed at once. There is a spoofed lookalike sender, mismatched routing across three domains, zero valid authentication and a non-microsoft destination domain. No legitimate signal is present positioning this email as malicious.

## Recommended actions

- Take the email's IOCs (and any attachment hash) to threat-intel sources like VirusTotal/URLhaus to confirm and enrich.
- Block the sender domain access-accsecurity.com and the IOC domain thebandalisty[.]com (add both to the mail gateway / web proxy blocklist)
- Raise this to a L2 analyst so the receiver of the email can be contacted to avoid interacting with this email
