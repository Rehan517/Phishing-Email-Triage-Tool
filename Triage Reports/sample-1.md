# PhishTriage Output:

```
==================================================
           PHISHTRIAGE REPORT
==================================================
VERDICT: LIKELY MALICIOUS — ESCALATE  (risk score: 3)

Notes:
  - From domain 'atendimento.com.br' and Return-Path domain 'ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06' do not match (suspicious)
  - DMARC result missing (could not fully assess)
  - SPF result missing (could not fully assess)
  - DKIM result missing (could not fully assess)
  - No authentication method could be verified (SPF/DKIM/DMARC all inconclusive)

HEADERS:
  From: BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>
  Reply-To: None
  Return-Path: root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06
  Hops: 5

AUTHENTICATION RESULTS:
  spf: temperror
  dkim: none
  dmarc: temperror

IOCs:
  Domains: ['fonts[.]googleapis[.]com', 'blog1seguimentmydomaine2bra[.]me', 'fonts[.]gstatic[.]com']
  URLs: 3 found
  Attachments: []
```

# Investigation: Impersonating Brazilian Bank

**Sample:** sample-1.eml (source: Phishing Pot)
**Date analysed:** 25/06/2026
**Verdict:** LIKELY MALICIOUS — ESCALATE

## Summary

This is an email impersonating a brazilian bank aiming to gain banking details. It entices the viewer with an offer and directs them into click the link to an attacker controlled page to get their banking details. Multiple header and authentication red flags confirm this email is not legitimate. Verdict: LIKELY MALICIOUS- ESCALATE

## What the email claims to be

The email is created to look like its from a brazilian bank providing an offer to the receiver and to take action on the attacker controlled page. The sender address 'banco.bradesco@atendimento.com.br' is a lookalike domain designed to resemble the brazilian bank. The lure relies on a premium offer to prompt the viewer to act.

## Findings (the evidence)

- Sender/header analysis:
  The From address <banco.bradesco@atendimento.com.br> is a lookalike domain impersonating a brazilian bank - it resembles an official address but is not the correct domain. The Reply-To is none, and the Return-Path is root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06, the biggest red flag as it a random server. The From claims atendimento.com.br (impersonating Bradesco), but the Return-Path is root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 which not a domain at all, but the root user on a default-named DigitalOcean cloud server (the sfo3 hostname is DigitalOcean's San Francisco region). A legitimate bank sends from its own authenticated mail infrastructure; mail originating as root from a throwaway rented VPS is a hallmark of attacker-controlled infrastructure.
- Authentication:
  No authentication method could be verified — SPF and DMARC returned 'temperror' and DKIM as 'none', meaning the email carries no valid proof it came from the domain it claims. Legitimate mail authenticates cleanly; the complete absence of verifiable authentication is itself a red flag.
- IOCs:
  There are 3 domains in the email where 2 are legitimate domains related to fonts. The other domain 'blog1seguimentmydomaine2bra[.]me' is a random domain directing the viewer to a malicious address. This address has no link to the brazilian bank, and is the likely destination where bank details would be harvested.

## Assessment & verdict

Every independent check failed at once. There is a spoofed lookalike sender, mismatched routing , zero valid authentication and a random destination domain. No legitimate signal is present positioning this email as malicious.

## Recommended actions

- Take the email's IOCs (and any attachment hash) to threat-intel sources like VirusTotal/URLhaus to confirm and enrich.
- Block the sender domain atendimento.com.br and the IOC domain blog1seguimentmydomaine2bra[.]me (add both to the mail gateway / web proxy blocklist)
- Raise this to a L2 analyst so the receiver of the email can be contacted to avoid interacting with this email
