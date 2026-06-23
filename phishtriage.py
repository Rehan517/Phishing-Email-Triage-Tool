import email
import re
import hashlib
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse  

def load_email(file_path):
    with open(file_path, 'rb') as f:   # 'rb' = read raw bytes
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def extract_headers(msg):
    headers = {
        'From': msg['From'],
        'Reply-To': msg['Reply-To'],
        'Return-Path': msg['Return-Path'],
        'Received': msg.get_all('Received'),  # Get all Received headers
        'Authentication-Results': msg.get_all('Authentication-Results'),
        
    }
    return headers

def check_authentication(msg):
    """Pull spf / dkim / dmarc results out of Authentication-Results."""
    results = {"spf": None, "dkim": None, "dmarc": None}

    # Google can add more than one of these headers; join them into one blob to search.
    auth_headers = msg.get_all("Authentication-Results") or []
    blob = " ".join(auth_headers)

    # Worked example — SPF:
    spf_match = re.search(r"spf=(\w+)", blob)
    results["spf"] = spf_match.group(1) if spf_match else None

    dkim_match = re.search(r"dkim=(\w+)", blob)
    results["dkim"] = dkim_match.group(1) if dkim_match else None

    dmarc_match = re.search(r"dmarc=(\w+)", blob)
    results["dmarc"] = dmarc_match.group(1) if dmarc_match else None

    return results

def extract_iocs(msg):
    """Extract IOCs (URLs first; domains + attachments next) from the email."""
    iocs = {"urls": [], "domains": [], "attachments": []}

    # 1. Gather text from the body parts (plain + html).
    body_text = ""
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            body_text += part.get_content()   # decodes payload to a string for us

    # 2. Find URLs in that text.
    url_pattern = r'https?://[^\s<>"\'\)]+'
    iocs["urls"] = list(set(re.findall(url_pattern, body_text)))

     # 3. Pull the domain out of each URL, keep only the unique ones.
    domains = set()
    for url in iocs["urls"]:
        domain = urlparse(url).netloc      # 'https://braze-images.com/x' -> 'braze-images.com'
        if domain:                         # skip blanks from any malformed URL
            domains.add(domain)
    iocs["domains"] = list(domains)


    # 4. Find attachments and fingerprint them (hash the bytes — never open the file).
    for part in msg.walk():
        filename = part.get_filename()
        if filename:                              # has a filename => it's an attachment
            payload = part.get_payload(decode=True)   # raw decoded bytes of the file
            if payload is None:
                continue                          # nothing to hash, skip safely

            attachment = {
                "filename": filename,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
            iocs["attachments"].append(attachment)

    iocs["urls_defanged"] = defang_list(iocs["urls"])
    iocs["domains_defanged"] = defang_list(iocs["domains"])

    return iocs


def defang(ioc):
    """Neutralise an IOC string so it's readable but not clickable."""
    ioc = ioc.replace("https://", "hxxps://")
    ioc = ioc.replace("http://", "hxxp://")
    ioc = ioc.replace(".", "[.]")
    return ioc

def defang_list(iocs):
    return [defang(item) for item in iocs]



def score_email(auth, iocs):
    """Turn findings into a risk score and a verdict. Offline-only (no external lookups)."""
    risk = 0
    notes = []                      # human-readable reasons, for the report
    incomplete = False

    # --- Authentication signals ---
    if auth["dmarc"] == "fail":
        risk += 3
        notes.append("DMARC failed (strong spoofing signal)")
    elif auth["dmarc"] is None:
        incomplete = True
        notes.append("DMARC result missing (could not fully assess)")


    if auth["spf"] == "fail":
        risk += 1
        notes.append("SPF failed (weak spoofing signal)")
    elif auth["spf"] is None:
        incomplete = True
        notes.append("SPF result missing (could not fully assess)")
    

    if auth["dkim"] == "fail":
        risk += 1
        notes.append("DKIM failed (weak spoofing signal)")
    elif auth["dkim"] is None:
        incomplete = True
        notes.append("DKIM result missing (could not fully assess)")

    # --- IOC signals ---
    if iocs["attachments"]:                       # non-empty list is truthy
        risk += 1
        notes.append(f"{len(iocs['attachments'])} attachment(s) present")

    # --- Map score to verdict ---
    if risk >= 3:
        verdict = "LIKELY MALICIOUS — ESCALATE"
    elif risk == 0 and not incomplete:
        verdict = "LIKELY BENIGN"
    else:
        verdict = "SUSPICIOUS — REVIEW"

    return {"verdict": verdict, "risk": risk, "notes": notes, "incomplete": incomplete}


def build_report(headers, auth, iocs, result):
    """Assemble a clean, human-readable triage report as a single string."""
    lines = []                                    # build up a list of lines, join at the end

    lines.append("=" * 50)
    lines.append("           PHISHTRIAGE REPORT")
    lines.append("=" * 50)
    lines.append(f"VERDICT: {result['verdict']}  (risk score: {result['risk']})")
    lines.append("")                              # blank line for spacing

    lines.append("Notes:")
    if result['notes']:
        for note in result['notes']:
            lines.append(f"  - {note}")
    else:
        lines.append("  - No risk signals detected")
    lines.append("")                              # blank line for spacing

    skip_in_headers = {"Received", "Authentication-Results"}
    lines.append("HEADERS:")
    for k, v in headers.items():
        if k in skip_in_headers:
            continue                      # skip noise / already-parsed-below
        lines.append(f"  {k}: {v}")

    if headers.get("Received"): # count the number of Received headers to get hop count
        lines.append(f'  Hops: {len(headers.get("Received", []))}')
    else:
        lines.append("  Hops: 0")  
    lines.append("")                              # blank line for spacing

    lines.append("AUTHENTICATION RESULTS:")
    for k, v in auth.items():
        lines.append(f"  {k}: {v}")
    lines.append("")                              # blank line for spacing

    lines.append("IOCs:")
    lines.append(f"  Domains: {iocs['domains_defanged']}")
    lines.append(f"  URLs: {len(iocs['urls_defanged'])} found")
    lines.append(f"  Attachments: {iocs['attachments']}")
    lines.append("")                              # blank line for spacing


    return "\n".join(lines)                        # one string, newline-separated




if __name__ == "__main__":
    msg = load_email('samples/test.eml')

    auth_results = check_authentication(msg)
    iocs = extract_iocs(msg)
    result = score_email(auth_results, iocs)

    print(build_report(extract_headers(msg), auth_results, iocs, result))
