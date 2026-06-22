import email
import re
from email import policy
from email.parser import BytesParser

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


if __name__ == "__main__":
    msg = load_email('samples/test.eml')
    for k, v in extract_headers(msg).items():
        print(f"{k}: {v}")

    auth_results = check_authentication(msg)
    print("\nAuthentication Results:")
    for k, v in auth_results.items():
        print(f"  {k}: {v}")