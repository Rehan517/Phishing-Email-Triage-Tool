import email
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

if __name__ == "__main__":
    msg = load_email('samples/test.eml')
    for k, v in extract_headers(msg).items():
        print(f"{k}: {v}")