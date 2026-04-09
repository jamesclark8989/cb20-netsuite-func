import os
import requests
import json
import time
import hmac
import hashlib
import base64
import urllib.parse
import secrets
from dotenv import load_dotenv

load_dotenv()

ACCOUNT_ID = os.environ.get("NETSUITE_ACCOUNT_ID")
CONSUMER_KEY = os.environ.get("NETSUITE_CONSUMER_KEY")
CONSUMER_SECRET = os.environ.get("NETSUITE_CONSUMER_SECRET")
TOKEN_ID = os.environ.get("NETSUITE_TOKEN_ID")
TOKEN_SECRET = os.environ.get("NETSUITE_TOKEN_SECRET")

print(f"Account ID: {ACCOUNT_ID}")
print(f"Consumer Key: {CONSUMER_KEY[:10] if CONSUMER_KEY else 'NOT LOADED'}")
print(f"Token ID: {TOKEN_ID[:10] if TOKEN_ID else 'NOT LOADED'}")

def generate_tba_header(method, url, params=None):
    oauth_nonce = secrets.token_hex(16)
    oauth_timestamp = str(int(time.time()))

    oauth_params = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_nonce": oauth_nonce,
        "oauth_signature_method": "HMAC-SHA256",
        "oauth_timestamp": oauth_timestamp,
        "oauth_token": TOKEN_ID,
        "oauth_version": "1.0",
    }

    all_params = {**oauth_params, **(params or {})}
    sorted_params = sorted(all_params.items())
    encoded_params = urllib.parse.urlencode(sorted_params)

    base_string = "&".join([
        method.upper(),
        urllib.parse.quote(url, safe=""),
        urllib.parse.quote(encoded_params, safe="")
    ])

    signing_key = f"{urllib.parse.quote(CONSUMER_SECRET, safe='')}&{urllib.parse.quote(TOKEN_SECRET, safe='')}"
    signature = base64.b64encode(
        hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha256).digest()
    ).decode()

    oauth_params["oauth_signature"] = signature
    realm = ACCOUNT_ID.replace("-", "_").upper()
    auth_header = "OAuth realm=\"" + realm + "\", " + ", ".join(
        f'{k}="{urllib.parse.quote(str(v), safe="")}"' for k, v in sorted(oauth_params.items())
    )
    return auth_header

def run_suiteql(query, limit=5):
    base_url = f"https://{ACCOUNT_ID}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql"
    query_params = {"limit": str(limit), "offset": "0"}
    auth_header = generate_tba_header("POST", base_url, query_params)
    url = f"{base_url}?limit={limit}&offset=0"

    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Prefer": "transient"
    }

    response = requests.post(url, headers=headers, json={"q": query})
    return response.status_code, response.text

# Explore Sales Orders
print("=== SALES ORDERS ===")
#status, data = run_suiteql("SELECT * FROM customer")
#status, data = run_suiteql("SELECT * FROM salesorder")
status, data = run_suiteql("SELECT * FROM salesorderitem WHERE salesorder = '7946'")
print(f"Status: {status}")
print(json.dumps(json.loads(data), indent=2))