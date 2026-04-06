import logging
import json
import time
import hmac
import hashlib
import base64
import urllib.parse
import secrets
import requests
import azure.functions as func

import os

ACCOUNT_ID = os.environ.get("NETSUITE_ACCOUNT_ID", "569730")
CONSUMER_KEY = os.environ.get("NETSUITE_CONSUMER_KEY")
CONSUMER_SECRET = os.environ.get("NETSUITE_CONSUMER_SECRET")
TOKEN_ID = os.environ.get("NETSUITE_TOKEN_ID")
TOKEN_SECRET = os.environ.get("NETSUITE_TOKEN_SECRET")

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

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("NetSuite query function triggered.")

    try:
        body = req.get_json()
        query = body.get("query")
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400)

    if not query:
        return func.HttpResponse("Missing 'query' in request body.", status_code=400)

    base_url = f"https://{ACCOUNT_ID}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql"
    query_params = {"limit": "5", "offset": "0"}
    auth_header = generate_tba_header("POST", base_url, query_params)
    url = base_url + "?limit=5&offset=0"

    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Prefer": "transient"
    }

    response = requests.post(url, headers=headers, json={"q": query})

    if response.status_code == 200:
        return func.HttpResponse(response.text, mimetype="application/json", status_code=200)
    else:
        return func.HttpResponse(
            f"NetSuite error {response.status_code}: {response.text}",
            status_code=response.status_code
        )