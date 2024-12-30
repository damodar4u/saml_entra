import requests
import urllib.parse
import logging
import json
import re
import base64
import zlib

# Setup logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LoginWorkflow")

# Initialize session
session = requests.Session()

# URLs
login_url = "https://login.microsoftonline.com/{tenant_id}/login"
kmsi_url = "https://login.microsoftonline.com/kmsi"
cred_type_url = "https://login.microsoftonline.com/common/GetCredentialType"

# Headers
common_headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

# Login payload
login_payload = {
    "login": "username@example.com",
    "passwd": "your_password_here",
    "flowToken": "",
    "canary": "",
    "hpgrequestid": "",
    "ctx": "",
    "LoginOptions": "1",
    "KeepMeSignedIn": "True",
    "type": 28
}

# Step 1: Initial request
response = session.post(cred_type_url, headers=common_headers, json={"username": login_payload["login"]}, verify=False)
if response.status_code == 200:
    response_json = response.json()
    login_payload["flowToken"] = response_json.get("FlowToken", "")
    login_payload["canary"] = response_json.get("Canary", "")
else:
    logger.error("Initial request failed. Status Code: %s", response.status_code)
    exit()

# Step 2: Login request
login_response = session.post(login_url, headers=common_headers, data=login_payload, verify=False, allow_redirects=True)
if login_response.status_code == 200:
    logger.info("Login successful.")
else:
    logger.error("Login failed. Status Code: %s", login_response.status_code)
    exit()

# Step 3: Keep me signed in (KMSI)
kmsi_payload = {
    "flowToken": login_payload["flowToken"],
    "canary": login_payload["canary"],
    "hpgrequestid": login_payload["hpgrequestid"],
    "ctx": login_payload["ctx"],
    "KeepMeSignedIn": True,
    "LoginOptions": "1",
    "type": 28
}
kmsi_response = session.post(kmsi_url, headers=common_headers, data=kmsi_payload, verify=False, allow_redirects=True)
if kmsi_response.status_code == 200:
    logger.info("KMSI successful.")
else:
    logger.error("KMSI failed. Status Code: %s", kmsi_response.status_code)
    exit()

# Cookies and session verification
cookies = session.cookies.get_dict()
logger.info("Session Cookies: %s", cookies)
