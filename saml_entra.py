import requests
import urllib.parse
import logging
import re
import base64
import zlib

# Setup logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SAMLWorkflow")

# Initialize session
session = requests.Session()

# URLs
application_endpoint = "https://your-application-endpoint"
saml2_url = "https://login.microsoftonline.com/{tenant_id}/saml2"
login_url = "https://login.microsoftonline.com/{tenant_id}/login"
kmsi_url = "https://login.microsoftonline.com/kmsi"
cred_type_url = "https://login.microsoftonline.com/common/GetCredentialType"

# Headers
common_headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

# Step 1: Generate SAML Request and Extract Initial Values
response = session.get(application_endpoint, headers={"Accept": "application/json"}, verify=False, allow_redirects=True)
if response.status_code == 200:
    logger.info("Successfully called application endpoint.")

    # Extract values using regular expressions
    response_text = response.text
    canary_match = re.search(r'"canary":"(.*?)"', response_text)
    flow_token_match = re.search(r'"sFT":"(.*?)"', response_text)
    s_ctx_match = re.search(r'"sCtx":"(.*?)"', response_text)
    x_ms_request_id = response.headers.get("x-ms-request-id", None)

    canary = canary_match.group(1) if canary_match else None
    flow_token = flow_token_match.group(1) if flow_token_match else None
    s_ctx = s_ctx_match.group(1) if s_ctx_match else None

    if not canary or not flow_token or not s_ctx:
        logger.error("Failed to extract required values: canary, flowToken, or sCtx.")
        exit()

    logger.info(f"Extracted Values - Canary: {canary}, FlowToken: {flow_token}, sCtx: {s_ctx}, x-ms-request-id: {x_ms_request_id}")

    # Extract SAML Request from URL
    parsed_url = urllib.parse.urlparse(response.url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    saml_request = query_params.get("SAMLRequest", [None])[0]

    if saml_request:
        decoded_bytes = base64.b64decode(saml_request)
        try:
            saml_request_str = zlib.decompress(decoded_bytes, -15).decode("utf-8")
            logger.info("Decompressed SAML Request successfully.")
        except Exception as e:
            logger.error("Failed to decompress SAML Request: %s", e)
    else:
        logger.error("SAMLRequest parameter missing in response.")
        exit()
else:
    logger.error("Failed to retrieve response from application endpoint. Status Code: %s", response.status_code)
    exit()

# Step 2: Send SAML2 Request to the Microsoft Login Endpoint
saml2_payload = {
    "SAMLRequest": saml_request,
    "RelayState": "custom_relay_state"  # Add your relay state if required
}
saml2_response = session.post(saml2_url, headers=common_headers, data=saml2_payload, verify=False, allow_redirects=True)
if saml2_response.status_code == 200:
    logger.info("SAML2 request sent successfully.")
    saml_response = saml2_response.text
    logger.info("SAML2 Response received.")
else:
    logger.error("Failed to send SAML2 request. Status Code: %s", saml2_response.status_code)
    exit()

# Step 3: Login Request
login_payload = {
    "login": "username@example.com",
    "passwd": "your_password_here",
    "flowToken": flow_token,
    "canary": canary,
    "ctx": s_ctx,
    "LoginOptions": "1",
    "KeepMeSignedIn": True,
    "type": 28
}
login_response = session.post(login_url, headers=common_headers, data=login_payload, verify=False, allow_redirects=True)
if login_response.status_code == 200:
    logger.info("Login successful.")
    x_ms_request_id = login_response.headers.get("x-ms-request-id", None)
    logger.info(f"x-ms-request-id from login response: {x_ms_request_id}")
else:
    logger.error("Login failed. Status Code: %s", login_response.status_code)
    exit()

# Step 4: Keep Me Signed In (KMSI)
kmsi_payload = {
    "flowToken": flow_token,
    "canary": canary,
    "KeepMeSignedIn": True,
    "LoginOptions": "1",
    "type": 28
}
kmsi_response = session.post(kmsi_url, headers=common_headers, data=kmsi_payload, verify=False, allow_redirects=True)
if kmsi_response.status_code == 200:
    logger.info("KMSI successful.")
    x_ms_request_id = kmsi_response.headers.get("x-ms-request-id", None)
    logger.info(f"x-ms-request-id from KMSI response: {x_ms_request_id}")
else:
    logger.error("KMSI failed. Status Code: %s", kmsi_response.status_code)
    exit()

# Step 5: Validate Cookies and Session
cookies = session.cookies.get_dict()
logger.info("Session Cookies: %s", cookies)
