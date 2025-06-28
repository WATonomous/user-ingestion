from datetime import datetime, timedelta
import logging
import os
import time

import requests
import yaml

import jwt

FISSION_CONFIGS_BASE_PATH = "/configs/fission-default/user-ingestion-configs"
FISSION_SECRETS_BASE_PATH = "/secrets/fission-default/user-ingestion-secrets"

logger = logging.getLogger()

# PR Body Helpers
pr_body_prefix = "<!-- This section is manged by repo-ingestion-bot. Please Do not edit manually! -->"
pr_body_postfix = "<!-- End of section managed by repo-ingestion-bot -->"

def wrap_pr_body(body):
    return "\n\n" + pr_body_prefix + "\n" + body + "\n" + pr_body_postfix + "\n\n"

def extract_pr_body(body):
    if not body or pr_body_prefix not in body or pr_body_postfix not in body:
        return ""
    return body.split(pr_body_prefix)[1].split(pr_body_postfix)[0]

def update_pr_body(body, new_body):
    if not body:
        return wrap_pr_body(new_body)
    if pr_body_prefix not in body or pr_body_postfix not in body:
        return body + wrap_pr_body(new_body)
    return body.split(pr_body_prefix)[0].rstrip() + wrap_pr_body(new_body) + body.split(pr_body_postfix)[1].lstrip()

def compare_line_by_line(str1, str2):
    return str1.splitlines() == str2.splitlines()

def extract_payload_data(payload):
    """
    Extracts fields from the payload for ingestion.
    """

    if not isinstance(payload.data, dict):
        raise ValueError("Payload data must be a JSON object")
    
    data = payload.data
    
    # Check general field exists and is a dictionary
    if "general" not in data or not isinstance(data["general"], dict):
        raise ValueError("Payload data must contain a 'general' object")
    
    general = data["general"]
    
    # Validate watcloud_username
    watcloud_username = general.get("watcloud_username")
    if not watcloud_username or not isinstance(watcloud_username, str):
        raise ValueError("Missing or invalid 'general.watcloud_username' in general data")
    
    # Validate contact_emails
    if not "contact_emails" in general:
        raise ValueError("Missing 'general.contact_emails' in payload data")
    if not isinstance(general["contact_emails"], list) or len(general["contact_emails"]) == 0:
        raise ValueError("'general.contact_emails' in payload data must be a non-empty list")

    # primary_email is used for email verification
    primary_email = general["contact_emails"][0]

    return watcloud_username, primary_email

def generate_data_file(data):
    return yaml.dump(data, default_flow_style=False, width=float('inf'))

def assert_throws(func, exception_class, message=None):
    """
    Assert that a function throws an exception.
    """
    try:
        func()
    except exception_class:
        pass
    else:
        raise AssertionError(message or f"{func} did not throw {exception_class}")

def fission_get_config(name):
    if os.environ.get(name):
        return os.environ[name]

    if os.path.exists(f"{FISSION_CONFIGS_BASE_PATH}/{name}"):
        with open(f"{FISSION_CONFIGS_BASE_PATH}/{name}", "r") as f:
            return f.read()

    return None

def fission_get_secret(name):
    if os.environ.get(name):
        return os.environ[name]

    if os.path.exists(f"{FISSION_SECRETS_BASE_PATH}/{name}"):
        with open(f"{FISSION_SECRETS_BASE_PATH}/{name}", "r") as f:
            return f.read()

    return None


def get_jwt(app_id, pem_path):
    """
    Get a JWT for GitHub Apps authentication
    Derived from:
    https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation#generating-an-installation-access-token
    """
    with open(pem_path, 'rb') as pem_file:
        signing_key = pem_file.read()

    payload = {
        # Issued at time
        'iat': int(time.time()),
        # JWT expiration time (10 minutes maximum)
        'exp': int(time.time()) + 600,
        # GitHub App's identifier
        'iss': app_id
    }

    # Create JWT
    encoded_jwt = jwt.encode(payload, signing_key, algorithm='RS256')

    return encoded_jwt


def get_github_token():
    if hasattr(get_github_token, "cache") and datetime.strptime(get_github_token.cache["expires_at"], "%Y-%m-%dT%H:%M:%SZ") - datetime.now() > timedelta(minutes=1):
        logger.debug(f"Using cached token. Expires at {get_github_token.cache['expires_at']}")
        return get_github_token.cache["token"]

    # Simple token
    if fission_get_secret("GITHUB_TOKEN"):
        return fission_get_secret("GITHUB_TOKEN")

    # App installation token
    app_id = fission_get_config("GITHUB_APP_ID")
    installation_id = fission_get_config("GITHUB_APP_INSTALLATION_ID")
    pem_path = fission_get_config("GITHUB_APP_PRIVATE_KEY_PATH")

    if not app_id or not installation_id or not pem_path:
        raise ValueError(f"Missing GitHub app configuration: {app_id=}, {installation_id=}, {pem_path=}")

    jwttok = get_jwt(app_id, pem_path)

    # Get an access token for the installation
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {jwttok}',
        'X-GitHub-Api-Version': '2022-11-28',
    }

    response = requests.post(url, headers=headers)
    response.raise_for_status()

    get_github_token.cache = response.json()

    logger.debug(f"Generated new token. Expires at {get_github_token.cache['expires_at']}")
    return get_github_token.cache["token"]