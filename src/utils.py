import base64
from datetime import datetime, timedelta
import logging
import os
from textwrap import dedent
import time
import zlib

import requests
import yaml

from fastapi.responses import JSONResponse
from github import Github, GithubException
import jwt
from slugify import slugify

FISSION_CONFIGS_BASE_PATH = "/configs/fission-default/user-ingestion-configs"
FISSION_SECRETS_BASE_PATH = "/secrets/fission-default/user-ingestion-secrets"
BRANCH_PREFIX = "user-ingestion-"
MAX_BRANCH_NAME_LENGTH = 255
MAX_FILE_NAME_LENGTH = 255

# PR Body Helpers
PR_BODY_PREFIX = "<!-- This section is manged by repo-ingestion-bot. Please Do not edit manually! -->"
PR_BODY_POSTFIX = "<!-- End of section managed by repo-ingestion-bot -->"

logger = logging.getLogger()


def fission_get_config(name):
    if os.environ.get(name):
        return os.environ[name]

    if os.path.exists(f"{FISSION_CONFIGS_BASE_PATH}/{name}"):
        with open(f"{FISSION_CONFIGS_BASE_PATH}/{name}", "r") as f:
            return f.read()

    return None


TARGET_REPO = fission_get_config("TARGET_REPO")
TARGET_REPO_DATA_DIR = fission_get_config("TARGET_REPO_DATA_DIR")
EMAIL_VERIFICATION_KEY = fission_get_config("EMAIL_VERIFICATION_KEY")

if not TARGET_REPO or not TARGET_REPO_DATA_DIR or not EMAIL_VERIFICATION_KEY:
    raise ValueError(
        f"Missing required configuration: {TARGET_REPO=}, {TARGET_REPO_DATA_DIR=}, {EMAIL_VERIFICATION_KEY=}"
    )


def fission_get_secret(name):
    if os.environ.get(name):
        return os.environ[name]

    if os.path.exists(f"{FISSION_SECRETS_BASE_PATH}/{name}"):
        with open(f"{FISSION_SECRETS_BASE_PATH}/{name}", "r") as f:
            return f.read()

    return None


def wrap_pr_body(body):
    return "\n\n" + PR_BODY_PREFIX + "\n" + body + "\n" + PR_BODY_POSTFIX + "\n\n"


def extract_pr_body(body):
    if not body or PR_BODY_PREFIX not in body or PR_BODY_POSTFIX not in body:
        return ""
    return body.split(PR_BODY_PREFIX)[1].split(PR_BODY_POSTFIX)[0]


def update_pr_body(body, new_body):
    if not body:
        return wrap_pr_body(new_body)
    if PR_BODY_PREFIX not in body or PR_BODY_POSTFIX not in body:
        return body + wrap_pr_body(new_body)
    return (
        body.split(PR_BODY_PREFIX)[0].rstrip()
        + wrap_pr_body(new_body)
        + body.split(PR_BODY_POSTFIX)[1].lstrip()
    )


def compare_line_by_line(str1, str2):
    return str1.splitlines() == str2.splitlines()


def extract_payload_data(data: dict):
    """
    Extracts fields from the payload for ingestion.
    """
    # Check general field exists and is a dictionary
    if "general" not in data or not isinstance(data["general"], dict):
        raise ValueError("Payload data must contain a 'general' object")

    general = data["general"]

    # Validate watcloud_username
    watcloud_username = general.get("watcloud_username")
    if not watcloud_username or not isinstance(watcloud_username, str):
        raise ValueError(
            "Missing or invalid 'general.watcloud_username' in general data"
        )

    # Validate contact_emails
    if not "contact_emails" in general:
        raise ValueError("Missing 'general.contact_emails' in payload data")
    if (
        not isinstance(general["contact_emails"], list)
        or len(general["contact_emails"]) == 0
    ):
        raise ValueError(
            "'general.contact_emails' in payload data must be a non-empty list"
        )

    # primary_email is used for email verification
    primary_email = general["contact_emails"][0]

    return watcloud_username, primary_email


def generate_data_file(data):
    return yaml.dump(data, default_flow_style=False, width=float("inf"))


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


def get_jwt(app_id, pem_path):
    """
    Get a JWT for GitHub Apps authentication
    Derived from:
    https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation#generating-an-installation-access-token
    """
    with open(pem_path, "rb") as pem_file:
        signing_key = pem_file.read()

    payload = {
        # Issued at time
        "iat": int(time.time()),
        # JWT expiration time (10 minutes maximum)
        "exp": int(time.time()) + 600,
        # GitHub App's identifier
        "iss": app_id,
    }

    # Create JWT
    encoded_jwt = jwt.encode(payload, signing_key, algorithm="RS256")

    return encoded_jwt


def get_github_token():
    if hasattr(get_github_token, "cache") and datetime.strptime(
        get_github_token.cache["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
    ) - datetime.now() > timedelta(minutes=1):
        logger.debug(
            f"Using cached token. Expires at {get_github_token.cache['expires_at']}"
        )
        return get_github_token.cache["token"]

    # Simple token
    if fission_get_secret("GITHUB_TOKEN"):
        return fission_get_secret("GITHUB_TOKEN")

    # App installation token
    app_id = fission_get_config("GITHUB_APP_ID")
    installation_id = fission_get_config("GITHUB_APP_INSTALLATION_ID")
    pem_path = fission_get_config("GITHUB_APP_PRIVATE_KEY_PATH")

    if not app_id or not installation_id or not pem_path:
        raise ValueError(
            f"Missing GitHub app configuration: {app_id=}, {installation_id=}, {pem_path=}"
        )

    jwttok = get_jwt(app_id, pem_path)

    # Get an access token for the installation
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {jwttok}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    response = requests.post(url, headers=headers)
    response.raise_for_status()

    get_github_token.cache = response.json()

    logger.debug(
        f"Generated new token. Expires at {get_github_token.cache['expires_at']}"
    )
    return get_github_token.cache["token"]


def compress_claims(claims: dict) -> str:
    raw = jwt.api_jws.json.dumps(claims).encode("utf-8")
    compressed = zlib.compress(raw)
    return base64.urlsafe_b64encode(compressed).decode("utf-8")


def decompress_claims(compressed: str) -> dict:
    compressed = base64.urlsafe_b64decode(compressed)
    return jwt.api_jws.json.loads(zlib.decompress(compressed))


async def send_verification_email(data):
    now = int(time.time())

    username, primary_email = extract_payload_data(data)

    compressed = compress_claims(
        {
            "username": username,
            "email": primary_email,
            "data": data,
            "iat": now,
            "exp": now + 3600,
        }
    )

    token = jwt.encode(
        {"compressed": compressed}, EMAIL_VERIFICATION_KEY, algorithm="HS256"
    )

    return JSONResponse(
        status_code=200, content={"message": f"Email sending to be implemented", "token": token}
    )


async def create_pr(username, data):
    try:
        # MARK: Prepare file content
        file_path = f"{TARGET_REPO_DATA_DIR}/{slugify(username, max_length=MAX_FILE_NAME_LENGTH)}.yml"
        file_content = generate_data_file(data)

        # MARK: Initialize GitHub client
        g = Github(get_github_token())
        repo = g.get_repo(TARGET_REPO)
        default_branch = repo.get_branch(repo.default_branch)
        branch_name = slugify(
            f"{BRANCH_PREFIX}{username}", max_length=MAX_BRANCH_NAME_LENGTH
        )

        logger.info(
            f"GitHub rate limit remaining: {g.rate_limiting[0]} / {g.rate_limiting[1]}"
        )

        # MARK: Check for existing PR
        org_login = (
            repo.organization.login
            if hasattr(repo, "organization") and repo.organization
            else repo.owner.login
        )
        pr_head = f"{org_login}:{branch_name}"
        prs = repo.get_pulls(head=pr_head, base=default_branch.name)
        try:
            pr = prs[0]
        except IndexError:
            pr = None

        # MARK: Create or update branch
        logger.info(f"Creating branch {branch_name} from {default_branch.commit.sha}")
        try:
            repo.create_git_ref(f"refs/heads/{branch_name}", default_branch.commit.sha)
        except GithubException as e:
            if e.status != 422:  # 422 means branch already exists
                raise e
            logger.info(f"Branch {branch_name} already exists")

            if not pr:
                logger.info(
                    f"Branch {branch_name} exists, but no PR found. This is an inconsistent state. Recreating the branch..."
                )
                repo.get_git_ref(f"heads/{branch_name}").delete()
                repo.create_git_ref(
                    f"refs/heads/{branch_name}", default_branch.commit.sha
                )

        # MARK: Create or update file
        try:
            existing_file = repo.get_contents(file_path, ref=branch_name)
            if existing_file.decoded_content.decode("utf-8") == file_content:
                logger.info(f"File {file_path} already up to date")
            else:
                logger.info(f"Updating file {file_path}...")
                repo.update_file(
                    file_path,
                    f"Update user `{username}`",
                    file_content,
                    existing_file.sha,
                    branch=branch_name,
                )
        except GithubException as e:
            if e.status != 404:  # 404 means file doesn't exist
                raise e
            existing_file = None
            logger.info(f"Creating file {file_path}...")
            repo.create_file(
                file_path, f"Create user `{username}`", file_content, branch=branch_name
            )

        # MARK: Create/Update PR
        # Note: The repo-ingestion tag is used for backward compatibility with the reviewer/checklist logic in infra-config
        pr_body = dedent(
            f"""
            ### Introduction

            This PR is automatically generated by the [user-ingestion](https://github.com/WATonomous/user-ingestion) service.
            Please review the changes and complete the checklist(s) in the PR description (if present).

            <!-- tags: user-ingestion,repo-ingestion -->
        """
        )

        if pr:
            assert_throws(
                lambda: prs[1],
                IndexError,
                f"Expected only one PR from {pr_head} to {default_branch.name}, but found more than one",
            )

            logger.info(
                f"PR from {pr_head} to {default_branch.name} already exists (#{prs[0].number}). Checking if it needs to be updated..."
            )

            if compare_line_by_line(extract_pr_body(pr.body).strip(), pr_body.strip()):
                logger.info(
                    f"PR from {pr_head} to {default_branch.name} already exists (#{pr.number}) and is up to date"
                )
            else:
                logger.info(
                    f"PR from {pr_head} to {default_branch.name} already exists (#{pr.number}) but is out of date. Updating..."
                )
                pr.edit(body=update_pr_body(pr.body, pr_body))
        else:
            logger.info(
                f"PR from {pr_head} to {default_branch.name} does not exist. Creating..."
            )

            pr_title = (
                f"Update user `{username}`"
                if existing_file
                else f"Create user `{username}`"
            )

            pr = repo.create_pull(
                title=pr_title,
                body=wrap_pr_body(pr_body),
                head=pr_head,
                base=default_branch.name,
            )

        # MARK: Add label
        pr.add_to_labels("user-ingestion")

        logger.info(
            f"GitHub rate limit remaining: {g.rate_limiting[0]} / {g.rate_limiting[1]}"
        )

        return JSONResponse(status_code=200, content={"pr_url": pr.html_url})
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": "Ingestion failed", "details": str(e)}
        )


async def process_token(token):
    # Decode and Decompress token
    try:
        decoded = jwt.decode(token, EMAIL_VERIFICATION_KEY, algorithms="HS256")
    except jwt.InvalidTokenError:
        return JSONResponse(status_code=400, content={"error": "Invalid token"})

    if "compressed" in decoded:
        claims = decompress_claims(decoded["compressed"])
    else:
        return JSONResponse(status_code=400, content={"message": "Invalid token"})

    if "exp" not in claims:
        return JSONResponse(
            status_code=500,
            content={"message": "Malformed JWT claims: exp not available"},
        )

    # Check for expiration
    now = int(time.time())
    if claims["exp"] < now:
        return JSONResponse(
            status_code=400,
            content={
                "message": f"Token expired at {claims['exp']}, but is being used at {now} ({now - claims['exp']} seconds late)"
            },
        )

    if "username" not in claims:
        return JSONResponse(
            status_code=500,
            content={"message": "Malformed JWT claims: username not available"},
        )

    if "email" not in claims:
        return JSONResponse(
            status_code=500,
            content={"message": "Malformed JWT claims: email not available"},
        )

    if "data" not in claims:
        return JSONResponse(
            status_code=500,
            content={"message": "Malformed JWT claims: data not available"},
        )

    return await create_pr(claims["username"], claims["data"])
