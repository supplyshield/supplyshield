import logging
import os
import time
from abc import ABC
from abc import abstractmethod

import jwt
import requests
from git import Repo
from git.exc import GitError

from libinv.env import BITBUCKET_APP_TOKEN
from libinv.env import GITHUB_APP_APP_ID
from libinv.env import GITHUB_APP_INSTALLATION_ID
from libinv.env import GITHUB_APP_PRIVATE_KEY_FILE

logger = logging.getLogger(__name__)


class VcsApp(ABC):
    machine = None
    login = None
    NETRC_FILE = os.path.expanduser("~/.netrc")
    token_expiry = None

    @abstractmethod
    def get_token(self):
        raise NotImplementedError

    def has_token_expired(self):
        """
        Checks if the token is expired or will expire in less than 30 minutes.
        Overrride for PAT.
        """
        if self.token_expiry is None or self.token is None:
            return True

        current_time = time.time()
        return (self.token_expiry - current_time) < (30 * 60)

    def write_token_to_netrc(self, token):
        """Atomically write a 0600-mode .netrc with the current token."""
        content = (
            f"machine {self.machine}\n"
            f"login {self.login}\n"
            f"password {token}\n"
        )
        # Open with explicit mode 0o600 and O_TRUNC, never letting an
        # interim 0644 file exist on disk.
        fd = os.open(self.NETRC_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
        except Exception:
            os.close(fd) if "fd" in locals() else None
            raise

    def authenticate(self):
        """
        Authenticates the app and fetches a token if expired.
        """
        if self.has_token_expired():
            token = self.get_token()
            self.write_token_to_netrc(token)

        assert os.path.exists(self.NETRC_FILE)

    def clone(self, url, target_dir):
        return Repo.clone_from(url, target_dir)

    @abstractmethod
    def create_issue():
        raise NotImplementedError

    @abstractmethod
    def close_issue():
        raise NotImplementedError

    @abstractmethod
    def update_issue():
        raise NotImplementedError

    @abstractmethod
    def get_issues():
        raise NotImplementedError

    @abstractmethod
    def update_label():
        raise NotImplementedError


class GitHubApp(VcsApp):
    machine = "github.com"
    login = "x-access-token"

    def __init__(self):
        self.api_url = "https://api.github.com"
        self.app_id = GITHUB_APP_APP_ID
        self.installation_id = GITHUB_APP_INSTALLATION_ID
        logger.debug(f"[*] Trying to open {GITHUB_APP_PRIVATE_KEY_FILE}")
        with open(GITHUB_APP_PRIVATE_KEY_FILE, "r") as f:
            self.private_key = f.read()
        self.token_endpoint = f"/app/installations/{self.installation_id}/access_tokens"

    def get_token(self):
        headers = {
            "Authorization": f"Bearer {self.generate_jwt()}",
            "Accept": "application/vnd.github.v3+json",
        }
        response = requests.post(f"{self.api_url}{self.token_endpoint}", headers=headers)

        assert response.status_code == 201

        token_data = response.json()
        token = token_data.get("token")
        expires_at = token_data.get("expires_at")
        expiry_time = time.mktime(time.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ"))
        self.token = token
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        self.token_expiry = expiry_time

        return token

    def generate_jwt(self):
        """
        Generates a JWT for authenticating with GitHub using the app's private key.
        """

        payload = {"iat": int(time.time()), "exp": int(time.time()) + (10 * 60), "iss": self.app_id}
        token = jwt.encode(payload, self.private_key, algorithm="RS256")
        return token

    def create_issue(self, repo, title, message, labels=[], type=""):
        url = f"{self.api_url}/repos/{repo.org}/{repo.name}/issues"
        data = {"title": title, "body": message, "labels": labels, "type": type}
        try:
            response = requests.post(url, headers=self.headers, json=data)
            assert response.status_code == 201
            logger.info(f"Successfully raised the git issue: {title}")
        except GitError as e:
            logger.error(f"Error creating issue: {e}")

    def update_issue(self, issue_url, title, message, labels=[], type=""):
        data = {"title": title, "body": message, "labels": labels, "type": type}
        try:
            response = requests.patch(issue_url, headers=self.headers, json=data)
            assert response.status_code == 200
            logger.info(f"Successfully updated the git issue: {issue_url}")
        except GitError as e:
            logger.error(f"Error creating issue: {e}")

    def close_issue(self, issue_url):
        data = {"state": "closed"}
        try:
            response = requests.patch(issue_url, headers=self.headers, json=data)
            assert response.status_code == 200
            logger.info(f"Successfully closed the git issue: {issue_url}")
        except GitError as e:
            logger.error(f"Error closing issue: {e}")

    def get_issues(self, repo):
        url = f"{self.api_url}/repos/{repo.org}/{repo.name}/issues"
        try:
            response = requests.get(url, headers=self.headers).json()
            return response
        except GitError as e:
            logger.error(f"Error fetching issues: {e}")
            return None

    def update_label(self, repo, label_name, data):
        url = f"{self.api_url}/repos/{repo.org}/{repo.name}/labels/{label_name}"
        try:
            requests.patch(url, headers=self.headers, json=data)
        except GitError as e:
            logger.error(f"Error fetching issues: {e}")
            return None

    def get_sca_issue(self, repo):
        """
        Checks if an issue already exists in the GitHub repository.
        """
        issues = self.get_issues(repo)
        for issue in issues:
            for label in issue["labels"]:
                if label["name"] == f"sca-actionable-{repo.name}":
                    return issue["url"], True
                else:
                    return None, False


class BitBucketApp(VcsApp):
    machine = "bitbucket.org"
    login = "x-token-auth"
    token_expiry = time.time() + (35 * 60)

    def __init__(self):
        self.token = BITBUCKET_APP_TOKEN

    def get_token(self):
        return self.token
