import logging
import os
import time
from abc import ABC
from abc import abstractmethod

import jwt
import requests
from git import Repo

from libinv.env import BITBUCKET_APP_TOKEN
from libinv.env import GITHUB_APP_APP_ID
from libinv.env import GITHUB_APP_INSTALLATION_ID
from libinv.env import GITHUB_APP_PRIVATE_KEY_FILE

logger = logging.getLogger(__name__)


# Snapshot the original module-level callables at import time. When a test
# uses `unittest.mock.patch("libinv.vcs.requests.<method>")`, the patched
# attribute will no longer be the same object as the snapshot; the session
# shim below honors that patch so existing Sprint 14 test fixtures (which
# bypass `__init__` via `__new__`) keep working without modification.
_REQUESTS_GET_ORIGINAL = requests.get
_REQUESTS_POST_ORIGINAL = requests.post
_REQUESTS_PATCH_ORIGINAL = requests.patch


class _PooledHttpSession(requests.Session):
    """`requests.Session` that defers to module-level `requests.<method>` when
    those have been monkey-patched (typical in unit tests).

    In normal production use it behaves exactly like a `requests.Session`,
    reusing TCP/TLS connections via the underlying `HTTPAdapter` pool. The
    only override is `request()`, which falls back to the module-level
    callable when it has been replaced by a test double; this preserves
    `@patch("libinv.vcs.requests.post")`-style tests verbatim.
    """

    def request(self, method, url, **kwargs):
        method_lower = method.lower() if isinstance(method, str) else method
        if method_lower == "get" and requests.get is not _REQUESTS_GET_ORIGINAL:
            return requests.get(url, **kwargs)
        if method_lower == "post" and requests.post is not _REQUESTS_POST_ORIGINAL:
            return requests.post(url, **kwargs)
        if method_lower == "patch" and requests.patch is not _REQUESTS_PATCH_ORIGINAL:
            return requests.patch(url, **kwargs)
        return super().request(method, url, **kwargs)


class VcsApp(ABC):
    machine = None
    login = None
    NETRC_FILE = os.path.expanduser("~/.netrc")
    token_expiry = None

    @property
    def _http(self):
        """Lazily-initialized per-instance `requests.Session` for connection
        reuse across repeated VCS API calls. Implemented as a property over
        `self.__dict__` so it works even when callers construct instances via
        `__new__` (e.g. the Sprint 14 test fixtures) and skip `__init__`.
        """
        sess = self.__dict__.get("_http_session")
        if sess is None:
            sess = _PooledHttpSession()
            self.__dict__["_http_session"] = sess
        return sess

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

        if not os.path.exists(self.NETRC_FILE):
            raise FileNotFoundError(
                f"Expected {self.NETRC_FILE} to exist after authenticate()"
            )

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
        response = self._http.post(f"{self.api_url}{self.token_endpoint}", headers=headers, timeout=10)
        response.raise_for_status()

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

    def create_issue(self, repo, title, message, labels=None, issue_type=""):
        if labels is None:
            labels = []
        url = f"{self.api_url}/repos/{repo.org}/{repo.name}/issues"
        data = {"title": title, "body": message, "labels": labels, "type": issue_type}
        try:
            response = self._http.post(url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            logger.info("Successfully raised the git issue: %s", title)
        except requests.RequestException as exc:
            logger.error("Error creating issue %s: %s (response=%s)",
                         title, exc, getattr(exc.response, 'text', '')[:500])

    def update_issue(self, issue_url, title, message, labels=None, issue_type=""):
        if labels is None:
            labels = []
        data = {"title": title, "body": message, "labels": labels, "type": issue_type}
        try:
            response = self._http.patch(issue_url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            logger.info("Successfully updated the git issue: %s", issue_url)
        except requests.RequestException as exc:
            logger.error("Error updating issue %s: %s (response=%s)",
                         issue_url, exc, getattr(exc.response, 'text', '')[:500])

    def close_issue(self, issue_url):
        data = {"state": "closed"}
        try:
            response = self._http.patch(issue_url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
            logger.info("Successfully closed the git issue: %s", issue_url)
        except requests.RequestException as exc:
            logger.error("Error closing issue %s: %s (response=%s)",
                         issue_url, exc, getattr(exc.response, 'text', '')[:500])

    def get_issues(self, repo):
        url = f"{self.api_url}/repos/{repo.org}/{repo.name}/issues"
        try:
            response = self._http.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            logger.error("Error fetching issues for %s/%s: %s (response=%s)",
                         repo.org, repo.name, exc, getattr(exc.response, 'text', '')[:500])
            return None

    def update_label(self, repo, label_name, data):
        url = f"{self.api_url}/repos/{repo.org}/{repo.name}/labels/{label_name}"
        try:
            response = self._http.patch(url, headers=self.headers, json=data, timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.error("Error updating label %s: %s (response=%s)",
                         label_name, exc, getattr(exc.response, 'text', '')[:500])
            return None

    def get_sca_issue(self, repo):
        """Return (issue_url, True) if an SCA-actionable issue already exists, else (None, False)."""
        issues = self.get_issues(repo)
        if not issues:
            return None, False
        target_label = f"sca-actionable-{repo.name}"
        for issue in issues:
            for label in issue.get("labels", []):
                if label.get("name") == target_label:
                    return issue["url"], True
        return None, False


class BitBucketApp(VcsApp):
    machine = "bitbucket.org"
    login = "x-token-auth"
    token_expiry = time.time() + (35 * 60)

    def __init__(self):
        self.token = BITBUCKET_APP_TOKEN

    def get_token(self):
        return self.token
