"""Unit tests for libinv.api.auth.register_global_auth.

Uses the ``flask_app_client`` fixture from conftest, which wires the auth
hook against a *minimal* Flask app (see fixture docstring for why we don't
import libinv.api.app directly).
"""

from unittest.mock import patch


# ---------------------------------------------------------------------------
# Non-mutating verbs should bypass auth entirely.
# ---------------------------------------------------------------------------
def test_get_endpoints_do_not_require_token(flask_app_client):
    resp = flask_app_client.get("/")
    assert resp.status_code == 200

    resp = flask_app_client.get("/libinv/sast/some-id")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# PUT (mutating) without token → 401
# ---------------------------------------------------------------------------
def test_put_without_token_returns_401(flask_app_client):
    resp = flask_app_client.put("/libinv/sast/update")
    assert resp.status_code == 401
    body = resp.get_json() or {}
    assert body.get("error") == "unauthorized"


# ---------------------------------------------------------------------------
# PUT with the wrong token → 401
# ---------------------------------------------------------------------------
def test_put_with_wrong_token_returns_401(flask_app_client):
    resp = flask_app_client.put(
        "/libinv/sast/update",
        headers={"X-API-Token": "definitely-not-the-real-token"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PUT with the correct token → auth gate passed; route handler runs.
# (The stub handler in conftest returns 400 because the body is empty —
#  that's fine, it means we got past the auth check.)
# ---------------------------------------------------------------------------
def test_put_with_correct_token_reaches_handler(flask_app_client):
    resp = flask_app_client.put(
        "/libinv/sast/update",
        headers={"X-API-Token": "test-token-for-tests"},
    )
    # 400 = body validation failed inside the route, NOT auth.
    assert resp.status_code == 400
    body = resp.get_json() or {}
    assert "sec_id" in body.get("error", "")


def test_put_with_correct_token_and_valid_body_returns_200(flask_app_client):
    resp = flask_app_client.put(
        "/libinv/sast/update",
        headers={"X-API-Token": "test-token-for-tests"},
        json={"sec_id": "x"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# hmac.compare_digest is used (constant-time comparison).
# ---------------------------------------------------------------------------
def test_auth_uses_hmac_compare_digest(flask_app_client):
    # Patch the symbol as imported into libinv.api.auth (not stdlib hmac).
    with patch("libinv.api.auth.hmac.compare_digest", return_value=True) as mock_cmp:
        resp = flask_app_client.put(
            "/libinv/sast/update",
            headers={"X-API-Token": "anything-because-cmp-is-mocked"},
            json={"sec_id": "x"},
        )
    assert resp.status_code == 200
    assert mock_cmp.called
    presented, expected = mock_cmp.call_args.args
    assert presented == "anything-because-cmp-is-mocked"
    assert expected == "test-token-for-tests"
