"""Sprint 31.1 — End-to-end SQS → daemon → DB → API integration test.

Strategy
--------
This test exercises the whole path that production hits when a build event
shows up on the SQS bridge queue:

    AWS SQS queue
        |
        v
    libinv.cli.daemon (poll / process_message)
        |
        v
    libinv.main.process_sqs_message  -> Wasp.eat_caterpillar_message
        |                              -> Repository created/fetched
        |                              -> Wasp row persisted
        |                              -> connect_using_queue_message_agreement
        |                                 -> Account row ensured
        |                                 -> Image rows bridged + linked
        v
    Flask API (libinv.api.wasp.get_wasp_by_id)

We do NOT boot the daemon's signal-handling loop. We invoke the message
handler in-process so the test is deterministic and finishes in seconds.

External dependencies (S3 upload, cdxgen, scancodeio HTTP calls, semgrep
subprocess) are patched out — this is an *integration* test for the SQL +
SQS + API plumbing, not for downstream scanners (which have their own
unit tests).

SQS is mocked with `moto` (``mock_aws``), so no real AWS account is
contacted. The ephemeral Postgres DB is the one provided by the
``engine`` fixture in ``tests/integration/conftest.py`` (Track-A wired
``pytest-postgresql`` + ``alembic upgrade head`` already).

Assertions per the row 04 contract:
  (a) exactly one new Wasp row materialised
  (b) downstream rows (Account + Image) materialised
  (c) the API route surfacing the new Wasp entity returns it via
      ``GET /wasp/get_wasp_by_id?id=<uuid>``
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest


# moto / boto3 ship together in modern moto releases.
try:
    from moto import mock_aws

    _HAS_MOTO = True
except ImportError:  # pragma: no cover - environment without moto
    _HAS_MOTO = False
    mock_aws = None  # type: ignore[assignment]


pytestmark = pytest.mark.skipif(
    not _HAS_MOTO,
    reason="moto not installed; add it to requirements to exercise the SQS mock path",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _bind_engine(engine, monkeypatch):
    """Rebind libinv.base globals to the integration engine.

    Mirrors the pattern from ``test_wasp_eat_caterpillar.py`` and
    ``test_n1_eager_loading.py``: the SUT (``Wasp.eat_caterpillar_message``,
    ``connect_using_queue_message_agreement``) uses ``libinv.base.Session`` /
    ``libinv.base.conn`` internally when a session isn't explicitly passed.
    """
    import libinv.base

    monkeypatch.setattr(libinv.base, "engine", engine)
    libinv.base.Session.configure(bind=engine)
    libinv.base.ScopedSession.configure(bind=engine)
    yield
    libinv.base.ScopedSession.remove()


@pytest.fixture
def aws_creds(monkeypatch):
    """Set dummy AWS credentials so moto's mock_aws stays in mock mode."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "test")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # ``libinv.env.SQS_QUEUE_NAME`` is read at import time from this env var.
    # We monkeypatch BOTH the env var (for boto3) and the already-imported
    # module attribute (for any code that snapshotted it).
    monkeypatch.setenv("SQS_QUEUE_NAME", "libinv-e2e-test-queue")
    from libinv import env as libinv_env
    from libinv import sqs as libinv_sqs

    monkeypatch.setattr(libinv_env, "SQS_QUEUE_NAME", "libinv-e2e-test-queue")
    # libinv.sqs imports SQS_QUEUE_NAME at module-import time — patch the
    # already-bound module reference too.
    monkeypatch.setattr(libinv_sqs, "SQS_QUEUE_NAME", "libinv-e2e-test-queue")


@pytest.fixture
def cleanup_e2e_rows(engine):
    """Tear down any rows the test created (Wasp, Repository, Image, Account)."""
    test_repo_name = "libinv-e2e-test-repo"
    test_account_id = "999888777666"

    yield {"repo_name": test_repo_name, "account_id": test_account_id}

    from sqlalchemy.orm import Session

    from libinv.models import Account
    from libinv.models import Image
    from libinv.models import Repository
    from libinv.models import Wasp

    with Session(bind=engine) as s:
        repos = s.query(Repository).filter(Repository.name == test_repo_name).all()
        repo_ids = [r.id for r in repos]
        if repo_ids:
            s.query(Image).filter(Image.repository_id.in_(repo_ids)).delete(
                synchronize_session=False
            )
            s.query(Wasp).filter(Wasp.repository_id.in_(repo_ids)).delete(
                synchronize_session=False
            )
            for r in repos:
                s.delete(r)
        s.query(Account).filter(Account.id == test_account_id).delete()
        s.commit()


def _build_caterpillar_payload(repo_name: str, account_id: str) -> dict:
    """A realistic Wasp.eat_caterpillar_message payload.

    Shape mirrors the docstring schema on ``Wasp.eat_caterpillar_message``:
    ``repository`` + ``aws_environment`` + ``job_url`` + ``ecr_image`` + ...
    The values are chosen so the SUT's downstream
    ``connect_using_queue_message_agreement`` has enough data to materialise
    one Image row.
    """
    return {
        "repository": {
            "url": f"git@github.com:e2e-org/{repo_name}.git",
            "commit": "abcdef0123" + ("0" * 30),
            "tag": "v0.0.1",
        },
        "aws_environment": "stage",
        "job_url": "https://jenkins.example/job/e2e/1",
        "buildx_enabled": "1",
        "type": "Bridge",
        "timestamp": "2026-05-24-23:57:00",
        "ecr_image": [
            {
                "name": f"{account_id}.dkr.ecr.ap-south-1.amazonaws.com/e2e-service",
                "digest": "sha256:" + ("a" * 64),
                "type": "Image",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }


def _build_sqs_message_metadata(payload: dict) -> dict:
    """Wrap the Wasp payload in the SQS envelope ``process_sqs_message`` expects.

    ``process_sqs_message`` reads ``Body`` (a JSON-encoded string) and
    ``ReceiptHandle`` (used to extend visibility + delete on success).
    """
    return {
        "Body": json.dumps(payload),
        "ReceiptHandle": "fake-receipt-handle-e2e",
        "MessageId": "fake-message-id-e2e",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@mock_aws
def test_e2e_sqs_message_creates_wasp_image_and_surfaces_via_api(
    engine, cleanup_e2e_rows, aws_creds, monkeypatch
):
    """Single SQS message → Wasp row + Image row + reachable through API."""
    import boto3

    from libinv import env as libinv_env

    repo_name = cleanup_e2e_rows["repo_name"]
    account_id = cleanup_e2e_rows["account_id"]

    # 1. Stand up the mock SQS queue (moto creates a fresh in-memory backend
    #    on @mock_aws entry; we only need the queue URL for completeness).
    sqs = boto3.client("sqs", region_name="us-east-1")
    queue_url = sqs.create_queue(QueueName=libinv_env.SQS_QUEUE_NAME)["QueueUrl"]
    payload = _build_caterpillar_payload(repo_name, account_id)
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload))

    # 2. Receive the message so we have a real envelope (ReceiptHandle etc.).
    received = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
    msg = received["Messages"][0]
    # Wrap with the keys process_sqs_message reads.
    message_metadata = {
        "Body": msg["Body"],
        "ReceiptHandle": msg["ReceiptHandle"],
        "MessageId": msg["MessageId"],
    }

    # 3. Patch the downstream scanners + S3 upload that
    #    ``process_sqs_message`` calls. They have their own unit tests; this
    #    test is for the SQS → DB → API plumbing.
    fake_cdx = type("FakeCdx", (), {"relative_to": lambda self, base: "fake.cdx.json"})()

    with patch("libinv.main.run_cdxgen_scan", return_value=fake_cdx), patch(
        "libinv.main.upload_to_s3", return_value=True
    ), patch("libinv.main.run_scancodeio", return_value=None), patch(
        "libinv.main.semgrep.run_cicd", return_value=None
    ), patch(
        "libinv.scanners.repository_scanner.Wasp.repo_dir",
        new_callable=lambda: property(lambda self: self.project_dir),
    ):
        from libinv.main import process_sqs_message

        process_sqs_message(message_metadata)

    # 4. (a) one new Wasp row, (b) downstream rows materialized
    from sqlalchemy.orm import Session

    from libinv.models import Account
    from libinv.models import Image
    from libinv.models import Repository
    from libinv.models import Wasp

    with Session(bind=engine) as s:
        repo = (
            s.query(Repository).filter(Repository.name == repo_name).one_or_none()
        )
        assert repo is not None, "Repository row was not created by the daemon"

        wasp_rows = s.query(Wasp).filter(Wasp.repository_id == repo.id).all()
        assert len(wasp_rows) == 1, (
            "Expected exactly one Wasp row per processed message, "
            f"got {len(wasp_rows)}"
        )
        wasp_uuid = wasp_rows[0].uuid

        # Downstream: Account + Image
        account = (
            s.query(Account).filter(Account.id == account_id).one_or_none()
        )
        assert account is not None, "Account row was not materialised"

        images = (
            s.query(Image)
            .filter(Image.repository_id == repo.id, Image.account_id == account_id)
            .all()
        )
        assert len(images) >= 1, "No Image row materialised from the ecr_image entry"
        assert images[0].digest == "sha256:" + ("a" * 64)

    # 5. (c) The API route returns the new entity.
    #    libinv.api.wasp.get_wasp_by_id resolves the wasp via uuid prefix on
    #    the ``id`` query param (``uuid = wasp_id.split('/')[0]``).
    from libinv.api.app import app as flask_app

    with flask_app.test_client() as client:
        resp = client.get("/wasp/get_wasp_by_id", query_string={"id": wasp_uuid})
        assert resp.status_code == 200, (
            f"Expected 200 from /wasp/get_wasp_by_id, got {resp.status_code} "
            f"body={resp.get_data(as_text=True)!r}"
        )
        body = resp.get_json()
        assert body is not None
        assert body["repository_id"] == repo.id
        assert body["environment"] == "stage"


@mock_aws
def test_e2e_sqs_unknown_message_id_returns_404_via_api(
    engine, cleanup_e2e_rows, aws_creds
):
    """API surface returns 404 for a uuid that was never written.

    This guards the API layer regression independently from the daemon path:
    even if no SQS message ever ran, the route must not 500 on lookup miss.
    """
    from libinv.api.app import app as flask_app

    with flask_app.test_client() as client:
        # uuid-shaped but never persisted
        resp = client.get(
            "/wasp/get_wasp_by_id",
            query_string={"id": "deadbeef-dead-dead-dead-deadbeefdead"},
        )
        assert resp.status_code == 404
        body = resp.get_json()
        assert body is not None
        assert body.get("error") == "Wasp not found"
