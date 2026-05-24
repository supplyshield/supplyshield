"""Regression test for Secbug.is_active semantics.

Audit found the method was inverted — returned True when deleted_at was
set (i.e., when the row was DELETED). Sprint 8 inverts the logic so
"active" means "not soft-deleted". This test pins that contract.
"""
from libinv.models import Secbug


def test_is_active_returns_true_when_not_deleted():
    s = Secbug(id="SEC-1")
    s.deleted_at = None
    assert s.is_active() is True


def test_is_active_returns_false_when_deleted():
    from datetime import datetime, timezone
    s = Secbug(id="SEC-2")
    s.deleted_at = datetime.now(timezone.utc)
    assert s.is_active() is False
