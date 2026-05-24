"""Sprint 24 — env.py type-bug regression tests."""

import importlib
import pytest


def test_parse_bool_unset_returns_default():
    from libinv.env import _parse_bool
    assert _parse_bool(None, default=False) is False
    assert _parse_bool(None, default=True) is True


def test_parse_bool_truthy_strings():
    from libinv.env import _parse_bool
    for v in ("1", "true", "True", "YES", "yes", "on", "Y"):
        assert _parse_bool(v, default=False) is True, v


def test_parse_bool_falsy_strings():
    from libinv.env import _parse_bool
    for v in ("0", "false", "False", "NO", "no", "off", "n", ""):
        assert _parse_bool(v, default=True) is False, v


def test_parse_bool_unknown_raises():
    from libinv.env import _parse_bool
    with pytest.raises(ValueError):
        _parse_bool("maybe", default=False)


def test_parse_csv_unset_returns_default():
    from libinv.env import _parse_csv
    assert _parse_csv(None) == []
    assert _parse_csv(None, default=["a", "b"]) == ["a", "b"]
    assert _parse_csv("") == []


def test_parse_csv_splits_and_strips():
    from libinv.env import _parse_csv
    assert _parse_csv("foo,bar,baz") == ["foo", "bar", "baz"]
    assert _parse_csv("  foo , bar ,  baz  ") == ["foo", "bar", "baz"]


def test_parse_csv_drops_empty_items():
    from libinv.env import _parse_csv
    assert _parse_csv("a,,b,  ,c") == ["a", "b", "c"]


def test_image_scan_enabled_reflects_env(monkeypatch):
    monkeypatch.setenv("IMAGE_SCAN_ENABLED", "true")
    import libinv.env as env_mod
    importlib.reload(env_mod)
    assert env_mod.IMAGE_SCAN_ENABLED is True

    monkeypatch.setenv("IMAGE_SCAN_ENABLED", "false")
    importlib.reload(env_mod)
    assert env_mod.IMAGE_SCAN_ENABLED is False

    monkeypatch.delenv("IMAGE_SCAN_ENABLED", raising=False)
    importlib.reload(env_mod)
    assert env_mod.IMAGE_SCAN_ENABLED is False  # default


def test_excluded_repos_csv(monkeypatch):
    monkeypatch.setenv("EXCLUDED_REPOS", "org1/repo1,org2/repo2,org3/repo3")
    import libinv.env as env_mod
    importlib.reload(env_mod)
    assert env_mod.EXCLUDED_REPOS == ["org1/repo1", "org2/repo2", "org3/repo3"]

    monkeypatch.delenv("EXCLUDED_REPOS", raising=False)
    importlib.reload(env_mod)
    assert env_mod.EXCLUDED_REPOS == []
