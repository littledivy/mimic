"""Tests for Session.save() / Session.load() disk persistence."""
import json
import os
import stat

import pytest

from mimic import Session


class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code
        self.text = "unauthorized"

    def json(self):
        raise ValueError("not json")


class _FakeHttp:
    """Stand-in for requests.Session that counts calls and returns a fixed status."""

    def __init__(self, status_code):
        self.status_code = status_code
        self.calls = 0

    def request(self, *args, **kwargs):
        self.calls += 1
        return _FakeResp(self.status_code)


def _sample():
    return Session(
        "https://prod-api.hingeaws.net",
        {"authorization": "Bearer abc123", "user-agent": "mimic/test"},
        host="prod-api.hingeaws.net",
    )


def test_save_load_roundtrip(tmp_path):
    path = str(tmp_path / "session.json")
    original = _sample()
    original.save(path)
    restored = Session.load(path)
    assert restored.base_url == original.base_url
    assert restored.headers == original.headers
    assert restored.host == original.host


def test_save_creates_file(tmp_path):
    path = str(tmp_path / "session.json")
    _sample().save(path)
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data["version"] == 1
    assert data["host"] == "prod-api.hingeaws.net"


def test_load_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        Session.load(str(tmp_path / "nope.json"))


def test_load_no_refresh(tmp_path):
    path = str(tmp_path / "session.json")
    _sample().save(path)
    s = Session.load(path)
    assert s._mitm is None
    fake = _FakeHttp(401)
    s._http = fake
    out = s.get("/whoami")
    assert out == "unauthorized"  # returned the 401 body, no re-pull
    assert fake.calls == 1  # one call only, no refresh + retry


def test_save_file_permissions(tmp_path):
    path = str(tmp_path / "session.json")
    _sample().save(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
