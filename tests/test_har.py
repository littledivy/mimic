"""Tests for HAR file import (mimic.sources.har + Session.from_har)."""
import json
import os

import pytest

from mimic import Session
from mimic.sources import har

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.har")


def test_load_basic():
    flows = har.load(FIXTURE)
    assert len(flows) == 4
    req = flows[0]["request"]
    assert req["host"] == "api.example.com"
    assert req["method"] == "GET"
    assert req["path"] == "/v1/users?page=1"
    assert req["scheme"] == "https"
    assert req["port"] == 443
    assert req["headers"][0] == ["Authorization", "Bearer token123"]


def test_hosts():
    assert har.hosts(FIXTURE) == [("api.example.com", 3), ("cdn.example.com", 1)]


def test_endpoints_dedup():
    eps = har.endpoints(FIXTURE, "api.example.com")
    assert len(eps) == 2
    users = [e for e in eps if e["path"] == "/v1/users"]
    assert len(users) == 1
    assert users[0]["status"] == 200  # latest (page=2) wins over the earlier 500


def test_session_from_har():
    s = Session.from_har(FIXTURE, "api.example.com")
    assert s.base_url == "https://api.example.com"
    assert s.host == "api.example.com"
    assert s.headers["Authorization"] == "Bearer token123"


def test_from_har_auto_host():
    s = Session.from_har(FIXTURE)
    assert s.host == "api.example.com"  # most-requested host in the file


def test_from_har_no_auth(tmp_path):
    path = tmp_path / "noauth.har"
    path.write_text(json.dumps({
        "log": {"entries": [{
            "request": {
                "method": "GET",
                "url": "https://api.example.com/health",
                "headers": [{"name": "Accept", "value": "application/json"}],
            },
            "response": {"status": 200},
        }]}
    }))
    with pytest.raises(RuntimeError):
        Session.from_har(str(path), "api.example.com")


def test_body_bytes_params_fallback():
    # HAR form bodies may use postData.params (no text); reconstruct them.
    pd = {"mimeType": "application/x-www-form-urlencoded",
          "params": [{"name": "user", "value": "alice"},
                     {"name": "pw", "value": "s3cret"}]}
    assert har._body_bytes(pd) == b"user=alice&pw=s3cret"
    # text still takes precedence, and empty/None still yields b"".
    assert har._body_bytes({"text": '{"a":1}'}) == b'{"a":1}'
    assert har._body_bytes(None) == b""
    assert har._body_bytes({}) == b""


def test_base64_response_body():
    eps = har.endpoints(FIXTURE, "api.example.com")
    msg = [e for e in eps if e["path"] == "/v1/messages"][0]
    assert '"ok"' in msg["response_body"]  # base64 "eyJvayI6IHRydWV9" -> {"ok": true}
    assert "true" in msg["response_body"]
    assert '"to"' in msg["request_body"]  # postData decoded too


def test_invalid_base64_response_body_falls_back_to_text():
    content = {"text": "not valid base64!", "encoding": "base64"}
    assert har._content_bytes(content) == b"not valid base64!"
