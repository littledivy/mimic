"""Tests for building a generated-client (App subclass) from captured auth."""
import os

from mimic import App

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.har")


class Example(App):
    HOST = "api.example.com"


def test_app_subclass_from_har():
    acc = Example.from_har(FIXTURE, "api.example.com")
    assert isinstance(acc, Example)
    assert acc.base_url == "https://api.example.com"
    assert acc.headers["Authorization"] == "Bearer token123"


def test_app_subclass_from_curl():
    acc = Example.from_curl("curl 'https://api.example.com/v1/users' -H 'Authorization: Bearer abc'")
    assert isinstance(acc, Example)
    assert acc.base_url == "https://api.example.com"
    assert acc.headers["Authorization"] == "Bearer abc"


def test_app_subclass_explicit_kwargs():
    acc = Example(base_url="https://api.example.com", headers={"Authorization": "Bearer x"})
    assert acc.headers == {"Authorization": "Bearer x"}
