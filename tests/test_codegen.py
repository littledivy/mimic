"""Tests for multi-language code generation (mimic.codegen)."""
import os

from mimic import codegen

ENDPOINTS = [
    {
        "method": "GET", "path": "/v1/posts", "status": 200, "query": "page=1",
        "request_body": "", "response_body": '{"posts": [{"id": 1}]}',
    },
]


def test_python_is_default():
    p = codegen.build_prompt("api.example.com", ENDPOINTS)
    assert "Python file" in p
    assert "mimic.App" in p
    assert p == codegen.build_prompt("api.example.com", ENDPOINTS, lang="python")


def test_ts_prompt():
    p = codegen.build_prompt("api.example.com", ENDPOINTS, lang="ts")
    assert "TypeScript file" in p
    assert "MimicClient" in p
    assert 'from "zod"' in p
    assert "api.example.com" in p and "/v1/posts" in p  # digest shared with python


def test_strip_fences_ts():
    fenced = "```typescript\nexport class Foo extends MimicClient {}\n```"
    assert codegen._strip_fences(fenced) == "export class Foo extends MimicClient {}\n"


def test_ts_runtime_template_ships():
    src = os.path.join(os.path.dirname(codegen.__file__), "templates", "mimic_client.ts")
    assert os.path.exists(src)
    assert "export class MimicClient" in open(src).read()


def test_write_runtime_ts(tmp_path):
    dest = codegen.write_runtime("ts", str(tmp_path))
    assert dest == str(tmp_path / "mimic_client.ts")
    assert "export class MimicClient" in (tmp_path / "mimic_client.ts").read_text()


def test_write_runtime_ts_preserves_existing(tmp_path):
    existing = tmp_path / "mimic_client.ts"
    existing.write_text("// edited locally\n")
    codegen.write_runtime("ts", str(tmp_path))
    assert existing.read_text() == "// edited locally\n"  # not overwritten


def test_write_runtime_python_is_noop(tmp_path):
    assert codegen.write_runtime("python", str(tmp_path)) is None
    assert not list(tmp_path.iterdir())
