"""Tests for multi-language code generation (mimic.codegen + cli helpers)."""
import os

from mimic import cli, codegen

RUNTIME = "mimic-runtime.ts"

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


def test_strip_fences_ts_capitalized():
    # AI generators sometimes capitalize the fence tag.
    fenced = "```TypeScript\nexport class Foo extends MimicClient {}\n```"
    assert codegen._strip_fences(fenced) == "export class Foo extends MimicClient {}\n"


def test_ts_runtime_template_ships():
    src = os.path.join(os.path.dirname(codegen.__file__), "templates", RUNTIME)
    assert os.path.exists(src)
    assert "export class MimicClient" in open(src).read()


def test_runtime_name_avoids_client_suffix():
    # The runtime must not end in `_client.ts`, or a downstream `*_client.ts`
    # gitignore rule would swallow the very file the CLI says to commit.
    assert not RUNTIME.endswith("_client.ts")


def test_write_runtime_ts(tmp_path):
    dest = codegen.write_runtime("ts", str(tmp_path))
    assert dest == str(tmp_path / RUNTIME)
    assert "export class MimicClient" in (tmp_path / RUNTIME).read_text()


def test_write_runtime_ts_bare_dir(tmp_path, monkeypatch):
    # os.path.dirname("app_client.ts") == "" — must resolve to cwd, not crash.
    monkeypatch.chdir(tmp_path)
    dest = codegen.write_runtime("ts", "")
    assert dest == os.path.join(".", RUNTIME)
    assert (tmp_path / RUNTIME).exists()


def test_write_runtime_ts_preserves_existing(tmp_path):
    existing = tmp_path / RUNTIME
    existing.write_text("// edited locally\n")
    codegen.write_runtime("ts", str(tmp_path))
    assert existing.read_text() == "// edited locally\n"  # not overwritten


def test_write_runtime_python_is_noop(tmp_path):
    assert codegen.write_runtime("python", str(tmp_path)) is None
    assert not list(tmp_path.iterdir())


# ---- cli helpers --------------------------------------------------------------

def test_default_out_extension():
    assert cli._default_out("api.example.com", "python") == "api_client.py"
    assert cli._default_out("api.example.com", "ts") == "api_client.ts"


def test_class_name_python_and_ts():
    assert cli._class_name("class Foo(App):\n    pass\n") == "Foo"
    assert cli._class_name("export class Foo extends MimicClient {}\n") == "Foo"
    assert cli._class_name("export class Foo extends MimicClient{}\n") == "Foo"  # no space
    assert cli._class_name("no class here") is None
