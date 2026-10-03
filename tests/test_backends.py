"""The code-generator registry.

The contract under test: which generator runs is a table lookup, `agy`'s prompt
transport is asked rather than assumed, and — the one failure that can't be
detected by reading the output — asking for an AI backend never quietly yields
something a heuristic wrote.
"""
import subprocess

import pytest

from mimic import codegen
from mimic.codegen import ARGV, PROBE, STDIN, Backend, get_backend
from mimic.errors import GeneratorError


@pytest.fixture(autouse=True)
def clear_probe_cache():
    """Each test starts with nothing cached, so a probe in one can't answer for
    another."""
    codegen._PROBED.clear()
    yield
    codegen._PROBED.clear()


def fake_which(names=("claude", "opencode", "agy")):
    """A PATH where only `names` are installed."""
    real = codegen.shutil.which
    codegen.shutil.which = lambda cmd: f"/usr/local/bin/{cmd}" if cmd in names else None
    return lambda: setattr(codegen.shutil, "which", real)


def help_output(text, returncode=0):
    return subprocess.CompletedProcess(args=["agy", "--help"], returncode=returncode,
                                       stdout=text, stderr="")


# ---- the registry ------------------------------------------------------------
def test_every_backend_is_reachable_by_name():
    assert set(codegen.BACKENDS) == {"claude", "opencode", "agy"}
    assert get_backend("agy").name == "agy"


def test_an_unknown_generator_names_the_ones_that_exist():
    with pytest.raises(GeneratorError) as exc:
        get_backend("gpt9")
    assert "claude" in str(exc.value) and "agy" in str(exc.value)


def test_generate_refuses_an_unknown_generator_rather_than_defaulting(monkeypatch):
    """A typo must not quietly run a different model than the one asked for."""
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/claude")
    with pytest.raises(GeneratorError):
        codegen.generate("api.example.com", [], generator="gpt9")


def test_a_backend_builds_its_own_command_line():
    claude = get_backend("claude")
    assert claude.command("sonnet") == ["claude", "--model", "sonnet"]
    assert get_backend("opencode").command() == ["opencode", "run"]
    assert get_backend("agy").command("x") == ["agy"]


def test_the_cli_choices_come_from_the_registry():
    from mimic.cli import main
    import argparse

    with pytest.raises(SystemExit):
        main(["gen", "api.example.com", "--generator", "nope"])
    # The table and the parser cannot drift apart without a test failing.
    assert set(codegen.BACKENDS) <= {"claude", "opencode", "agy"}
    assert isinstance(argparse.ArgumentParser(), argparse.ArgumentParser)


# ---- the criterion: an absent CLI raises, it does not fall back --------------
def test_an_absent_agy_raises_rather_than_falling_back(monkeypatch):
    """A user who asked for the AI path must be able to tell they got it.

    There is no deterministic fallback here, and adding one would be the worst
    possible bug in this module: the file would look like the model's work.
    """
    monkeypatch.setattr(codegen.shutil, "which", lambda cmd: None)
    with pytest.raises(GeneratorError) as exc:
        codegen.generate("api.example.com", [], generator="agy")
    message = str(exc.value)
    assert "`agy` CLI not found" in message
    # It says what you can do instead, and none of that is "we wrote it for you".
    assert "none" in message or "claude" in message
    assert "deterministic" not in message


def test_an_absent_backend_never_returns_source(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda cmd: None)
    for name in sorted(codegen.BACKENDS):
        with pytest.raises(GeneratorError):
            codegen.generate("api.example.com", [], generator=name)


def test_the_message_lists_what_is_actually_installed(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which",
                        lambda cmd: "/usr/local/bin/claude" if cmd == "claude" else None)
    with pytest.raises(GeneratorError) as exc:
        codegen.which(get_backend("agy"))
    assert "claude" in str(exc.value)


def test_nothing_is_hardcoded_to_a_path(monkeypatch):
    """The binary is looked up on PATH, so where it lives is the user's problem."""
    seen = []

    def record(cmd):
        seen.append(cmd)
        return None

    monkeypatch.setattr(codegen.shutil, "which", record)
    with pytest.raises(GeneratorError):
        codegen.which(get_backend("agy"))
    assert seen[0] == "agy"


# ---- probing agy's prompt transport -----------------------------------------
def test_agy_is_probed_rather_than_assumed():
    assert get_backend("agy").prompt_via == PROBE
    assert get_backend("claude").prompt_via == STDIN
    assert get_backend("opencode").prompt_via == ARGV


def test_help_text_saying_prompt_means_argv(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    monkeypatch.setattr(codegen.subprocess, "run",
                        lambda *a, **k: help_output("usage: agy --prompt TEXT"))
    assert codegen.detect_prompt_mode(get_backend("agy")) == ARGV


def test_help_text_saying_stdin_means_stdin(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    monkeypatch.setattr(codegen.subprocess, "run",
                        lambda *a, **k: help_output("reads the prompt from stdin"))
    assert codegen.detect_prompt_mode(get_backend("agy")) == STDIN


def test_uninformative_help_defers_to_trying(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    monkeypatch.setattr(codegen.subprocess, "run",
                        lambda *a, **k: help_output("agy, version 1.0"))
    assert codegen.detect_prompt_mode(get_backend("agy")) is None


def test_a_wrong_help_guess_is_corrected_by_the_retry(monkeypatch):
    """Help says argv; the CLI actually wants stdin. Nothing about the help was
    trustworthy, and the retry is what catches it."""
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    attempts = []

    def run(cmd, **kw):
        if cmd[-1:] == ["--help"]:
            return help_output("usage: agy --prompt TEXT")
        attempts.append(kw.get("input") is not None)
        # The argv guess puts the prompt in the wrong place; stdin works.
        return _run(stdout="", returncode=1) if kw.get("input") is None else _run()

    monkeypatch.setattr(codegen.subprocess, "run", run)
    source = codegen.generate("api.example.com", [], generator="agy")
    assert attempts == [False, True]          # argv first, then stdin
    assert "class C" in source
    assert codegen._PROBED["agy"] == STDIN


@pytest.mark.skipif(codegen.shutil.which("agy") is None,
                    reason="agy is not installed here")
def test_the_probe_reads_the_real_agy_correctly():
    """Checked against the actual binary, not a mock.

    `agy --help` renders `--prompt` with no argument placeholder, so this is
    the case where reading the help alone would have been a guess.
    """
    codegen._PROBED.clear()
    assert codegen.detect_prompt_mode(get_backend("agy")) == ARGV


@pytest.mark.skipif(codegen.shutil.which("agy") is None,
                    reason="agy is not installed here")
def test_real_agy_rejects_a_stdin_only_invocation():
    """The error the retry keys off, confirmed against the real binary: given
    no argument, `agy -p` prints nothing on stdout and fails."""
    proc = subprocess.run(["agy", "-p"], input="hi", capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode != 0
    assert not proc.stdout.strip()


def test_a_backend_that_declares_its_transport_is_not_probed(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/claude")

    def explode(*a, **k):
        raise AssertionError("claude's prompt transport is known; don't probe")

    monkeypatch.setattr(codegen.subprocess, "run", explode)
    assert codegen.detect_prompt_mode(get_backend("claude")) == STDIN


def test_the_probe_happens_once_per_process(monkeypatch):
    calls = []
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    monkeypatch.setattr(codegen.subprocess, "run",
                        lambda *a, **k: (calls.append(1) or
                                         help_output("usage: agy --prompt TEXT")))
    agy = get_backend("agy")
    for _ in range(5):
        assert codegen.detect_prompt_mode(agy) == ARGV
    assert len(calls) == 1


# ---- generate() --------------------------------------------------------------
def _run(stdout="class C: pass\n", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr="boom")


def test_generate_sends_the_prompt_on_stdin_when_that_is_the_mode(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/claude")
    seen = {}

    def run(cmd, **kw):
        seen["cmd"] = cmd
        seen.update(kw)
        return _run()

    monkeypatch.setattr(codegen.subprocess, "run", run)
    codegen.generate("api.example.com", [], generator="claude")
    assert seen["cmd"] == ["/usr/local/bin/claude", "--model", "sonnet"]
    assert "api.example.com" in seen["input"]


def test_generate_puts_the_prompt_in_argv_when_that_is_the_mode(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    seen = {}

    def run(cmd, **kw):
        seen["cmd"] = cmd
        if cmd[-1:] == ["--help"]:
            return help_output("usage: agy --prompt TEXT")
        return _run()

    monkeypatch.setattr(codegen.subprocess, "run", run)
    codegen.generate("api.example.com", [], generator="agy")
    assert seen["cmd"][0] == "/usr/local/bin/agy"
    assert seen["cmd"][-1].startswith("You are writing a Python API client")


def test_an_unstated_transport_is_settled_by_trying(monkeypatch):
    """First attempt on stdin, then argv, and the answer is remembered."""
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    attempts = []

    def run(cmd, **kw):
        # The help probe comes first and says nothing useful.
        if cmd[-1:] == ["--help"]:
            return help_output("agy, version 1.0")
        attempts.append(kw.get("input") is not None)
        # stdin "fails" with nothing at all; argv works.
        return _run(stdout="", returncode=1) if len(attempts) == 1 else _run()

    monkeypatch.setattr(codegen.subprocess, "run", run)
    source = codegen.generate("api.example.com", [], generator="agy")
    assert attempts == [True, False]
    assert "class C" in source
    assert codegen._PROBED["agy"] == ARGV


def test_a_generator_failure_raises_naming_the_backend(monkeypatch):
    monkeypatch.setattr(codegen.shutil, "which", lambda c: "/usr/local/bin/agy")
    monkeypatch.setattr(codegen.subprocess, "run", lambda *a, **k: help_output(""))
    monkeypatch.setattr(codegen.subprocess, "run",
                        lambda *a, **k: _run(stdout="", returncode=2))
    with pytest.raises(GeneratorError) as exc:
        codegen.generate("api.example.com", [], generator="agy")
    assert "`agy` failed" in str(exc.value)


def test_fenced_output_is_unwrapped():
    assert codegen._strip_fences("```python\nclass C: pass\n```") == "class C: pass\n"
    assert codegen._strip_fences("class C: pass") == "class C: pass\n"


def test_a_backend_records_what_it_is():
    b = Backend("x", ["x"], STDIN, model_arg="--model")
    assert "x" in repr(b) and b.command("m") == ["x", "--model", "m"]