"""Regressions found by running the CLI end to end, not by calling it.

Every test here has a shape like "I ran `mimic <command>` and it did this".
They are grouped separately from the unit tests because what they protect is
the path a real user walks — argv in, one line out — and each was a case where
the unit suite was green and the command was not.

The journey that found them: `mimic record` (a real mitmweb), real traffic
through the proxy, then hosts / learn / gen / profile save / run / unpin. All of
it against mitmproxy 12, which is what `mimic record` installs for you.
"""
import argparse
import subprocess

import pytest
import requests

from mimic import cli, codegen, codegen_det, session, vault
from mimic.errors import MimicError, RequestError
from mimic.sources import mitm

from conftest import make_flow


# ---- the proxy token --------------------------------------------------------

def test_record_pins_the_token_it_then_reads_with(monkeypatch):
    """mitmproxy 11+ sets `web_password` to `secrets.token_hex(16)` when it
    isn't given one, so a bare `mitmweb` has a fresh token every start and every
    API call 403s. `mimic record` launches the proxy, so it has to pin the
    token its own reader will use — this is the bug that made `mimic hosts`
    fail against a proxy mimic had just started."""
    monkeypatch.setattr("shutil.which",
                        lambda n: "/usr/bin/" + n if n in ("mitmweb", "uvx") else None)
    for launcher in ("mitmweb", "uvx"):
        monkeypatch.setattr("shutil.which",
                            lambda n, l=launcher: f"/usr/bin/{l}"
                            if n in (l, "uvx") else None)
        cmd = cli._mitmweb_cmd()
        assert cmd is not None
        assert f"web_password={mitm.DEFAULT_TOKEN}" in cmd, cmd


def test_the_reader_and_the_launcher_agree_on_the_token(monkeypatch):
    """Two constants that must be the same value, or the pinning above is
    decoration."""
    assert mitm.Mitm().token == mitm.DEFAULT_TOKEN


def test_a_rejected_token_is_named_rather_than_reported_as_a_status(monkeypatch):
    """403 is the one status with an obvious cause and an obvious fix, and the
    bare "mitmweb /flows returned 403" named neither."""
    class Refusing:
        def get(self, url, **kw):
            class R:
                status_code = 403
                json = staticmethod(lambda: [])
            return R()

    m = mitm.Mitm(url="http://127.0.0.1:9")
    m._http = Refusing()
    with pytest.raises(mitm.MitmError) as caught:
        m.flows()
    assert "MITM_TOKEN" in str(caught.value)


# ---- the taxonomy -----------------------------------------------------------

def test_a_capture_failure_is_a_mimic_error_not_a_bare_runtime_error():
    """`doctor` was the only thing catching this, so every command that reads a
    capture — hosts, learn, gen, profile save, run — tracebacked instead."""
    assert issubclass(mitm.MitmError, MimicError)


@pytest.mark.parametrize("path,status", [("/boom", 503), ("/nope", 404),
                                          ("/gone", 410), ("/oops", 500)])
def test_every_failed_response_is_a_request_error(path, status, loopback):
    """404 and 503 raised a bare `requests.HTTPError` that was NOT a MimicError,
    so `except MimicError` — which every CLI command and any user code relies
    on — missed them. The docs promise RequestError for a failed response.

    Against a real socket, because the bug lived in the seam between the
    transport's `raise_for_status` and the session's error mapping.
    """
    loopback.route(path, lambda call: (status, {}, b'{"error":"no"}'))
    s = session.Session(loopback.base_url, attempts=1)

    with pytest.raises(MimicError) as caught:
        s.get(path)
    # Both contracts hold at once: the documented old one and the new one.
    assert isinstance(caught.value, RequestError)
    assert isinstance(caught.value, requests.HTTPError)
    assert str(status) in str(caught.value)


# ---- the CLI boundary -------------------------------------------------------

def _args(**kw):
    base = dict(har=None, host="api.example.com", name="p", recipe="r.json",
                out=None, model="sonnet", generator="deterministic",
                prompt_only=False, rate=None, no_pacing=False)
    base.update(kw)
    return argparse.Namespace(**base)


def test_a_capture_read_failure_exits_with_the_reason_not_a_traceback(monkeypatch):
    """The choke point every capture command shares. `mimic learn` with the
    `capture` extra absent printed a Python traceback ending in a class name."""
    class Unreachable:
        def flows(self, fresh=False):
            raise mitm.MitmError("reading a full capture needs mitmproxy installed")

        def capture(self, fresh=False):
            raise mitm.MitmError("reading a full capture needs mitmproxy installed")

    monkeypatch.setattr(mitm, "default", lambda: Unreachable())

    with pytest.raises(SystemExit) as caught:
        cli.cmd_learn(_args())
    assert "mitmproxy" in str(caught.value)
    assert "Traceback" not in str(caught.value)


def test_hosts_leaves_the_same_way_learn_does(monkeypatch):
    """`hosts` goes through the same read and used to fail the same way."""
    class Unreachable:
        def flows(self, fresh=False):
            raise mitm.MitmError("can't reach mitmweb at http://127.0.0.1:8081")

        def capture(self, fresh=False):
            raise mitm.MitmError("can't reach mitmweb")

    monkeypatch.setattr(mitm, "default", lambda: Unreachable())
    with pytest.raises(SystemExit) as caught:
        cli.cmd_hosts(_args())
    assert "mitmweb" in str(caught.value)


def test_a_capture_that_succeeds_actually_comes_back(monkeypatch):
    """The wrapper returns the read's *result*. An earlier version called it
    again on what came back, and every test that used a failing fake was
    perfectly happy — `mimic profile save` and `mimic run` died with
    "'list' object is not callable" on a working proxy."""
    flows = [make_flow(host="api.example.com", path="/v1/x", status=200,
                       resp_body={"ok": True})]
    monkeypatch.setattr(mitm, "default", lambda: _reading(flows))

    got_client, got_flows = cli._flows_for(_args())
    assert got_client is not None
    assert got_flows == flows


def test_learn_asks_for_bodies_and_hosts_does_not(monkeypatch):
    client = _reading([make_flow()])
    monkeypatch.setattr(mitm, "default", lambda: client)
    cli._flows_for(_args(), want_bodies=True)
    assert client.asked == ["capture"]


def test_hosts_asks_for_the_listing_only(monkeypatch):
    client = _reading([make_flow()])
    monkeypatch.setattr(mitm, "default", lambda: client)
    cli._flows_for(_args())
    assert client.asked == ["flows"]


class _reading:
    def __init__(self, flows):
        self._flows = flows
        self.asked = []

    def flows(self, fresh=False):
        self.asked.append("flows")
        return self._flows

    def capture(self, fresh=False):
        self.asked.append("capture")
        return self._flows


def test_the_missing_extra_message_does_not_claim_learn_works_without_it():
    """It did not: `learn` is the command that needs the bodies."""
    from mimic.sources.mitm import _read_dump
    with pytest.raises(mitm.MitmError) as caught:
        # A payload no mitmproxy import can parse gets past the import guard
        # only if mitmproxy IS importable, so force the import to fail.
        import builtins
        real = builtins.__import__

        def no_mitmproxy(name, *a, **k):
            if name.startswith("mitmproxy"):
                raise ImportError(name)
            return real(name, *a, **k)

        builtins.__import__ = no_mitmproxy
        try:
            _read_dump(b"x")
        finally:
            builtins.__import__ = real
    text = str(caught.value)
    assert "learn" in text and "gen" in text
    assert "`mimic learn` work without it" not in text


# ---- the vault in a script --------------------------------------------------

def test_a_scripted_run_can_supply_the_passphrase_without_a_terminal(monkeypatch, tmp_path):
    """`mimic run` exists to be run from a script. getpass raised a bare
    EOFError with no tty, so the documented "a run as data" path could not be
    automated at all."""
    monkeypatch.setenv("MIMIC_VAULT_PASSPHRASE", "from the environment")
    assert vault.Vault(directory=tmp_path)._secret() == "from the environment"


def test_no_terminal_and_no_env_var_is_named_as_such(monkeypatch, tmp_path):
    monkeypatch.delenv("MIMIC_VAULT_PASSPHRASE", raising=False)

    def no_tty(prompt):
        raise EOFError

    monkeypatch.setattr("getpass.getpass", no_tty)
    with pytest.raises(MimicError) as caught:
        vault.Vault(directory=tmp_path)._secret()
    assert "MIMIC_VAULT_PASSPHRASE" in str(caught.value)


# ---- generated code that can be imported ------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.2.2", "api.example.com",
                                  "prod-api.hingeaws.net", "my-api", "", "a.b-c.d"])
def test_the_generated_class_is_always_a_legal_identifier(host):
    """`127.0.0.1` produced `class 127Client` — a syntax error in the file
    mimic had just written. `10.0.2.2` is the Android emulator's host."""
    name = codegen_det._class_name(host)
    assert name.isidentifier(), name
    compile(f"class {name}: pass", "<gen>", "exec")


@pytest.mark.parametrize("path", ["/2fa/verify", "/2024/status", "/123", "/feed"])
def test_generated_method_names_are_always_legal_identifiers(path):
    """Same defect in method names: `def 2fa_verify(...)` won't parse."""
    name = codegen_det._snake(path)
    assert name.isidentifier(), name
    compile(f"def {name}(): pass", "<gen>", "exec")


# ---- generator failures -----------------------------------------------------

def _proc(rc, out="", err=""):
    return subprocess.CompletedProcess(["claude"], rc, out, err)


def test_a_generator_that_explains_itself_on_stdout_is_believed(monkeypatch):
    """`claude -p` prints "Not logged in · Please run /login" on stdout and
    exits 1 with an empty stderr. mimic reported only the stderr, so the one
    line naming the fix was discarded in favour of a bare exit code."""
    _fake_claude(monkeypatch, _proc(1, out="Not logged in · Please run /login"))

    with pytest.raises(MimicError) as caught:
        codegen.generate("api.example.com", [])
    assert "Not logged in" in str(caught.value)


def test_a_generator_that_says_nothing_is_not_reported_as_blank(monkeypatch):
    _fake_claude(monkeypatch, _proc(1))

    with pytest.raises(MimicError) as caught:
        codegen.generate("api.example.com", [])
    assert "printed nothing" in str(caught.value)


def test_stderr_still_wins_when_there_is_some(monkeypatch):
    _fake_claude(monkeypatch, _proc(1, out="ignored", err="the real reason"))

    with pytest.raises(MimicError) as caught:
        codegen.generate("api.example.com", [])
    assert "the real reason" in str(caught.value)
    assert "ignored" not in str(caught.value)


def _fake_claude(monkeypatch, proc):
    """A claude that exists, is known, and fails the way `proc` says."""
    monkeypatch.setattr(codegen, "which", lambda b: "/usr/bin/claude")
    monkeypatch.setattr(codegen, "detect_prompt_mode", lambda b: codegen.STDIN)
    monkeypatch.setattr(codegen, "_try", lambda *a, **k: proc)
    monkeypatch.setattr(codegen, "_PROBED", {}, raising=False)


# ---- the shipped install ----------------------------------------------------

def test_the_shipped_install_carries_the_extras_the_journey_needs():
    """`install.sh` installed no extras at all, so a fresh mimic could run
    `mimic hosts` and nothing past it. `fingerprint` stays out: the default
    transport is plain requests."""
    text = open("install.sh").read()
    assert "capture" in text and "vault" in text
    assert "fingerprint" not in text.split("uv tool install")[1].split("\n")[0]


def test_doctor_checks_the_extras_the_next_command_needs():
    """It passed everything and then `mimic learn` failed, which is the same
    silent-until-it-bites shape this codebase exists to avoid."""
    src = open(cli.__file__.replace(".pyc", ".py")).read()
    assert 'find_spec("mitmproxy")' in src
    assert 'find_spec("cryptography")' in src


def test_record_no_longer_claims_pinned_apps_are_unsupported():
    """It printed "those aren't supported" on every `mimic record`, three layers
    after `mimic unpin` grew the bypass that supports them."""
    text = open(cli.__file__.replace(".pyc", ".py")).read()
    assert "those aren't supported" not in text
    assert "mimic unpin" in text
