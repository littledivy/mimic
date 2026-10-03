"""The shared Frida mechanism, and which platform `mimic unpin` decides to use.

`unpin.py` had no tests at all before this pass. These cover the parts that are
mimic's own rather than upstream's: how frida is invoked, how its output is read
back, and the dispatch between three platforms that share a mechanism.
"""
import argparse
import subprocess

import pytest

from mimic import android, flutter, unpin
from mimic.errors import ToolchainError


@pytest.fixture
def no_toolchain(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)


def _args(**kw):
    base = dict(target="com.example.app", android=False, flutter=False,
                ca=None, proxy_host="192.168.1.5", workdir=None,
                codesign=None)
    base.update(kw)
    return argparse.Namespace(**base)


# ---- dispatch ----------------------------------------------------------------

def test_an_apk_handed_to_the_ios_path_says_so(no_toolchain, tmp_path):
    """`objection patchipa` on an APK fails with something about a bundle, which
    is a long way from 'you wanted a different flag'."""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    with pytest.raises(SystemExit) as caught:
        unpin.cmd_unpin(_args(target=str(apk)))
    assert "--flutter" in str(caught.value)


def test_both_platform_flags_is_refused_rather_than_one_winning(no_toolchain):
    with pytest.raises(SystemExit, match="Pick the one that matches"):
        unpin.cmd_unpin(_args(android=True, flutter=True))


def test_a_missing_tool_is_named_before_anything_is_fetched_or_written(
        no_toolchain, monkeypatch):
    """Cost order. The clone is a network round trip and `_patch_config` rewrites
    a file in the user's tree; both come after the toolchain check, so "install
    frida-tools" is the first thing a user without frida reads rather than the
    thing they read a minute later."""
    def fail_if_reached(args):
        pytest.fail("fetched the hook repo for a run that cannot happen")

    monkeypatch.setattr(unpin, "_workdir_and_scripts", fail_if_reached)
    monkeypatch.setattr(unpin, "_patch_config",
                        lambda *a, **k: pytest.fail("patched config.js"))

    with pytest.raises(ToolchainError) as caught:
        unpin.cmd_unpin(_args(android=True, target="com.example.app"))
    assert caught.value.tool == "frida"
    assert "pipx install frida-tools" in str(caught.value)


def test_the_android_cli_reports_a_missing_tool_as_a_line_not_a_traceback(
        no_toolchain, monkeypatch):
    """`mimic unpin` reaches the toolchain check through the CLI parser, which is
    where the user is. A MimicError that escapes as a traceback there is a line
    the user had to have been shown and wasn't."""
    from mimic import cli

    with pytest.raises(SystemExit) as caught:
        cli.main(["unpin", "--android", "com.example.app"])
    assert "frida-tools" in str(caught.value)
    assert "Traceback" not in str(caught.value)


def test_the_platform_is_never_inferred_from_the_target(no_toolchain):
    """`com.example.app` is a valid Android package *and* a valid iOS bundle id.
    Guessing between them would hook a process the user didn't ask for."""
    with pytest.raises(SystemExit):
        # No --android, no .apk: this goes to the iOS path, which needs a CA.
        unpin.cmd_unpin(_args(ca=str("/nonexistent/ca.pem")))


def test_the_flutter_path_is_reached_by_flag(tmp_path, monkeypatch):
    """The dispatch itself, with the repack stubbed — this is about which branch
    runs, not about reFlutter."""
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    seen = {}

    def fake_run(target, proxy_host):
        seen["target"] = target
        seen["proxy_host"] = proxy_host
        return "nothing to patch", None

    monkeypatch.setattr(flutter, "run", fake_run)
    unpin.cmd_unpin(_args(target=str(apk), flutter=True))
    assert seen == {"target": str(apk), "proxy_host": "192.168.1.5"}


# ---- running frida -----------------------------------------------------------

def _fake_frida(monkeypatch, **kw):
    """Put a `frida` on PATH and record how it was invoked."""
    seen = {}

    def fake_run(command, **run_kw):
        seen["command"] = command
        seen.update(run_kw)
        # Bytes, because run_frida asks for bytes: stdout is a pipe and no text
        # mode is set, which is what makes the output decodable as UTF-8.
        stdout = kw.pop("stdout", "")
        return subprocess.CompletedProcess(
            command, kw.pop("returncode", 0),
            stdout.encode("utf-8") if isinstance(stdout, str) else stdout)

    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/frida"
                        if name == "frida" else None)
    monkeypatch.setattr("subprocess.run", fake_run)
    return seen


def test_the_spawned_app_is_not_left_paused(monkeypatch):
    """The one flag whose absence makes every other result wrong.

    frida spawns suspended and, without `--no-pause`, leaves it that way. The app
    never starts, never loads the libraries being hooked, and every probe
    reports the mechanism absent — an app declared unpinned because it never ran.
    """
    seen = _fake_frida(monkeypatch)
    unpin.run_frida(["/tmp/a.js"], "com.example.app")

    assert "--no-pause" in seen["command"]
    assert seen["command"][-2:] == ["-f", "com.example.app"]


def test_every_script_is_loaded_and_frida_runs_on_usb(monkeypatch):
    """The whole argv, not a few members of it.

    Asserting `"-U" in command` and a `-l` count lets anything else through —
    a dropped `--runtime` reaches the device as a different JavaScript engine,
    where a hook that binds on V8 can quietly throw on QEMU and report the
    mechanism absent.
    """
    seen = _fake_frida(monkeypatch)
    unpin.run_frida(["/tmp/config.js", "/tmp/probe.js"], "com.example.app")

    assert seen["command"] == [
        "/usr/local/bin/frida", "--no-pause", "--runtime=v8", "-U",
        "-l", "/tmp/config.js", "-l", "/tmp/probe.js",
        "-f", "com.example.app",
    ]


def test_a_named_device_is_passed_through(monkeypatch):
    seen = _fake_frida(monkeypatch)
    unpin.run_frida(["/tmp/a.js"], "com.example.app", device="1234")
    assert "-D1234" in seen["command"]


def test_an_indented_probe_line_is_still_a_probe_line():
    """frida indents some of its own output before forwarding a script's
    `console.log`. Anchoring to the start of the *stripped* line is what keeps
    the prefix usable there, and anchoring to the raw line is what keeps an app
    that logs the prefix itself from being read as a verdict."""
    indented = "    " + unpin.PROBE_PREFIX + '{"target": "okhttp-cert-pinner"}'
    assert unpin.parse_probes(indented) == [
        {"target": "okhttp-cert-pinner"}]


def test_a_log_line_that_merely_mentions_the_prefix_is_not_a_record():
    """The app's own logcat goes down the same stream. This one starts with the
    timestamp, not the prefix, so it is not ours to read — and reading it would
    raise on the app's arbitrary text."""
    noisy = "[09-13 12:00:01] app: saw MIMIC-PROBE in a log line\n"
    assert unpin.parse_probes(noisy) == []


def test_the_hooks_script_output_is_returned(monkeypatch):
    _fake_frida(monkeypatch, stdout="[*] attached\nMIMIC-PROBE {\"a\": 1}\n")
    output = unpin.run_frida(["/tmp/a.js"], "com.example.app")
    assert "MIMIC-PROBE" in output


def test_a_timeout_keeps_whatever_the_probes_already_reported(monkeypatch):
    """Probes report as they run, so a session that hangs on the last one can
    still have answered the earlier ones. Throwing that away would turn a
    partial answer into no answer — and 'no answer' reads as 'nothing to
    patch'."""
    def fake_run(command, **kw):
        raise subprocess.TimeoutExpired(command, 1.0,
                                       output=b"MIMIC-PROBE {\"target\": \"okhttp\"}\n")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/frida"
                        if name == "frida" else None)
    monkeypatch.setattr("subprocess.run", fake_run)

    output = unpin.run_frida(["/tmp/a.js"], "com.example.app", timeout=1)
    assert unpin.parse_probes(output) == [{"target": "okhttp"}]


def test_a_frida_that_never_starts_is_a_named_error(no_toolchain):
    with pytest.raises(ToolchainError, match="frida"):
        unpin.run_frida(["/tmp/a.js"], "com.example.app")


def test_a_non_zero_exit_is_not_treated_as_failure(monkeypatch):
    """frida's exit status mostly describes its own teardown. The app runs on
    afterwards, and the probes' answer is the one that means something."""
    _fake_frida(monkeypatch, returncode=1, stdout="MIMIC-PROBE {\"target\": \"x\"}")
    output = unpin.run_frida(["/tmp/a.js"], "com.example.app")
    assert unpin.parse_probes(output) == [{"target": "x"}]


# ---- the iOS command, still built the way it was -----------------------------

def test_the_ios_command_loads_config_first_and_spawns_by_id(tmp_path):
    scripts = "/scripts"
    command = unpin._frida_command(scripts, "com.example.ios", gadget=False)

    assert command.splitlines()[0] == "frida -U \\"
    assert "config.js" in command
    assert command.rstrip().endswith("-f com.example.ios")


def test_the_gadget_path_attaches_rather_than_spawns():
    """A gadget is already running inside the app; spawning by id would start a
    second, ungadgetted copy and attach to nothing."""
    command = unpin._frida_command("/scripts", "Gadget", gadget=True)
    assert command.rstrip().endswith("-n Gadget")


def test_every_ios_script_exists_in_the_upstream_repo(tmp_path):
    """A rename upstream would otherwise surface as a script that silently fails
    to load — and an app reported as still pinned, for the wrong reason."""
    scripts = tmp_path / "frida-scripts"
    (scripts / "ios").mkdir(parents=True)
    for name in unpin.IOS_SCRIPTS:
        (scripts / name).write_text("// upstream placeholder")

    command = unpin._frida_command(str(scripts), "com.example.ios", gadget=False)
    for name in unpin.IOS_SCRIPTS:
        assert str(scripts / name) in command


# ---- config baking -----------------------------------------------------------

def test_the_ca_and_proxy_are_baked_into_config(tmp_path):
    scripts = tmp_path / "frida-scripts"
    scripts.mkdir()
    config = scripts / "config.js"
    config.write_text(
        "const CERT_PEM = `placeholder`;\n"
        "const PROXY_HOST = '127.0.0.1';\n"
        "const PROXY_PORT = 8000;\n"
    )
    unpin._patch_config(str(scripts), "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
                        "10.0.0.7")

    baked = config.read_text()
    assert "10.0.0.7" in baked
    assert "BEGIN CERTIFICATE" in baked
    assert "placeholder" not in baked


def test_a_config_that_changed_shape_says_so_rather_than_writing_half_a_patch(
        tmp_path):
    """Upstream moved a constant and we'd otherwise write a config with the CA
    but not the proxy, which fails at attach time with a ReferenceError."""
    scripts = tmp_path / "frida-scripts"
    scripts.mkdir()
    (scripts / "config.js").write_text("const SOMETHING_ELSE = 1;\n")

    with pytest.raises(SystemExit, match="changed shape"):
        unpin._patch_config(str(scripts), "pem", "10.0.0.7")


# ---- the probe script --------------------------------------------------------

def test_the_probe_declares_a_library_for_every_target(monkeypatch):
    """`assess` reports "hooked X, which is not Y" from the target's list. A
    target with no libraries would fail every real hook it ever took."""
    for target in android.TARGETS:
        assert target.libraries
        for library in target.libraries:
            assert target.matches(library)


def test_the_probe_script_is_self_consistent():
    """It emits the keys `assess` reads. A typo here would surface only on a
    device, as a target that reported nothing."""
    for key in ("process:", "present:", "forced:", "used:", "library:"):
        assert key in android.PROBE_JS, key
    for target in android.TARGETS:
        assert f"emit('{target.key}'" in android.PROBE_JS, target.key
    for library in android.OKHTTP.libraries:
        assert library in android.PROBE_JS, library
    assert android.NETWORK_SECURITY_CONFIG.libraries[0] in android.PROBE_JS


def test_the_probe_does_not_claim_success_without_asking_the_question():
    """The probe's own record for a target has to carry `forced: false` as its
    starting point. Defaulting it to true would make every hook look confirmed
    on a run where the check never executed."""
    assert "var forced = false" in android.PROBE_JS
    assert "var probing = false" in android.PROBE_JS