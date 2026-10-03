"""Android pinning targets: what got patched, and what didn't.

These run against recorded frida output rather than a device. That's deliberate
and it's also the limit of them: every judgement mimic makes from what the probe
reports is exercised here, and whether the probe's hooks bind on a given Android
version is not. The probe script says so about itself at `mimic.android.PROBE_JS`.
"""
import json
import os
import subprocess

import pytest

from mimic import android, unpin
from mimic.errors import ToolchainError

PACKAGE = "com.example.app"

#: What a session looks like when the app has no pinning at all: both mechanisms
#: absent, and the runtime probe confirming it really did finish. The third
#: record matters — without it a crash mid-probe and a genuinely unpinned app
#: produce the same two records.
UNPINNED_SESSION = "\n".join([
    "[*] attaching to com.example.app",
    unpin.PROBE_PREFIX + json.dumps(
        {"target": "okhttp-cert-pinner", "process": PACKAGE, "present": False,
         "library": None, "used": False,
         "detail": "no OkHttp CertificatePinner class in this app"}),
    unpin.PROBE_PREFIX + json.dumps(
        {"target": "network-security-config", "process": PACKAGE,
         "present": False, "library": None, "used": False,
         "detail": "no network_security_config support in this process"}),
    unpin.PROBE_PREFIX + json.dumps(
        {"target": "runtime", "process": PACKAGE, "present": True,
         "library": None, "forced": True, "used": True,
         "detail": "probes completed"}),
]) + "\n"


def _probe(target, **over):
    record = {"target": target, "process": PACKAGE, "present": True,
              "library": "okhttp3.CertificatePinner", "forced": True,
              "used": True, "detail": None}
    record.update(over)
    return record


# ---- the headline: an app with no pinning says so ----------------------------

def test_an_unpinned_app_is_reported_as_having_nothing_to_patch():
    """Not as a success. An app with neither mechanism is the case most likely to
    be reported wrong — "unpinned" and "nothing to do" look identical from the
    outside, and getting it backwards sends people hunting a pinning problem
    they don't have."""
    verdicts = android.report(PACKAGE, unpin.parse_probes(UNPINNED_SESSION))

    assert [v.status for v in verdicts] == [android.ABSENT, android.ABSENT]
    assert all(v.is_nothing_to_patch for v in verdicts)
    assert not any(v.status == android.PATCHED for v in verdicts)


def test_the_rendered_report_says_nothing_to_patch_rather_than_patched():
    text = android.render(PACKAGE, android.report(
        PACKAGE, unpin.parse_probes(UNPINNED_SESSION)))
    assert "nothing to patch" in text
    assert "patched:" not in text.replace("nothing to patch", "")


def test_a_mechanism_that_is_present_but_never_used_is_also_nothing_to_patch():
    """Different reason, same conclusion. An app that ships OkHttp but never
    pins with it is not a pinning problem, and saying "patched" there trains
    people to ignore the word."""
    session = "\n".join([
        unpin.PROBE_PREFIX + json.dumps(
            _probe("okhttp-cert-pinner", used=False,
                   detail="loaded but check() never ran")),
        unpin.PROBE_PREFIX + json.dumps(
            {"target": "network-security-config", "process": PACKAGE,
             "present": False, "library": None, "used": False}),
    ])
    verdicts = android.report(PACKAGE, unpin.parse_probes(session))
    okhttp = verdicts[0]
    assert okhttp.status == android.UNUSED
    assert okhttp.is_nothing_to_patch


def test_a_mechanism_that_never_ran_is_not_mistaken_for_a_hook_that_failed():
    """The two flags are judged in one order only, and the other order reads the
    same probe output as a failure.

    This is what the probe actually emits for a mechanism that was found but
    never called: `used` never flipped, so `forced` is still the `false` it was
    declared with. Asking "is it forced" about code that never executed gives an
    answer, and it is always no — so a pinned-but-idle app would be reported as
    "could not be confirmed, treat this app as still pinned" every time.
    """
    session = unpin.PROBE_PREFIX + json.dumps(
        _probe("okhttp-cert-pinner", forced=False, used=False,
               detail="loaded but check() never ran"))
    verdict = android.report(PACKAGE, unpin.parse_probes(session))[0]

    assert verdict.status == android.UNUSED
    assert "never ran" in verdict.detail


# ---- hooking the wrong thing -------------------------------------------------

def test_attaching_to_the_wrong_process_is_detected():
    """The silent one. Every hook can succeed against an app you didn't ask
    about, and the verdicts would still look like successes — so the process
    identity is checked before anything the record claims is believed."""
    session = "\n".join([
        unpin.PROBE_PREFIX + json.dumps(
            _probe("okhttp-cert-pinner", process="com.other.app")),
    ])
    verdicts = android.report(PACKAGE, unpin.parse_probes(session))

    assert all(v.status == android.FAILED for v in verdicts)
    assert "com.other.app" in verdicts[0].detail
    assert PACKAGE in verdicts[0].detail


def test_a_probe_that_found_no_application_is_not_read_as_unpinned():
    """No Application means the process died, or was never an app. Every target
    has no record, which has to be a failure rather than an absence."""
    session = unpin.PROBE_PREFIX + json.dumps(
        {"target": "runtime", "process": None, "present": False,
         "library": None, "detail": "no Android Application appeared"})
    verdicts = android.report(PACKAGE, unpin.parse_probes(session))
    assert all(v.status == android.FAILED for v in verdicts)


def test_the_probes_own_account_of_itself_is_passed_on_to_the_verdict():
    """The probe already knows whether it died looking for the Application or
    ran out of time. Both look the same from here — no record for any target —
    so without passing its note along every failure would say "the hook script
    may have failed to load", sending the user to look at the wrong file."""
    session = unpin.PROBE_PREFIX + json.dumps(
        {"target": android.RUNTIME_KEY, "process": None, "present": False,
         "library": None, "detail": "no Android Application appeared in 30s"})
    verdicts = android.report(PACKAGE, unpin.parse_probes(session))

    assert all("no Android Application appeared in 30s" in v.detail
               for v in verdicts)
    assert all("failed to load" not in v.detail for v in verdicts)


def test_a_completed_probe_does_not_blame_a_dead_application_for_a_missing_target():
    """The runtime note says why the probe reported nothing — but only when the
    probe really had nothing to work with. A session that ran to completion and
    still missed a target lost that probe, and handing it the "no Application
    appeared" note would send the user after a process that was there fine."""
    session = "\n".join([
        unpin.PROBE_PREFIX + json.dumps(
            _probe("okhttp-cert-pinner", forced=True, used=True)),
        unpin.PROBE_PREFIX + json.dumps(
            {"target": android.RUNTIME_KEY, "process": PACKAGE, "present": True,
             "library": None, "forced": True, "used": True,
             "detail": "probes completed"}),
    ])
    verdict = android.report(PACKAGE, unpin.parse_probes(session))[1]

    assert verdict.status == android.FAILED
    assert "never reported" in verdict.detail
    assert "Application" not in verdict.detail


def test_a_probe_that_reported_a_target_is_not_overridden_by_its_own_runtime_note():
    """The runtime record explains absent targets. It never re-judges one that
    did report — otherwise a completed session would relabel its own verdicts."""
    session = "\n".join([
        unpin.PROBE_PREFIX + json.dumps(
            _probe("okhttp-cert-pinner", forced=False, used=True,
                   detail="still rejecting our CA")),
        unpin.PROBE_PREFIX + json.dumps(
            {"target": android.RUNTIME_KEY, "process": None, "present": False,
             "library": None, "detail": "no Android Application appeared"}),
    ])
    verdicts = android.report(PACKAGE, unpin.parse_probes(session))

    assert verdicts[0].detail == "still rejecting our CA"
    assert "no Android Application appeared" in verdicts[1].detail


def test_hooking_the_wrong_library_is_detected():
    """OkHttp's pinner exists in three packages and the NSC config in another
    entirely. A hook that landed on the wrong one reports success unless the
    library is checked against what this target is entitled to claim."""
    session = unpin.PROBE_PREFIX + json.dumps(
        _probe("okhttp-cert-pinner", library="com.example.SomeOtherPinner"))
    verdict = android.report(PACKAGE, unpin.parse_probes(session))[0]

    assert verdict.status == android.FAILED
    assert "com.example.SomeOtherPinner" in verdict.detail
    assert "not OkHttp CertificatePinner" in verdict.detail


def test_each_of_the_three_okhttp_pin_locations_counts_as_the_right_library():
    for library in android.OKHTTP.libraries:
        session = unpin.PROBE_PREFIX + json.dumps(
            _probe("okhttp-cert-pinner", library=library))
        verdict = android.report(PACKAGE, unpin.parse_probes(session))[0]
        assert verdict.status == android.PATCHED, library


def test_a_hook_that_loaded_but_did_not_take_is_a_failure():
    """The class is there, the class is right, and `check()` still throws when
    asked about a host it isn't pinned for. Reporting that as patched is exactly
    the silent no-op this module exists to catch."""
    session = unpin.PROBE_PREFIX + json.dumps(
        _probe("okhttp-cert-pinner", forced=False, used=True,
               detail="SSLPeerUnverifiedException for mimic.invalid"))
    verdict = android.report(PACKAGE, unpin.parse_probes(session))[0]

    assert verdict.status == android.FAILED
    # The device's own words, verbatim. mimic's fallback also says the patch
    # "did not take effect", so a substring of *that* would pass either way.
    assert verdict.detail == "SSLPeerUnverifiedException for mimic.invalid"


def test_a_failed_probe_without_a_detail_still_explains_itself():
    """The probe's `detail` is a courtesy, not a contract. When it is missing the
    failure still has to say what failed and where to look, or the user is back
    to an unconfirmed verdict with nothing to act on."""
    session = unpin.PROBE_PREFIX + json.dumps(
        _probe("okhttp-cert-pinner", forced=False, used=True, detail=None))
    verdict = android.report(PACKAGE, unpin.parse_probes(session))[0]

    assert verdict.status == android.FAILED
    assert "did not take effect" in verdict.detail
    assert android.OKHTTP.label in verdict.detail


def test_a_missing_probe_record_is_a_failure_not_an_absence():
    """Silence is not evidence. An app with no pinning produces records saying
    so; a probe that never ran produces none, and those must not be read as the
    same thing."""
    verdicts = android.report(PACKAGE, [])
    assert all(v.status == android.FAILED for v in verdicts)
    assert "never reported" in verdicts[0].detail


# ---- reporting ---------------------------------------------------------------

def test_a_fully_pinned_app_names_exactly_what_it_patched():
    session = "\n".join([
        unpin.PROBE_PREFIX + json.dumps(_probe("okhttp-cert-pinner")),
        unpin.PROBE_PREFIX + json.dumps(_probe(
            "network-security-config",
            library="android.security.net.config.NetworkSecurityConfig")),
    ])
    verdicts = android.report(PACKAGE, unpin.parse_probes(session))
    text = android.render(PACKAGE, verdicts)

    assert all(v.status == android.PATCHED for v in verdicts)
    assert "OkHttp CertificatePinner" in text
    assert "network_security_config trust anchors" in text


def test_one_unconfirmed_target_tells_you_to_treat_the_app_as_still_pinned():
    """A partial result has to read as partial. Two of three patched is not
    success, and a report that says "patched" without saying so sends the user
    to `mimic record` for a capture that will be empty."""
    session = "\n".join([
        unpin.PROBE_PREFIX + json.dumps(_probe("okhttp-cert-pinner")),
        unpin.PROBE_PREFIX + json.dumps(_probe(
            "network-security-config",
            library="android.security.net.config.NetworkSecurityConfig",
            forced=False, detail="still rejecting our CA")),
    ])
    text = android.render(PACKAGE, android.report(
        PACKAGE, unpin.parse_probes(session)))
    assert "treat this app as still pinned" in text


def test_every_target_appears_even_when_the_probe_was_silent():
    """Iterated from TARGETS, not from the records, so a target that reported
    nothing can't quietly drop out of the report."""
    verdicts = android.report(PACKAGE, [])
    assert [v.target.key for v in verdicts] == [
        "okhttp-cert-pinner", "network-security-config"]


def test_a_duplicate_probe_record_does_not_hide_the_first():
    """A script that loads twice reports twice. Taking the last would let a
    second, later failure overwrite the record of what actually worked."""
    records = unpin.parse_probes("\n".join([
        unpin.PROBE_PREFIX + json.dumps(_probe("okhttp-cert-pinner")),
        unpin.PROBE_PREFIX + json.dumps(_probe("okhttp-cert-pinner",
                                                forced=False)),
    ]))
    verdicts = android.report(PACKAGE, records)
    assert verdicts[0].status == android.PATCHED


# ---- parsing the session -----------------------------------------------------

def test_the_app_s_own_logging_is_ignored():
    """Including a line that mentions the prefix. Anchoring on `in` rather than
    `startswith` meant the app's own output could be parsed as our record and
    rejected as corrupt — turning a busy log into a failed capture."""
    text = ("D/OkHttp: pin failed for api.example.com\n"
            + UNPINNED_SESSION
            + "I saw MIMIC-PROBE in the app's own output\n")
    assert len(unpin.parse_probes(text)) == 3


def test_an_unreadable_probe_line_is_an_error_rather_than_silence():
    """Our own script emitting nonsense has to surface. Dropping it would turn a
    broken probe into "nothing to patch" — the one conclusion that must never be
    reached by accident."""
    with pytest.raises(ValueError, match="isn't valid JSON"):
        unpin.parse_probes(unpin.PROBE_PREFIX + "{not json")


def test_a_non_object_probe_line_is_dropped_rather_than_crashing():
    assert unpin.parse_probes(unpin.PROBE_PREFIX + "[1, 2]") == []


def test_parsing_an_empty_session_yields_nothing():
    assert unpin.parse_probes("") == []
    assert unpin.parse_probes(None) == []


# ---- the toolchain -----------------------------------------------------------

@pytest.fixture
def no_toolchain(monkeypatch):
    """Make every external tool look absent.

    `frida` and `adb` are installed on plenty of developer machines — including
    the one running this suite — so a test that relies on them being missing
    passes on a bare CI box and fails everywhere else. The absence is forced
    here rather than assumed.
    """
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)


def test_a_missing_frida_names_itself_and_how_to_install_it(no_toolchain):
    """The discipline `curl_cffi` and mitmproxy already follow. A silent skip
    here reports an app as unpinned when it never got attached to anything."""
    with pytest.raises(ToolchainError) as caught:
        unpin.require_frida()
    assert caught.value.tool == "frida"
    assert "frida-tools" in caught.value.install
    assert "pipx install frida-tools" in str(caught.value)


def test_a_missing_android_sdk_names_the_tool_and_the_documentation(no_toolchain):
    with pytest.raises(ToolchainError) as caught:
        unpin.require_adb()
    assert caught.value.tool == "adb"
    assert "developer.android.com" in caught.value.install
    assert "ANDROID_HOME" in str(caught.value)


def test_an_sdk_on_disk_counts_even_when_it_is_not_on_path(monkeypatch, tmp_path):
    """The normal Android case: the SDK is installed, PATH just doesn't have it.
    Telling someone to fix their PATH when they have the tool would be a lie."""
    sdk = tmp_path / "sdk"
    (sdk / "platform-tools").mkdir(parents=True)
    adb = sdk / "platform-tools" / "adb"
    adb.write_text("#!/bin/sh\n")
    adb.chmod(0o755)

    monkeypatch.setenv("ANDROID_HOME", str(sdk))
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert unpin.require_adb() == str(adb)


def test_a_non_executable_file_in_the_sdk_is_not_mistaken_for_the_tool(
        monkeypatch, tmp_path):
    """A checkout with the right layout and no binary is the state after a
    half-finished install, and running it would fail with something opaque."""
    sdk = tmp_path / "sdk"
    (sdk / "platform-tools").mkdir(parents=True)
    (sdk / "platform-tools" / "adb").write_text("not executable")
    monkeypatch.setenv("ANDROID_HOME", str(sdk))
    monkeypatch.setattr("shutil.which", lambda name: None)

    with pytest.raises(ToolchainError):
        unpin.require_adb()


def test_android_sdk_root_is_honoured_as_well_as_android_home(monkeypatch, tmp_path):
    """Both spellings are in real use, and only honouring one would send half
    the Android users to a download page they don't need."""
    sdk = tmp_path / "sdk"
    (sdk / "platform-tools").mkdir(parents=True)
    adb = sdk / "platform-tools" / "adb"
    adb.write_text("#!/bin/sh\n")
    adb.chmod(0o755)

    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert unpin.require_adb() == str(adb)


def test_the_android_load_set_starts_with_config():
    """Every other script reads `CERT_PEM`, `CERT_DER` or `waitForModule` from
    it. Loaded second, they throw a ReferenceError at attach time — which is
    reported as "the probe never reported" and looks like a device problem."""
    assert unpin.ANDROID_SCRIPTS[0] == "config.js"
    assert "android/android-certificate-unpinning.js" in unpin.ANDROID_SCRIPTS
    assert "android/android-proxy-override.js" in unpin.ANDROID_SCRIPTS


def test_the_probe_is_written_next_to_the_hooks_it_follows(tmp_path):
    scripts = tmp_path / "frida-scripts"
    scripts.mkdir()
    path = unpin.write_probe(str(scripts), android.PROBE_JS)

    assert path.endswith("mimic-probe.js")
    assert "MIMIC-PROBE" in open(path).read()


def test_both_targets_name_the_hook_that_patches_them():
    """So a failure points at a file the user can go read."""
    for target in android.TARGETS:
        assert target.script.endswith(".js")


# ---- the wiring: run() is what puts the probe and the hooks on the device -----

def _fake_session(monkeypatch, output):
    """Stand in for a frida that ran the load set and printed `output`.

    Returns the loaded script paths, in order, so a test can assert on what the
    device was actually given rather than on the argv.
    """
    seen = {"scripts": []}

    def fake_run(command, **kw):
        seen["scripts"] = [command[i + 1] for i, a in enumerate(command)
                           if a == "-l"]
        return subprocess.CompletedProcess(command, 0, output.encode("utf-8"))

    monkeypatch.setattr(
        "shutil.which",
        lambda name: f"/usr/local/bin/{name}" if name in ("frida", "adb") else None)
    monkeypatch.setattr("subprocess.run", fake_run)
    return seen


def test_run_reads_the_report_back_out_of_the_session(monkeypatch, tmp_path):
    """The whole premise: the report comes from what the probe said about the
    running process, not from the fact that a script loaded. If `run` didn't load
    the probe, or didn't parse what came back, every verdict would be the
    "the probe never reported" failure — a whole app declared still pinned
    because the plumbing, not the pins, was broken.
    """
    scripts = tmp_path / "frida-scripts"
    scripts.mkdir()
    seen = _fake_session(monkeypatch, UNPINNED_SESSION)

    text, raw = android.run(PACKAGE, str(scripts))

    assert raw == UNPINNED_SESSION
    assert "nothing to patch — this app pins by neither mechanism" in text
    probe = [p for p in seen["scripts"] if p.endswith("mimic-probe.js")]
    assert len(probe) == 1
    # Same order `ANDROID_SCRIPTS` declares, joined to the directory it was
    # cloned into — the load order is the contract, the path prefix isn't.
    assert seen["scripts"][:-1] == [
        os.path.join(str(scripts), name) for name in unpin.ANDROID_SCRIPTS]


def test_run_never_returns_a_report_it_could_not_read(monkeypatch, tmp_path):
    """A corrupt probe line is mimic's own script misbehaving. Reporting
    "nothing to patch" from a probe whose output couldn't be parsed is the one
    conclusion that must never be reached by accident."""
    scripts = tmp_path / "frida-scripts"
    scripts.mkdir()
    _fake_session(monkeypatch, unpin.PROBE_PREFIX + "{not json")

    with pytest.raises(ToolchainError) as caught:
        android.run(PACKAGE, str(scripts))
    assert "unreadable report" in str(caught.value)
    assert "nothing to patch" not in str(caught.value)


def test_run_requires_both_tools_before_it_reports_anything(monkeypatch, tmp_path):
    """No device means a named toolchain error, not an empty report. Half the
    pipeline running — frida found, adb not — is still nothing to report on."""
    scripts = tmp_path / "frida-scripts"
    scripts.mkdir()
    monkeypatch.setattr("shutil.which",
                        lambda name: "/usr/local/bin/frida"
                        if name == "frida" else None)
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)

    with pytest.raises(ToolchainError) as caught:
        android.run(PACKAGE, str(scripts))
    assert caught.value.tool == "adb"
