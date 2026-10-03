"""Flutter: which ABIs are in the APK, and which came back patched.

The ABIs are read out of real zip archives rather than mocked, because the whole
point of this module is that the answer comes from the files themselves instead
of from trusting a log line. An APK is a zip and the standard library reads one,
so these tests build actual APKs and diff them.
"""
import os
import subprocess
import sys
import zipfile

import pytest

from mimic import flutter, unpin
from mimic.errors import ToolchainError


def make_apk(path, abis, extra=(), engine=True):
    """A real APK-shaped zip carrying a `libflutter.so` per ABI.

    `engine=False` produces an ordinary Android APK — it still has a `lib/`
    directory, just not Flutter's engine in it, which is the case worth being
    able to tell apart.
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex")
        for abi in abis:
            if engine:
                zf.writestr(f"lib/{abi}/libflutter.so", b"\x7fELF" + abi.encode())
            zf.writestr(f"lib/{abi}/libapp.so", b"other native lib")
        for name in extra:
            zf.writestr(name, b"x")
    return str(path)


@pytest.fixture
def no_reflutter(monkeypatch):
    """reFlutter is genuinely absent on most machines; don't depend on it."""
    monkeypatch.setattr("shutil.which", lambda name: None)


# ---- reading the APKs --------------------------------------------------------

def test_abis_are_read_out_of_the_apk(tmp_path):
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a", "armeabi-v7a", "x86_64"])
    assert flutter.abis_in(apk) == ("arm64-v8a", "armeabi-v7a", "x86_64")


def test_abi_order_is_stable_and_primary_first(tmp_path):
    """Zip listing order carries no meaning, and the order tells the reader
    which ABI is the primary one. Derived from the canonical precedence so two
    runs over the same APK always produce the same report."""
    apk = make_apk(tmp_path / "app.apk", ["x86_64", "armeabi-v7a", "arm64-v8a"])
    assert flutter.abis_in(apk) == ("arm64-v8a", "armeabi-v7a", "x86_64")
    assert flutter.abis_in(apk) == flutter.abis_in(apk)


def test_an_apk_with_no_flutter_engine_reads_as_none(tmp_path):
    """It still has native libraries in `lib/` — just not Flutter's."""
    apk = make_apk(tmp_path / "plain.apk", ["arm64-v8a"], engine=False)
    assert flutter.abis_in(apk) == ()
    assert flutter.is_flutter(apk) is False


def test_other_native_libraries_are_not_mistaken_for_the_engine(tmp_path):
    """`libapp.so` sits in the same directory as `libflutter.so`. Matching on
    the directory would report an ABI that ships no Flutter engine in it."""
    apk = make_apk(tmp_path / "app.apk", [], engine=False)
    assert flutter.abis_in(apk) == ()


def test_the_engine_is_matched_at_exactly_one_path(tmp_path):
    """`lib/<abi>/libflutter.so`, not a name anywhere in the archive. A Flutter
    SDK that ships a stray copy under `assets/`, or a deeper vendor path, would
    otherwise be read as an ABI the app can run on — and reFlutter would then
    abort on it having nothing to patch."""
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a"],
                   extra=["assets/x86_64/libflutter.so",
                          "lib/arm64-v8a/x86/libflutter.so",
                          "libflutter.so"])
    assert flutter.abis_in(apk) == ("arm64-v8a",)


def test_an_architecture_reflutter_cannot_patch_is_not_claimed(tmp_path):
    """reFlutter aborts without writing on an architecture it has no prebuilt
    engine for, and Flutter does ship `riscv64`. Counting it would turn a clean
    `x of y ABIs patched` into a result that can never reach all of them — the
    report would name an ABI as unpatched that mimic never asked anyone to patch.
    """
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a", "riscv64"])
    assert flutter.abis_in(apk) == ("arm64-v8a",)
    text = flutter.render(apk, flutter.abis_in(apk), ("arm64-v8a",), ())
    assert "riscv64" not in text


def test_patching_a_path_that_is_not_there_says_so(monkeypatch, tmp_path):
    """`run()` reaches the same conclusion earlier, by reading the APK. Called
    directly, `patch()` has to refuse by name too rather than hand a missing
    path to reFlutter and report the missing output as reFlutter's fault."""
    monkeypatch.setattr("shutil.which",
                        lambda name: "/usr/local/bin/reflutter"
                        if name == "reflutter" else None)
    with pytest.raises(ValueError, match="no such APK"):
        flutter.patch(str(tmp_path / "nope.apk"), "192.168.1.5")


def test_a_file_that_is_not_a_zip_is_rejected_by_name(tmp_path):
    path = tmp_path / "broken.apk"
    path.write_bytes(b"this is not a zip")
    with pytest.raises(ValueError, match="isn't a readable APK"):
        flutter.abis_in(str(path))


def test_a_missing_file_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="isn't a readable APK"):
        flutter.abis_in(str(tmp_path / "nope.apk"))


# ---- accounting for what came back -------------------------------------------

def test_the_patched_set_is_read_from_the_output_not_the_log(tmp_path):
    """reFlutter's output naming and log lines are not a contract mimic should
    build an answer on. The ABIs that came back in the APK it wrote are."""
    before = ("arm64-v8a", "armeabi-v7a")
    after = ("arm64-v8a", "armeabi-v7a")
    patched, missing = flutter.patched_abis(before, after)
    assert patched == before
    assert missing == ()


def test_an_abi_missing_from_the_output_is_reported_as_unpatched():
    """The partial case the mission is really about. reFlutter patches per-ISA
    and aborts on architectures it has no prebuilt engine for, so an APK can
    come back with fewer ABIs than it went in with."""
    patched, missing = flutter.patched_abis(
        ("arm64-v8a", "armeabi-v7a", "x86_64"), ("arm64-v8a", "x86_64"))
    assert patched == ("arm64-v8a", "x86_64")
    assert missing == ("armeabi-v7a",)


def test_an_abi_only_in_the_output_is_not_counted_as_patched():
    """It wasn't in the APK we were asked to patch, so calling it patched is a
    claim about a file the user never supplied."""
    patched, missing = flutter.patched_abis(("arm64-v8a",),
                                            ("arm64-v8a", "x86_64"))
    assert patched == ("arm64-v8a",)
    assert missing == ()


def test_a_fully_patched_report_names_every_abi():
    text = flutter.render("app.apk", ("arm64-v8a", "armeabi-v7a"),
                          ("arm64-v8a", "armeabi-v7a"), ())
    assert text.count("[+]") == 2
    assert "arm64-v8a: patched" in text
    assert "PARTIAL" not in text


def test_a_partial_report_says_partial_and_names_what_is_missing():
    """The whole point. A partial patch set presented as a success sends someone
    to install an APK that still rejects the proxy on the ABI they didn't notice."""
    text = flutter.render("app.apk", ("arm64-v8a", "armeabi-v7a"),
                          ("arm64-v8a",), ("armeabi-v7a",))
    assert "PARTIAL" in text
    assert "1 of 2 ABIs patched" in text
    assert "[!] armeabi-v7a: NOT patched" in text
    assert "[+] arm64-v8a: patched" in text


def test_a_non_flutter_apk_is_reported_as_nothing_to_patch():
    text = flutter.render("plain.apk", (), (), ())
    assert "nothing to patch" in text
    assert "[+]" not in text


# ---- the toolchain -----------------------------------------------------------

def test_a_missing_reflutter_names_itself_and_how_to_install_it(no_reflutter):
    """`pip3 install reflutter`, not `reFlutter` — the package is lower-case and
    a wrong install command is the difference between a fix and a dead end."""
    with pytest.raises(ToolchainError) as caught:
        flutter.require_reflutter()
    assert caught.value.tool == "reflutter"
    assert "pip3 install reflutter" in str(caught.value)


def test_a_missing_reflutter_stops_before_the_apk_is_touched(no_reflutter, tmp_path):
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a"])
    with pytest.raises(ToolchainError):
        flutter.run(apk, "192.168.1.5")
    assert not (tmp_path / "app.RE.apk").exists()


def test_a_flutter_apk_with_no_toolchain_is_an_error_not_a_skip(no_reflutter,
                                                                tmp_path):
    """An unpinned-by-absence app is a report; a missing tool is an error. The
    second must never read as the first, or `mimic record` returns an empty
    capture with a cheerful message."""
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a"])
    with pytest.raises(ToolchainError, match="reflutter"):
        flutter.run(apk, "192.168.1.5")


def test_a_non_flutter_apk_needs_no_toolchain_at_all(no_reflutter, tmp_path):
    """Nothing to patch is a real answer, so it must not first demand reflutter —
    that would make an ordinary APK look broken."""
    apk = make_apk(tmp_path / "plain.apk", ["arm64-v8a"], engine=False)
    text, patched = flutter.run(apk, "192.168.1.5")

    assert patched is None
    assert "nothing to patch" in text


def test_a_reflutter_that_writes_nothing_is_a_named_error(monkeypatch, tmp_path):
    """It aborts on an engine it has no prebuilt patch for. That is a message,
    not a patched APK, and not a silently unchanged capture."""
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a"])
    script = tmp_path / "reflutter"
    script.write_text("#!/bin/sh\necho 'no engine for snapshot hash abc123'\n")
    script.chmod(0o755)

    monkeypatch.setattr("shutil.which", lambda name: str(script)
                        if name == "reflutter" else None)
    with pytest.raises(ToolchainError) as caught:
        flutter.patch(apk, "192.168.1.5")
    assert "snapshot hash" in str(caught.value)


def test_a_reflutter_that_cannot_be_run_is_a_named_error(monkeypatch, tmp_path):
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a"])
    monkeypatch.setattr("shutil.which", lambda name: "/nonexistent/reflutter")
    monkeypatch.setattr("os.access", lambda path, mode: True)

    with pytest.raises(ToolchainError, match="couldn't run reflutter"):
        flutter.patch(apk, "192.168.1.5")


# ---- the repack round trip, with a stand-in for reFlutter --------------------

def test_a_successful_repack_reports_exactly_the_abis_it_wrote(monkeypatch, tmp_path):
    """End to end with the real APK handling and a stand-in for the tool.

    Only reFlutter is faked: it needs a device and a download. Everything mimic
    owns — reading the input, reading the output, diffing them, and saying what
    was missed — is the real code on real archives.
    """
    source = make_apk(tmp_path / "app.apk", ["arm64-v8a", "armeabi-v7a"])
    stand_in = tmp_path / "reflutter"
    stand_in.write_text(f'''#!/bin/sh
# A stand-in for reFlutter: repack with the same ABIs it was given.
cp "{source}" "${{1%.apk}}.RE.apk"
''')
    stand_in.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda name: str(stand_in)
                        if name == "reflutter" else None)

    text, patched = flutter.run(source, "192.168.1.5")

    assert patched == str(tmp_path / "app.RE.apk")
    assert "arm64-v8a: patched" in text
    assert "armeabi-v7a: patched" in text
    assert "PARTIAL" not in text


def test_a_repack_that_drops_an_abi_is_reported_as_partial(monkeypatch, tmp_path):
    """reFlutter's own documented behaviour on an architecture it can't patch.
    The APK goes in with three ABIs and comes back with two."""
    source = make_apk(tmp_path / "app.apk", ["arm64-v8a", "armeabi-v7a", "x86_64"])
    stand_in = tmp_path / "reflutter"
    stand_in.write_text('''#!/bin/sh
python3 - "$1" <<'EOF'
import sys, zipfile
src = sys.argv[1]
out = src[:-4] + ".RE.apk"
zin = zipfile.ZipFile(src)
zout = zipfile.ZipFile(out, "w")
for item in zin.infolist():
    if "armeabi-v7a" in item.filename:
        continue
    zout.writestr(item, zin.read(item.filename))
EOF
''')
    stand_in.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda name: str(stand_in)
                        if name == "reflutter" else None)

    text, patched = flutter.run(source, "192.168.1.5")

    assert patched is not None
    assert "PARTIAL" in text
    assert "2 of 3 ABIs patched" in text
    assert "[!] armeabi-v7a: NOT patched" in text


def test_the_repack_output_name_is_derived_not_parsed(monkeypatch, tmp_path):
    """reFlutter writes `<stem>.RE.apk`. Deriving that is more reliable than
    scraping a path out of its log, and a log line can be reworded."""
    source = make_apk(tmp_path / "app.apk", ["arm64-v8a"])
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["stdin"] = kw.get("input")
        with zipfile.ZipFile(str(tmp_path / "app.RE.apk"), "w") as zf:
            zf.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF")
        return subprocess.CompletedProcess(cmd, 0, "done")

    monkeypatch.setattr("shutil.which", lambda name: "/bin/true"
                        if name == "reflutter" else None)
    monkeypatch.setattr("subprocess.run", fake_run)

    out = flutter.patch(source, "192.168.1.5")
    assert out == str(tmp_path / "app.RE.apk")
    # The proxy address is answered on stdin so a scripted run doesn't block on
    # reFlutter's interactive prompt.
    assert seen["stdin"].strip() == "192.168.1.5"
    assert seen["cmd"][0] == "/bin/true"


def test_the_real_reflutter_is_never_required_to_read_an_apk(monkeypatch, tmp_path):
    """Reading ABIs is pure stdlib zip work. Tying it to a missing tool would
    make `is_flutter` unusable for the question it's most often asked — is this
    an APK worth running through the tool at all?"""
    apk = make_apk(tmp_path / "app.apk", ["arm64-v8a"])
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert flutter.is_flutter(apk) is True
    assert flutter.abis_in(apk) == ("arm64-v8a",)


def test_run_reports_nothing_when_the_apk_does_not_exist(tmp_path):
    with pytest.raises(ValueError, match="isn't a readable APK"):
        flutter.run(str(tmp_path / "ghost.apk"), "192.168.1.5")


def test_run_refuses_a_directory(tmp_path):
    """`os.path.exists` is true for a directory, and handing one to a zip reader
    produces a confusing error several frames away."""
    directory = tmp_path / "not-an-apk"
    directory.mkdir()
    with pytest.raises(ValueError, match="isn't a readable APK"):
        flutter.abis_in(str(directory))


def test_unpin_exposes_the_android_script_list_for_the_hook_path():
    """The Flutter *repack* path uses none of these — the repacked engine needs
    no hooks. Kept as the assertion that the two paths stay separate."""
    assert unpin.ANDROID_SCRIPTS[0] == "config.js"
    assert not hasattr(flutter, "ANDROID_SCRIPTS")


def test_the_python_version_supports_what_the_module_uses():
    """`subprocess.run(text=True)` and `os.path.splitext` are ancient, but the
    repack relies on stdin being text — a bytes stdin would send a repr."""
    assert sys.version_info >= (3, 9)
    assert os.path.splitext("a.apk") == ("a", ".apk")