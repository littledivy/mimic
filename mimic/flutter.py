"""Flutter certificate pinning, by repacking `libflutter.so` with reFlutter.

Flutter is not interceptable by the Android hooks in `mimic.android`, and the
reason is structural rather than a gap in coverage: the Dart HTTP stack ships
its own BoringSSL and validates certificates itself, never calling into the
Java trust managers those hooks replace. An app can be completely unpinned at
the Java layer and still reject mitmproxy's CA.

Two routes exist and mimic drives the one that works on a stock release APK:

  - **Repack** (this module). reFlutter swaps in a prebuilt engine whose
    verification always succeeds. Works on stripped release builds; the device
    afterwards must be *running the repacked app*, not the original.
  - **Runtime hook.** Upstream ships `android-disable-flutter-certificate-pinning.js`
    and `mimic unpin --android` can load it. It only resolves against engines
    that still carry a symbol table — debug, profile, Shorebird.

## ABIs are the thing to be honest about

`lib/<abi>/libflutter.so` exists once per ABI an APK ships, and reFlutter
patches per-ISA, aborting without output on architectures it has no prebuilt
engine for. A partial patch set is therefore a reachable outcome, not a
theoretical one.

So the answer is read from the two zips rather than from reFlutter's log: the
ABIs that went in, and the ABIs that came out. An ABI present in the input and
missing from the output is unpatched, and the run as a whole is partial.
"""
import os
import subprocess
import zipfile

from . import unpin
from .errors import ToolchainError

#: The ABI directory names an APK can carry `libflutter.so` under, in the
#: precedence order that tells the reader which one is primary. Anything outside
#: this list (riscv64, for one) is excluded on purpose: reFlutter has no prebuilt
#: engine for it, so counting it would put an unreachable denominator in the
#: report.
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

#: reFlutter's interactive prompt asks for the proxy address. mimic always knows
#: it (its own LAN IP, or an explicit --proxy-host), so it answers rather than
#: letting a prompt block a run that was started from a script.
REFLUTTER = "reflutter"
REFLUTTER_INSTALL = "pip3 install reflutter   (or: uv tool install reflutter)"

#: reFlutter unpacks and repacks; a cold copy of a large APK over a slow disk is
#: not instant, but a hung process is worse than a bounded one.
REFLUTTER_TIMEOUT = 600.0


def abis_in(apk):
    """ABIs the APK at `apk` ships a `libflutter.so` for, in a stable order.

    Ordered by the canonical ABI precedence rather than by zip order, because
    the order tells the reader which ABI is the primary one and zip listings
    have no such notion. Returns a tuple so it can't be mutated into
    disagreement with the set it was compared against.
    """
    try:
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"{apk} isn't a readable APK (a zip): {exc}") from exc

    found = set()
    for name in names:
        parts = name.split("/")
        if len(parts) == 3 and parts[0] == "lib" and parts[2] == "libflutter.so":
            if parts[1] in ABIS:
                found.add(parts[1])
    return tuple(sorted(found, key=ABIS.index))


def is_flutter(apk):
    """Whether `apk` ships a Flutter engine at all.

    Checked so an ordinary Android APK is reported as "nothing to patch" rather
    than handed to a tool that will repack it and produce the same broken capture
    with a longer story.
    """
    return bool(abis_in(apk))


def patched_abis(before, after):
    """Which ABIs survived into the output, and which are unaccounted for.

    The intersection is the honest answer: an ABI is only *patched* if it is
    present both in what went in and in what came out.
    """
    before, after = set(before), set(after)
    return tuple(sorted(after & before, key=ABIS.index)), \
        tuple(sorted(before - after, key=ABIS.index))


def render(apk, before, patched, missing):
    """The report. Names every ABI and says plainly what didn't happen."""
    lines = [f"Flutter engine patching for {os.path.basename(apk)}:"]
    for abi in before:
        if abi in patched:
            lines.append(f"  [+] {abi}: patched")
        else:
            lines.append(f"  [!] {abi}: NOT patched — no libflutter.so for this "
                         f"ABI in the output")
    for abi in patched:
        if abi not in before:
            lines.append(f"  [?] {abi}: appeared in the output but wasn't in the "
                         f"input")

    lines.append("")
    if not before:
        lines.append("nothing to patch — this APK ships no Flutter engine.")
    elif missing:
        lines.append(f"PARTIAL: {len(patched)} of {len(before)} ABIs patched. The "
                     f"app will still reject mitmproxy's CA on "
                     f"{', '.join(missing)}.")
        lines.append("An APK ships all its ABIs in one file, so this means the "
                     "repack dropped some. Rebuild from a single-ABI source, or "
                     "use `mimic unpin --android` with the runtime Flutter hook on "
                     "a debug/profile build.")
    else:
        lines.append(f"patched: {', '.join(patched)}.")
        lines.append("The app must now be installed from the repacked APK — "
                     "the original still pins.")
    return "\n".join(lines)


def require_reflutter():
    """reFlutter, or a `ToolchainError` that says how to install it."""
    return unpin.require(REFLUTTER, REFLUTTER_INSTALL)


def patch(apk, proxy_host):
    """Repack `apk` with reFlutter. Returns the path to the patched APK.

    reFlutter names its output `<stem>.RE.apk` beside the input, which is
    derived here rather than parsed back out of its output text: a log line is
    not a reliable thing to build a file path from, and the naming rule is
    simple and stable. There is no output-directory option because there is
    nothing to choose — the APK goes back where it came from.
    """
    tool = require_reflutter()
    if not os.path.exists(apk):
        raise ValueError(f"no such APK: {apk}")

    expected = os.path.join(os.path.dirname(os.path.abspath(apk)),
                            _output_name(apk))

    command = [tool, os.path.abspath(apk)]
    # reFlutter prompts for the proxy address unless told not to; answering it
    # on stdin keeps the command usable from a script and from a CI job.
    try:
        done = subprocess.run(
            command, input=f"{proxy_host}\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=REFLUTTER_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolchainError(
            f"couldn't run {REFLUTTER}: {exc}\n"
            f"    {REFLUTTER_INSTALL}\n"
            f"reFlutter unpacks the APK and repacks it with a patched engine, so "
            f"it has to actually run — there is nothing to fall back to here.",
            tool=REFLUTTER, install=REFLUTTER_INSTALL, field=REFLUTTER,
        ) from exc

    if not os.path.exists(expected):
        raise ToolchainError(
            f"{REFLUTTER} didn't produce {expected}.\n"
            f"    {(done.stdout or '').strip()[-400:] or '(it printed nothing)'}\n"
            f"reFlutter aborts on an engine it has no prebuilt patch for; check "
            f"its message above for the snapshot hash it found.",
            tool=REFLUTTER, install=REFLUTTER_INSTALL, field=REFLUTTER,
        )
    return expected


def _output_name(apk):
    stem, _ = os.path.splitext(os.path.basename(apk))
    return f"{stem}.RE.apk"


def run(apk, proxy_host):
    """Patch the Flutter engine and report exactly which ABIs came out patched.

    Returns `(text, patched_apk_or_None)`. The APK path is None when there was
    nothing to patch, so a caller can't accidentally install a repack of an app
    that never needed one.
    """
    before = abis_in(apk)
    if not before:
        return render(apk, before, (), ()), None

    patched_apk = patch(apk, proxy_host)
    after = abis_in(patched_apk)
    patched, missing = patched_abis(before, after)
    return render(apk, before, patched, missing), patched_apk