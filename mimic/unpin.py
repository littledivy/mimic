"""Defeat certificate pinning so mimic can capture a pinned app.

Pinning doesn't stop replay — it stops *capture*. A pinned app rejects
mitmproxy's cert, so the proxy never sees the plaintext. The fix is app-side:
make the app stop checking.

mimic doesn't reimplement the hooks (they move across OS versions and TLS
stacks). It drives the maintained upstream —
httptoolkit/frida-interception-and-unpinning — and owns two things: baking
*your* mitmproxy CA and proxy address into the scripts, and reporting which
pinning mechanism actually got patched. That second one exists because the
upstream hooks are quiet by design: the Android script prints
`== Certificate unpinning completed ==` whether it replaced one method or
thirty, and skips an absent class in silence. A loaded script is not a patch
that took, and an unpinned app looks exactly like a successful run.

Four device paths over one mechanism:

  - iOS, jailbroken (frida-server on the phone): `mimic unpin <bundle-id>`
    prints the ready `frida -U …` command.
  - iOS, stock (Frida gadget): `mimic unpin <app.ipa>` runs
    `objection patchipa`, then hands signing and install to Sideloadly /
    pymobiledevice3.
  - Android (`--android <package>`) — verdicts in `mimic.android`.
  - Flutter APKs (`--flutter <app.apk>`) — repack, not hook; see `mimic.flutter`.
"""
import json
import os
import re
import shutil
import subprocess
import sys

from .errors import ToolchainError

SCRIPTS_REPO = "https://github.com/httptoolkit/frida-interception-and-unpinning"

# Load order matters: config.js first (it defines CERT_PEM/PROXY_*/CERT_DER and
# the module observer the others read), then the platform hooks, then the shared
# native hooks. Mirrors the upstream README's invocations.
IOS_SCRIPTS = [
    "config.js",
    "ios/ios-connect-hook.js",
    "ios/ios-disable-detection.js",
    "native-tls-hook.js",
    "native-connect-hook.js",
]

#: The Android load set. `config.js` is not optional — the Flutter hook uses
#: `waitForModule` and `CERT_DER` from it. Proxy override comes first because it
#: is what sends the traffic anywhere at all; without it the other two are
#: decorating a connection that never reaches mitmproxy.
ANDROID_SCRIPTS = [
    "config.js",
    "android/android-proxy-override.js",
    "android/android-system-certificate-injection.js",
    "android/android-certificate-unpinning.js",
]

#: How long to let a spawned app run before reading its report. Long enough for a
#: cold start on a mid-range phone, short enough that a hang is a message rather
#: than a stuck terminal.
FRIDA_TIMEOUT = 45.0

DEFAULT_CA = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
PROXY_PORT = 8080  # mitmweb's proxy listener — same port `mimic record` prints

#: Marks a machine-readable line emitted by mimic's own probe script.
#:
#: Deliberately not Frida's `send()` channel: that arrives wrapped in whatever
#: formatting the installed frida-tools happens to use, which is not something
#: this should depend on. A prefixed line survives version drift, and the probe
#: output can be replayed from a file in a test.
PROBE_PREFIX = "MIMIC-PROBE "


def which_any(*candidates):
    """The first of `candidates` that exists, searching PATH and absolute paths.

    Absolute candidates matter because the Android SDK is routinely installed but
    not on PATH — `ANDROID_HOME/platform-tools/adb` is the normal case, and
    telling someone to fix their PATH when they have the tool would be a lie.
    """
    for candidate in candidates:
        if not candidate:
            continue
        found = shutil.which(candidate)
        if found:
            return found
        if os.path.isabs(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def require(tool, install, *, search=()):
    """Return `tool`'s path, or raise a `ToolchainError` that says how to get it.

    Never returns None and never falls back to a default: a command that runs
    anyway and quietly does nothing is the failure this whole module exists to
    avoid, and the user has to be told *which* piece was missing.
    """
    found = which_any(tool, *(search or ()))
    if found:
        return found
    raise ToolchainError(
        f"{tool} isn't installed, and this can't work without it.\n"
        f"    {install}\n"
        f"mimic won't skip past a missing tool here: the app would still be "
        f"pinned and you'd get an empty capture with nothing to explain it.",
        tool=tool, install=install, field=tool,
    )


def require_frida():
    """`frida` itself — the thing that attaches to the process."""
    return require("frida", "pipx install frida-tools   (or: uv tool install frida-tools)")


def require_adb():
    """`adb`, for launching the app and installing a repacked one.

    Found on PATH or under the SDK, because `ANDROID_HOME/platform-tools/adb` is
    where it lands for anyone who installed the SDK and never edited their shell.
    """
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    in_sdk = os.path.join(sdk, "platform-tools", "adb") if sdk else None
    return require(
        "adb",
        "install the Android SDK platform-tools:\n"
        "    https://developer.android.com/tools/releases/platform-tools\n"
        "    then set ANDROID_HOME (or put adb on your PATH)",
        search=[in_sdk],
    )


def parse_probes(text):
    """Pull mimic's probe records out of a frida session's output.

    Anchored to the start of a line, not merely present somewhere in one: the
    app being captured logs through the same stream, and a log line that happens
    to mention the prefix would otherwise be parsed as a probe record and
    rejected as corrupt.

    A line that *does* start with the prefix but carries unusable JSON is an
    error rather than something to skip. That is our own script misbehaving, and
    quietly dropping it is how a broken probe becomes "no pinning found" — the
    one conclusion this must never reach by accident.
    """
    records = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith(PROBE_PREFIX):
            continue
        payload = stripped[len(PROBE_PREFIX):].strip()
        try:
            record = json.loads(payload)
        except ValueError as exc:
            raise ValueError(
                f"mimic's probe emitted a line that isn't valid JSON: {payload[:120]}"
            ) from exc
        if isinstance(record, dict):
            records.append(record)
    return records


def _clone_or_update(dst):
    """Fetch (or refresh) the upstream Frida scripts into `dst`."""
    if not shutil.which("git"):
        return False
    if os.path.isdir(os.path.join(dst, ".git")):
        subprocess.run(["git", "-C", dst, "pull", "--quiet", "--ff-only"],
                       check=False)
        return True
    r = subprocess.run(["git", "clone", "--depth", "1", "--quiet",
                        SCRIPTS_REPO, dst], check=False)
    return r.returncode == 0


def _patch_config(scripts_dir, ca_pem, proxy_host):
    """Bake the CA + proxy into a copy of upstream config.js, in place.

    We patch upstream's file rather than hand-write one so all its helper code
    (the base64/DER machinery the hooks depend on) stays intact and current.
    """
    path = os.path.join(scripts_dir, "config.js")
    with open(path) as f:
        src = f.read()

    ca = ca_pem.strip()
    src, n_cert = re.subn(r"const CERT_PEM = `.*?`;",
                          f"const CERT_PEM = `{ca}`;", src, count=1, flags=re.S)
    src, n_host = re.subn(r"const PROXY_HOST = '[^']*';",
                          f"const PROXY_HOST = '{proxy_host}';", src, count=1)
    src, n_port = re.subn(r"const PROXY_PORT = \d+;",
                          f"const PROXY_PORT = {PROXY_PORT};", src, count=1)
    if not (n_cert and n_host and n_port):
        sys.exit("config.js from upstream changed shape — mimic couldn't patch "
                 f"it (cert={n_cert} host={n_host} port={n_port}). Open an issue.")

    with open(path, "w") as f:
        f.write(src)


def _lan_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "<this-machine-ip>"
    finally:
        s.close()


def _frida_command(scripts_dir, target, gadget):
    flag = "-n" if gadget else "-f"  # attach to running gadget vs spawn by id
    lines = ["frida -U \\"]
    for s in IOS_SCRIPTS:
        lines.append(f"    -l {os.path.join(scripts_dir, s)} \\")
    lines.append(f"    {flag} {target}")
    return "\n".join(lines)


def write_probe(scripts_dir, source):
    """Write mimic's probe next to the upstream scripts. Returns its path.

    Kept as a real file rather than inlined with `-e` so that a user can open
    it, read what is actually being asserted on their device, and paste it into
    an issue when a hook stops matching.
    """
    path = os.path.join(scripts_dir, "mimic-probe.js")
    with open(path, "w") as f:
        f.write(source)
    return path


def run_frida(scripts, package, *, device=None, timeout=FRIDA_TIMEOUT):
    """Spawn `package` with `scripts` loaded and return everything it printed.

    `--no-pause` is not optional: without it frida leaves the spawned process
    stopped, the app never reaches the library loads being hooked, every probe
    reports absent, and the result is an app declared unpinned that was never
    allowed to run.

    A timeout keeps whatever was printed before it, because probes report as
    they go and a session that hangs on the last one may have answered the
    first two. The exit status is deliberately not consulted: the app keeps
    running after frida detaches, and frida's teardown says nothing about
    whether the hooks took.
    """
    command = [require_frida(), "--no-pause", "--runtime=v8"]
    command.append(f"-D{device}" if device else "-U")
    for script in scripts:
        command += ["-l", script]
    command += ["-f", package]

    try:
        done = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return done.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        # `output` is what arrived before the deadline, not nothing.
        output = exc.output or b""
        return output.decode("utf-8", "replace")


def cmd_unpin(args):
    """Dispatch to the right platform. The three share the mechanism, not the job.

    The platform is an explicit flag rather than inferred from the target,
    because an Android package name and an iOS bundle id are the same shape of
    string and guessing between them would silently hook the wrong thing. What
    *is* inferred is the one unambiguous case: a `.apk` handed to the iOS path
    would otherwise be fed to `objection patchipa`, which is a confusing way to
    discover the flag exists.
    """
    android = getattr(args, "android", False)
    flutter = getattr(args, "flutter", False)
    target = args.target

    if android and flutter:
        sys.exit("--android hooks a running app; --flutter repacks an APK's "
                 "engine. Pick the one that matches what you have.")
    if flutter:
        return _unpin_flutter(args)
    if target.lower().endswith(".apk"):
        sys.exit(f"{target} looks like an Android APK. Use `mimic unpin "
                 f"--flutter {target}` — the Dart engine needs repacking, not "
                 f"hooking.")
    if android:
        return _unpin_android(args)
    return _unpin_ios(args)


def _workdir_and_scripts(args):
    """Fetch upstream's hooks. Returns `(workdir, scripts_dir)`.

    Shared by both hooking paths. The Flutter repack needs none of this, because
    reFlutter compiles the bypass into a prebuilt engine rather than reading a
    CA from anywhere.
    """
    workdir = args.workdir or "mimic-unpin"
    scripts_dir = os.path.join(workdir, "frida-scripts")
    os.makedirs(workdir, exist_ok=True)

    print(f"fetching unpinning scripts → {scripts_dir}", file=sys.stderr)
    if not _clone_or_update(scripts_dir):
        sys.exit(
            "couldn't fetch the Frida scripts (need git + network). Clone them "
            f"yourself:\n    git clone {SCRIPTS_REPO} {scripts_dir}\n"
            "then re-run `mimic unpin`.")
    return workdir, scripts_dir


def _ca_pem(args):
    ca_path = args.ca or DEFAULT_CA
    if not os.path.exists(ca_path):
        sys.exit(f"no mitmproxy CA at {ca_path} — run `mimic record` once so "
                 f"mitmproxy generates it, or pass --ca <path>.")
    with open(ca_path) as f:
        return f.read()


def _unpin_android(args):
    from . import android

    # Toolchain, then CA, then the clone — in cost order. Everything after this
    # line is slow and writes into the user's working directory, and none of it
    # is worth doing for a run that is going to stop before it attaches to
    # anything. Reading the failure *after* a git clone of the hook repo turns a
    # one-line "install frida-tools" into a minute of waiting for the same line.
    require_frida()
    require_adb()
    ca_pem = _ca_pem(args)
    _workdir, scripts_dir = _workdir_and_scripts(args)
    host = args.proxy_host or _lan_ip()
    _patch_config(scripts_dir, ca_pem, host)
    print(f"baked your CA + proxy {host}:{PROXY_PORT} into config.js")

    print(f"attaching to {args.target} over USB — use the app now.",
          file=sys.stderr)
    text, _output = android.run(args.target, scripts_dir)
    print(text)
    print("\nAnything left unconfirmed is still pinned, and `mimic record` will "
          "show nothing for it. That's the honest answer, not a reason to retry "
          "blind.")


def _unpin_flutter(args):
    from . import flutter

    host = args.proxy_host or _lan_ip()
    print(f"patching the Flutter engine in {args.target} (proxy {host})\n")
    text, patched = flutter.run(args.target, host)
    print(text)
    if patched:
        print(f"\npatched APK → {patched}")
        print("Install *this*, not the original — the original still pins.")
        print("A repacked APK has to be re-signed; reFlutter says so if it "
              "hasn't been, and its output is not installable until it has.")


def _unpin_ios(args):
    target = args.target
    is_ipa = target.lower().endswith(".ipa")

    ca_pem = _ca_pem(args)
    workdir, scripts_dir = _workdir_and_scripts(args)
    host = args.proxy_host or _lan_ip()
    _patch_config(scripts_dir, ca_pem, host)
    print(f"baked your CA + proxy {host}:{PROXY_PORT} into config.js\n")

    if not is_ipa:
        # Jailbroken path: bundle id → attach over USB to frida-server.
        print("Jailbroken device (frida-server) path:\n")
        print("  1. phone + Mac on the same network; `mimic record` running here")
        print("  2. run this to launch the app with pinning disabled:\n")
        print(_frida_command(scripts_dir, target, gadget=False))
        print("\n  3. use the app, then:  mimic hosts   →   mimic gen <api-host>")
        return

    # Stock device path: inject the Frida gadget into the IPA via objection.
    print("Stock device (Frida gadget) path:\n")
    if not shutil.which("objection"):
        sys.exit(
            "objection not found — it does the gadget injection.\n"
            "    pipx install objection      (or: uv tool install objection)\n"
            "then re-run `mimic unpin`.")

    out_ipa = os.path.join(workdir, os.path.basename(target)[:-4] + "-patched.ipa")
    cmd = ["objection", "patchipa", "--source", target, "--output", out_ipa]
    if args.codesign:
        cmd += ["--codesign-signature", args.codesign]
    print("injecting Frida gadget:\n    " + " ".join(cmd) + "\n")
    r = subprocess.run(cmd, check=False)
    if r.returncode != 0:
        sys.exit("objection patchipa failed (needs a *decrypted* IPA; App Store "
                 "binaries are encrypted). See the note below.")

    print(f"\npatched IPA → {out_ipa}\n")
    print("Next — sign + install (mimic hands this off; Apple auth lives here):")
    print("  • easiest:   drag the patched IPA into Sideloadly and install")
    print("  • scripted:  pymobiledevice3 apps install " + out_ipa)
    print("\nThen attach the unpinning scripts to the gadget:\n")
    print(_frida_command(scripts_dir, "Gadget", gadget=True))
    print("\nThen use the app and:  mimic hosts   →   mimic gen <api-host>")
    print("\nNotes:")
    print("  - Needs a DECRYPTED IPA. Your own app build works; an App Store")
    print("    app must be decrypted first (a jailbroken device, once).")
    print("  - Free Apple certs expire in 7 days. TrollStore (iOS ≤17.0.x)")
    print("    avoids the re-sign churn.")
    print("  - Flutter apps ignore the proxy + use private BoringSSL — this")
    print("    path won't capture them without reFlutter.")
