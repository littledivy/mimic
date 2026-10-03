"""mimic CLI — capture any iOS app, generate a client.

    mimic record            start the proxy + print iPhone setup steps
    mimic hosts             list captured hosts (pick your API host here)
    mimic learn <host>      show the endpoints mimic saw for a host
    mimic gen <host>        AI-write a Python client for a host
    mimic unpin <ipa|id>    defeat cert pinning (Frida) so capture works
    mimic doctor            check your setup
    mimic run <recipe.json>  execute a declarative run spec
    mimic profile save      save the captured identity to the encrypted vault
    mimic profile list      what is in the vault
    mimic profile load      open a saved profile into a Session
"""
import argparse
import importlib.util
import os
import re
import shutil
import socket
import subprocess
import sys

from . import codegen
from . import codegen_det
from . import extract
from . import recipes
from . import unpin
from .errors import MimicError
from .orchestrate import HostLimiter
from .identity import Profile
from .session import Session
from .sources import endpoints, hosts
from .sources import har
from .sources import mitm
from .vault import Vault


def _flows_for(args, want_bodies=False):
    """Flows for this command: from a HAR file, or from live mitmweb.

    `want_bodies` matters only for mitmweb: a HAR file already carries its
    bodies, while reading them from mitmweb means one bulk `capture()` instead
    of two requests per endpoint. Both are cached briefly, so a command that
    asks for both isn't paying twice.

    Wrapped, because this is the one read every capture command shares: a proxy
    that isn't running, a token it rejects, or the `capture` extra being absent
    are each a line the user fixes by reading, and none of them is the fault of
    whichever command happened to ask first.
    """
    if getattr(args, "har", None):
        return None, har.load(args.har)
    m = mitm.default()
    return m, _die_if_unusable(m.capture if want_bodies else m.flows)


def _sdk_adb(sdk):
    """`adb` inside an SDK that isn't on PATH — the common Android case."""
    return os.path.join(sdk, "platform-tools", "adb") if sdk else None


def _lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "<this-machine-ip>"
    finally:
        s.close()


def _mitmweb_cmd():
    """Prefer mitmweb on PATH; otherwise run it ephemerally through uv.

    `--set web_password=...` is not optional. mitmproxy 11+ invents a random
    token per process when that option is unset, so without it nothing this
    process launches can be read back: every API call is a 403, and `mimic
    hosts` fails against a proxy mimic itself just started.
    """
    args = ["--set", f"web_password={mitm.DEFAULT_TOKEN}"]
    if shutil.which("mitmweb"):
        return ["mitmweb", *args]
    if shutil.which("uvx"):
        return ["uvx", "--from", "mitmproxy", "mitmweb", *args]
    return None


def cmd_record(args):
    ip = _lan_ip()
    print(
        f"""
iPhone capture — do this once, then just reopen the app to add traffic:

  1. iPhone → Settings → Wi-Fi → (your network) ⓘ → Configure Proxy → Manual
        Server: {ip}      Port: 8080
  2. Safari → http://mitm.it → download the Apple (.pem) profile
  3. Settings → General → VPN & Device Management → install the profile
  4. Settings → General → About → Certificate Trust Settings
        → turn ON full trust for "mitmproxy"          ← everyone forgets this
  5. open the target app and use it normally
  6. back here:   mimic hosts      then   mimic gen <api-host>

  mitmweb dashboard: http://127.0.0.1:8081   (mimic reads flows from here)

  A pinned app (banks, many finance apps) shows nothing here — that's the
  certificate check, not a broken setup. `mimic unpin` sets up a bypass; see
  docs/pinning.md. Most apps aren't pinned and just work: if `mimic hosts`
  shows the app's API host, you're good.
"""
    )
    cmd = _mitmweb_cmd()
    if not cmd:
        sys.exit(
            "no proxy available — install uv (https://astral.sh/uv) so mimic can\n"
            "run mitmproxy for you, or `pipx install mitmproxy` yourself."
        )
    sys.stdout.flush()  # show the steps before the proxy takes over the terminal
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        sys.exit("failed to launch mitmweb")


def cmd_doctor(args):
    ok = True

    def check(name, present, fix):
        nonlocal ok
        mark = "ok " if present else "MISSING"
        print(f"  [{mark}] {name}")
        if not present:
            ok = False
            print(f"          → {fix}")

    print("mimic setup check:\n")
    check("proxy (mitmweb or uvx)", _mitmweb_cmd() is not None,
          "install uv: curl -LsSf https://astral.sh/uv/install.sh | sh")
    check("AI generator (claude or opencode)",
          shutil.which("claude") is not None or shutil.which("opencode") is not None,
          "install Claude Code or OpenCode (https://opencode.ai), or use `mimic gen --prompt-only`")
    reachable = False
    try:
        mitm.default().flows(fresh=True)
        reachable = True
    except mitm.MitmError:
        pass
    check("mitmweb running + reachable", reachable,
          "run `mimic record` in another terminal")

    # The extras the commands above need, checked here rather than discovered at
    # `mimic learn`: a check that passes everything and then fails the next
    # command is worse than one that names what is missing. `find_spec` answers
    # "is it installed" without paying mitmproxy's import to say so.
    check("capture extra (bodies for learn/gen)",
          importlib.util.find_spec("mitmproxy") is not None,
          "pipx install mitmproxy   (or: uv tool install "
          "'mimic-client[capture]' — rerun install.sh)")
    check("vault extra (encrypted profiles)",
          importlib.util.find_spec("cryptography") is not None,
          "pipx install cryptography   (or: uv tool install "
          "'mimic-client[vault]' — rerun install.sh)")

    def opt(name, present, fix):
        # Optional — only needed for `mimic unpin`; never fails the check.
        print(f"  [{'ok ' if present else '  -'}] {name}")
        if not present:
            print(f"          → {fix}")

    print("\noptional — only for `mimic unpin` (pinned apps):")
    opt("git (fetch unpinning scripts)", shutil.which("git") is not None,
        "install git (Xcode CLT: xcode-select --install)")
    opt("frida (run the hooks)", unpin.which_any("frida") is not None,
        "pipx install frida-tools   (or: uv tool install frida-tools)")
    opt("objection (iOS gadget inject, no-JB path)", shutil.which("objection") is not None,
        "pipx install objection   (or: uv tool install objection)")
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    opt("adb (Android device)", unpin.which_any("adb", _sdk_adb(sdk)) is not None,
        "install the Android SDK platform-tools, then set ANDROID_HOME")
    opt("reflutter (patch a Flutter APK)", shutil.which("reflutter") is not None,
        "pip3 install reflutter   (or: uv tool install reflutter)")

    print(f"\nLAN IP for the phone proxy: {_lan_ip()}:8080")
    sys.exit(0 if ok else 1)


def cmd_hosts(args):
    _, flows = _flows_for(args)
    rows = hosts(flows)
    if not rows:
        if getattr(args, "har", None):
            sys.exit("no entries in the HAR file")
        sys.exit("no traffic captured yet — run `mimic record` and use the app")
    print(f"{'requests':>9}  host")
    for host, n in rows:
        print(f"{n:>9}  {host}")
    print("\nPick your API host (usually the one with JSON, not media/cdn).")


def _label(e):
    """How an endpoint is shown: the operation name for GraphQL, else the path."""
    operation = e.get("operation")
    return f"{e['path']} [{e.get('operation_type', 'query')}: {operation}]" \
        if operation else e["path"]


def cmd_learn(args):
    _, flows = _flows_for(args, want_bodies=True)
    eps = endpoints(flows, args.host)
    if not eps:
        sys.exit(f"no requests to {args.host} found")
    print(f"{args.host}: {len(eps)} endpoints\n")
    for e in eps:
        print(f"  {e['method']:5s} {_label(e)}   -> {e['status']}")
        if e.get("variables"):
            print(f"        variables: {', '.join(e['variables'])}")


def cmd_gen(args):
    _, flows = _flows_for(args, want_bodies=True)
    eps = endpoints(flows, args.host)
    if not eps:
        sys.exit(f"no requests to {args.host} found")

    if args.prompt_only:
        print(codegen.build_prompt(args.host, eps))
        return

    out = args.out or _default_out(args.host)
    if args.generator == "deterministic":
        # No AI, and no pretence of one: every type comes from the capture.
        source = _die_if_unusable(codegen_det.client_source, args.host, eps)
        how = f"inferred from {len(eps)} captured endpoints"
    else:
        print(f"asking {args.generator} to write a client from {len(eps)} endpoints…",
              file=sys.stderr)
        source = _die_if_unusable(codegen.generate, args.host, eps,
                                  model=args.model, generator=args.generator)
        how = f"written by {args.generator}"
    with open(out, "w") as f:
        f.write(source)
    cls = _class_name(source)
    print(f"\nwrote {out} ({how})")
    print(f"\n    from {out[:-3]} import {cls or 'Client'}")
    print(f"    acc = {cls or 'Client'}()")
    print("    # then call the generated methods\n")


def _die_if_unusable(fn, *args, **kw):
    """Run something that inspects a capture and exit with the reason if it can't.

    Both a contradictory capture and a missing `cryptography` are things the
    user fixes by reading one line, not by reading a traceback.
    """
    try:
        return fn(*args, **kw)
    except MimicError as exc:
        sys.exit(str(exc))


def cmd_unpin(args):
    """`mimic unpin` for all three platforms, with the reasons kept readable.

    Everything that stops an unpin run short of a session — a missing `frida`,
    `adb` or `reflutter`, an APK that isn't there, an APK that isn't a zip — is
    a line the user fixes by reading, not by reading a traceback. That includes
    the ValueError an unreadable APK raises, which is why it's caught beside the
    MimicError rather than left to propagate.
    """
    try:
        unpin.cmd_unpin(args)
    except (MimicError, ValueError, OSError) as exc:
        sys.exit(str(exc))


def cmd_profile_save(args):
    _, flows = _flows_for(args)
    headers = extract.session_headers(flows, args.host)
    if not headers:
        sys.exit(
            f"no authenticated request to {args.host} captured yet — open the "
            f"app once, then save the profile again"
        )
    profile = _die_if_unusable(
        Profile.from_capture, args.name, headers,
        extract.base_url(flows, args.host), args.host,
    )
    path = _die_if_unusable(Vault().save, args.name, profile.to_bytes())
    print(f"saved profile {args.name!r} -> {path}")
    print(profile.persona.describe())


def cmd_profile_list(args):
    names = Vault().names()
    if not names:
        sys.exit(
            "the vault is empty — save one with:\n"
            "    mimic profile save <name> --host <api-host>"
        )
    print(f"{len(names)} profile{'s' if len(names) != 1 else ''} in the vault\n")
    for name in names:
        print(f"  {name}")


def cmd_profile_load(args):
    # One vault, one load, one prompt: from_profile decrypts and validates, and
    # hands the profile back on the session it built.
    session = _die_if_unusable(Session.from_profile, args.name, Vault())
    profile = session.profile

    print(f"{profile.name}  ->  {profile.base_url}")
    print("\npersona:")
    print(profile.persona.describe())
    # Header names, never values: this is a credential on a shared terminal.
    print(f"\nreplaying {len(session.headers)} headers: "
          f"{', '.join(sorted(session.headers))}")
    print("\nfrom Python:\n")
    print("    from mimic import Session\n"
          "    from mimic.vault import Vault\n\n"
          f"    s = Session.from_profile({args.name!r}, Vault())\n"
          "    s.get('/…')")


def cmd_run(args):
    """Execute a recipe — endpoints, pacing and profile, with no code written."""
    try:
        recipe = recipes.Recipe.from_file(args.recipe)
    except (OSError, ValueError, MimicError) as exc:
        sys.exit(f"{args.recipe}: {exc}")

    _, flows = _flows_for(args)
    eps = endpoints(flows, recipe.host)
    if not eps:
        sys.exit(f"no requests to {recipe.host} found — capture them first")

    limiter = None
    if recipe.rate and not args.no_pacing:
        limiter = HostLimiter(rate=recipe.rate)
    run = _die_if_unusable(recipe.run, eps, limiter=limiter)

    print(run)
    for task, error in run.failed:
        print(f"  failed  {task.id}: {type(error).__name__}: {error}")
    for task in run.pending:
        print(f"  pending {task.id}: {task.method} {task.path}")
    sys.exit(0 if run.ok else 1)


def _default_out(host):
    stem = re.sub(r"[^a-z0-9]+", "_", host.split(".")[0].lower()).strip("_")
    return f"{stem or 'app'}_client.py"


def _class_name(source):
    m = re.search(r"class\s+(\w+)\s*\(", source)
    return m.group(1) if m else None


def main(argv=None):
    p = argparse.ArgumentParser(prog="mimic", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("record", help="start the proxy + iPhone setup steps").set_defaults(func=cmd_record)
    sub.add_parser("doctor", help="check your setup").set_defaults(func=cmd_doctor)
    hp = sub.add_parser("hosts", help="list captured hosts")
    hp.add_argument("--har", metavar="FILE", help="read from a HAR file instead of mitmweb")
    hp.set_defaults(func=cmd_hosts)

    lp = sub.add_parser("learn", help="show endpoints for a host")
    lp.add_argument("host")
    lp.add_argument("--har", metavar="FILE", help="read from a HAR file instead of mitmweb")
    lp.set_defaults(func=cmd_learn)

    gp = sub.add_parser("gen", help="AI-generate a client for a host")
    gp.add_argument("host")
    gp.add_argument("-o", "--out", help="output .py path")
    gp.add_argument("--model", default="sonnet", help="model name (claude default: sonnet)")
    gp.add_argument("--generator", default="claude",
                    choices=sorted(codegen.BACKENDS) + ["deterministic"],
                    help="claude/opencode/agy call an AI; 'deterministic' infers "
                         "the client from the capture with no AI at all")
    gp.add_argument("--prompt-only", action="store_true", help="print the prompt instead of calling the AI generator")
    gp.add_argument("--har", metavar="FILE", help="read from a HAR file instead of mitmweb")
    gp.set_defaults(func=cmd_gen)

    up = sub.add_parser("unpin", help="defeat cert pinning so capture works")
    up.add_argument("target", help="an iOS bundle-id / .ipa, an Android package, or an APK")
    up.add_argument("--android", action="store_true",
                    help="target is an Android package; hook it and report each "
                         "pinning mechanism patched")
    up.add_argument("--flutter", action="store_true",
                    help="target is an Android APK; repack its libflutter.so and "
                         "report which ABIs were patched")
    up.add_argument("--ca", help="mitmproxy CA cert (default: ~/.mitmproxy/mitmproxy-ca-cert.pem)")
    up.add_argument("--proxy-host", help="proxy host to bake in (default: this Mac's LAN IP)")
    up.add_argument("--workdir", help="where to put scripts + patched IPA (default: mimic-unpin/)")
    up.add_argument("--codesign", help="signing identity for `objection patchipa`")
    up.set_defaults(func=cmd_unpin)

    rp = sub.add_parser("run", help="execute a recipe (no code required)")
    rp.add_argument("recipe", help="path to a recipe .json file")
    rp.add_argument("--har", metavar="FILE", help="read from a HAR file instead of mitmweb")
    rp.add_argument("--no-pacing", action="store_true",
                    help="ignore the recipe's rate limit")
    rp.set_defaults(func=cmd_run)

    pp = sub.add_parser("profile", help="save/list/load an encrypted profile")
    psub = pp.add_subparsers(dest="subcmd", required=True)

    sp = psub.add_parser("save", help="save the captured identity to the vault")
    sp.add_argument("name", help="profile name (letters, digits, '-', '_', '.')")
    sp.add_argument("--host", required=True, help="the API host to profile")
    sp.add_argument("--har", metavar="FILE", help="read from a HAR file instead of mitmweb")
    sp.set_defaults(func=cmd_profile_save)

    lp2 = psub.add_parser("list", help="list saved profiles")
    lp2.set_defaults(func=cmd_profile_list)

    dp = psub.add_parser("load", help="open a saved profile into a Session")
    dp.add_argument("name")
    dp.set_defaults(func=cmd_profile_load)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
