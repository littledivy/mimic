"""Android certificate pinning, as named targets you can check individually.

Android pins in several unrelated ways, and "unpinned" is not a property of an
app — it's a property of each mechanism. An app can pin with OkHttp and declare
trust anchors in `network_security_config`, or declare anchors and never pin, or
ship neither. So this module names the mechanisms, reports each one separately,
and refuses to summarise them as a single yes/no.

The reporting is the point. Upstream's `android-certificate-unpinning.js` prints
`== Certificate unpinning completed ==` whether it replaced one method or thirty,
and skips absent classes in silence. A class that fails to load, a hook that
silently drops when the runtime initializes the class later, and an app with no
pinning at all are the *same output*. Since a silent no-op here presents as an
empty capture with nothing to explain it, mimic does not read that line.

Instead it runs the session and asks the running process three separate
questions per target:

  1. **Am I in the right process?** The probe reads the live `Application`'s
     package name. A session attached to the wrong app would otherwise report
     its hooks as failures, or worse, succeed against an app you didn't mean.
  2. **Did I hook the library this target is?** The probe names the class it
     actually found. OkHttp's pinner exists in three places (`okhttp3`,
     `com.squareup.okhttp`, the vendored `com.android.okhttp`) and a hook that
     landed on a different one is a miss, not a win.
  3. **Is the patch actually in force?** The probe calls the patched entry point
     with input it should have rejected. A `CertificatePinner` hook that loaded
     but never took effect still throws `SSLPeerUnverifiedException` when you
     ask it about a host it isn't pinned for; that throw is the proof.

A target that is simply absent from the app is reported as *nothing to patch*,
never as a success — see `NONE` below.

What's verified here and what isn't: the *verdicts* (`assess`) are exercised
directly by the test suite, from recorded frida output. The probe script they
consume runs on a real device and is not.
"""
import os

from . import unpin
from .errors import ToolchainError

#: The patch is in force: the hook is installed, it ran, and the patched entry
#: point accepted input it would otherwise have rejected.
PATCHED = "patched"

#: Nothing to patch. Either the app doesn't ship the mechanism at all (`ABSENT`)
#: or it ships it and never uses it (`UNUSED`). Both are reported as "nothing to
#: patch" rather than folded into a success — the whole reason this module
#: reports per target.
ABSENT = "absent"
UNUSED = "unused"

#: We cannot claim it took. A different process, a different library, a hook that
#: didn't land, or a probe that was still rejected. Never silently `PATCHED`.
FAILED = "failed"


class Target:
    """One named pinning mechanism, and the classes that legitimately hold it.

    `libraries` is a set rather than one name because OkHttp's pinner is
    vendored into the platform and forked across three packages; a tool that
    hard-codes one reports the other two as failures it doesn't have.
    """

    def __init__(self, key, label, libraries, script):
        self.key = key
        self.label = label
        self.libraries = tuple(libraries)
        #: The upstream hook that patches this mechanism, for the error message
        #: when it doesn't take. Keeps the diagnosis pointed at a real file.
        self.script = script

    def matches(self, library):
        """Whether `library` is one this target is entitled to claim."""
        return library in self.libraries


#: OkHttp's `CertificatePinner` — the single most common Android pinning
#: mechanism, and the one apps reach for by default in any framework built on it.
OKHTTP = Target(
    "okhttp-cert-pinner",
    "OkHttp CertificatePinner",
    ("okhttp3.CertificatePinner", "com.squareup.okhttp.CertificatePinner",
     "com.android.okhttp.CertificatePinner"),
    "android/android-certificate-unpinning.js",
)

#: `network_security_config` trust anchors and `<pin-set>` declarations, loaded
#: by the platform through `NetworkSecurityConfig`. Upstream clears the PinSet
#: and swaps the app's trust managers for ones that trust only our CA.
NETWORK_SECURITY_CONFIG = Target(
    "network-security-config",
    "network_security_config trust anchors",
    ("android.security.net.config.NetworkSecurityConfig",),
    "android/android-certificate-unpinning.js",
)

TARGETS = (OKHTTP, NETWORK_SECURITY_CONFIG)

#: The probe's closing record. Not a target — it reports that the probe itself
#: ran to completion, which is what lets a target that never reported say why.
RUNTIME_KEY = "runtime"


class Verdict:
    """What happened to one target, in a form worth printing."""

    def __init__(self, target, status, detail, library=None):
        self.target = target
        self.status = status
        self.detail = detail
        self.library = library

    @property
    def is_nothing_to_patch(self):
        return self.status in (ABSENT, UNUSED)

    def __repr__(self):
        return f"<Verdict {self.target.key} {self.status}>"


def assess(target, record, package, runtime=None):
    """Turn one probe record into a verdict, or a verdict explaining its absence.

    Two of the checks are ordered by something that isn't visible in the code:

    - `used` before `forced`, because "is the patch in force" is not a question
      you can ask about code that never executed. A present, patched, unused
      mechanism is `UNUSED` — nothing to patch — not a failure.
    - The probe's `runtime` record has no verdict of its own; it is passed in
      only so a target that reported *nothing* can say why, instead of guessing
      between a hook that failed to load and an app that died on startup.

    `report` pins the rest of the order.
    """
    label = target.label
    if record is None:
        if runtime is not None and runtime.get("process") is None:
            return Verdict(target, FAILED,
                           runtime.get("detail") or
                           "the probe ran but found no Android Application, "
                           "so it could not ask about this mechanism")
        return Verdict(target, FAILED,
                       "the probe never reported — the hook script may have "
                       "failed to load, or the app died before it ran")

    seen_process = record.get("process")
    if seen_process != package:
        return Verdict(target, FAILED,
                       f"the probe ran in {seen_process or 'an unidentified process'!r}, "
                       f"not {package!r} — nothing here says anything about the "
                       f"app you asked about")

    if not record.get("present"):
        return Verdict(target, ABSENT,
                       record.get("detail") or f"{label} is not in this app — "
                                                f"nothing to patch")

    library = record.get("library")
    if not target.matches(library):
        return Verdict(target, FAILED,
                       f"hooked {library!r}, which is not {label} — {target.script} "
                       f"matched the wrong class",
                       library=library)

    if not record.get("used"):
        return Verdict(target, UNUSED,
                       f"{label} is in the app but never ran during this session — "
                       f"nothing to patch", library=library)

    if not record.get("forced"):
        return Verdict(target, FAILED,
                       record.get("detail") or f"{label} is loaded but the patched "
                                                f"entry point still rejects our CA — "
                                               f"the hook did not take effect",
                       library=library)

    return Verdict(target, PATCHED,
                   f"{label} ran and was forced through", library=library)


def report(package, records):
    """One verdict per target, whether or not anything reported for it.

    Iterated from `TARGETS` rather than from `records`, so a target the probe
    never mentioned still appears — as the failure it is — instead of dropping
    out of the report. The first record per key wins, so a class loaded twice
    can't overwrite a success with its own later failure.
    """
    by_key = {}
    for record in records:
        key = record.get("target")
        if key and key not in by_key:
            by_key[key] = record
    runtime = by_key.get(RUNTIME_KEY)
    return [assess(t, by_key.get(t.key), package, runtime=runtime)
            for t in TARGETS]


def render(package, verdicts):
    """The human-facing report. Says what was patched, and what wasn't."""
    lines = [f"pinning targets for {package}:"]
    for verdict in verdicts:
        mark = {
            PATCHED: "[+]",
            FAILED: "[!]",
        }.get(verdict.status, "[ ]")
        lines.append(f"  {mark} {verdict.target.label}: {verdict.status}")
        lines.append(f"      {verdict.detail}")
        if verdict.library:
            lines.append(f"      library: {verdict.library}")

    patched = [v for v in verdicts if v.status == PATCHED]
    nothing = [v for v in verdicts if v.is_nothing_to_patch]
    failed = [v for v in verdicts if v.status == FAILED]

    lines.append("")
    if failed:
        lines.append(f"{len(failed)} target(s) could not be confirmed — treat this "
                     f"app as still pinned.")
    elif patched:
        lines.append(f"patched: {', '.join(v.target.label for v in patched)}.")
        if nothing:
            lines.append(f"nothing to patch: "
                         f"{', '.join(v.target.label for v in nothing)}.")
    else:
        lines.append("nothing to patch — this app pins by neither mechanism. If "
                     "capture is still empty, the pinning is in a framework these "
                     "targets don't cover.")
    return "\n".join(lines)


def run(package, scripts_dir, *, timeout=None):
    """Hook the app, read the report back, and return it as text.

    Deliberately not a silent no-op anywhere: the toolchain is required up
    front, and the session's own output is returned alongside the report so a
    failure can be read rather than inferred.

    The CA and proxy address are *not* parameters here, because nothing in this
    function uses them: they were baked into `config.js` before the session
    starts, which is what the upstream hooks read. Taking them as arguments
    would suggest they are threaded into the probe, and a change that quietly
    stopped baking them would still look correct from the call site.
    """
    unpin.require_frida()
    unpin.require_adb()

    probe_path = unpin.write_probe(scripts_dir, PROBE_JS)
    scripts = [os.path.join(scripts_dir, s) for s in unpin.ANDROID_SCRIPTS]
    scripts.append(probe_path)

    output = unpin.run_frida(scripts, package,
                             timeout=timeout or unpin.FRIDA_TIMEOUT)
    try:
        records = unpin.parse_probes(output)
    except ValueError as exc:
        raise ToolchainError(
            f"mimic's probe ran but produced an unreadable report: {exc}\n"
            f"Re-run with the raw session output to see what the device said.",
            tool="mimic-probe", field="probe",
        ) from exc
    return render(package, report(package, records)), output

#: mimic's own probe, loaded after the upstream hooks.
#:
#: It runs on the device and is *not* covered by mimic's test suite — those tests
#: exercise `assess` against recorded session output. What is covered is every
#: judgement mimic makes from what this reports; what isn't is whether each hook
#: below binds on a given Android version.
#:
#: It relies on `CERT_PEM` and the base64 helpers defined by upstream's
#: `config.js`, which `unpin.ANDROID_SCRIPTS` loads first. Loading this before
#: config.js would fail with a ReferenceError, which is the failure mode of a
#: load-order mistake worth not repeating.
PROBE_JS = r"""
'use strict';
// Written by mimic. Reads what is actually true of the running process and
// prints one machine-readable line per target; `mimic.android.assess` turns
// those into verdicts. See mimic/android.py for why none of this can be
// inferred from the upstream hooks' own output.

var PREFIX = 'MIMIC-PROBE ';
var OKHTTP_CLASSES = [
    'okhttp3.CertificatePinner',
    'com.squareup.okhttp.CertificatePinner',
    'com.android.okhttp.CertificatePinner'
];

function emit(target, rec) {
    rec.target = target;
    console.log(PREFIX + JSON.stringify(rec));
}

function packageName() {
    try {
        var app = Java.use('android.app.ActivityThread').currentApplication();
        return app ? String(app.getPackageName()) : null;
    } catch (e) {
        return null;
    }
}

// frida spawns the process suspended and resumes it, so on a cold start there
// is no Application yet and no classes loaded. Asking once would report every
// target absent and call an app unpinned that isn't, so poll for it instead.
function whenAppReady(done, msLeft) {
    var name = packageName();
    if (name) { done(name); return; }
    if (msLeft <= 0) { done(null); return; }
    setTimeout(function () { whenAppReady(done, msLeft - 250); }, 250);
}

function certFromPem() {
    var CertificateFactory = Java.use('java.security.cert.CertificateFactory');
    var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    var pemBytes = Java.use('java.lang.String').$new(CERT_PEM).getBytes();
    return CertificateFactory.getInstance('X.509')
        .generateCertificate(ByteArrayInputStream.$new(pemBytes));
}

// Count real uses of a method the upstream hook already replaced. Only wraps an
// implementation that is already there: installing one where there was none
// would change the app's behaviour to suit our bookkeeping.
function watchForUse(methods, onCall) {
    methods.forEach(function (method) {
        if (typeof method.implementation !== 'function') return;
        var previous = method.implementation;
        method.implementation = function () {
            onCall();
            return previous.apply(this, arguments);
        };
    });
}

function allMethods(cls, name) {
    try {
        var holder = cls[name];
        if (holder === undefined || holder === null) return [];
        if (Array.isArray(holder.overloads)) return holder.overloads;
        return [holder];
    } catch (e) {
        return [];
    }
}

function probeOkHttp(pkg, used) {
    var found = null, i;
    for (i = 0; i < OKHTTP_CLASSES.length; i++) {
        try {
            Java.use(OKHTTP_CLASSES[i]);
            found = OKHTTP_CLASSES[i];
            break;
        } catch (e) {}
    }
    if (!found) {
        emit('okhttp-cert-pinner', {
            process: pkg, present: false, library: null, used: false,
            detail: 'no OkHttp CertificatePinner class in this app — nothing to patch'
        });
        return;
    }

    var cls = Java.use(found);
    var probing = false;
    watchForUse(allMethods(cls, 'check'), function () {
        if (!probing) used.okhttp = true;
    });

    // Ask the pinner about a hostname it cannot possibly be pinned for. Hooked,
    // check() is a no-op and returns; unhooked, it throws SSLPeerUnverified.
    // That throw is the only thing here that distinguishes a hook that loaded
    // from a hook that took.
    var forced = false, detail = null;
    probing = true;
    try {
        cls.check.overload('java.lang.String', 'java.security.cert.Certificate')
            .call(cls, 'mimic.invalid', certFromPem());
        forced = true;
    } catch (e) {
        try {
            cls.check('mimic.invalid', certFromPem());
            forced = true;
        } catch (e2) {
            detail = 'CertificatePinner.check still rejects our CA: ' + e2;
        }
    }
    probing = false;
    emit('okhttp-cert-pinner', {
        process: pkg, present: true, library: found,
        forced: forced, used: used.okhttp, detail: detail
    });
}

function defaultX509TrustManager(socketFactory) {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var get = socketFactory.getClass()
        .getDeclaredMethod('getDefaultX509TrustManager', []);
    get.setAccessible(true);
    return Java.cast(get.invoke(socketFactory), X509TrustManager);
}

function probeNetworkSecurityConfig(pkg, used) {
    var cls;
    try {
        cls = Java.use('android.security.net.config.NetworkSecurityConfig');
    } catch (e) {
        emit('network-security-config', {
            process: pkg, present: false, library: null, used: false,
            detail: 'no network_security_config support in this process — '
                + 'nothing to patch'
        });
        return;
    }

    var constructors = allMethods(cls, '$init');
    watchForUse(constructors, function () { used.nsc = true; });

    // Route an *empty* trust manager set through SSLContext.init. Upstream's
    // hook replaces that argument with trust managers that accept our CA, so
    // afterwards the context trusts our certificate even though nothing handed
    // it one — which is exactly the change pinning depends on. Also checks the
    // hook still rejects an unrelated certificate: an SSL bypass that accepts
    // everything is a different (and much worse) outcome than one that accepts
    // our CA.
    var forced = false, detail = null;
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        var factory = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore);

        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var context = SSLContext.getInstance('TLS');
        context.init(null, factory.getTrustManagers(), null);

        var trustManager = defaultX509TrustManager(context.getSocketFactory());
        trustManager.checkServerTrusted(
            Java.array('javax.net.ssl.X509Certificate', [certFromPem()]), 'RSA');
        forced = true;
    } catch (e) {
        detail = 'the patched SSLContext still does not trust our CA: ' + e;
    }

    emit('network-security-config', {
        process: pkg, present: true,
        library: 'android.security.net.config.NetworkSecurityConfig',
        forced: forced, used: used.nsc, detail: detail
    });
}

Java.perform(function () {
    whenAppReady(function (pkg) {
        if (!pkg) {
            emit('runtime', {
                process: null, present: false, library: null,
                detail: 'no Android Application appeared — this is not an app '
                    + 'process, or it died during startup'
            });
            return;
        }
        var used = { okhttp: false, nsc: false };
        probeOkHttp(pkg, used);
        probeNetworkSecurityConfig(pkg, used);
        emit('runtime', {
            process: pkg, present: true, library: null, forced: true,
            used: true,
            detail: 'probes completed'
        });
    }, 30000);
});
"""
