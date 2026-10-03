# Certificate pinning

mimic captures traffic through a proxy (mitmproxy). A pinned app rejects the
proxy's cert, so the proxy sees nothing and there's nothing to capture. This
page covers getting past that.

## What pinning does

Normal TLS authenticates the server to the client: the app checks that the
server's cert is signed by a trusted CA. To MITM it, you add your own CA to the
device trust store and the proxy presents a cert signed by that CA. Pinning
hardcodes the exact cert (or public-key hash) the app will accept, so a proxy
cert signed by any other CA, including one you control, gets rejected.

So two things are true:

Pinning stops capture, not replay. It only makes traffic hard to observe. Once
you can see a request, the auth bundle in it replays the same as it would for an
unpinned app. Pinning adds no replay resistance; that's what DPoP is for (see
[dpop.md](dpop.md)).

You can't beat it by handing the app a cert. The pinned value is a public cert,
and presenting it in a handshake needs the matching private key, which sits on
the server. The fix is on the app side: stop the app from checking, by hooking
its TLS verification at runtime with [Frida](https://frida.re).

mimic doesn't reimplement those hooks; they change across OS versions and TLS
stacks. `mimic unpin` drives the upstream that maintains them,
[httptoolkit/frida-interception-and-unpinning][ht], and handles the mimic-specific
part: baking your mitmproxy CA and proxy address into the scripts, and on
Android **reporting which pinning mechanism actually got patched**.

That last part is not decoration. The upstream hooks are quiet by design: the
Android unpinning script prints `== Certificate unpinning completed ==` whether
it replaced one method or thirty, and a class that isn't in the app is skipped
without a word. A hook that failed to load, a hook that loaded and didn't take,
and an app with no pinning at all are the same output — and all three look like
success right up until `mimic hosts` shows an empty capture with nothing to
explain it. So on Android mimic reads the running process back after the session
and prints a verdict per mechanism instead of an exit code.

## Prerequisites

```bash
mimic doctor        # see the "optional — only for mimic unpin" section
```

- git, to fetch the unpinning scripts.
- frida, to run the hooks (`pipx install frida-tools`).
- objection, for the no-jailbreak iOS path only (`pipx install objection`).
- adb, for Android only — found on `PATH` or under `$ANDROID_HOME/platform-tools`
  (or `$ANDROID_SDK_ROOT`), which is where it lands if you installed the SDK and
  never edited your shell.
- reflutter, for Flutter APKs only (`pip3 install reflutter`).
- A mitmproxy CA at `~/.mitmproxy/mitmproxy-ca-cert.pem`. Running `mimic record`
  once generates it. Not needed for `--flutter`; reFlutter compiles the bypass
  into the engine rather than reading a CA from anywhere.

Anything missing is named with the command that installs it. `mimic unpin`
refuses to skip past it — a run that quietly did nothing leaves you with a
pinned app and an empty capture, which is the exact state this page exists to
get you out of.

## Path A: jailbroken device

The phone runs `frida-server` and you attach over USB. No repackaging, no
signing.

```bash
mimic record                       # one terminal — starts the proxy
mimic unpin com.example.app        # bundle id → prints a frida command
```

`unpin` fetches the scripts, bakes in your CA and this Mac's LAN IP:8080, and
prints:

```bash
frida -U \
    -l mimic-unpin/frida-scripts/config.js \
    -l mimic-unpin/frida-scripts/ios/ios-connect-hook.js \
    -l mimic-unpin/frida-scripts/ios/ios-disable-detection.js \
    -l mimic-unpin/frida-scripts/native-tls-hook.js \
    -l mimic-unpin/frida-scripts/native-connect-hook.js \
    -f com.example.app
```

Run it, use the app, then `mimic hosts` and `mimic gen <host>` as usual.

## Path B: stock device (Frida gadget)

No jailbreak. You inject the Frida gadget into a decrypted IPA, re-sign, and
sideload.

```bash
mimic unpin ./MyApp.ipa --codesign <TEAM_ID>
```

`unpin` bakes the config, runs `objection patchipa` to inject the gadget, and
writes `mimic-unpin/MyApp-patched.ipa`. It stops there and prints the signing
and install step, since that's what tools like Sideloadly handle:

- drag the patched IPA into [Sideloadly](https://sideloadly.io), or
- `pymobiledevice3 apps install mimic-unpin/MyApp-patched.ipa`

Then attach the scripts to the gadget (`unpin` prints the `frida -U` command) and
capture as usual.

### The catches

- You need a decrypted IPA. Your own app build is fine. An App Store app is
  FairPlay-encrypted, and decrypting it takes a jailbroken device once (or a
  pre-decrypted IPA). "No jailbreak" often means "no jailbreak, if someone
  already decrypted it."
- Free Apple certs expire after 7 days.
  [TrollStore](https://github.com/opa334/TrollStore) (iOS 17.0.x and below)
  installs with real entitlements permanently and skips the weekly re-sign.
- Apps with binary-integrity checks detect the re-signed bundle and refuse to
  run.

## Path C: Android

```bash
mimic record                    # one terminal — starts the proxy
mimic unpin --android com.example.app
```

Plug the phone in over USB with USB debugging on. `unpin` fetches the upstream
`android/` hooks, bakes in your CA and this Mac's LAN IP, spawns the app with
`frida --no-pause`, and reads back what happened. Use the app while it runs.

Android pins in two unrelated ways, so mimic names both and reports each one
separately rather than answering yes/no:

- **OkHttp `CertificatePinner`** — the default choice in anything built on
  OkHttp. The class lives in one of three packages (`okhttp3`,
  `com.squareup.okhttp`, and the `com.android.okhttp` copy vendored into the
  platform), and all three count as the right one.
- **`network_security_config` trust anchors** — the `<pin-set>` declarations the
  platform loads through `NetworkSecurityConfig`.

```
pinning targets for com.example.app:
  [+] OkHttp CertificatePinner: patched
      OkHttp CertificatePinner ran and was forced through
      library: okhttp3.CertificatePinner
  [ ] network_security_config trust anchors: absent
      network_security_config is not in this app — nothing to patch

patched: OkHttp CertificatePinner.
nothing to patch: network_security_config trust anchors.
```

Reading that report:

- **`patched`** is a confirmation, not a load. The probe calls the patched entry
  point with input it should have rejected — a `CertificatePinner.check` for a
  hostname the app cannot be pinned for, an empty trust-manager set pushed
  through `SSLContext.init`. If the call still throws, the hook didn't take and
  the target is `failed`, not `patched`.
- **`absent` / `unused` are "nothing to patch"**, never a success. An app with
  neither mechanism is reported as such in those words. A mechanism that's
  present but never ran during the session is `unused`, because "is it forced"
  isn't a question you can ask about code that never executed.
- **`failed` means treat the app as still pinned.** The report says which: the
  wrong process, the wrong class, a hook that loaded and didn't take, or a probe
  that never reported. Anything left unconfirmed is printed that way on purpose.

### The catches

- The phone must be reachable by `frida` over USB, and USB debugging on. A
  device with only wireless debugging works; `frida -D<id>` picks the device if
  more than one is attached.
- The report covers what mimic asked about. An app pinning through a framework
  neither target covers is not "unpinned" — it's outside the two mechanisms, and
  the report says so rather than declaring victory.
- Apps with root-detection or integrity checks may refuse to run while hooked.

## Path D: Flutter APKs

Flutter is a different problem, for a structural reason rather than a gap in
coverage: the Dart engine ships its own BoringSSL and does its own certificate
validation. It never calls the Java trust managers, so a Flutter app can be
completely unpinned at the Java layer and still reject mitmproxy's CA. No
Java-side hook reaches it, which is why this path repacks rather than hooks.

```bash
mimic unpin --flutter ./MyApp.apk
```

`unpin` runs [reFlutter](https://github.com/Impact-I/reFlutter), which unpacks
the APK and swaps in a prebuilt engine whose verification always succeeds,
writing `MyApp.RE.apk` beside the input.

```
Flutter engine patching for MyApp.apk:
  [+] arm64-v8a: patched
  [!] armeabi-v7a: NOT patched — no libflutter.so for this ABI in the output

PARTIAL: 1 of 2 ABIs patched. The app will still reject mitmproxy's CA on armeabi-v7a.
```

**ABIs are separate artifacts and mimic reports them as such.** An APK ships one
`libflutter.so` per architecture it supports, and reFlutter patches per-ISA —
which is why a result can come back short. mimic doesn't infer this from
reFlutter's log line; it reads the ABI list out of the APK you handed in and out
of the APK that came back, both of which are just zips the standard library can
open. An ABI that went in and didn't come out is reported unpatched, and the
whole run as `PARTIAL`. Architectures reFlutter has no prebuilt engine for
(`riscv64`) aren't counted at all, so the denominator is one you can actually
reach.

An APK with no `libflutter.so` is reported as "nothing to patch" and left alone,
without needing reFlutter installed.

### The catches

- **Install the repacked APK, not the original.** The original still pins. A
  repacked APK has to be re-signed before it will install; reFlutter says so if
  it hasn't been.
- reFlutter matches the engine against a table of known Flutter releases. An app
  on a snapshot it doesn't recognise aborts without writing anything — mimic
  reports that as an error with reFlutter's own message (including the snapshot
  hash it found) rather than reporting a failed patch.
- x64 assets need Flutter 3.41 or newer on the target.

## Framework notes

- React Native uses `NSURLSession` / `OkHttp` and honors the system proxy. The
  standard hooks work on both platforms.
- Flutter (above) ignores the system proxy and does its own TLS, so `SecTrustEvaluate`
  and the Java trust-manager hooks never fire and a device proxy captures
  nothing. It needs the engine repacked.
- If a partial Flutter result is more of a problem than the capture is worth,
  `--android` can load upstream's runtime Flutter hook alongside the Java ones —
  but it only resolves against engines that still carry a symbol table, which
  means debug and profile builds and Shorebird, not a stock release APK.

## What still won't work

- DPoP / sender-constrained tokens. Each request is signed per request, so a
  captured one doesn't replay. Unlike pinning, mimic can do this one — but a
  server-forced nonce costs a round trip, and a Secure Enclave key needs the app
  running on a tethered device to sign. See [dpop.md](dpop.md).
- Hardware attestation (App Attest, DeviceCheck). Out of scope.

[ht]: https://github.com/httptoolkit/frida-interception-and-unpinning
