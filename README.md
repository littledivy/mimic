# mimic

Intercept any app, then call it from Python like a library.

```python
from hinge_client import Hinge

acc = Hinge()                 # reuses your captured session
recs = acc.get_recommendations()
acc.like(subject_id, comment="hi lol")
```

You don't write `hinge_client.py`. mimic captures your own app traffic and an AI
generates the client from it.

## How it works

Most apps authenticate every request with the same bundle of values: a bearer
token, some device ids, a session id, cookies. They're stable across calls.
Capture them once from a real request you made, and you can replay them on new
requests to the same API.

```
capture traffic   ->   extract auth   ->   generate client
  (mitmproxy)         (mimic.Session)      (claude reads the
                                            captured endpoints)
```

The generated client is plain Python on top of `mimic.App`, and you edit it like
any other file. It gives you named methods, body templates, and the multi-step
call chaining mobile APIs tend to need (fetch a token in one call, spend it in
the next).

## Install

```bash
sh install.sh
```

Installs [`uv`](https://astral.sh/uv) if you don't have it, then mimic in an
isolated tool env. It pulls mitmproxy and cryptography, because `mimic learn`,
`mimic gen` and `mimic profile save` can't run without them. (Manual:
`uv tool install 'mimic-client[capture,vault]'` — without those extras mimic
stops working after `mimic hosts`.)

```bash
mimic doctor                    # checks exactly the things the next command needs
```

## Use it (iPhone)

```bash
mimic record                    # starts the proxy, prints the iPhone steps
```

`record` fills in your Mac's LAN IP and walks you through it:

1. iPhone -> Wi-Fi -> Configure Proxy -> Manual -> `<your-mac-ip>:8080`
2. Safari -> `http://mitm.it` -> install the Apple profile
3. Settings -> General -> About -> Certificate Trust Settings -> turn on full
   trust for mitmproxy. This step is easy to miss and nothing works without it.
4. open the app, use it normally

Then:

```bash
mimic hosts                     # list captured hosts; pick your API host
mimic learn  prod-api.hingeaws.net    # see the endpoints mimic saw
mimic gen    prod-api.hingeaws.net    # generate hinge_client.py
```

Then `from hinge_client import Hinge; Hinge().get_recommendations()`.

### GraphQL apps

Every operation in a GraphQL app goes to one URL, so mimic reads the operation
out of the request body and keys endpoints by it — the whole API stays
distinguishable instead of collapsing into one entry:

```
$ mimic learn api.example.com
api.example.com: 2 endpoints

  POST  /graphql [query: GetFeed]        -> 200
        variables: first
  POST  /graphql [mutation: SendMessage] -> 200
        variables: body, to
```

Those variables become the method's arguments in the generated client.

### Pinned apps (iOS, Android, Flutter)

A pinned app rejects the proxy's cert, so `mimic hosts` shows nothing. That
blocks capture, not replay — get past the pin and everything above works the
same. `mimic unpin` sets it up:

```bash
mimic unpin com.example.app              # iOS, jailbroken: prints the frida command
mimic unpin ./MyApp.ipa --codesign TEAM  # iOS, stock: injects the gadget
mimic unpin --android com.example.app    # Android: hooks and reports per mechanism
mimic unpin --flutter ./MyApp.apk        # Flutter: repacks libflutter.so
```

On Android it doesn't print a command and walk away — it runs the session and
tells you what it actually changed, one named mechanism at a time:

```
pinning targets for com.example.app:
  [+] OkHttp CertificatePinner: patched
      library: okhttp3.CertificatePinner
  [ ] network_security_config trust anchors: absent
      network_security_config is not in this app — nothing to patch

patched: OkHttp CertificatePinner.
nothing to patch: network_security_config trust anchors.
```

`patched` there means the hook was *confirmed in force on the running process*,
not that a script loaded. An app with no pinning says "nothing to patch" in
those words rather than reporting success, and anything unconfirmed is printed
as still pinned. Flutter takes the repack route because the Dart engine does its
own TLS and no Java hook reaches it — and a partial result is reported as
partial, naming which ABIs didn't come back.

Missing tooling is named with the command that installs it. `unpin` won't skip
past an absent `frida`, `adb` or `reflutter`: a run that quietly did nothing
leaves you exactly where you started, with an empty capture and nothing to
explain it. Full detail in [docs/pinning.md](docs/pinning.md).

## The library

Three ways to build a session by hand, if you don't want codegen:

```python
from mimic import Session

Session.from_mitm("prod-api.hingeaws.net")        # pull auth from mitmweb
Session.from_curl(open("copied.txt").read())      # paste "Copy as cURL" from devtools
Session(base_url="https://x.com", headers={...})  # explicit
```

`.get(path)`, `.post(path, json=...)`, and the other common HTTP verb helpers
return parsed JSON and raise `requests.HTTPError` for failed responses. If your
token rotates, a `401` on an idempotent request triggers one re-pull from
mitmweb and a retry. Non-idempotent requests are not retried unless you explicitly
pass `refresh=True`.

### Keeping a replay alive

A captured session dies in specific, fixable ways, and mimic handles each one
rather than letting it show up as an unexplained failure:

- **Cookies rotate.** A server that reissues its session cookie sends the new
  one in `Set-Cookie`. mimic parses your captured `Cookie` header into a live
  cookie jar and drops the header, so rotation propagates instead of being
  recorded and silently never sent.
- **Nothing hangs.** Every request has a `(5, 30)` connect/read timeout, and a
  `429`/`5xx`/connection failure is retried with exponential backoff and
  jitter, honoring `Retry-After`. Retries default to idempotent methods only —
  pass `retry=True` to opt a `POST` in, `retry=False` to opt out.
- **Per-request headers aren't replayed.** A captured `x-csrf-token`,
  `x-timestamp`, `x-nonce` or `x-signature` is valid for exactly one request.
  mimic drops them at capture time rather than resending a value the server has
  already seen, and a `403` on such an endpoint raises `SignatureError` naming
  the header instead of blaming your session.

Tune it per session:

```python
Session(url, headers, timeout=(3, 15), attempts=5, backoff=0.5, max_sleep=30)
```

### Errors

Failures stay `requests.HTTPError` subclasses, so existing `except` clauses keep
working. Catch `MimicError` to tell the cases apart:

| Error | Means |
|---|---|
| `AuthError` | `401`, and re-pulling from mitmweb didn't help — re-capture |
| `SignatureError` | `403` on an endpoint that signs its own requests; `.headers` names them |
| `DpopError` | a DPoP proof couldn't be produced — no key, a dead device, a bad clock |
| `RateLimitError` | `429` that outlived the retry budget; `.retry_after` |
| `SchemaDriftError` | the response no longer matches what the client was generated against; `.diff` |
| `PinBlocked` | capture-side: the app rejected the proxy's certificate |

```python
from mimic import RateLimitError, Session

s = Session(url, headers, attempts=5)
try:
    s.get("/recs")
except RateLimitError as e:
    time.sleep(e.retry_after or 60)
```

### Catching the app changing under you

mimic records the shape of each captured response — every field path and its
type — so a live response that has lost a field fails loudly, naming it, instead
of turning into a `KeyError` in your code or a silently empty value:

```python
from mimic import SchemaDriftError, Session
from mimic.sources import shapes

s = Session(url, headers, shapes=shapes(capture, "api.example.com"))
s.get("/users")
# SchemaDriftError: GET /users no longer matches the response it was
# generated against: $.data[].displayName was string, now absent
```

A field *appearing* is a compatible change and is left alone. Pass `raw=True` to
a call to skip the check and get the body back verbatim.

`shapes(capture, host)` works the same on both backends:

```python
from mimic.sources import har, mitm

m = mitm.default()
shapes(m.capture(), "api.example.com")        # one bulk read, bodies included
shapes(har.load("traffic.har"), "api.example.com")
```

### Transports

Requests go through a swappable transport. The default is plain `requests`,
chosen for being legible — point a proxy at it, read the traceback, see exactly
what went out.

```python
Session(url, headers, transport="requests")   # default, no extra needed
```

Session owns all the policy (retry, refresh, cookies, parsing, error mapping)
and a transport owns exactly one round trip, so switching transports changes
the fingerprint and nothing else. Every failed response is a
`requests.HTTPError` either way.

### Fingerprints

A replayed request carries the right credentials but, by default, handshakes
like `requests` — which servers that fingerprint clients can tell apart.
mimic measures the target's fingerprint from a capture and can replay it:

```python
from mimic.fingerprint import from_client_hello   # mitmproxy.tls.ClientHello
from mimic.transport.curl_transport import CurlTransport

fp = from_client_hello(hello)        # JA3 + MD5, JA4, and the Akamai H2 string
print(fp)                             # ja3 0539a808…, ja4 t12d1514H_…, h2 …
Session(url, headers, transport=CurlTransport(fingerprint=fp))
```

Install the extra: `pip install curl_cffi` (or `mimic[fingerprint]`).

**What actually works today.** curl-impersonate can only toggle a fixed set of
TLS extensions, so it usually refuses to rebuild a ClientHello from a captured
JA3 — real handshakes always contain extensions it can't set. When that happens
you get a clear error naming the problem and two working alternatives:

```python
Session(url, headers, transport=CurlTransport(impersonate="safari_ios"))
Session(url, headers)                     # plain requests
```

The JA3/JA4/Akamai computation is exact and useful regardless — it is what
other tooling reads, and it is the input a fixed curl-impersonate would need.

Note that `mitmweb`'s flow records carry the negotiated SNI, ALPN and TLS
version but not the offered cipher suites, so `from_client_hello` needs the
ClientHello itself (which mitmproxy parses) rather than a flow record.

### Profiles

Captured headers are a bundle the real app wrote together, so they agree with
each other. Assemble a profile by hand and it can stop agreeing — a User-Agent
from one client, `x-app-version` from another. Servers that check that send back
a bare 403 with nothing pointing at the header that broke it, so mimic checks
at load time and names both:

```python
from mimic import Persona, PersonaConflict

try:
    Persona.from_headers(headers).validate()
except PersonaConflict as e:
    print(e)
# these captured headers describe different clients: user-agent vs
# x-client-version: user-agent says MyApp 2.1.0, but x-client-version says 3.0.0
```

Two rules it won't break: nothing is invented (a device id the capture never
showed stays absent), and anything read out of one header is marked *inferred*
and can never contradict itself.

A profile — persona plus the base URL and headers it belongs to — can be stored
encrypted, so a capture on disk isn't a live session token readable by every
process and backup agent on the machine:

```bash
mimic profile save hinge-iphone --host prod-api.hingeaws.net
mimic profile list
mimic profile load hinge-iphone
```

```python
from mimic import Session, Vault

s = Session.from_profile("hinge-iphone", Vault())   # prompts for the passphrase
s.get("/rec/v2")
```

Needs the extra: `pip install cryptography` (or `mimic[vault]`). AES-GCM with a
fresh salt and nonce per write, the profile name bound in as authenticated
data (renaming the file breaks it), and writes renamed into place so an
interrupted save can't leave half a profile behind. A wrong passphrase and a
modified file are the same failure — that's what authenticated encryption is
for, and mimic says so rather than guessing which it was.

`mimic.vault` takes bytes in and gives bytes back; it never learns what a
profile is. `Session.from_profile` is the only line that joins them, and it
takes any object with `.load(name)`, so the optional dependency stays off the
import path of everything else.

### DPoP: per-request proof-of-possession

Every other credential mimic replays is a bearer: the same token on every call,
so capture it once and use it forever. [RFC 9449][rfc9449] takes that away. Each
request carries a `DPoP` header — a JWT signed by a private key the client
holds — whose claims (`htm`, `htu`, `iat`, `jti`, and the server's `nonce`) tie it
to *that one request*, and the access token is bound to the key's thumbprint as
`cnf.jkt`. Copying the header replays nothing.

```python
from mimic.dpop import SoftwareKey
from mimic.transport import get_transport

key = SoftwareKey.generate()                       # offline key, vault-stored
key.save(Vault(), "hinge-dpop")
key.thumbprint                                     # -> send as `cnf.jkt`

Session(url, headers, transport=get_transport("requests", dpop=key))
```

Needs the extra: `pip install cryptography` (or `mimic[dpop]` — same package as
the vault extra).

Two ways to hold the key, and which one you need depends on the app:

| Where the key lives | Use | Cost |
|---|---|---|
| mimic generated it, or a jailbroken device let you dump a software Keychain key | `SoftwareKey` — signs in-process | free |
| Secure Enclave (`kSecAttrTokenIDSecureEnclave`) — the usual choice for a well-built app | `device_oracle` — the tethered device signs, mimic never sees the key | one round trip per signature |

**An enclave key cannot be extracted — not by mimic, not by a jailbreak.** There
is no third route. `device_oracle` with no bridge raises a `DpopError` saying so
rather than sending a request with no proof, which the server would answer with a
401 indistinguishable from a revoked token:

```python
from mimic.dpop import device_oracle

signer = device_oracle("ES256", public_jwk, command=["frida", "-U", …])
```

The bridge is a command that reads a base64url JWS signing input on stdin and
writes a base64url signature to stdout — the shape `mimic unpin` already
establishes for talking to Frida. mimic doesn't ship the hook: which routine to
intercept is app-specific and moves between iOS versions, the same reason
`mimic.unpin` orchestrates upstream scripts rather than reimplementing them.

**What nonces cost.** A server that issues one (`DPoP-Nonce` in the response)
can't be pre-minted for. mimic handles the exchange for you — it sends, reads the
nonce off the 401, and re-signs — but that means **one extra round trip per new
`Session`**, and a `DPoP-Nonce` sent with a 200 removes it for later requests. On
the oracle path each of those round trips is a signature delegated to a tethered
device. That's the protocol's cost, not a workaround for it.

Three things it refuses to do rather than do badly:

- **Sign with a clock the server will reject.** `iat` is whole seconds and is
  checked against the window RFC 9449 §11.1 allows; and because `iat` is read off
  the very clock it's compared against, the skew is measured against the `Date`
  header every response carries. A machine an hour out gets one clear
  "this machine's clock is 3600s behind the server's" instead of a stream of 401s
  that look like a stolen token.
- **Send a proof that follows a redirect.** Signing happens per request on its way
  to the socket, not once per call, so the `htu` claim always describes the URL
  actually being requested.
- **Sign at all without a key.** A dead bridge, a non-extractable key, or a
  key file whose halves disagree is a `DpopError` naming the cause.

DPoP is signed on the `requests` transport only. `curl_cffi` offers no per-request
hook, so a proof could only be attached once per call and would go stale across a
redirect; `CurlTransport(dpop=…)` says so rather than half-supporting it.

Details and the honest edge cases: [docs/dpop.md](docs/dpop.md).

### Running many calls

A capture is dozens of endpoints; hitting all of them is a run. `mimic.orchestrate`
is the machinery for that, in four modules with one owner each:

```python
from mimic.orchestrate import Emitter, HostLimiter, Runner, Task, TaskQueue

events = Emitter()
events.on("task.finished", lambda name, d: print(d["id"], "->", d))

queue = TaskQueue([Task("me", "GET", "/v1/me", host="api.example.com"),
                   Task("feed", "GET", "/v1/feed", host="api.example.com")])

run = Runner({"api.example.com": session},
             limiter=HostLimiter(rate=5), events=events).run(queue)

run.ok, run.results, run.pending
```

**Pacing is per host.** Each host gets its own token bucket, so one slow or
throttling API can't spend another's budget. When a server sends `Retry-After`,
that number goes straight to the limiter and the host is held for exactly that
long — mimic uses the server's answer rather than a schedule of its own:

```python
from mimic import RateLimitError

try:
    session.get("/v1/feed")
except RateLimitError as e:
    limiter.defer("api.example.com", e.retry_after)     # seconds, from the server
```

A rate limit slows a run; it doesn't end one. Completed work is never discarded,
and the runner adds no retry policy of its own — `Session` still owns "how hard
do we try", so there is exactly one place that decides.

**A run always reports.** `cancel()` (from another thread or a subscriber), or
Ctrl-C, stops after the task in flight and still returns what finished, what
failed, and what never started:

```python
run.finished    # ((task, body), …)
run.failed      # ((task, exception), …)
run.pending     # (task, …) — sent nothing at all, ready to pick up again
```

**Events are free to observe.** `mimic.orchestrate.events` imports nothing from
the rest of mimic, so subscribing costs nothing and can't create a cycle. A
subscriber that raises is recorded, not propagated: a broken observer never ends
a run.

| module | owns | imports from mimic |
| --- | --- | --- |
| `events` | what happened | nothing |
| `queue` | what is left, and what became of it | nothing |
| `ratelimit` | how fast, and how long after a 429 | nothing |
| `runner` | doing it | all three |

### A client with no AI in the loop

`mimic gen` hands the capture to an AI, which writes a good client and types it
from its own reading of the evidence. When you would rather have types you can
check:

```bash
mimic gen api.example.com --generator deterministic
```

```python
from mimic.codegen_det import client_source
from mimic.sources import endpoints

print(client_source("api.example.com", endpoints(flows, "api.example.com")))
```

The rule is that **every type is traceable to a recorded value**, and the ones
that aren't say so in the generated file:

```python
def get_users(self, id: Union[int, float]) -> dict:
    """GET /users/{id} -> 200
    observed at: /users/8931, /users/8932

    response fields recorded at generation time:
      $                dict
      $.user           dict
      $.user.id        Union[int, float]
      $.user.name      str
      $.user.nickname  Any  UNKNOWN: capture only ever saw this field as null
    """
    # id: observed at $.user.id as number
    return self.get(f'/users/{id}')
```

A field the capture only ever showed as `null` is left as `Any` and flagged,
because a confident-looking `str` there would be a guess dressed as a fact. The
client subclasses `App` and ships the recorded shapes, so it inherits retry,
cookies, drift detection and the transport seam rather than reimplementing any
of it — `mimic.SchemaDriftError` works in a generated client exactly as it does
in a hand-written one.

Choosing a generator resolves through one registry (`mimic.codegen.BACKENDS`);
adding another is a table entry. `agy` is registered with `prompt_via="probe"`
rather than an assumption: mimic asks the binary at call time whether it reads
its prompt from stdin or takes it as an argument, caching the answer. If a
generator isn't installed you get an error naming it — **never** a silent
fallback to the deterministic path, because a file that looks like the model's
work and isn't is the one failure here you couldn't detect by reading it.

### Recipes: a run as data

Endpoints, pacing and which saved profile to run as, with no code written:

```json
{
  "name": "backfill",
  "host": "api.example.com",
  "profile": "hinge-iphone",
  "rate": 5,
  "steps": [
    {"id": "me",   "method": "GET", "path": "/v1/me"},
    {"id": "user", "method": "GET", "path": "/users/{id}",
     "values": {"id": 8931}}
  ]
}
```

```bash
mimic run backfill.json
```

```python
from mimic.recipes import Recipe
Recipe.from_file("backfill.json").run(endpoints)
```

Every step is matched against the capture *before* the run starts, so an
endpoint the capture never saw, a templated path with no value for one of its
parameters, and a `concurrency` the sequential runner can't honour are all
reported together, up front — rather than one line of output at step forty.
Past that point it's the Layer 4 runner: pacing per host, progress events, and a
finished/failed/pending breakdown.

## Capture backends

- **mitmproxy** for iOS and Android apps (the default). `mimic record` launches
  the proxy for you, and reads its JSON flow API. `mimic hosts` needs only that;
  `learn` and `gen` also need the request/response bodies, which mimic takes in
  a single bulk read of the whole capture rather than one request per endpoint.
  Reading that dump needs the `mitmproxy` package importable — `install.sh`
  includes it, and `mimic doctor` tells you if it's missing. Flutter apps don't
  route through it at all; they need their engine repacked (see
  [pinned apps](#pinned-apps-ios-android-flutter)).
- **cURL / paste** for anything with a web version. `Copy as cURL` in devtools,
  then `Session.from_curl(text)`. No proxy, no cert.
- **HAR file** for web apps and anything you can capture in a browser. In Chrome
  or Firefox devtools, open the Network tab, right-click a request, and choose
  "Save all as HAR". Then `mimic hosts --har traffic.har` and
  `mimic gen api.example.com --har traffic.har`, or build a session directly with
  `Session.from_har("traffic.har", "api.example.com")`. No proxy, no cert.

Bodies are decoded before analysis, so a gzipped response still yields its
GraphQL operation and its response shape instead of silently yielding neither.

## Limitations

Two auth schemes get in the way, for different reasons:

- **Certificate pinning** (banking, Instagram). The app rejects the mitmproxy
  cert, so the proxy sees no traffic and nothing shows up in `mimic hosts`. This
  blocks *capture*, not replay — get past the pin and the rest works normally.
  `mimic unpin` sets up a bypass for iOS (Frida), Android (Frida, reported per
  pinning mechanism) and Flutter (engine repack); see
  [docs/pinning.md](docs/pinning.md). Two limits worth knowing: mimic reports on
  two Android mechanisms (OkHttp `CertificatePinner` and
  `network_security_config`) — an app pinning through some third framework is
  outside both, and the report says so rather than claiming success; and a
  Flutter repack that comes back with fewer ABIs than it went in with is a
  partial result, not a working one.
- **DPoP / sender-constrained tokens** used to defeat the model outright. mimic
  now builds the proofs ([above](#dpopp-per-request-proof-of-possession)), but a
  server-forced nonce costs a round trip per new session, and a Secure Enclave
  key has to be signed by a tethered device — there's no network-only path. See
  [docs/dpop.md](docs/dpop.md).

If `mimic hosts` shows the app's API host, you're good.

[rfc9449]: https://www.rfc-editor.org/rfc/rfc9449

## Ethics

Use it on your own accounts and data. It replays your session; it is not a tool
for accessing anyone else's. Respect each app's terms of service.

## License

MIT, see [LICENSE](LICENSE). Provided as-is, no warranty. Use on your own
accounts and data; you are responsible for complying with each app's terms.
