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
isolated tool env. mitmproxy isn't a separate install; mimic launches it via
`uvx` on first `record`. (Manual: `uv tool install mimic-client`.)

```bash
mimic doctor                    # confirm proxy + claude are ready
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

## Capture backends

- **mitmproxy** for iOS apps (the default). mimic reads its JSON flow API and
  runs it via `uvx`, so there's nothing extra to install.
- **cURL / paste** for anything with a web version. `Copy as cURL` in devtools,
  then `Session.from_curl(text)`. No proxy, no cert.

## Limitations

Two auth schemes get in the way, for different reasons:

- **Certificate pinning** (banking, Instagram). The app rejects the mitmproxy
  cert, so the proxy sees no traffic and nothing shows up in `mimic hosts`. This
  blocks *capture*, not replay — get past the pin and the rest works normally.
  `mimic unpin <ipa|bundle-id>` sets up a Frida-based bypass; see
  [docs/pinning.md](docs/pinning.md).
- **DPoP / sender-constrained tokens.** Each request carries a fresh proof
  signed by a private key that never leaves the device, so captured requests
  don't replay. This defeats the core model, not just capture; there's no clean
  workaround. See [docs/dpop.md](docs/dpop.md).

If `mimic hosts` shows the app's API host, you're good.

## Ethics

Use it on your own accounts and data. It replays your session; it is not a tool
for accessing anyone else's. Respect each app's terms of service.

## License

MIT, see [LICENSE](LICENSE). Provided as-is, no warranty. Use on your own
accounts and data; you are responsible for complying with each app's terms.
