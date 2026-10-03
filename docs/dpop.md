# DPoP / sender-constrained tokens

[Cert pinning](pinning.md) blocks capture; you get past it and mimic works as
normal. DPoP was the harder problem: it breaks the replay itself, which is the
thing mimic does.

`mimic.dpop` builds the proofs now. This page covers what that takes and, more
importantly, where it still doesn't work.

## Why replay fails, and what fixes it

A plain app authenticates every request with the same reusable bundle: a bearer
token, cookies, device ids. Capture it once, replay it, done. That's mimic.

DPoP ([RFC 9449][rfc]) doesn't work that way. Every request carries a fresh
`DPoP:` header, a JWT signed by a private key the client holds, with claims that
tie it to that one request:

| Claim | Ties the proof to | Why a copy fails |
|-------|-------------------|------------------|
| `htm` | HTTP method | reuse on another verb is rejected |
| `htu` | request URL | reuse on another endpoint is rejected |
| `iat` | issue time | server accepts only a few-second window |
| `jti` | unique id | server caches it; single use |
| `nonce` | server-issued value | unpredictable, short-lived (§8) |
| `ath` | the access token | proof is tied to that token |

The access token is bound to the key's thumbprint (`cnf.jkt`, an RFC 7638
thumbprint of the JWK the proof advertises), so a stolen token does nothing
without a matching signature on every request.

```python
from mimic.dpop import SoftwareKey
from mimic.transport import get_transport

key = SoftwareKey.generate()
Session(url, headers, transport=get_transport("requests", dpop=key))
```

## Where the key has to live

This is the part that decides everything else. You usually can't extract the
key, but you might be able to borrow the app's ability to use it.

| Key storage | Extractable? | Replay path |
|-------------|--------------|-------------|
| mimic generated it | n/a — you have it | `SoftwareKey`, signs in-process, no extra cost |
| Keychain software key (lazier apps) | Yes, on a jailbroken device (keychain-dumper, or a Frida `SecItemCopyMatching` hook) | Dump it, `SoftwareKey.load(vault, name)`, sign offline |
| Secure Enclave (P-256, `kSecAttrTokenIDSecureEnclave`) — recommended, common | **No.** A jailbreak gives userland root, not enclave access. | `device_oracle` only, tethered to the running app |

Fingerprint the target first: dump the keychain and check whether the DPoP key is
Secure-Enclave-backed or a plain software key. That answer decides the rest.

### The oracle

For an enclave key, keep the app running on a device you control and have it
sign. mimic owns the protocol and the transport of that request, not the hook:

```python
signer = device_oracle("ES256", public_jwk, command=["frida", "-U", …])
```

The bridge reads a base64url JWS signing input on stdin and writes a base64url
signature to stdout. mimic deliberately doesn't ship a Frida script — which
routine to intercept is app-specific and moves between iOS versions, the same
reason `mimic unpin` orchestrates upstream scripts rather than reimplementing
them.

**If you have an enclave key and no bridge, there is nothing mimic can do.**
`device_oracle` raises a `DpopError` saying exactly that. The alternative —
sending the request without a proof — is worse than failing, because the server
answers it with a 401 indistinguishable from a revoked token.

## The nonce problem

A working signer still can't do fully offline replay against a server that uses
nonces (RFC 9449 §8/§9). They're server-issued, opaque and short-lived, so
proofs can't be pre-minted.

mimic does the exchange for you: send, read `DPoP-Nonce` off the challenge, sign
again with it, and the caller sees one successful request. **That is one extra
round trip per new `Session`,** and there is no way around it — the nonce doesn't
exist until the server has seen a request without it. A server that sends the next
nonce along with a `200` (§8.2) removes the cost for every later request.

On the oracle path it costs more: each round trip is a signature delegated to a
tethered device. Two requests to get the first one, one device call each.

## What it refuses to do

A signer that degrades quietly is worse than no signer, because the failure shows
up as a 401 that reads like a dead session. `DpopError` covers:

- **A clock the server will reject.** `iat` is whole seconds, inside the §11.1
  window, and never goes backwards between proofs. Since `iat` is read off the
  same clock it's compared against, the skew is measured against the `Date` header
  every response already carries — which is how a machine 28 hours out gets one
  clear message instead of a run of rejections. The first request still goes out
  before the offset is known; every one after it is checked.
- **A key file whose halves disagree.** `d` that doesn't produce the advertised
  `x`/`y` is a mismatch, and signing with it produces a proof that fails
  verification at every server with nothing to say why.
- **A bridge that fails.** Non-zero exit, empty stdout (the shape a hook that
  didn't attach takes), or a timeout all raise. So does a bridge that writes
  padded base64 — the unpadded form is the only one this protocol uses.
- **A key in the header.** §4.3 check 7, enforced at construction.

## Limits worth knowing

- **requests transport only.** `curl_cffi` has no per-request hook, so a proof
  could only be attached once per call and would arrive at a redirect target
  still claiming the old `htu`, which §4.3 check 9 rejects. `CurlTransport`
  refuses `dpop=` with that reason rather than half-supporting it.
- **One retry per request.** If the server challenges a proof that already
  carried a nonce, the answer is an error, not more attempts — it is rotating
  faster than the exchange can follow.
- **`transport='requests'` has to be built explicitly.** DPoP is a transport
  concern, so it goes through `get_transport(transport, dpop=signer)`.

## Conformance

RFC 9449 publishes **no verifiable test vectors**: the signatures in its worked
examples (Figures 2 and 13) do not verify against the JWK they carry. What is
pinned byte-for-byte in `tests/test_dpop.py` instead:

- Figure 13's header and payload segments, reproduced exactly — which pins the
  member order, the `dpop+jwt` type, the claim set, unpadded base64url and the
  `htu` normalization at once;
- RFC 7638 §3.1 and RFC 8037 §A.3 thumbprints;
- RFC 8037 §A.4's Ed25519 signature, reproduced exactly (Ed25519 is
  deterministic, which ECDSA in `cryptography` is not);
- and, for every proof mimic mints, verification against the public key it
  advertised.

[rfc]: https://www.rfc-editor.org/rfc/rfc9449