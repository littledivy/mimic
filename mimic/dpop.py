"""DPoP proofs — the one thing a captured request can't be replayed from.

Every other credential mimic replays is a bearer: the same token, cookie or
device id on every call, so capture it once and use it forever. RFC 9449 takes
that away. Each request carries a `DPoP` header — a JWT signed by a private key
the client holds — whose claims tie it to *that one request*:

    {"jti": "…", "htm": "POST", "htu": "https://api.example.com/token",
     "iat": 1562262616}

An access token issued against this key is bound to the key's thumbprint
(`cnf.jkt`), so copying the header replays nothing: the proof goes stale on
`iat`, the server refuses a repeated `jti`, and moving it to another endpoint
breaks `htu`.

    from mimic.dpop import SoftwareKey, device_oracle

    key = SoftwareKey.generate()                 # offline, stored in the vault
    proof = key.proof("POST", "https://api.example.com/token")

Two signers, because the key usually isn't yours to extract:

- `SoftwareKey` holds the key in this process. That is the case when mimic
  generated it, or when a jailbroken device let you dump a Keychain one.
- `device_oracle` never sees the key. It hands each signing input to a tethered
  device over the Frida bridge `mimic unpin` sets up, and gets back a signature.
  A Secure Enclave key is never extractable — not by mimic, not by a jailbreak —
  so this is the only route for those, and it costs a round trip per proof.

The honest limit, stated once here: when the server uses nonces (§8/§9) the
first request of a run has nothing to put in `nonce`, so it is answered with a
challenge and has to be sent again. Against a nonce-using server, expect one
extra round trip per new `Session`, and one more per signature on the oracle
path. That's the protocol, not a limitation of this module.
"""
import base64
import hashlib
import json
import re
import secrets
import subprocess
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from types import SimpleNamespace
from urllib.parse import urlsplit

from .errors import DpopError

#: The header the proof rides in, and the one the server answers on.
DPOP_HEADER = "DPoP"
NONCE_HEADER = "DPoP-Nonce"

#: `typ` is mandatory (RFC 9449 §4.3 check 4) and has exactly this value.
PROOF_TYP = "dpop+jwt"

#: §11.1 — servers accept proofs only for a brief window, "on the order of
#: seconds or minutes". These bound what mimic will sign. A proof outside the
#: window is one a server rejects, and it rejects it the same way it rejects a
#: stolen token, so an unchecked bad clock reads as a dead session.
MAX_AGE = 300.0
MAX_SKEW = 60.0

#: `jti` only has to be unguessable and unique (§11.1 suggests rejecting
#: needlessly large ones), so 128 random bits is the whole requirement.
JTI_BYTES = 16

INSTALL_HINT = "pip install 'mimic-client[dpop]'  # or: pip install cryptography"

#: Curve names differ between `cryptography` ("secp256r1"), JWK ("P-256") and
#: JWS ("ES256"). Three tables rather than one, because folding them together is
#: how a P-384 key ends up labelled P-256 and produces proofs nobody accepts.
_CRV_OF_CURVE = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
_CURVE_OF_CRV = {"P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}
_CRV_OF_ALG = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
_SUPPORTED_ALGS = frozenset(_CRV_OF_ALG) | {"EdDSA"}

#: RFC 7638 §3.2. Only the required members of a key take part in its
#: thumbprint, and they go in lexicographic order — which is *not* the order a
#: DPoP header lists them in. Two different serializations of the same key, and
#: confusing them is the classic way to compute a thumbprint nobody matches.
_REQUIRED_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
}

# base64url, unpadded (RFC 7515 §2). Deliberately not `base64.urlsafe_b64decode`'s
# tolerance: `=` and the standard-alphabet `+` and `/` are rejected, because a
# padded or standard-alphabet segment means whoever produced it is not speaking
# this encoding and the proof has already lost byte-agreement with the spec.
_B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")

_DEFAULT_PORTS = {"http": 80, "https": 443}

_BACKEND = None


def _backend():
    """The `cryptography` pieces, imported on demand.

    Deferred for the same reason `mimic.vault` defers them: the package has to
    stay importable on a machine that has never heard of `cryptography`, and a
    DPoP proof is opt-in like every other extra.
    """
    global _BACKEND
    if _BACKEND is None:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
        except ImportError:
            raise DpopError(
                f"signing DPoP proofs needs the `cryptography` package — {INSTALL_HINT}"
            )
        _BACKEND = SimpleNamespace(ec=ec, ed25519=ed25519, hashes=hashes,
                                   utils=utils, serialization=serialization)
    return _BACKEND


# ---- base64url ----------------------------------------------------------------

def b64url_encode(raw):
    """`bytes` → base64url with the padding stripped."""
    if not isinstance(raw, (bytes, bytearray)):
        raise DpopError(f"base64url input must be bytes, got {type(raw).__name__}")
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    """base64url → `bytes`, refusing anything that isn't the unpadded form.

    `base64.urlsafe_b64decode` accepts padded input and quietly tolerates the
    standard alphabet, so a padded segment would decode to the right bytes here
    and still be a proof the server's parser may reject. Checking here keeps
    that a clear local error instead of a 401.
    """
    if not isinstance(text, str):
        raise DpopError(f"base64url input must be str, got {type(text).__name__}")
    if "=" in text:
        raise DpopError(
            "base64url value is '='-padded; RFC 7515 §2 requires the padding-free "
            "form",
            field="base64url", expected="no padding", got=text,
        )
    if not _B64URL.match(text):
        raise DpopError(
            "base64url value contains characters outside [A-Za-z0-9_-] — "
            "standard-alphabet '+' and '/' are not URL-safe",
            field="base64url", expected="[A-Za-z0-9_-]", got=text,
        )
    if len(text) % 4 == 1:
        # A single leftover character can't be the tail of any base64 quantum.
        raise DpopError(
            f"base64url value has an impossible length ({len(text)})",
            field="base64url", expected="length %% 4 != 1", got=len(text),
        )
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---- keys ---------------------------------------------------------------------

def jwk_for(public_key):
    """The public JWK for a key, in the member order RFC 9449 prints it.

    `typ`/`alg`/`jwk` then `kty`/`x`/`y`/`crv`, which is the byte sequence a
    published DPoP header carries. It is *not* the thumbprint order — see
    `thumbprint`.
    """
    crypto = _backend()
    if isinstance(public_key, crypto.ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(
            encoding=crypto.serialization.Encoding.Raw,
            format=crypto.serialization.PublicFormat.Raw,
        )
        return {"kty": "OKP", "x": b64url_encode(raw), "crv": "Ed25519"}
    if not isinstance(public_key, crypto.ec.EllipticCurvePublicKey):
        raise DpopError(
            f"a DPoP key must be an EC or Ed25519 public key, got "
            f"{type(public_key).__name__} — RFC 9449 §4.3 check 5 rejects every "
            f"symmetric algorithm, because a symmetric key would have to be "
            f"shared with the server",
            field="key", expected="EC or Ed25519", got=type(public_key).__name__,
        )
    numbers = public_key.public_numbers()
    size = (public_key.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "x": b64url_encode(numbers.x.to_bytes(size, "big")),
        "y": b64url_encode(numbers.y.to_bytes(size, "big")),
        "crv": _CRV_OF_CURVE[public_key.curve.name],
    }


def thumbprint(jwk):
    """RFC 7638 JWK Thumbprint — the value an access token's `cnf.jkt` carries.

    SHA-256 over the required members only, lexicographically ordered, no
    whitespace. The digest is base64url without padding, so it drops straight
    into `cnf`.
    """
    kty = jwk.get("kty")
    members = _REQUIRED_MEMBERS.get(kty)
    if members is None:
        raise DpopError(
            f"RFC 7638 §3.2 defines no thumbprint members for a {kty!r} key",
            field="kty", expected=sorted(_REQUIRED_MEMBERS), got=kty,
        )
    missing = [m for m in members if m not in jwk]
    if missing:
        raise DpopError(
            f"a {kty} JWK is missing {', '.join(missing)}, which its thumbprint requires",
            field=missing[0], expected=members, got=sorted(jwk),
        )
    canonical = json.dumps({m: jwk[m] for m in sorted(members)},
                           separators=(",", ":"))
    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def access_token_hash(token):
    """`ath`: base64url(SHA-256(ASCII(token))). RFC 9449 §4.2.

    Present whenever the proof accompanies an access token, which is every call
    to a protected resource — without it the server has no way to tell which
    token the proof belongs to.
    """
    return b64url_encode(hashlib.sha256(token.encode("ascii")).digest())


# ---- htu ----------------------------------------------------------------------

def htu(url):
    """The `htu` claim for `url` — RFC 9449 §4.3 check 9.

    Query and fragment are dropped, scheme and host are lowercased, the port
    survives unless it is the scheme's default, and an empty path becomes `/`.
    That last one matters more than it looks: `https://h` and `https://h/` are
    the same request to a server but two different strings here, so signing the
    one the caller happened to write buys a proof the other is refused.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise DpopError(f"could not read a DPoP `htu` out of {url!r}: {exc}",
                        field="htu", expected="an absolute URL", got=url) from exc
    # urlsplit already applies RFC 3986 §6.2.2.1 case normalization to the
    # scheme and host, so there is nothing to lowercase here.
    scheme = parts.scheme
    host = parts.hostname or ""
    if not scheme or not host:
        raise DpopError(
            f"a DPoP `htu` has to name an absolute URL, got {url!r}",
            field="htu", expected="scheme://host/path", got=url,
        )
    if ":" in host:  # urlsplit drops the brackets; htu needs them back
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path or '/'}"


# ---- proofs -------------------------------------------------------------------

def _json(claims):
    """Compact JSON, no spaces — JWT segments are UTF-8 octets, not prose."""
    return json.dumps(claims, separators=(",", ":")).encode("utf-8")


def encode(header, payload, sign):
    """Serialize and sign one DPoP JWT from already-final claim sets.

    Split out from `Signer.proof` so a known claim set can be turned into exact
    bytes with nothing else in the way — no key, no clock, no fresh `jti`. That
    is what pinning a published RFC example byte-for-byte needs.

    `sign` takes the `header.payload` signing input and returns raw signature
    bytes.
    """
    encoded = "%s.%s" % (b64url_encode(_json(header)), b64url_encode(_json(payload)))
    return "%s.%s" % (encoded, b64url_encode(sign(encoded.encode("ascii"))))


class Signer:
    """Everything RFC 9449 says except the one thing that varies: the key.

    Subclasses supply `sign(bytes) -> bytes` and nothing else, so the proof
    layout, the clock rules, `jti` uniqueness and nonce threading are written
    once and behave identically whether the signature happens in this process
    or on a phone down a USB cable.
    """

    def __init__(self, alg, jwk, sign, *, clock=None, new_jti=None):
        if alg not in _SUPPORTED_ALGS:
            raise DpopError(
                f"{alg!r} is not a DPoP algorithm — RFC 9449 §4.2 requires an "
                f"asymmetric one, and this module implements "
                f"{', '.join(sorted(_SUPPORTED_ALGS))}",
                field="alg", expected=sorted(_SUPPORTED_ALGS), got=alg,
            )
        if "d" in jwk:
            # §4.3 check 7: the header must carry the public key only. Leaking
            # the private half into every request would be worse than the bug.
            raise DpopError("refusing to put a private key in a DPoP header — "
                            "RFC 9449 §4.3 check 7", field="jwk")
        self.alg = alg
        self.jwk = dict(jwk)
        self._sign = sign
        self._clock = clock or time.time
        self._new_jti = new_jti or (lambda: b64url_encode(secrets.token_bytes(JTI_BYTES)))
        self._nonce = None  # the nonce in hand, from the last response
        self._sent_nonce = None  # the nonce in the proof we last produced
        self._last_iat = None  # catches a clock that steps backwards
        self._skew = None  # server's clock minus ours, from the last response

    @property
    def thumbprint(self):
        """The value to send as `cnf.jkt`, so the server can bind a token."""
        return thumbprint(self.jwk)

    @property
    def nonce(self):
        """The server nonce currently in hand, or None."""
        return self._nonce

    def absorb(self, response):
        """Take a `DPoP-Nonce` out of `response` and keep it for the next proof.

        Returns True only when this response is asking for the request to be
        re-signed and sent again — that is, when it carried a nonce the proof
        we last built didn't have. A response carrying a *different* nonce just
        updates the value for the next proof, as §8.2 requires; repeating a
        request that already worked isn't implied by that.

        Limiting the True case to "the proof had no nonce" is what keeps the
        handshake to one retry per request. Past that point a second challenge
        means the server is rotating nonces faster than the exchange can
        follow, and hammering it is worse than failing.

        Also reads the response's `Date` header, which is the only clock a
        server hands out for free. See `_learn_skew`.
        """
        self._learn_skew(response)
        found = _first_header(response, NONCE_HEADER)
        if found is None or found == self._sent_nonce:
            return False
        challenged = self._sent_nonce is None
        self._nonce = found
        return challenged

    def proof(self, method, url, *, access_token=None, iat=None, jti=None):
        """Build one DPoP proof for `method` + `url`, as a compact JWT.

        Claim order follows RFC 9449 Figure 14, and `nonce` and `ath` follow
        `iat` as in Figures 21 and 14. Order is cosmetic to a JSON parser but
        this is a wire format people diff, so it is worth matching.
        """
        payload = {
            "jti": self._new_jti() if jti is None else jti,
            "htm": str(method).upper(),
            "htu": htu(url),
            "iat": self._timestamp(iat),
        }
        if access_token:
            payload["ath"] = access_token_hash(access_token)
        if self._nonce:
            payload["nonce"] = self._nonce

        header = {"typ": PROOF_TYP, "alg": self.alg, "jwk": self.jwk}
        token = encode(header, payload, self._sign)
        # Only now: `absorb` compares against the nonce that actually went out,
        # so a signing failure can't leave it believing a nonce was used.
        self._sent_nonce = self._nonce
        return token

    def _timestamp(self, iat):
        """The `iat` claim, checked before it becomes part of a signature.

        Four things would produce a proof the server rejects — and it rejects all
        of them the way it rejects a forged one, so the symptom is an
        unexplained 401 rather than a clock message. Catching them here is the
        difference between "fix your clock" and "re-capture everything".

        First, and only if a response has been seen: a clock that is *wrong*
        rather than merely stepped. `iat` is read off the same clock it is
        compared against, so without `_learn_skew` a machine an hour out signs a
        perfectly self-consistent, perfectly doomed proof.

        Then the clock as this process sees it: `iat` must be whole seconds, no
        more than `MAX_SKEW` in the future, no more than `MAX_AGE` old, and not
        *backwards* from the last proof. That last one has no `MAX_` bound on
        purpose — an `iat` that retreats means the clock was stepped (an NTP
        correction, a suspend), which would otherwise put a window the server
        already accepted back into the past.
        """
        now = self._clock()
        if self._skew is not None and abs(self._skew) > MAX_SKEW:
            # _skew is server - local, so a negative one means *we* are ahead.
            raise DpopError(
                f"this machine's clock is {abs(self._skew):.0f}s "
                f"{'ahead of' if self._skew < 0 else 'behind'} the server's, and "
                f"RFC 9449 §11.1 lets a server accept only seconds of difference "
                f"— every proof dated from it would be rejected as replayed, with "
                f"nothing to distinguish that from a stolen token. Fix the clock "
                f"(`sudo sntp -sS <pool.ntp.org>` or turn on automatic time), then "
                f"retry.",
                field="iat", expected=f"|server - local| <= {MAX_SKEW:.0f}s",
                got=f"{self._skew:+.0f}s",
            )
        if iat is None:
            value = int(now)
        else:
            # bool is an int subclass; `True` would serialize as iat=true.
            if isinstance(iat, bool) or not isinstance(iat, int):
                raise DpopError(
                    f"`iat` must be whole seconds since the epoch as an int, got "
                    f"{iat!r} — a float or a string serializes to something no "
                    f"server will read as a NumericDate",
                    field="iat", expected="int seconds", got=iat,
                )
            value = iat
        if value > now + MAX_SKEW:
            raise DpopError(
                f"this machine's clock reads {value - now:.0f}s ahead, and a DPoP "
                f"proof dated in the future is one a server rejects without "
                f"saying why (RFC 9449 §11.1 allows only seconds of skew)",
                field="iat", expected=f"<= {int(now + MAX_SKEW)}", got=value,
            )
        if value < now - MAX_AGE:
            raise DpopError(
                f"`iat` is {now - value:.0f}s old, past the {MAX_AGE:.0f}s window a "
                f"server will accept a DPoP proof in — it would reject this as "
                f"replayed",
                field="iat", expected=f">= {int(now - MAX_AGE)}", got=value,
            )
        if self._last_iat is not None and value < self._last_iat:
            raise DpopError(
                f"`iat` went backwards, from {self._last_iat} to {value} — the "
                f"clock was stepped, and the proof minted at {self._last_iat} is "
                f"already outside the replay window",
                field="iat", expected=f">= {self._last_iat}", got=value,
            )
        self._last_iat = value
        return value

    def _learn_skew(self, response):
        """Record how far this machine's clock is from the server's.

        Every HTTP response carries a `Date` header, which makes it the only
        clock reference available without asking the server for anything. §11.1
        notes that a server may refuse to compare a client `iat` to its own time
        precisely because that gap can be large — so the gap is worth measuring
        rather than assuming.

        Both clocks advance together, so the offset read here stays true until
        one of them is stepped; there is nothing to correct for, and nothing to
        age out. A response with no usable `Date` leaves whatever was already
        known in place rather than forgetting it.
        """
        raw = _first_header(response, "Date")
        if not raw:
            return
        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when is not None:
            self._skew = when.timestamp() - self._clock()


def _first_header(response, name):
    """The first value of `name`, in the order the response carried it.

    A server that sends two `DPoP-Nonce`s breaks §8's "MUST NOT be more than
    one", and `requests` folds them into one comma-joined string — so the
    folded value can't be split to recover the order without guessing, since a
    nonce may legally contain a comma. The raw message keeps them apart, so it
    is consulted first and the folded form is only a last resort.
    """
    for source in (getattr(getattr(response, "raw", None), "headers", None),
                   getattr(response, "headers", None)):
        getlist = getattr(source, "getlist", None)
        if getlist is not None:
            values = [v.strip() for v in getlist(name) if v and v.strip()]
            if values:
                return values[0]
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(name)
    return value.strip() if value and value.strip() else None


# ---- signers ------------------------------------------------------------------

class SoftwareKey(Signer):
    """Signs in this process with a key mimic holds.

    Two ways to get one: `generate()` for a key of your own, or `load()` for
    one dumped off a jailbroken device whose Keychain entry turned out to be a
    software key rather than an enclave one. Both are ordinary files in the
    vault, encrypted and bound to their name like any other profile — a DPoP
    private key that sits in plaintext on disk is a token thief's shortcut to
    every token bound to it.
    """

    @classmethod
    def generate(cls, alg="ES256"):
        """A fresh key pair. Nothing else has ever seen the private half."""
        crypto = _backend()
        if alg == "EdDSA":
            key = crypto.ed25519.Ed25519PrivateKey.generate()
        else:
            curve = getattr(crypto.ec, _CURVE_OF_CRV[_CRV_OF_ALG[alg]].upper())()
            key = crypto.ec.generate_private_key(curve)
        return cls._wrap(alg, key)

    @classmethod
    def load(cls, vault, name):
        """Read a key saved by `save`, from anything with `load(name) -> bytes`.

        Duck-typed on purpose, for the same reason `Session.from_profile` is:
        this module never imports `mimic.vault`, so `import mimic` stays free
        of `cryptography`.
        """
        try:
            stored = json.loads(bytes(vault.load(name)).decode("utf-8"))
            jwk, alg = stored["jwk"], stored["alg"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            raise DpopError(
                f"DPoP key {name!r} isn't a readable key file: {exc}"
            ) from exc
        return cls._wrap(alg, _private_key(jwk), expected=jwk)

    def save(self, vault, name):
        """Encrypt this key into the vault under `name`. Returns the path.

        The stored document is the JWS algorithm plus the private JWK, which is
        what `load` reads back. Keeping the two together means a key file says
        how it is meant to be signed, rather than leaving that to be inferred
        from a curve name.
        """
        return vault.save(name, _json({"alg": self.alg,
                                       "jwk": _private_jwk(self)}))

    @classmethod
    def _wrap(cls, alg, key, expected=None):
        signer = cls(alg, jwk_for(key.public_key()), _raw_signer(alg, key))
        signer._key = key  # kept only so `save` can re-derive `d`
        if expected is not None and thumbprint(signer.jwk) != thumbprint(expected):
            # A JWK whose `d` doesn't actually produce the advertised `x`/`y` is
            # a mismatched or edited file. `cryptography` wouldn't notice — it
            # would sign with one key while the proof advertised another, and
            # every request would fail signature verification at a server with
            # no clue why. `d` isn't a thumbprint member, so comparing the two
            # public halves is enough to catch it.
            raise DpopError(
                "this key file's private half doesn't produce its advertised "
                "public key — it has been edited, or the halves came from "
                "different keys",
                field="d",
            )
        return signer


class DeviceOracle(Signer):
    """Signs by asking a tethered device; the private key never crosses over.

    The bridge is a command that reads a base64url JWS signing input on stdin
    and writes a base64url signature to stdout — the shape `mimic unpin` already
    establishes for talking to Frida on the other end of a USB cable. mimic
    doesn't ship the hook: which routine to intercept is app-specific and moves
    between iOS versions, the same reason `mimic.unpin` orchestrates upstream
    scripts rather than reimplementing them.

    Every signature is a round trip, and a server that issues nonces makes it
    two — one to learn the nonce, one to have the device sign a proof carrying
    it. That cost is inherent to a non-extractable key, not to this design.
    """

    #: Long enough for a phone to wake, short enough that a dead link fails
    #: where the caller can see it rather than hanging the whole run.
    DEFAULT_TIMEOUT = 10.0

    def __init__(self, alg, jwk, command, timeout=DEFAULT_TIMEOUT):
        if not command:
            raise DpopError(
                "a device oracle needs a bridge command to sign with",
                field="command", expected="a command that signs on stdin",
            )
        self.command = list(command)
        self.timeout = timeout
        super().__init__(alg, jwk, self._sign_on_device)

    def _sign_on_device(self, signing_input):
        try:
            done = subprocess.run(self.command, input=signing_input,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            # An unreachable bridge has to be loud. Signing nothing, or worse
            # signing with some other key, both show up as a 401 that reads as
            # a revoked session.
            raise DpopError(
                f"couldn't reach the DPoP device bridge {self.command[0]!r}: "
                f"{exc}\nKeep the app running on the tethered device — mimic signs "
                f"by asking it, never locally.",
                field="command", expected=" ".join(self.command), got=str(exc),
            ) from exc
        if done.returncode != 0:
            detail = done.stderr.decode("utf-8", "replace").strip() or "no stderr"
            raise DpopError(
                f"the DPoP device bridge exited {done.returncode}: {detail}",
                field="command", expected=0, got=done.returncode,
            )
        out = done.stdout.decode("ascii", "replace").strip()
        if not out:
            raise DpopError(
                f"the DPoP device bridge {self.command[0]!r} exited 0 without "
                f"writing a signature — refusing to send an unsigned proof",
                field="command", expected="a base64url signature on stdout",
            )
        return b64url_decode(out)


def device_oracle(alg, jwk, command=None, *, extractable=False,
                  timeout=DeviceOracle.DEFAULT_TIMEOUT):
    """A signer for a key that lives on a device, or a clear reason there isn't one.

    `jwk` is the *public* half the device advertised. A proof has to carry it,
    and the private half never crosses the wire in either direction.

    `extractable=False` says the key is Secure Enclave- or Keychain-backed and
    is meant to stay put. That is the normal case for a well-built app, and it
    needs a live `command` to ask. With no command there is nothing that can
    sign, so this raises rather than returning a signer that would attach no
    proof — which the server answers with a 401 indistinguishable from a
    revoked token.
    """
    if command:
        return DeviceOracle(alg, jwk, command, timeout=timeout)
    if extractable:
        raise DpopError(
            "this device's DPoP key can be extracted, so it needs no oracle — "
            "dump it and sign offline with SoftwareKey.load(vault, name)",
            field="command", expected="a dumped key, or a device bridge command",
        )
    raise DpopError(
        "this DPoP key is non-extractable (Secure Enclave or Keychain), so the "
        "signature can only come from the device itself — which nothing here can "
        "do without a bridge.\n"
        "Two routes that work:\n"
        "    1. keep the app running on a tethered device and pass "
        "command=<the frida bridge> (see `mimic unpin`)\n"
        "    2. point at a different endpoint that isn't sender-constrained\n"
        "There is no third one: an enclave key cannot be read out, not by "
        "mimic and not by a jailbreak.",
        field="command", expected="a device bridge command",
    )


# ---- key plumbing -------------------------------------------------------------

def _private_jwk(signer):
    """`signer`'s public JWK plus its `d` — the form kept in the vault."""
    crypto = _backend()
    key = signer._key
    jwk = dict(signer.jwk)
    if isinstance(key, crypto.ed25519.Ed25519PrivateKey):
        raw = key.private_bytes(
            encoding=crypto.serialization.Encoding.Raw,
            format=crypto.serialization.PrivateFormat.Raw,
            encryption_algorithm=crypto.serialization.NoEncryption(),
        )
    else:
        raw = key.private_numbers().private_value.to_bytes(
            (key.curve.key_size + 7) // 8, "big")
    jwk["d"] = b64url_encode(raw)
    return jwk


def _private_key(jwk):
    """Rebuild a private key from a stored JWK."""
    crypto = _backend()
    try:
        kty, crv, secret = jwk["kty"], jwk["crv"], b64url_decode(jwk["d"])
    except KeyError as exc:
        raise DpopError(
            f"this key file has no {exc.args[0]!r} member, so it isn't a private JWK",
            field=exc.args[0],
        ) from exc
    if kty == "OKP" and crv == "Ed25519":
        return crypto.ed25519.Ed25519PrivateKey.from_private_bytes(secret)
    if kty == "EC" and crv in _CURVE_OF_CRV:
        curve = getattr(crypto.ec, _CURVE_OF_CRV[crv].upper())()
        return crypto.ec.derive_private_key(int.from_bytes(secret, "big"), curve)
    raise DpopError(
        f"mimic has no DPoP signer for a {kty}/{crv} key",
        field="kty", expected="EC in P-256/P-384/P-521, or OKP/Ed25519",
        got=f"{kty}/{crv}",
    )


def _raw_signer(alg, key):
    """A `sign(bytes) -> bytes` closure producing JWS-shaped signatures.

    `cryptography` returns ECDSA signatures DER-encoded; JWS wants the raw
    fixed-width `R || S` pair. A server handed the DER form rejects the proof,
    and the rejection names nothing useful, so it is unwrapped here.
    """
    crypto = _backend()
    if alg == "EdDSA":
        return key.sign
    size = (key.curve.key_size + 7) // 8
    digest = {"ES256": crypto.hashes.SHA256,
              "ES384": crypto.hashes.SHA384,
              "ES512": crypto.hashes.SHA512}[alg]
    decode = crypto.utils.decode_dss_signature

    def sign(data):
        r, s = decode(key.sign(data, crypto.ec.ECDSA(digest())))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    return sign