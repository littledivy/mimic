"""RFC 9449: the published vectors, the boundaries, and the nonce handshake.

A note on what the RFC actually gives us, because it shapes this file.

**RFC 9449 publishes no verifiable test vectors.** Its two worked examples
(Figures 2 and 13) carry signatures that do not verify against the very JWK
they advertise — they are illustrative, and the signature segments are
placeholder text. So "reproduce the RFC's test vector exactly" is not
achievable from the RFC, and a test that claimed to would be asserting nothing.

What it *does* publish, byte for byte, is the header and payload of Figure 13.
Those are pinned here as frozen constants and reproduced exactly, which pins the
member order, the `dpop+jwt` type, the claim set, base64url without padding, and
the `htu` normalization all at once. The signature is then checked two other
ways: against RFC 8037 §A.4's published Ed25519 vector (which does verify and
does reproduce exactly, since Ed25519 is deterministic), and by verifying every
proof this module mints against the public key it advertised.

RFC 7638 §3.1 and RFC 8037 §A.3 do publish thumbprints, and both are pinned.

Tests needing the optional extra skip when it isn't installed; the ones that
only exercise base64url or `htu` run either way.
"""
import importlib.util
import json
import os
import subprocess
import sys
import time

import pytest

from mimic.dpop import (
    DPOP_HEADER,
    MAX_AGE,
    MAX_SKEW,
    NONCE_HEADER,
    SoftwareKey,
    access_token_hash,
    b64url_decode,
    b64url_encode,
    device_oracle,
    encode,
    htu,
    jwk_for,
    thumbprint,
)
from conftest import Loopback

from mimic.errors import AuthError, DpopError
from mimic.session import Session

HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None
needs_crypto = pytest.mark.skipif(not HAS_CRYPTO, reason="needs the dpop extra")


# ---- frozen published vectors --------------------------------------------------

# RFC 9449 Figure 13's `DPoP` header, header and payload segments only. Copied
# out of the RFC text; the signature segment there does not verify, so it is
# left out rather than pasted in to look thorough.
RFC9449_HEADER_SEG = (
    "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwi"
    "eCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5"
    "IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNy"
    "diI6IlAtMjU2In19"
)
RFC9449_PAYLOAD_SEG = (
    "eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6"
    "Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2"
    "MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NB"
    "cWtzbVFFbyJ9"
)
RFC9449_JWK = {
    "kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv": "P-256",
}
RFC9449_HEADER = {
    "typ": "dpop+jwt", "alg": "ES256", "jwk": RFC9449_JWK,
}
RFC9449_PAYLOAD = {
    "jti": "e1j3V_bKic8-LAEB", "htm": "GET",
    "htu": "https://resource.example.org/protectedresource",
    "iat": 1562262618,
    "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
}

# RFC 7638 §3.1's example RSA key, and the thumbprint the RFC prints for it.
RFC7638_MODULUS = (
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7a"
    "PFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXAr"
    "wl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0z"
    "gdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcR"
    "wr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
)
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

# RFC 8037 §A.1's Ed25519 key, §A.3's thumbprint and §A.4's signature.
RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
RFC8037_D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
RFC8037_SIGNING_INPUT = (
    b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
)
RFC8037_SIGNATURE = (
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt"
    "9g7sVvpAr_MuM0KAg"
)


# ---- the published vectors ----------------------------------------------------

def test_rfc9449_header_and_payload_reproduce_byte_for_byte():
    """RFC 9449 Figure 13, to the byte.

    `encode` takes a `sign` callable, so the exact claim sets from the RFC go
    in and the exact segments come out. The signature can't be checked — the
    RFC's own doesn't verify — but every byte before it can be, which is the
    part that actually depends on how mimic serializes and what it puts in.
    """
    token = encode(RFC9449_HEADER, RFC9449_PAYLOAD, lambda data: b"\x00" * 64)
    header_seg, payload_seg, _ = token.split(".")
    assert header_seg == RFC9449_HEADER_SEG
    assert payload_seg == RFC9449_PAYLOAD_SEG


def test_rfc9449_segments_really_are_the_published_bytes():
    """Guard the constants themselves.

    A typo in a frozen vector makes the test above pass for the wrong reason,
    and a frozen vector that nobody re-checks against the source is a rumour.
    Decoding them proves they are the JSON the RFC prints, claim for claim.
    """
    header = json.loads(b64url_decode(RFC9449_HEADER_SEG))
    payload = json.loads(b64url_decode(RFC9449_PAYLOAD_SEG))
    assert header == RFC9449_HEADER
    assert payload == RFC9449_PAYLOAD
    assert "=" not in RFC9449_HEADER_SEG + RFC9449_PAYLOAD_SEG


def test_rfc7638_thumbprint():
    assert thumbprint({
        "kty": "RSA", "n": RFC7638_MODULUS, "e": "AQAB",
        "alg": "RS256", "kid": "2011-04-29",
    }) == RFC7638_THUMBPRINT


def test_rfc7638_ignores_members_that_are_not_required():
    """§3.2: only the required members take part.

    `alg` and `kid` above are ignored — that is the whole point, and it's why a
    server can compute a token's `cnf.jkt` from a key it was handed in any
    shape.
    """
    lean = thumbprint({"kty": "RSA", "n": RFC7638_MODULUS, "e": "AQAB"})
    assert lean == RFC7638_THUMBPRINT


def test_rfc8037_thumbprint():
    assert thumbprint({"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X}) == \
        RFC8037_THUMBPRINT


@needs_crypto
def test_rfc8037_ed25519_signature_reproduces():
    """RFC 8037 §A.4, end to end: the RFC's key, its input, its signature.

    Ed25519 is deterministic, so this is a true byte-for-byte vector — the one
    RFC 9449 doesn't have. It exercises the same base64url and signing path a
    DPoP proof uses.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = SoftwareKey._wrap("EdDSA",
                            ed25519.Ed25519PrivateKey.from_private_bytes(
                                b64url_decode(RFC8037_D)))
    assert key.jwk["x"] == RFC8037_X
    assert key.thumbprint == RFC8037_THUMBPRINT
    assert b64url_encode(key._sign(RFC8037_SIGNING_INPUT)) == RFC8037_SIGNATURE


@needs_crypto
@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_proof_verifies_against_the_key_it_advertised(alg):
    """A proof a server can actually check.

    ES256 signatures cross as raw `r || s` per RFC 7518 §3.4, which is not what
    `cryptography`'s `verify` accepts — it wants DER. Getting that backwards
    yields a proof every server rejects and no error anywhere, so the round trip
    is checked explicitly rather than assumed.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

    key = SoftwareKey.generate(alg)
    header_seg, payload_seg, sig_seg = key.proof("POST", "https://a.example/x").split(".")
    header = json.loads(b64url_decode(header_seg))
    assert header["jwk"] == key.jwk

    signature = b64url_decode(sig_seg)
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    if alg == "EdDSA":
        ed25519.Ed25519PublicKey.from_public_bytes(
            b64url_decode(header["jwk"]["x"])).verify(signature, signing_input)
        return
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64url_decode(header["jwk"]["x"]), "big"),
        int.from_bytes(b64url_decode(header["jwk"]["y"]), "big"),
        ec.SECP256R1())
    half = len(signature) // 2
    numbers.public_key().verify(
        utils.encode_dss_signature(
            int.from_bytes(signature[:half], "big"),
            int.from_bytes(signature[half:], "big")),
        signing_input, ec.ECDSA(hashes.SHA256()))


@needs_crypto
def test_es256_signature_is_raw_r_s_not_der():
    """64 bytes, never 70-something.

    DER starts `0x30`; a JWS signature segment starts with whatever `r` happens
    to be. Pinning the length catches a `cryptography` upgrade that changes the
    default encoding, which would be a proof no server accepts.
    """
    key = SoftwareKey.generate("ES256")
    assert len(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[2])) == 64


@needs_crypto
def test_a_key_that_is_neither_ec_nor_ed25519_is_refused():
    """An RSA or symmetric key is the obvious thing to hand this if you came
    from a captured JWK, and §4.2/§4.3 reject both — a symmetric key would have
    to be shared with the server, so it proves nothing."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    with pytest.raises(DpopError) as caught:
        jwk_for(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
    assert caught.value.field == "key"
    assert "symmetric" in str(caught.value)


@needs_crypto
def test_header_carries_no_private_key():
    """§4.3 check 7, and the single worst thing that could leak here."""
    key = SoftwareKey.generate()
    header = json.loads(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[0]))
    assert "d" not in header["jwk"]
    assert set(header["jwk"]) == {"kty", "x", "y", "crv"}
    assert header["typ"] == "dpop+jwt"


@needs_crypto
def test_signer_refuses_a_jwk_carrying_a_private_key():
    from mimic.dpop import Signer

    with pytest.raises(DpopError, match="private key"):
        Signer("ES256", dict(RFC9449_JWK, d="AAAA"), lambda data: b"")


def test_symmetric_alg_is_refused():
    """§4.3 check 5, and §4.2: a symmetric key would have to be shared with the
    server, which is not proof of possession of anything."""
    from mimic.dpop import Signer

    with pytest.raises(DpopError, match="asymmetric"):
        Signer("HS256", RFC9449_JWK, lambda data: b"")


def test_unknown_alg_names_what_is_supported():
    from mimic.dpop import Signer

    with pytest.raises(DpopError) as caught:
        Signer("RS256", {"kty": "RSA"}, lambda data: b"")
    assert "EdDSA" in str(caught.value)


# ---- base64url ----------------------------------------------------------------

@pytest.mark.parametrize("raw", [b"", b"a", b"ab", b"abc", b"abcd",
                                bytes(range(256)), b"\xff\xfe"])
def test_base64url_round_trips_without_padding(raw):
    encoded = b64url_encode(raw)
    assert "=" not in encoded
    assert "+" not in encoded and "/" not in encoded
    assert b64url_decode(encoded) == raw


@pytest.mark.parametrize("raw", [b"\x00" * 32, b"\xff" * 32, b"\x01" * 33])
def test_a_fixed_width_signature_encodes_to_the_expected_width(raw):
    """32 bytes -> 43 chars unpadded, and 33 -> 44. Nothing rounds up to '='."""
    assert len(b64url_encode(raw)) == 43 + (len(raw) == 33)


@pytest.mark.parametrize("padded", ["QQ==", "QUI=", "YQ==", "QUJDRA=="])
def test_decode_rejects_padding(padded):
    """RFC 7515 §2: the padding-free form, always.

    `base64.urlsafe_b64decode` accepts all of these and returns the right bytes,
    so accepting them means the proof disagrees with every other implementation
    over something a server parses strictly.
    """
    with pytest.raises(DpopError, match="padding"):
        b64url_decode(padded)


@pytest.mark.parametrize("bad", ["a+b", "QQ/", "üü", "QQ Q"])
def test_decode_rejects_the_standard_alphabet(bad):
    with pytest.raises(DpopError, match="URL-safe"):
        b64url_decode(bad)


def test_decode_rejects_an_impossible_length():
    """One leftover character can't be the tail of any base64 quantum."""
    with pytest.raises(DpopError, match="impossible length"):
        b64url_decode("QUJDQ")


def test_decode_rejects_non_strings():
    with pytest.raises(DpopError, match="must be str"):
        b64url_decode(b"QQ")


def test_encode_rejects_non_bytes():
    with pytest.raises(DpopError, match="must be bytes"):
        b64url_encode("QQ")


# ---- htu ----------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://a.example/v1/x", "https://a.example/v1/x"),
    # query and fragment are excluded — §4.3 check 9
    ("https://a.example/v1/x?a=b&c=d", "https://a.example/v1/x"),
    ("https://a.example/v1/x#frag", "https://a.example/v1/x"),
    ("https://a.example/v1/x?a=b#frag", "https://a.example/v1/x"),
    # scheme and host lowercased
    ("HTTPS://A.EXAMPLE/V1/X", "https://a.example/V1/X"),
    # default ports dropped, others kept
    ("https://a.example:443/x", "https://a.example/x"),
    ("http://a.example:80/x", "http://a.example/x"),
    ("https://a.example:8443/x", "https://a.example:8443/x"),
    ("http://a.example:443/x", "http://a.example:443/x"),
    # an empty path is "/", so these are one target and not two
    ("https://a.example", "https://a.example/"),
    ("https://a.example/", "https://a.example/"),
])
def test_htu_normalization(url, expected):
    assert htu(url) == expected


def test_htu_keeps_ipv6_brackets():
    """`urlsplit` strips them; a URL that loses them isn't a URL."""
    assert htu("https://[::1]:8443/v1") == "https://[::1]:8443/v1"


@pytest.mark.parametrize("bad", ["", "/v1/x", "not a url", "https://:8443/x"])
def test_htu_needs_an_absolute_url(bad):
    with pytest.raises(DpopError, match="absolute URL"):
        htu(bad)


def test_htu_reports_an_unreadable_port_as_a_dpop_error():
    """`urlsplit` raises a bare ValueError for this; callers of `proof` should
    only ever have to catch `MimicError`."""
    with pytest.raises(DpopError) as caught:
        htu("https://a.example:notaport/x")
    assert caught.value.field == "htu"


# ---- jti / iat ----------------------------------------------------------------

@needs_crypto
def test_jti_is_unique_across_proofs():
    """§11.1: the server declines a `jti` it has seen before, so a repeating one
    would eventually reject a request that was perfectly valid."""
    key = SoftwareKey.generate()
    seen = {json.loads(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[1]))["jti"]
            for _ in range(200)}
    assert len(seen) == 200


@needs_crypto
def test_iat_is_whole_seconds():
    """A float serializes as `1562262618.5`, which is not a NumericDate any
    server will accept."""
    key = SoftwareKey.generate()
    key._clock = lambda: 1562262618.9
    payload = json.loads(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[1]))
    assert payload["iat"] == 1562262618
    assert isinstance(payload["iat"], int)


@needs_crypto
@pytest.mark.parametrize("bad", [1.5, True, "1562262618", [1562262618], 1562262618.0])
def test_iat_rejects_anything_but_an_int(bad):
    """Including `True`, which is an int in Python but `true` in the proof."""
    key = SoftwareKey.generate()
    with pytest.raises(DpopError, match="whole seconds"):
        key.proof("GET", "https://a.example/x", iat=bad)


@needs_crypto
def test_iat_defaults_to_now_rather_than_a_literal_null():
    key = SoftwareKey.generate()
    key._clock = lambda: 1_562_262_618.0
    payload = json.loads(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[1]))
    assert payload["iat"] == 1562262618


@needs_crypto
def test_iat_inside_the_window_is_accepted():
    key = SoftwareKey.generate()
    key._clock = lambda: 1_000_000.0
    key.proof("GET", "https://a.example/x", iat=int(1_000_000 - MAX_AGE))
    key.proof("GET", "https://a.example/x", iat=int(1_000_000 + MAX_SKEW))


@needs_crypto
def test_stale_iat_names_the_age():
    key = SoftwareKey.generate()
    key._clock = lambda: 1_000_000.0
    with pytest.raises(DpopError) as caught:
        key.proof("GET", "https://a.example/x", iat=int(1_000_000 - MAX_AGE - 100))
    assert caught.value.field == "iat"
    assert "400s old" in str(caught.value)


@needs_crypto
def test_iat_from_the_future_names_the_skew():
    key = SoftwareKey.generate()
    key._clock = lambda: 1_000_000.0
    with pytest.raises(DpopError, match="ahead"):
        key.proof("GET", "https://a.example/x", iat=int(1_000_000 + MAX_SKEW + 60))


@needs_crypto
def test_a_clock_that_steps_backwards_is_caught():
    """An NTP correction mid-run would put a window the server already accepted
    into the past — and silently, because each proof looks fine on its own."""
    key = SoftwareKey.generate()
    clock = [1_000_000.0]
    key._clock = lambda: clock[0]
    key.proof("GET", "https://a.example/x")
    clock[0] -= 60
    with pytest.raises(DpopError, match="went backwards"):
        key.proof("GET", "https://a.example/x")


class _Response:
    """Just enough response for `absorb`: `headers` and an optional raw list."""

    def __init__(self, headers=(), raw=None):
        self.headers = dict(headers)
        self.raw = type("Raw", (), {"headers": raw})() if raw is not None else None


@needs_crypto
def test_clock_skew_against_the_server_is_caught_before_the_next_proof():
    """The check that actually catches a wrong clock.

    `iat` is read off the same clock it is compared against, so a machine an
    hour out signs a perfectly self-consistent, perfectly doomed proof. The
    `Date` header every response already carries is the only reference there is.
    """
    key = SoftwareKey.generate()
    key._clock = lambda: 1_000_000.0
    key.absorb(_Response(headers={"Date": "Mon, 01 Jan 2035 00:00:00 GMT"}))
    with pytest.raises(DpopError) as caught:
        key.proof("GET", "https://a.example/x")
    assert "2035" not in str(caught.value)
    assert caught.value.field == "iat"
    assert "clock" in str(caught.value)


@needs_crypto
def test_a_correct_clock_raises_nothing():
    """The other half: a `Date` within a few seconds of us must stay silent,
    or every request would fail on a machine that is fine."""
    key = SoftwareKey.generate()
    now = 1_000_000.0
    key._clock = lambda: now
    from email.utils import formatdate

    key.absorb(_Response(headers={"Date": formatdate(now, usegmt=True)}))
    key.proof("GET", "https://a.example/x")
    key.proof("GET", "https://a.example/x")


@needs_crypto
@pytest.mark.parametrize("bad", ["", "not-a-date", "Mon, 99 Xxx 2035 99:99:99 GMT"])
def test_an_unusable_date_header_is_ignored_not_fatal(bad):
    key = SoftwareKey.generate()
    key._clock = lambda: 1_000_000.0
    key.absorb(_Response(headers={"Date": bad}))
    key.proof("GET", "https://a.example/x")


@needs_crypto
def test_a_missing_date_header_leaves_a_known_skew_alone():
    """A response with no `Date` shouldn't forget what the last one said."""
    key = SoftwareKey.generate()
    key._clock = lambda: 1_000_000.0
    key.absorb(_Response(headers={"Date": "Mon, 01 Jan 2035 00:00:00 GMT"}))
    key.absorb(_Response())
    with pytest.raises(DpopError, match="clock"):
        key.proof("GET", "https://a.example/x")


# ---- the access token binding -------------------------------------------------

def test_access_token_hash_matches_the_rfc_definition():
    import hashlib

    token = "SlAV32hkKG"
    assert access_token_hash(token) == b64url_encode(
        hashlib.sha256(token.encode("ascii")).digest())


@needs_crypto
def test_ath_is_only_added_when_a_token_is_being_sent():
    key = SoftwareKey.generate()
    bare = json.loads(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[1]))
    bound = json.loads(b64url_decode(
        key.proof("GET", "https://a.example/x", access_token="t").split(".")[1]))
    assert "ath" not in bare
    assert bound["ath"] == access_token_hash("t")


@needs_crypto
def test_claim_order_matches_the_rfc_examples():
    """Cosmetic to a parser, but this is a wire format people diff by hand."""
    key = SoftwareKey.generate()
    key._nonce = "n"
    payload = json.loads(b64url_decode(
        key.proof("get", "https://a.example/x", access_token="t").split(".")[1]))
    assert list(payload) == ["jti", "htm", "htu", "iat", "ath", "nonce"]
    assert payload["htm"] == "GET"

# ---- nonce threading, over a real socket --------------------------------------
#
# `absorb` and `_first_header` are unit-testable on their own, but the thing
# that has to be true is that a nonce a server sent on a 401 ends up in the very
# next proof. That crosses the adapter, the redirect machinery, `requests`' header
# folding and `Session`'s retry loop, so it gets a real server.

NONCE = "eyJ7S_zG.eyJH0-Z.HX4w-7v"


def _payload(call):
    return json.loads(b64url_decode(call.headers[DPOP_HEADER].split(".")[1]))


def _requiring_nonce(loopback, path, nonce=NONCE):
    """A §7.1/§9 resource server: 401 + nonce until the proof carries one."""
    def handler(call):
        if _payload(call).get("nonce") == nonce:
            return 200, {}, b'{"ok":true}'
        return (401, {"WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                      NONCE_HEADER: nonce}, b'{"error":"use_dpop_nonce"}')
    loopback.route(path, handler)


@needs_crypto
def test_nonce_from_a_401_reaches_the_very_next_proof(loopback):
    """The headline: send, get challenged, sign again with what it handed back.

    Everything about this is load-bearing. The first proof can't have a nonce
    because there isn't one yet; the 401 carries it; `absorb` has to see a header
    `requests` may have folded; and `Session` has to decide the re-send is worth
    an attempt from its budget.
    """
    from mimic.transport import get_transport

    _requiring_nonce(loopback, "/protected")
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))

    assert session.get("/protected") == {"ok": True}
    assert len(loopback.calls) == 2
    assert "nonce" not in _payload(loopback.calls[0])
    assert _payload(loopback.calls[1])["nonce"] == NONCE


@needs_crypto
def test_each_retry_carries_its_own_fresh_proof(loopback):
    """§11.1: a `jti` the server has seen is refused. Re-signing per request is
    the whole point — reusing the first proof would be the replay DPoP exists to
    prevent."""
    from mimic.transport import get_transport

    _requiring_nonce(loopback, "/protected")
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    session.get("/protected")
    seen = [_payload(c)["jti"] for c in loopback.calls]
    assert len(set(seen)) == len(seen)


@needs_crypto
def test_the_nonce_is_reused_so_the_second_call_needs_no_challenge(loopback):
    """§8.2: the client keeps using a nonce until the server replaces it, so a
    warmed-up session costs one round trip per request and not two."""
    from mimic.transport import get_transport

    _requiring_nonce(loopback, "/protected")
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    session.get("/protected")
    before = len(loopback.calls)
    session.get("/protected")
    assert len(loopback.calls) - before == 1


@needs_crypto
def test_a_nonce_on_a_200_is_absorbed_without_a_retry(loopback):
    """§8.2's cheaper half: a server may hand the next nonce down with a
    success. Absorbing it here is what removes the round trip."""
    from mimic.transport import get_transport

    loopback.route("/thing", lambda c: (200, {NONCE_HEADER: "next-one"},
                                        b'{"ok":true}'))
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    session.get("/thing")
    assert key.nonce == "next-one"
    assert len(loopback.calls) == 1


@needs_crypto
def test_a_new_nonce_replaces_the_old_one_for_the_next_proof(loopback):
    """A rotating server is normal. The new value wins, and the request that
    already succeeded is not repeated."""
    from mimic.transport import get_transport

    loopback.route("/rot", lambda c: (200, {NONCE_HEADER: f"n{len(loopback.calls)}"},
                                      b'{"ok":true}'))
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    session.get("/rot")
    assert key.nonce == "n1"
    before = len(loopback.calls)
    session.get("/rot")
    assert key.nonce == "n2"
    assert len(loopback.calls) - before == 1


@needs_crypto
def test_a_server_that_challenges_forever_is_given_one_retry_only(loopback):
    """Past the handshake a further challenge means the server is rotating nonces
    faster than the exchange can follow. Retrying into that is worse than
    failing, so exactly one extra attempt happens and then it reports itself."""
    from mimic.transport import get_transport

    def handler(call):
        return (401, {NONCE_HEADER: f"rotating-{len(loopback.calls)}"},
                b'{"error":"use_dpop_nonce"}')

    loopback.route("/always", handler)
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    with pytest.raises(AuthError):
        session.get("/always")
    assert len(loopback.calls) == 2


@needs_crypto
def test_a_challenge_with_a_single_attempt_budget_reports_rather_than_returning_none(loopback):
    """`attempts=1` leaves no room for the re-send. Falling out of the loop would
    hand the caller `None` where a response was due; this is the `not last` guard
    the retry branch already needs."""
    from mimic.transport import get_transport

    _requiring_nonce(loopback, "/one")
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={}, attempts=1,
                      transport=get_transport("requests", dpop=key))
    with pytest.raises(AuthError):
        session.get("/one")
    assert len(loopback.calls) == 1


@needs_crypto
def test_a_401_without_a_nonce_is_still_an_auth_error(loopback):
    """The challenge branch must not swallow an ordinary credential failure."""
    from mimic.transport import get_transport

    loopback.route("/plain", lambda c: (401, {}, b'{"error":"unauthorized"}'))
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    with pytest.raises(AuthError):
        session.get("/plain")
    assert len(loopback.calls) == 1


@needs_crypto
def test_the_proof_survives_a_redirect(loopback):
    """The reason signing happens in an adapter and not in `request()`.

    `requests` re-prepares a request for each hop and keeps custom headers
    verbatim, so a proof attached once would arrive at `/moved` still claiming
    `htu: /start` — which §4.3 check 9 rejects.
    """
    from mimic.transport import get_transport

    loopback.route("/start", lambda c: (302, {"Location": "/moved"}, b""))
    loopback.route("/moved", lambda c: (200, {}, b'{"ok":true}'))
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    assert session.get("/start") == {"ok": True}
    assert [c.path for c in loopback.calls] == ["/start", "/moved"]
    assert _payload(loopback.calls[-1])["htu"].endswith("/moved")


@needs_crypto
def test_the_proof_is_bound_to_the_token_being_sent(loopback):
    """§4.2: `ath` is mandatory alongside an access token."""
    from mimic.transport import get_transport

    loopback.route("/me", lambda c: (200, {}, b'{"ok":true}'))
    key = SoftwareKey.generate()
    session = Session(loopback.base_url,
                      headers={"Authorization": "DPoP tok-123"},
                      transport=get_transport("requests", dpop=key))
    session.get("/me")
    assert _payload(loopback.calls[0])["ath"] == access_token_hash("tok-123")


@needs_crypto
def test_no_authorization_header_means_no_ath(loopback):
    from mimic.transport import get_transport

    loopback.route("/pub", lambda c: (200, {}, b'{"ok":true}'))
    key = SoftwareKey.generate()
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    session.get("/pub")
    assert "ath" not in _payload(loopback.calls[0])


@needs_crypto
def test_a_stale_iat_is_caught_before_anything_reaches_the_server(loopback):
    """The done-mean, at the seam: refused locally, so no server sees the proof.

    The skew is measured against the `Date` the server sends, which is the only
    clock reference there is — `iat` is read off the very clock it is compared
    against, so a machine that is simply wrong looks self-consistent. Learning
    the offset costs one response, so the first request goes out and every one
    after it is checked.
    """
    from mimic.transport import get_transport

    loopback.route("/thing", lambda c: (200, {}, b'{"ok":true}'))
    key = SoftwareKey.generate()
    key._clock = lambda: time.time() - 100_000  # a machine ~28 hours behind
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))

    session.get("/thing")          # goes out; the response teaches us the offset
    before = len(loopback.calls)

    with pytest.raises(DpopError) as caught:
        session.get("/thing")
    assert caught.value.field == "iat"
    assert "behind" in str(caught.value)
    assert len(loopback.calls) == before


@needs_crypto
def test_a_clock_wrong_in_the_other_direction_is_caught_too(loopback):
    """Ahead reads as replayed just as surely as behind does."""
    from mimic.transport import get_transport

    loopback.route("/thing", lambda c: (200, {}, b'{"ok":true}'))
    key = SoftwareKey.generate()
    key._clock = lambda: time.time() + 100_000
    session = Session(loopback.base_url, headers={},
                      transport=get_transport("requests", dpop=key))
    session.get("/thing")
    before = len(loopback.calls)
    with pytest.raises(DpopError, match="ahead"):
        session.get("/thing")
    assert len(loopback.calls) == before


# ---- nonce selection ----------------------------------------------------------

@needs_crypto
def test_two_nonce_headers_the_first_arrived_wins():
    """§8 forbids more than one, and `requests` folds them into `'a, b'`.

    The folded form can't be split safely — a nonce may legally contain a comma
    — so the raw message is read instead, which keeps them apart and in order.
    """
    key = SoftwareKey.generate()
    key.absorb(_Response(headers={NONCE_HEADER: "SECOND, FIRST"},
                         raw=_Headers([("DPoP-Nonce", "FIRST"),
                                       ("DPoP-Nonce", "SECOND")])))
    assert key.nonce == "FIRST"


@needs_crypto
def test_a_folded_nonce_with_no_raw_message_is_taken_as_one_value():
    """Better a doubtful nonce than a guessed one: splitting on ',' could cut a
    single legitimate nonce in half."""
    key = SoftwareKey.generate()
    key.absorb(_Response(headers={NONCE_HEADER: "a,b"}))
    assert key.nonce == "a,b"


class _Headers:
    """An `http.client.HTTPMessage`-alike: case-insensitive, ordered."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def getlist(self, name):
        lowered = name.lower()
        return [v for k, v in self._pairs if k.lower() == lowered]

    def get(self, name, default=None):
        values = self.getlist(name)
        return values[0] if values else default


@needs_crypto
def test_absorbing_a_nonce_the_proof_already_had_is_not_a_challenge():
    """A server echoing the nonce we used is telling us it was right, not
    asking for another attempt."""
    key = SoftwareKey.generate()
    key._nonce = "same"
    key.proof("GET", "https://a.example/x")
    assert key.absorb(_Response(headers={NONCE_HEADER: "same"})) is False


@needs_crypto
def test_a_response_with_no_nonce_is_not_a_challenge():
    key = SoftwareKey.generate()
    assert key.absorb(_Response()) is False
    assert key.nonce is None


@needs_crypto
def test_absorbing_a_blank_nonce_header_keeps_the_old_one():
    key = SoftwareKey.generate()
    key._nonce = "kept"
    assert key.absorb(_Response(headers={NONCE_HEADER: "   "})) is False
    assert key.nonce == "kept"


@needs_crypto
def test_a_failed_signing_leaves_the_signer_believing_no_nonce_was_sent():
    """`proof` records the nonce it sent only after the signature succeeds, so a
    failure can't leave it one retry short of the handshake."""
    from mimic.dpop import Signer

    def explode(data):
        raise DpopError("device went away")

    key = Signer("ES256", RFC9449_JWK, explode)
    key._nonce = "n"
    with pytest.raises(DpopError):
        key.proof("GET", "https://a.example/x")
    assert key._sent_nonce is None


# ---- the vault-backed software key --------------------------------------------

def _verify_es256(jwt):
    """Verify `jwt` the way a server would, using only its own `jwk`."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    header_seg, payload_seg, sig_seg = jwt.split(".")
    jwk = json.loads(b64url_decode(header_seg))["jwk"]
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64url_decode(jwk["x"]), "big"),
        int.from_bytes(b64url_decode(jwk["y"]), "big"),
        ec.SECP256R1())
    signature = b64url_decode(sig_seg)
    half = len(signature) // 2
    numbers.public_key().verify(
        utils.encode_dss_signature(
            int.from_bytes(signature[:half], "big"),
            int.from_bytes(signature[half:], "big")),
        f"{header_seg}.{payload_seg}".encode(), ec.ECDSA(hashes.SHA256()))


@needs_crypto
def test_a_key_survives_a_round_trip_through_the_vault(tmp_path):
    """The private half is a credential like any other — it gets the vault's
    encryption, atomic write and name binding, not a plaintext file."""
    from mimic.vault import Vault

    vault = Vault(directory=tmp_path, passphrase="hunter2", n=2 ** 4)
    key = SoftwareKey.generate()
    key.save(vault, "dpop-key")

    reloaded = SoftwareKey.load(vault, "dpop-key")
    assert reloaded.jwk == key.jwk
    assert reloaded.alg == key.alg
    assert reloaded.thumbprint == key.thumbprint
    # The same key, not a lookalike: the reloaded half verifies the proof.
    _verify_es256(reloaded.proof("GET", "https://a.example/x"))


@needs_crypto
def test_a_stored_key_file_is_not_plaintext(tmp_path):
    """The file on disk must be the vault's ciphertext envelope, not a JSON blob
    with a private key sitting in it."""
    from mimic.vault import Vault

    vault = Vault(directory=tmp_path, passphrase="hunter2", n=2 ** 4)
    key = SoftwareKey.generate()
    path = key.save(vault, "dpop-key")
    raw = open(path, "rb").read()
    assert b'"d"' not in raw
    assert json.loads(raw)["version"] == 1


@needs_crypto
def test_a_stored_key_holding_only_the_public_half_is_rejected(tmp_path):
    from mimic.vault import Vault

    vault = Vault(directory=tmp_path, passphrase="hunter2", n=2 ** 4)
    key = SoftwareKey.generate()
    vault.save("dpop-key", json.dumps({"alg": key.alg, "jwk": key.jwk}).encode())
    with pytest.raises(DpopError, match="private JWK"):
        SoftwareKey.load(vault, "dpop-key")


@needs_crypto
def test_a_key_file_whose_halves_disagree_is_refused(tmp_path):
    """The dangerous corruption: the file parses, signs, and every proof fails
    verification at a server with nothing to say why.

    `cryptography` would derive a key from `d` without comparing it to `x`, so
    without this check the mismatch surfaces as an unexplained 401 on every
    single request instead of as a message naming the key.
    """
    from mimic.vault import Vault

    vault = Vault(directory=tmp_path, passphrase="hunter2", n=2 ** 4)
    good, other = SoftwareKey.generate(), SoftwareKey.generate()
    from mimic.dpop import _private_jwk

    mangled = dict(_private_jwk(other), **{"x": good.jwk["x"], "y": good.jwk["y"]})
    vault.save("mixed", json.dumps({"alg": good.alg, "jwk": mangled}).encode())

    with pytest.raises(DpopError, match="private half"):
        SoftwareKey.load(vault, "mixed")


@needs_crypto
def test_a_key_file_that_is_not_json_names_itself(tmp_path):
    from mimic.vault import Vault

    vault = Vault(directory=tmp_path, passphrase="hunter2", n=2 ** 4)
    vault.save("junk", b"not json at all")
    with pytest.raises(DpopError, match="readable key file"):
        SoftwareKey.load(vault, "junk")


@needs_crypto
def test_a_curve_mimic_has_no_signer_for_is_refused(tmp_path):
    from mimic.vault import Vault

    vault = Vault(directory=tmp_path, passphrase="hunter2", n=2 ** 4)
    vault.save("x448", json.dumps(
        {"alg": "ES256", "jwk": {"kty": "OKP", "crv": "X448", "d": "AAAA",
                                 "x": "AAAA"}}).encode())
    with pytest.raises(DpopError, match="no DPoP signer"):
        SoftwareKey.load(vault, "x448")


@needs_crypto
@pytest.mark.parametrize("alg", ["ES384", "ES512"])
def test_the_larger_curves_round_trip(alg):
    """P-384 and P-521 exist in the tables, so they had better work end to end."""
    key = SoftwareKey.generate(alg)
    assert key.alg == alg
    assert key.jwk["crv"] == {"ES384": "P-384", "ES512": "P-521"}[alg]
    length = {"ES384": 96, "ES512": 132}[alg]
    assert len(b64url_decode(key.proof("GET", "https://a.example/x").split(".")[2])) == length


# ---- the tethered-device oracle -----------------------------------------------

DEVICE_SCRIPT = """
import sys
sys.path.insert(0, {repo!r})
from mimic.dpop import b64url_encode, _raw_signer, _private_key
key = _private_key({jwk})
sys.stdout.write(b64url_encode(_raw_signer({alg!r}, key)(sys.stdin.buffer.read())))
"""


def _device_command(key, tmp_path):
    """A stand-in for the Frida bridge: reads stdin, writes a signature."""
    from mimic.dpop import _private_jwk

    script = tmp_path / "device.py"
    script.write_text(DEVICE_SCRIPT.format(
        repo=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        jwk=_private_jwk(key), alg=key.alg))
    return [sys.executable, str(script)]


@needs_crypto
def test_the_oracle_signs_through_the_bridge_and_the_result_verifies(tmp_path):
    """The tethered path, end to end: mimic never touches the key, the bridge
    does, and what comes back is a real signature over the real signing input."""
    software = SoftwareKey.generate()
    oracle = device_oracle("ES256", software.jwk, _device_command(software, tmp_path))

    assert oracle.thumbprint == software.thumbprint
    assert oracle.jwk == software.jwk
    _verify_es256(oracle.proof("GET", "https://a.example/x"))


@needs_crypto
def test_the_oracle_drives_a_session_end_to_end(tmp_path):
    """Same nonce handshake as the software key, one subprocess per signature.

    This is the cost the docs have to be honest about: a request costs a process
    spawn against a tethered device, and a nonce-using server costs two requests
    to learn the nonce before the device signs anything that carries it.
    """
    from mimic.transport import get_transport

    software = SoftwareKey.generate()
    oracle = device_oracle("ES256", software.jwk, _device_command(software, tmp_path))
    server = Loopback().start()
    try:
        _requiring_nonce(server, "/protected")
        session = Session(server.base_url, headers={},
                          transport=get_transport("requests", dpop=oracle))
        assert session.get("/protected") == {"ok": True}
        assert len(server.calls) == 2
        assert _payload(server.calls[1])["nonce"] == NONCE
    finally:
        server.stop()


@needs_crypto
def test_an_enclave_key_with_no_device_degrades_to_a_named_error():
    """The done-mean: no pretending to sign.

    A Secure Enclave key cannot be extracted — not by mimic, not by a jailbreak —
    so a caller who has one and no bridge has no working path. The only wrong
    answer is returning something that would send an unsigned request and read
    the resulting 401 as a dead session.
    """
    key = SoftwareKey.generate()
    with pytest.raises(DpopError) as caught:
        device_oracle("ES256", key.jwk)  # extractable=False, command=None
    message = str(caught.value)
    assert caught.value.field == "command"
    assert "non-extractable" in message
    assert "mimic unpin" in message          # points at the route that does work
    assert "no third one" in message         # and says there isn't a third


@needs_crypto
def test_an_extractable_key_is_told_to_use_the_software_path():
    """The same mistake with the opposite diagnosis shouldn't get the enclave
    story — the key can be dumped, so that's the advice."""
    key = SoftwareKey.generate()
    with pytest.raises(DpopError, match="can be extracted"):
        device_oracle("ES256", key.jwk, extractable=True)


@needs_crypto
def test_the_oracle_needs_a_command_even_when_constructed_directly():
    """`device_oracle` catches an empty command on the way in; constructing the
    signer yourself shouldn't get further than it does."""
    from mimic.dpop import DeviceOracle

    with pytest.raises(DpopError, match="needs a bridge command"):
        DeviceOracle("ES256", RFC9449_JWK, [])


@needs_crypto
def test_an_unreachable_bridge_is_named_rather_than_signed_around():
    oracle = device_oracle("ES256", RFC9449_JWK, ["definitely-not-a-real-binary-xyz"])
    with pytest.raises(DpopError) as caught:
        oracle.proof("GET", "https://a.example/x")
    assert caught.value.field == "command"
    assert "definitely-not-a-real-binary-xyz" in str(caught.value)


@needs_crypto
def test_a_bridge_that_fails_says_what_it_printed(tmp_path):
    script = tmp_path / "boom.py"
    script.write_text("import sys; sys.stderr.write('no frida-server\\n'); sys.exit(3)")
    oracle = device_oracle("ES256", RFC9449_JWK, [sys.executable, str(script)])
    with pytest.raises(DpopError, match="exited 3.*no frida-server"):
        oracle.proof("GET", "https://a.example/x")


@needs_crypto
def test_a_bridge_that_signs_nothing_refuses_rather_than_sending_it(tmp_path):
    """Exiting 0 with empty stdout is the shape a hook that didn't attach takes.
    Sending that on as an empty signature would be worse than failing."""
    script = tmp_path / "silent.py"
    script.write_text("import sys; sys.exit(0)")
    oracle = device_oracle("ES256", RFC9449_JWK, [sys.executable, str(script)])
    with pytest.raises(DpopError, match="without writing a signature"):
        oracle.proof("GET", "https://a.example/x")


@needs_crypto
def test_a_bridge_that_writes_padded_base64_is_rejected(tmp_path):
    """Same rule as everywhere else: the unpadded form, or it isn't this
    protocol's encoding."""
    script = tmp_path / "padded.py"
    script.write_text("import sys; sys.stdout.write('QUJDRA==' + chr(10))")
    oracle = device_oracle("ES256", RFC9449_JWK, [sys.executable, str(script)])
    with pytest.raises(DpopError, match="padding"):
        oracle.proof("GET", "https://a.example/x")


@needs_crypto
def test_a_bridge_that_hangs_is_cut_off(tmp_path):
    """A phone that stopped answering must not hold a run open forever."""
    script = tmp_path / "hang.py"
    script.write_text("import time; time.sleep(30)")
    oracle = device_oracle("ES256", RFC9449_JWK, [sys.executable, str(script)],
                           timeout=0.4)
    with pytest.raises(DpopError, match="couldn't reach"):
        oracle.proof("GET", "https://a.example/x")


@needs_crypto
def test_the_oracle_holds_no_private_key():
    """The property the whole design rests on. `_key` is set only by
    `SoftwareKey._wrap`; an oracle must never acquire one."""
    oracle = device_oracle("ES256", RFC9449_JWK, [sys.executable, "-c", "pass"])
    assert getattr(oracle, "_key", None) is None
    assert "d" not in oracle.jwk


# ---- the seam -----------------------------------------------------------------

@needs_crypto
def test_a_transport_without_dpop_never_signs_and_never_claims_a_challenge(loopback):
    """The default is no DPoP at all, and it has to say so by doing nothing."""
    from mimic.transport import get_transport

    transport = get_transport("requests")
    assert transport.dpop is None
    loopback.route("/plain", lambda c: (200, {}, b"{}"))
    Session(loopback.base_url, transport=transport).get("/plain")
    assert DPOP_HEADER not in loopback.calls[0].headers
    assert transport.absorb_nonce(_Response(headers={NONCE_HEADER: "x"})) is False


def test_the_base_transport_declines_a_nonce_challenge():
    from mimic.transport.base import Transport

    class Bare(Transport):
        def request(self, *a, **kw):
            raise NotImplementedError

    assert Bare().dpop is None
    assert Bare().absorb_nonce(_Response(headers={NONCE_HEADER: "x"})) is False


@needs_crypto
def test_curl_transport_refuses_dpop_rather_than_half_supporting_it():
    """Signing once per call would attach a proof that follows a redirect to a
    URL it no longer describes, so the combination is refused with a reason
    instead of quietly sending proofs that work until the first redirect."""
    pytest.importorskip("curl_cffi")
    from mimic.transport import get_transport

    with pytest.raises(DpopError, match="requests transport only"):
        get_transport("curl", dpop=SoftwareKey.generate())


def test_the_curl_refusal_is_checked_before_curl_is_even_loaded():
    """The error is about DPoP, so it shouldn't be masked by a missing extra."""
    from mimic.transport.curl_transport import CurlTransport

    with pytest.raises(DpopError, match="requests transport only"):
        CurlTransport(dpop=object())


# ---- the module imports without the extra -------------------------------------

def test_importing_dpop_needs_neither_the_extra_nor_requests():
    """Same rule as the vault: the package has to stay importable on a machine
    that has never heard of `cryptography`, and nothing here should reach for it
    until a key is actually made."""
    code = (
        "import sys; import mimic.dpop as d; "
        "assert d.SoftwareKey is not None; "
        "print('ok')"
    )
    env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    done = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, env=env, cwd=os.path.dirname(
                              os.path.dirname(os.path.abspath(__file__))))
    assert "ok" in done.stdout, done.stderr


def test_asking_for_a_key_without_the_extra_names_the_install():
    import mimic.dpop as dpop

    saved = dpop._BACKEND
    dpop._BACKEND = None
    saved_modules = {name: sys.modules.get(name)
                     for name in ("cryptography", "cryptography.hazmat",
                                  "cryptography.hazmat.primitives")}
    for name in saved_modules:
        sys.modules[name] = None  # makes `import cryptography` raise ImportError
    try:
        with pytest.raises(DpopError, match="mimic-client\\[dpop\\]"):
            dpop.SoftwareKey.generate()
        with pytest.raises(DpopError, match="mimic-client\\[dpop\\]"):
            dpop.jwk_for(object())
    finally:
        dpop._BACKEND = saved
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
